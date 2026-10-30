"""Machine-learning layer for TriScan (scikit-learn Random Forests).

Three detectors share one implementation:

    network  -> BENIGN / SUSPICIOUS / MALICIOUS
    website  -> SAFE   / SUSPICIOUS / MALICIOUS
    system   -> HEALTHY / WARNING   / CRITICAL

Training data
-------------
No labelled public dataset ships with TriScan, so on first run each model is
trained on a *synthetic* dataset sampled from class-conditional distributions
that encode common security heuristics. That gives a working baseline.
For real-world accuracy, drop your own labelled CSV into ``data/``:

    data/network_dataset.csv   data/website_dataset.csv   data/system_dataset.csv

(columns = the feature names listed below + a ``label`` column holding the
class name or 0/1/2) and run ``python triscan.py --train``.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
MODEL_DIR = DATA_DIR / "models"

# Each spec entry: feature -> (kind, per-class parameter, extra)
#   bern : probability of 1
#   pois : poisson mean
#   norm : gaussian mean (extra = std), clipped to [lo, hi]
NETWORK_SPEC = {
    "is_private":        ("bern", [0.45, 0.15, 0.03], None),
    "is_india":          ("bern", [0.15, 0.25, 0.10], None),
    "open_ports":        ("pois", [1.5, 3.0, 5.0], None),
    "risky_ports":       ("pois", [0.1, 1.2, 3.0], None),
    "is_hosting_proxy":  ("bern", [0.10, 0.40, 0.70], None),
    "no_reverse_dns":    ("bern", [0.20, 0.60, 0.85], None),
    "latency_ms":        ("norm", [40, 90, 140], (40, 0, 800)),
    "conn_count":        ("pois", [2.0, 4.0, 9.0], None),
}

WEBSITE_SPEC = {
    "no_https":                ("bern", [0.08, 0.35, 0.50], None),
    "tls_problem":             ("bern", [0.03, 0.20, 0.30], None),
    "missing_sec_headers":     ("pois", [2.5, 4.0, 4.5], None),
    "insecure_cookies":        ("pois", [0.4, 1.0, 1.0], None),
    "mixed_content":           ("pois", [0.3, 1.5, 1.5], None),
    "password_over_http":      ("bern", [0.01, 0.25, 0.30], None),
    "external_forms":          ("bern", [0.03, 0.25, 0.35], None),
    "hidden_iframes":          ("pois", [0.02, 0.5, 2.0], None),
    "obfuscated_js":           ("pois", [0.05, 1.0, 3.0], None),
    "miner_signatures":        ("bern", [0.0, 0.10, 0.40], None),
    "exec_downloads":          ("pois", [0.02, 0.5, 1.5], None),
    "suspicious_script_hosts": ("pois", [0.05, 0.8, 2.0], None),
    "info_leaks":              ("pois", [0.4, 1.5, 1.5], None),
    "exposed_files":           ("pois", [0.03, 0.7, 1.0], None),
    "broken_link_ratio":       ("norm", [0.03, 0.10, 0.15], (0.05, 0.0, 1.0)),
    "url_is_ip":               ("bern", [0.01, 0.10, 0.25], None),
    "url_length":              ("norm", [30, 45, 70], (18, 8, 300)),
    "host_dots":               ("pois", [1.2, 1.8, 2.8], None),
    "suspicious_tld":          ("bern", [0.03, 0.20, 0.40], None),
    "cross_domain_redirects":  ("pois", [0.1, 0.4, 1.0], None),
}

SYSTEM_SPEC = {
    "cpu_percent":     ("norm", [25, 55, 90], (15, 0, 100)),
    "ram_percent":     ("norm", [40, 70, 92], (12, 0, 100)),
    "disk_percent":    ("norm", [45, 70, 93], (15, 0, 100)),
    "swap_percent":    ("norm", [5, 25, 70], (15, 0, 100)),
    "world_writable":  ("pois", [0.2, 3.0, 12.0], None),
    "suid_unusual":    ("pois", [0.1, 1.5, 5.0], None),
    "risky_listeners": ("pois", [0.2, 1.5, 4.0], None),
    "tmp_executables": ("pois", [0.1, 1.5, 6.0], None),
    "suspicious_procs": ("pois", [0.0, 0.2, 1.5], None),
    "perm_issues":     ("pois", [0.0, 1.0, 3.0], None),
    "battery_pct":     ("norm", [70, 45, 20], (25, 0, 100)),
    "on_battery":      ("bern", [0.20, 0.40, 0.60], None),
}

# Features that exceed these hints are clipped so the forest never extrapolates wildly.
LABELS = {
    "network": ["BENIGN", "SUSPICIOUS", "MALICIOUS"],
    "website": ["SAFE", "SUSPICIOUS", "MALICIOUS"],
    "system":  ["HEALTHY", "WARNING", "CRITICAL"],
}
PRIORS = {
    "network": [0.55, 0.30, 0.15],
    "website": [0.60, 0.25, 0.15],
    "system":  [0.55, 0.30, 0.15],
}
SPECS = {"network": NETWORK_SPEC, "website": WEBSITE_SPEC, "system": SYSTEM_SPEC}


def _sample(spec: dict, priors, n: int, rng: np.random.Generator):
    y = rng.choice(len(priors), size=n, p=priors)
    cols = []
    for _, (kind, params, extra) in spec.items():
        p = np.asarray(params, dtype=float)[y]
        if kind == "bern":
            col = (rng.random(n) < p).astype(float)
        elif kind == "pois":
            col = rng.poisson(p).astype(float)
        else:  # norm
            std, lo, hi = extra
            col = np.clip(rng.normal(p, std), lo, hi)
        cols.append(col)
    X = np.column_stack(cols)
    names = list(spec)
    if "is_private" in names and "is_india" in names:   # private addresses are never "India"
        X[:, names.index("is_india")] *= 1 - X[:, names.index("is_private")]
    return X, y


class Detector:
    """A Random Forest classifier with lazy training, persistence and
    occlusion-based explanations."""

    def __init__(self, key: str):
        self.key = key
        self.spec = SPECS[key]
        self.features = list(self.spec)
        self.labels = LABELS[key]
        self.priors = PRIORS[key]
        self.model = None
        self.meta: dict = {}
        # "Normal" reference values (benign-class centre) used for explanations.
        self.baseline = np.array([
            (self.spec[f][1][0]) for f in self.features], dtype=float)

    # ---------- persistence ----------
    @property
    def _path(self) -> Path:
        return MODEL_DIR / f"{self.key}_rf.joblib"

    @property
    def _meta_path(self) -> Path:
        return MODEL_DIR / f"{self.key}_meta.json"

    def ensure(self):
        if self.model is not None:
            return self
        import joblib
        if self._path.exists():
            try:
                self.model = joblib.load(self._path)
                if self._meta_path.exists():
                    self.meta = json.loads(self._meta_path.read_text())
                if getattr(self.model, "n_features_in_", None) == len(self.features):
                    return self
            except Exception:
                pass
        self.train()
        return self

    # ---------- training ----------
    def _dataset(self, n: int, seed: int):
        csv = DATA_DIR / f"{self.key}_dataset.csv"
        if csv.exists():
            import pandas as pd
            df = pd.read_csv(csv)
            missing = [f for f in self.features if f not in df.columns]
            if missing or "label" not in df.columns:
                raise ValueError(f"{csv.name} is missing columns: {missing or ['label']}")
            lab = df["label"]
            if lab.dtype == object:
                lab = lab.str.upper().map({l: i for i, l in enumerate(self.labels)})
            return df[self.features].to_numpy(float), lab.to_numpy(int), f"csv:{csv.name}"
        rng = np.random.default_rng(seed)
        X, y = _sample(self.spec, self.priors, n, rng)
        return X, y, "synthetic"

    def train(self, n: int = 8000, seed: int = 42) -> dict:
        import joblib
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, f1_score
        from sklearn.model_selection import train_test_split

        X, y, source = self._dataset(n, seed)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=seed, stratify=y)
        clf = RandomForestClassifier(
            n_estimators=200, max_depth=14, min_samples_leaf=2,
            class_weight="balanced", random_state=seed, n_jobs=-1,
        ).fit(Xtr, ytr)
        pred = clf.predict(Xte)
        self.model = clf
        self.meta = {
            "detector": self.key,
            "source": source,
            "samples": int(len(X)),
            "accuracy": round(float(accuracy_score(yte, pred)), 4),
            "macro_f1": round(float(f1_score(yte, pred, average="macro")), 4),
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "features": self.features,
        }
        if source != "synthetic":
            self.baseline = np.median(X[y == 0], axis=0)
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, self._path)
        self._meta_path.write_text(json.dumps(self.meta, indent=2))
        return self.meta

    # ---------- inference ----------
    def _vec(self, feats: dict) -> np.ndarray:
        return np.array([[float(feats.get(f, 0) or 0) for f in self.features]])

    def _threat(self, proba: np.ndarray) -> float:
        """Expected severity mapped to 0-100 (class 1 counts half, class 2 full)."""
        k = len(proba) - 1
        return float(sum(p * i / k for i, p in enumerate(proba)) * 100)

    def predict(self, feats: dict, explain: bool = True) -> dict:
        self.ensure()
        x = self._vec(feats)
        proba = self.model.predict_proba(x)[0]
        full = np.zeros(len(self.labels))
        for cls, p in zip(self.model.classes_, proba):
            full[int(cls)] = p
        idx = int(np.argmax(full))
        score = self._threat(full)
        drivers = []
        if explain:
            for i, f in enumerate(self.features):
                if x[0, i] == self.baseline[i]:
                    continue
                x2 = x.copy()
                x2[0, i] = self.baseline[i]
                p2 = np.zeros(len(self.labels))
                for cls, p in zip(self.model.classes_, self.model.predict_proba(x2)[0]):
                    p2[int(cls)] = p
                delta = score - self._threat(p2)
                if delta > 1.0:
                    drivers.append((f, float(x[0, i]), round(delta, 1)))
            drivers.sort(key=lambda t: -t[2])
        return {
            "label": self.labels[idx],
            "score": round(score, 1),
            "proba": {l: round(float(p), 3) for l, p in zip(self.labels, full)},
            "drivers": drivers[:4],
        }


DETECTORS = {k: Detector(k) for k in SPECS}


def get(key: str) -> Detector:
    return DETECTORS[key].ensure()


def train_all(n: int = 8000) -> dict:
    return {k: d.train(n) for k, d in DETECTORS.items()}


if __name__ == "__main__":
    for k, m in train_all().items():
        print(f"{k:8s} acc={m['accuracy']:.3f} f1={m['macro_f1']:.3f} source={m['source']}")
