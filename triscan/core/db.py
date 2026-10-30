"""Django bootstrap + history helpers (the only module that touches the ORM)."""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def init() -> None:
    """Configure Django, create migrations on first run and apply them."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django
    django.setup()
    from django.core.management import call_command

    mig = ROOT / "history" / "migrations"
    if not any(p.suffix == ".py" and p.name != "__init__.py" for p in mig.glob("*.py")):
        call_command("makemigrations", "history", interactive=False, verbosity=0)
    call_command("migrate", interactive=False, verbosity=0)


def _json_safe(obj):
    return json.loads(json.dumps(obj, default=lambda o: sorted(o) if isinstance(o, (set, frozenset)) else str(o)))


def save_scan(user, scan_type: str, target: str, risk_level: str, ml_score: float,
              summary: str, details: dict):
    from history.models import ScanRecord
    return ScanRecord.objects.create(
        user=user, scan_type=scan_type, target=target[:500], risk_level=risk_level,
        ml_score=float(ml_score), summary=summary, details=_json_safe(details),
    )


def list_scans(user, limit: int = 25):
    from history.models import ScanRecord
    return list(ScanRecord.objects.filter(user=user)[:limit])


def get_scan(user, pk: int):
    from history.models import ScanRecord
    return ScanRecord.objects.filter(user=user, pk=pk).first()


def delete_scan(user, pk: int) -> bool:
    from history.models import ScanRecord
    n, _ = ScanRecord.objects.filter(user=user, pk=pk).delete()
    return bool(n)


def log_login(username: str, success: bool) -> None:
    from history.models import LoginEvent
    LoginEvent.objects.create(username=username[:150], success=success)
