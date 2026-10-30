from django.conf import settings
from django.db import models


class ScanRecord(models.Model):
    """One saved scan (network / website / system) belonging to a user."""

    TYPES = [
        ("network", "Network scan"),
        ("website", "Website scan"),
        ("system", "System scan"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scans"
    )
    scan_type = models.CharField(max_length=16, choices=TYPES)
    target = models.CharField(max_length=500)
    risk_level = models.CharField(max_length=20)
    ml_score = models.FloatField(default=0.0, help_text="ML threat score 0-100")
    summary = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"#{self.pk} {self.scan_type} {self.target} [{self.risk_level}]"


class LoginEvent(models.Model):
    """Audit trail of login attempts made through the TriScan CLI."""

    username = models.CharField(max_length=150)
    success = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
