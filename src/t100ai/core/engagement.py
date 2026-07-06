"""Engagement Management - Multi-client professional audit management."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class Engagement:
    """A professional security engagement (audit/pentest)."""
    id: str
    client_name: str
    engagement_type: str  # pentest, audit, red-team, blue-team, ir
    scope: list[str] = field(default_factory=list)
    start_date: str = ""
    end_date: str = ""
    status: str = "planned"  # planned, active, paused, completed, cancelled
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    notes: str = ""
    team_members: list[str] = field(default_factory=list)
    rules_of_engagement: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.updated_at:
            self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "client_name": self.client_name,
            "engagement_type": self.engagement_type,
            "scope": self.scope,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "status": self.status,
            "findings_count": self.findings_count,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "notes": self.notes,
            "team_members": self.team_members,
            "rules_of_engagement": self.rules_of_engagement,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class EngagementManager:
    """Manages multiple security engagements (audits/pentests).

    Supports multi-client operations with full lifecycle management.

    Usage:
        mgr = EngagementManager()
        eng = mgr.create_engagement("Acme Corp", "pentest", scope=["10.0.0.0/24"])
        mgr.start_engagement(eng.id)
        mgr.add_finding(eng.id, "HIGH")
        report = mgr.get_engagement_report(eng.id)
    """

    def __init__(self, storage_path: Optional[str] = None) -> None:
        self._engagements: dict[str, Engagement] = {}
        self._storage = Path(storage_path) if storage_path else None
        if self._storage and self._storage.exists():
            self._load()

    def create_engagement(self, client_name: str, engagement_type: str,
                          scope: Optional[list[str]] = None,
                          team_members: Optional[list[str]] = None,
                          rules_of_engment: str = "") -> Engagement:
        """Create a new engagement."""
        eng = Engagement(
            id=f"ENG-{uuid.uuid4().hex[:8].upper()}",
            client_name=client_name,
            engagement_type=engagement_type,
            scope=scope or [],
            team_members=team_members or [],
            rules_of_engagement=rules_of_engment,
        )
        self._engagements[eng.id] = eng
        self._save()
        return eng

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        """Get an engagement by ID."""
        return self._engagements.get(engagement_id)

    def list_engagements(self, status: Optional[str] = None,
                         client: Optional[str] = None) -> list[Engagement]:
        """List engagements with optional filters."""
        result = list(self._engagements.values())
        if status:
            result = [e for e in result if e.status == status]
        if client:
            result = [e for e in result if client.lower() in e.client_name.lower()]
        return sorted(result, key=lambda e: e.created_at, reverse=True)

    def start_engagement(self, engagement_id: str) -> bool:
        """Start an engagement."""
        eng = self._engagements.get(engagement_id)
        if not eng or eng.status not in ("planned", "paused"):
            return False
        eng.status = "active"
        eng.start_date = datetime.now(timezone.utc).isoformat()
        eng.updated_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

    def pause_engagement(self, engagement_id: str) -> bool:
        """Pause an engagement."""
        eng = self._engagements.get(engagement_id)
        if not eng or eng.status != "active":
            return False
        eng.status = "paused"
        eng.updated_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

    def complete_engagement(self, engagement_id: str) -> bool:
        """Complete an engagement."""
        eng = self._engagements.get(engagement_id)
        if not eng or eng.status not in ("active", "paused"):
            return False
        eng.status = "completed"
        eng.end_date = datetime.now(timezone.utc).isoformat()
        eng.updated_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

    def add_finding(self, engagement_id: str, severity: str) -> bool:
        """Record a finding for an engagement."""
        eng = self._engagements.get(engagement_id)
        if not eng:
            return False
        eng.findings_count += 1
        if severity == "CRIT":
            eng.critical_findings += 1
        elif severity == "HIGH":
            eng.high_findings += 1
        eng.updated_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return True

    def get_engagement_report(self, engagement_id: str) -> Optional[dict[str, Any]]:
        """Generate a report for an engagement."""
        eng = self._engagements.get(engagement_id)
        if not eng:
            return None
        return {
            "engagement": eng.to_dict(),
            "summary": {
                "total_findings": eng.findings_count,
                "critical": eng.critical_findings,
                "high": eng.high_findings,
                "medium": max(0, eng.findings_count - eng.critical_findings - eng.high_findings),
                "risk_level": "CRITICAL" if eng.critical_findings > 0 else "HIGH" if eng.high_findings > 0 else "MEDIUM",
            },
            "timeline": {
                "created": eng.created_at,
                "started": eng.start_date,
                "completed": eng.end_date,
                "duration_days": self._calc_duration(eng),
            },
        }

    def get_stats(self) -> dict[str, Any]:
        """Return overall engagement statistics."""
        engagements = list(self._engagements.values())
        by_status: dict[str, int] = {}
        by_type: dict[str, int] = {}
        total_findings = 0
        total_critical = 0
        for eng in engagements:
            by_status[eng.status] = by_status.get(eng.status, 0) + 1
            by_type[eng.engagement_type] = by_type.get(eng.engagement_type, 0) + 1
            total_findings += eng.findings_count
            total_critical += eng.critical_findings

        return {
            "total_engagements": len(engagements),
            "by_status": by_status,
            "by_type": by_type,
            "total_findings": total_findings,
            "total_critical": total_critical,
            "active_engagements": by_status.get("active", 0),
            "unique_clients": len({e.client_name for e in engagements}),
        }

    def _calc_duration(self, eng: Engagement) -> int:
        """Calculate engagement duration in days."""
        try:
            start = datetime.fromisoformat(eng.start_date)
            end = datetime.fromisoformat(eng.end_date) if eng.end_date else datetime.now(timezone.utc)
            return (end - start).days
        except Exception:
            return 0

    def _save(self) -> None:
        """Persist to disk."""
        if not self._storage:
            return
        self._storage.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v.to_dict() for k, v in self._engagements.items()}
        self._storage.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        """Load from disk."""
        if not self._storage or not self._storage.exists():
            return
        try:
            data = json.loads(self._storage.read_text())
            for eng_id, eng_data in data.items():
                self._engagements[eng_id] = Engagement(**eng_data)
        except Exception:
            pass
