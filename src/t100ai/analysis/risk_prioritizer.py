"""Risk Prioritization Engine - Composite scoring for finding prioritization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RiskFactors:
    """Factors used in risk calculation."""
    cvss_score: float = 0.0
    exploitability: float = 0.5
    business_impact: float = 0.5
    exposure: float = 0.5
    asset_value: float = 0.5
    threat_intel_match: bool = False
    active_exploit: bool = False
    compliance_violation: bool = False


class RiskPrioritizer:
    """Prioritizes findings using a composite risk score.

    Score = (CVSS × 0.3) + (Exploitability × 0.2) + (Business Impact × 0.2)
          + (Exposure × 0.15) + (Asset Value × 0.15)

    Bonus multipliers:
    - Active exploit in the wild: × 1.3
    - Threat intel match: × 1.2
    - Compliance violation: × 1.1
    """

    WEIGHTS = {
        "cvss": 0.30,
        "exploitability": 0.20,
        "business_impact": 0.20,
        "exposure": 0.15,
        "asset_value": 0.15,
    }

    def calculate_risk(self, factors: RiskFactors) -> dict[str, Any]:
        """Calculate composite risk score."""
        base = (
            (factors.cvss_score / 10.0) * self.WEIGHTS["cvss"]
            + factors.exploitability * self.WEIGHTS["exploitability"]
            + factors.business_impact * self.WEIGHTS["business_impact"]
            + factors.exposure * self.WEIGHTS["exposure"]
            + factors.asset_value * self.WEIGHTS["asset_value"]
        )

        multiplier = 1.0
        if factors.active_exploit:
            multiplier *= 1.3
        if factors.threat_intel_match:
            multiplier *= 1.2
        if factors.compliance_violation:
            multiplier *= 1.1

        score = min(1.0, base * multiplier)

        if score >= 0.9:
            priority = "P0 - Immediate"
        elif score >= 0.7:
            priority = "P1 - Critical"
        elif score >= 0.5:
            priority = "P2 - High"
        elif score >= 0.3:
            priority = "P3 - Medium"
        else:
            priority = "P4 - Low"

        return {
            "score": round(score, 3),
            "priority": priority,
            "multiplier": round(multiplier, 2),
            "base_score": round(base, 3),
        }

    def prioritize(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Prioritize a list of findings."""
        scored = []
        for f in findings:
            factors = RiskFactors(
                cvss_score=f.get("cvss", 0.0),
                exploitability=f.get("exploitability", 0.5),
                business_impact=f.get("business_impact", 0.5),
                exposure=f.get("exposure", 0.5),
                asset_value=f.get("asset_value", 0.5),
                threat_intel_match=f.get("threat_intel_match", False),
                active_exploit=f.get("active_exploit", False),
                compliance_violation=f.get("compliance_violation", False),
            )
            risk = self.calculate_risk(factors)
            scored.append({**f, "risk": risk})

        return sorted(scored, key=lambda x: x["risk"]["score"], reverse=True)
