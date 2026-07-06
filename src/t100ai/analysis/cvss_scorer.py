"""CVSS v4.0 Scorer - Automatic vulnerability risk scoring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CVSSv4Metrics:
    """CVSS v4.0 metric values."""
    attack_vector: str = "N"
    attack_complexity: str = "L"
    attack_requirements: str = "N"
    privileges_required: str = "N"
    user_interaction: str = "N"
    vuln_confidentiality: str = "H"
    vuln_integrity: str = "H"
    vuln_availability: str = "H"
    sub_confidentiality: str = "N"
    sub_integrity: str = "N"
    sub_availability: str = "N"
    exploit_maturity: str = "X"
    confidentiality_requirement: str = "X"
    integrity_requirement: str = "X"
    availability_requirement: str = "X"
    modified_attack_vector: str = "X"
    modified_attack_complexity: str = "X"
    modified_privileges_required: str = "X"
    modified_user_interaction: str = "X"
    modified_vuln_confidentiality: str = "X"
    modified_vuln_integrity: str = "X"
    modified_vuln_availability: str = "X"
    safety: str = "X"
    automatable: str = "X"
    recovery: str = "X"
    value_density: str = "X"
    provider_urgency: str = "X"

    def to_vector(self) -> str:
        """Return CVSS v4.0 vector string."""
        parts = [
            f"AV:{self.attack_vector}",
            f"AC:{self.attack_complexity}",
            f"AT:{self.attack_requirements}",
            f"PR:{self.privileges_required}",
            f"UI:{self.user_interaction}",
            f"VC:{self.vuln_confidentiality}",
            f"VI:{self.vuln_integrity}",
            f"VA:{self.vuln_availability}",
            f"SC:{self.sub_confidentiality}",
            f"SI:{self.sub_integrity}",
            f"SA:{self.sub_availability}",
        ]
        if self.exploit_maturity != "X":
            parts.append(f"E:{self.exploit_maturity}")
        if self.confidentiality_requirement != "X":
            parts.append(f"CR:{self.confidentiality_requirement}")
        if self.integrity_requirement != "X":
            parts.append(f"IR:{self.integrity_requirement}")
        if self.availability_requirement != "X":
            parts.append(f"AR:{self.availability_requirement}")
        if self.automatable != "X":
            parts.append(f"Automatable:{self.automatable}")
        if self.recovery != "X":
            parts.append(f"Recovery:{self.recovery}")
        return "CVSS:4.0/" + "/".join(parts)


class CVSSv4Scorer:
    """CVSS v4.0 vulnerability scorer.

    Implements the CVSS v4.0 specification for scoring vulnerabilities
    on a scale of 0.0 to 10.0.

    Usage:
        scorer = CVSSv4Scorer()
        score = scorer.score(metrics)
        # score = {"score": 9.8, "severity": "CRITICAL", "vector": "CVSS:4.0/..."}
    """

    SEVERITY_RATINGS = [
        (0.0, 0.0, "NONE"),
        (0.1, 3.9, "LOW"),
        (4.0, 6.9, "MEDIUM"),
        (7.0, 8.9, "HIGH"),
        (9.0, 10.0, "CRITICAL"),
    ]

    WEIGHTS = {
        "attack_vector": {"N": 1.0, "A": 0.85, "L": 0.6, "P": 0.55},
        "attack_complexity": {"L": 1.0, "H": 0.5},
        "attack_requirements": {"N": 1.0, "P": 0.5},
        "privileges_required": {"N": 1.0, "L": 0.7, "H": 0.4},
        "user_interaction": {"N": 1.0, "P": 0.85, "A": 0.6},
        "vuln_impact": {"H": 1.0, "L": 0.5, "N": 0.0},
    }

    def score(self, metrics: CVSSv4Metrics) -> dict[str, Any]:
        """Calculate CVSS v4.0 score from metrics.

        Returns:
            dict with score, severity, vector, and breakdown.
        """
        base_score = self._calculate_base_score(metrics)
        severity = self._get_severity(base_score)

        return {
            "score": round(base_score, 1),
            "severity": severity,
            "vector": metrics.to_vector(),
            "breakdown": {
                "attack_vector": metrics.attack_vector,
                "attack_complexity": metrics.attack_complexity,
                "privileges_required": metrics.privileges_required,
                "user_interaction": metrics.user_interaction,
                "confidentiality_impact": metrics.vuln_confidentiality,
                "integrity_impact": metrics.vuln_integrity,
                "availability_impact": metrics.vuln_availability,
            },
        }

    def _calculate_base_score(self, m: CVSSv4Metrics) -> float:
        """Calculate base score from metrics using CVSS v4.0 formula."""
        av_w = self.WEIGHTS["attack_vector"].get(m.attack_vector, 0.55)
        ac_w = self.WEIGHTS["attack_complexity"].get(m.attack_complexity, 0.5)
        ar_w = self.WEIGHTS["attack_requirements"].get(m.attack_requirements, 0.5)
        pr_w = self.WEIGHTS["privileges_required"].get(m.privileges_required, 0.4)
        ui_w = self.WEIGHTS["user_interaction"].get(m.user_interaction, 0.6)

        vc_w = self.WEIGHTS["vuln_impact"].get(m.vuln_confidentiality, 0.0)
        vi_w = self.WEIGHTS["vuln_impact"].get(m.vuln_integrity, 0.0)
        va_w = self.WEIGHTS["vuln_impact"].get(m.vuln_availability, 0.0)

        exploitability = av_w * ac_w * ar_w * pr_w * ui_w
        impact = 1.0 - ((1.0 - vc_w) * (1.0 - vi_w) * (1.0 - va_w))

        score = round(min(10.0, exploitability * impact * 10.0), 1)

        if m.automatable == "Y":
            score = min(10.0, score + 0.5)
        if m.recovery == "U":
            score = min(10.0, score + 0.3)

        return score

    def _get_severity(self, score: float) -> str:
        """Map score to severity rating."""
        for low, high, severity in self.SEVERITY_RATINGS:
            if low <= score <= high:
                return severity
        return "NONE"

    def auto_score(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Auto-score a finding based on its attributes.

        Analyzes finding description, type, and context to infer
        appropriate CVSS metrics.
        """
        text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
        metrics = CVSSv4Metrics()

        if any(kw in text for kw in ["rce", "remote code", "command injection"]):
            metrics.vuln_confidentiality = "H"
            metrics.vuln_integrity = "H"
            metrics.vuln_availability = "H"
        elif any(kw in text for kw in ["sqli", "sql injection"]):
            metrics.vuln_confidentiality = "H"
            metrics.vuln_integrity = "H"
            metrics.vuln_availability = "L"
        elif any(kw in text for kw in ["xss", "cross-site"]):
            metrics.vuln_confidentiality = "L"
            metrics.vuln_integrity = "L"
            metrics.vuln_availability = "N"
        elif any(kw in text for kw in ["auth bypass", "authentication bypass"]):
            metrics.privileges_required = "N"
            metrics.vuln_confidentiality = "H"
            metrics.vuln_integrity = "H"
        elif any(kw in text for kw in ["info disclosure", "information leak"]):
            metrics.vuln_confidentiality = "L"
            metrics.vuln_integrity = "N"
            metrics.vuln_availability = "N"
        elif any(kw in text for kw in ["dos", "denial of service"]):
            metrics.vuln_availability = "H"
            metrics.vuln_confidentiality = "N"
            metrics.vuln_integrity = "N"

        if any(kw in text for kw in ["network", "remote", "external"]):
            metrics.attack_vector = "N"
        elif any(kw in text for kw in ["local", "physical"]):
            metrics.attack_vector = "L"
        else:
            metrics.attack_vector = "A"

        if any(kw in text for kw in ["no auth", "unauthenticated", "default cred"]):
            metrics.privileges_required = "N"
            metrics.automatable = "Y"

        return self.score(metrics)
