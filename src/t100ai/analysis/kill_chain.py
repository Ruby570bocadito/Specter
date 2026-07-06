"""Kill Chain Mapping - Maps findings to attack frameworks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KillChainStep:
    """A step in the kill chain with associated findings."""
    phase: str
    phase_order: int
    findings: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    description: str = ""


LOCKHEED_KILL_CHAIN = {
    "reconnaissance": {"order": 1, "description": "Target identification and information gathering"},
    "weaponization": {"order": 2, "description": "Creating attack payload"},
    "delivery": {"order": 3, "description": "Transmitting weapon to target"},
    "exploitation": {"order": 4, "description": "Exploiting vulnerability"},
    "installation": {"order": 5, "description": "Installing malware/backdoor"},
    "command_and_control": {"order": 6, "description": "Establishing C2 channel"},
    "actions_on_objectives": {"order": 7, "description": "Achieving attacker goals"},
}

MITRE_PHASE_MAP = {
    "reconnaissance": ["reconnaissance", "resource-development"],
    "weaponization": ["resource-development"],
    "delivery": ["initial-access"],
    "exploitation": ["execution", "privilege-escalation", "defense-evasion"],
    "installation": ["persistence", "privilege-escalation"],
    "command_and_control": ["command-and-control"],
    "actions_on_objectives": ["collection", "exfiltration", "impact"],
}

FINDING_PHASE_MAP = {
    "nmap": "reconnaissance",
    "whois": "reconnaissance",
    "dns": "reconnaissance",
    "osint": "reconnaissance",
    "subdomain": "reconnaissance",
    "shodan": "reconnaissance",
    "phishing": "delivery",
    "spear_phishing": "delivery",
    "exploit": "exploitation",
    "rce": "exploitation",
    "sqli": "exploitation",
    "xss": "exploitation",
    "lfi": "exploitation",
    "ssrf": "exploitation",
    "backdoor": "installation",
    "webshell": "installation",
    "persistence": "installation",
    "c2": "command_and_control",
    "beacon": "command_and_control",
    "tunnel": "command_and_control",
    "data_exfil": "actions_on_objectives",
    "lateral_movement": "actions_on_objectives",
    "privilege_escalation": "exploitation",
    "credential_dump": "exploitation",
    "ransomware": "actions_on_objectives",
    "defacement": "actions_on_objectives",
}


class KillChainMapper:
    """Maps findings to Lockheed Martin Kill Chain and MITRE ATT&CK.

    Usage:
        mapper = KillChainMapper()
        mapper.map_finding("F1", "nmap", "Port scan detected")
        chain = mapper.get_kill_chain()
    """

    def __init__(self) -> None:
        self._steps: dict[str, KillChainStep] = {}
        for phase, info in LOCKHEED_KILL_CHAIN.items():
            self._steps[phase] = KillChainStep(
                phase=phase,
                phase_order=info["order"],
                mitre_tactics=MITRE_PHASE_MAP.get(phase, []),
                description=info["description"],
            )

    def map_finding(self, finding_id: str, finding_type: str, description: str = "") -> str:
        """Map a finding to a kill chain phase."""
        phase = FINDING_PHASE_MAP.get(finding_type.lower(), "reconnaissance")
        if phase in self._steps:
            self._steps[phase].findings.append(finding_id)
        return phase

    def get_kill_chain(self) -> list[dict[str, Any]]:
        """Return the kill chain with findings mapped."""
        result = []
        for phase in sorted(self._steps.values(), key=lambda s: s.phase_order):
            result.append({
                "phase": phase.phase,
                "order": phase.phase_order,
                "description": phase.description,
                "findings": phase.findings,
                "mitre_tactics": phase.mitre_tactics,
                "has_findings": len(phase.findings) > 0,
            })
        return result

    def get_coverage(self) -> dict[str, Any]:
        """Return kill chain coverage statistics."""
        total_phases = len(self._steps)
        covered_phases = sum(1 for s in self._steps.values() if s.findings)
        all_mitre = set()
        for s in self._steps.values():
            all_mitre.update(s.mitre_tactics)
        covered_mitre = set()
        for s in self._steps.values():
            if s.findings:
                covered_mitre.update(s.mitre_tactics)

        return {
            "total_phases": total_phases,
            "covered_phases": covered_phases,
            "coverage_pct": round(covered_phases / max(total_phases, 1) * 100, 1),
            "mitre_tactics_total": len(all_mitre),
            "mitre_tactics_covered": len(covered_mitre),
        }

    def get_uncovered_phases(self) -> list[str]:
        """Return phases with no findings mapped."""
        return [s.phase for s in self._steps.values() if not s.findings]
