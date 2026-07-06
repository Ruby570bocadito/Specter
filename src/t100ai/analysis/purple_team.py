"""Purple Teaming - Sigma rule generation from findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SigmaRule:
    """A Sigma detection rule generated from a finding."""
    title: str
    description: str
    logsource_category: str
    logsource_product: str
    detection_selection: dict[str, Any]
    detection_condition: str
    level: str
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)

    def to_yaml(self) -> str:
        """Export as Sigma YAML format."""
        lines = [
            f"title: {self.title}",
            f"description: {self.description}",
            "logsource:",
            f"  category: {self.logsource_category}",
            f"  product: {self.logsource_product}",
            "detection:",
            "  selection:",
        ]
        for key, val in self.detection_selection.items():
            if isinstance(val, list):
                lines.append(f"    {key}:")
                for v in val:
                    lines.append(f"      - '{v}'")
            else:
                lines.append(f"    {key}: '{val}'")
        lines.append(f"  condition: {self.detection_condition}")
        lines.append(f"level: {self.level}")
        if self.tags:
            lines.append("tags:")
            for t in self.tags:
                lines.append(f"  - {t}")
        if self.falsepositives:
            lines.append("falsepositives:")
            for fp in self.falsepositives:
                lines.append(f"  - {fp}")
        return "\n".join(lines)


SIGMA_TEMPLATES: dict[str, dict[str, Any]] = {
    "sqli": {
        "title": "SQL Injection Attempt",
        "category": "webserver",
        "product": "apache",
        "selection": {"c-uri": ["*SELECT*", "*UNION*", "*OR 1=1*", "*DROP TABLE*", "*--*", "*' OR '*"]},
        "condition": "selection",
        "level": "high",
        "tags": ["attack.t1190", "attack.initial-access"],
        "falsepositives": ["Legitimate SQL queries in application logs"],
    },
    "xss": {
        "title": "Cross-Site Scripting Attempt",
        "category": "webserver",
        "product": "apache",
        "selection": {"c-uri": ["*<script>*", "*javascript:*", "*onerror=*", "*onload=*"]},
        "condition": "selection",
        "level": "medium",
        "tags": ["attack.t1190"],
        "falsepositives": ["Legitimate JavaScript in URLs"],
    },
    "brute_force": {
        "title": "Brute Force Login Attempt",
        "category": "authentication",
        "product": "linux",
        "selection": {"EventID": [4625], "Keywords": ["Audit Failure"]},
        "condition": "selection",
        "level": "medium",
        "tags": ["attack.t1110"],
        "falsepositives": ["Users forgetting passwords"],
    },
    "lateral_movement": {
        "title": "Lateral Movement via PsExec",
        "category": "process_creation",
        "product": "windows",
        "selection": {"Image": "*\\PSEXESVC.exe", "ParentImage": "*\\services.exe"},
        "condition": "selection",
        "level": "high",
        "tags": ["attack.t1570", "attack.lateral-movement"],
        "falsepositives": ["Legitimate admin tool usage"],
    },
    "privilege_escalation": {
        "title": "Privilege Escalation via SUID",
        "category": "process_creation",
        "product": "linux",
        "selection": {"c-user": "root", "c-group": "root"},
        "condition": "selection",
        "level": "high",
        "tags": ["attack.t1548"],
        "falsepositives": ["Legitimate root processes"],
    },
    "data_exfiltration": {
        "title": "Potential Data Exfiltration",
        "category": "network_connection",
        "product": "firewall",
        "selection": {"action": "allow", "bytes_out": ">100000000"},
        "condition": "selection",
        "level": "high",
        "tags": ["attack.t1041", "attack.exfiltration"],
        "falsepositives": ["Large legitimate file transfers"],
    },
}


class PurpleTeamEngine:
    """Generates Sigma detection rules from pentest findings.

    Bridges the gap between offensive findings and defensive detections.

    Usage:
        engine = PurpleTeamEngine()
        rule = engine.generate_sigma_rule("sqli", "SQL Injection in login")
        print(rule.to_yaml())
    """

    def generate_sigma_rule(self, finding_type: str, finding_description: str) -> SigmaRule:
        """Generate a Sigma rule from a finding type."""
        template = SIGMA_TEMPLATES.get(finding_type.lower())
        if not template:
            return self._generate_generic_rule(finding_type, finding_description)

        return SigmaRule(
            title=template["title"],
            description=finding_description,
            logsource_category=template["category"],
            logsource_product=template["product"],
            detection_selection=template["selection"],
            detection_condition=template["condition"],
            level=template["level"],
            tags=template.get("tags", []),
            falsepositives=template.get("falsepositives", []),
        )

    def _generate_generic_rule(self, finding_type: str, description: str) -> SigmaRule:
        """Generate a generic Sigma rule for unknown finding types."""
        return SigmaRule(
            title=f"Detection for {finding_type}",
            description=description,
            logsource_category="process_creation",
            logsource_product="linux",
            detection_selection={"CommandLine": f"*{finding_type}*"},
            detection_condition="selection",
            level="medium",
            tags=["attack.t1059"],
        )

    def generate_all_rules(self, findings: list[dict[str, str]]) -> list[SigmaRule]:
        """Generate Sigma rules for all findings."""
        rules = []
        for f in findings:
            rule = self.generate_sigma_rule(
                f.get("type", "unknown"),
                f.get("description", ""),
            )
            rules.append(rule)
        return rules
