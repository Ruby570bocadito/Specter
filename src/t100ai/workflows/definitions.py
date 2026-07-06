"""Workflow definitions - Built-in security workflows for T-100AI."""

from typing import Any

BUILTIN_WORKFLOWS: dict[str, dict[str, Any]] = {
    "full_pentest": {
        "description": "Full penetration testing workflow",
        "steps": ["recon", "enumerate", "exploit", "postex", "report"],
        "stop_on_failure": False,
    },
    "web_audit": {
        "description": "Web application security audit",
        "steps": ["web_scan", "dir_fuzz", "vuln_scan", "report"],
        "stop_on_failure": False,
    },
    "quick_scan": {
        "description": "Quick network scan",
        "steps": ["ping_sweep", "port_scan", "service_enum"],
        "stop_on_failure": True,
    },
    "ad_attack": {
        "description": "Active Directory attack chain",
        "steps": ["ldap_enum", "bloodhound", "kerberoast", "report"],
        "stop_on_failure": False,
    },
    "ir_response": {
        "description": "Incident response workflow",
        "steps": ["collect_evidence", "analyze", "contain", "report"],
        "stop_on_failure": True,
    },
}
