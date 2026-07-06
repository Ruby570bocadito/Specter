"""Example Plugin: Hash Analyzer.

Demonstrates a crypto plugin that identifies and analyzes password hashes.
"""

import re
from typing import Any


class HashAnalyzer:
    """Plugin de ejemplo: análisis e identificación de hashes."""

    name = "hash_analyzer"
    version = "1.0.0"
    description = "Hash identification and analysis"
    author = "T-100AI Team"

    HASH_PATTERNS = {
        "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
        "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
        "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
        "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
        "ntlm": re.compile(r"^[a-fA-F0-9]{32}$"),
        "bcrypt": re.compile(r"^\$2[aby]?\$\d{2}\$.{53}$"),
        "mysql": re.compile(r"^\*[a-fA-F0-9]{40}$"),
    }

    HASH_INFO = {
        "md5": {"bits": 128, "crackable": "Yes (fast)", "tool": "hashcat -m 0"},
        "sha1": {"bits": 160, "crackable": "Yes", "tool": "hashcat -m 100"},
        "sha256": {"bits": 256, "crackable": "Yes (slow)", "tool": "hashcat -m 1400"},
        "sha512": {"bits": 512, "crackable": "Very slow", "tool": "hashcat -m 1700"},
        "ntlm": {"bits": 128, "crackable": "Yes (very fast)", "tool": "hashcat -m 1000"},
        "bcrypt": {"bits": 184, "crackable": "Very slow", "tool": "hashcat -m 3200"},
        "mysql": {"bits": 160, "crackable": "Yes", "tool": "hashcat -m 200"},
    }

    def run(self, hash_value: str, **kwargs: Any) -> dict[str, Any]:
        """Identify and analyze a hash."""
        results = []
        for hash_type, pattern in self.HASH_PATTERNS.items():
            if pattern.match(hash_value):
                info = self.HASH_INFO.get(hash_type, {})
                results.append({
                    "type": hash_type,
                    "bits": info.get("bits", "unknown"),
                    "crackable": info.get("crackable", "unknown"),
                    "tool": info.get("tool", ""),
                })

        if not results:
            return {
                "success": False,
                "error": f"Unknown hash format: {hash_value}",
                "hash": hash_value,
            }

        return {
            "success": True,
            "hash": hash_value,
            "possible_types": results,
            "recommendation": f"Try: hashcat -m {results[0]['tool'].split('-m ')[1]} {hash_value} wordlist.txt",
        }
