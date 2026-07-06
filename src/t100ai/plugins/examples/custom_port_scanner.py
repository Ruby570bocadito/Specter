"""Example Plugin: Custom Port Scanner.

Demonstrates a simple recon plugin that wraps nmap with custom profiles.
"""

import asyncio
import shutil
from typing import Any


class CustomPortScanner:
    """Plugin de ejemplo: escaneo de puertos con perfiles personalizados."""

    name = "custom_port_scanner"
    version = "1.0.0"
    description = "Custom port scanning profiles"
    author = "T-100AI Team"

    SCAN_PROFILES = {
        "stealth": "-sS -T1 --max-rate 1 --host-timeout 30s",
        "fast": "-sS -T5 -p- --min-rate 10000",
        "thorough": "-sV -sC -O -A --script vuln -p-",
        "udp": "-sU --top-ports 100",
    }

    async def run(self, target: str, profile: str = "fast") -> dict[str, Any]:
        """Run a custom port scan."""
        if profile not in self.SCAN_PROFILES:
            return {
                "success": False,
                "error": f"Profile '{profile}' not found. Available: {list(self.SCAN_PROFILES.keys())}",
            }

        if not shutil.which("nmap"):
            return {"success": False, "error": "nmap not found"}

        args = self.SCAN_PROFILES[profile]
        cmd = f"nmap {args} {target}"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode(errors="replace") + stderr.decode(errors="replace")

        return {
            "success": proc.returncode == 0,
            "output": output,
            "profile": profile,
            "target": target,
        }
