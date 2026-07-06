"""LLM Handler with offline fallback for T-100AI.

Wraps OllamaClient and falls back to rule-based responses when
Ollama is not available. Includes response caching.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Optional


class LLMHandler:
    """LLM handler with Ollama wrapper and rule-based fallback."""

    def __init__(self) -> None:
        self._client: Optional[Any] = None
        self._cache: dict[str, str] = {}
        self._cache_ttl: int = 300
        self._cache_timestamps: dict[str, float] = {}
        self._available: Optional[bool] = None

    def _get_client(self) -> Optional[Any]:
        """Lazy-load the Ollama client."""
        if self._client is not None:
            return self._client
        try:
            from t100ai.llm.connection_manager import OllamaConnectionManager
            cm = OllamaConnectionManager.get_instance()
            if not cm._connected:
                try:
                    cm.connect()
                except Exception:
                    self._available = False
                    return None
            self._client = cm
            self._available = True
            return self._client
        except Exception:
            self._available = False
            return None

    def is_available(self) -> bool:
        """Check if Ollama is available."""
        if self._available is not None:
            return self._available
        client = self._get_client()
        return client is not None

    def generate_response(self, prompt: str, system_prompt: str = "") -> str:
        """Generate a response, falling back to rules if Ollama unavailable."""
        cache_key = hashlib.md5(f"{prompt}:{system_prompt}".encode()).hexdigest()
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        client = self._get_client()
        if client is not None:
            try:
                response = self._call_ollama(client, prompt, system_prompt)
                self._set_cached(cache_key, response)
                return response
            except Exception:
                pass

        response = self.get_fallback_response(prompt)
        self._set_cached(cache_key, response)
        return response

    def _call_ollama(self, client: Any, prompt: str, system_prompt: str) -> str:
        """Call Ollama and return the response."""
        chunks = list(client.generate_stream(prompt, system_prompt))
        return "".join(chunks)

    def get_fallback_response(self, prompt: str) -> str:
        """Return rule-based response for common pentesting queries."""
        prompt_lower = prompt.lower()

        if any(kw in prompt_lower for kw in ["hola", "hello", "hi ", "buenas", "que tal"]):
            return "Hola! Soy T-100AI, tu asistente de ciberseguridad. Estoy listo para ayudarte con pentesting, analisis de vulnerabilidades, y mas. Que necesitas?"

        if any(kw in prompt_lower for kw in ["que puedes", "que haces", "capacidades", "help", "ayuda"]):
            return (
                "Soy T-100AI v2.0, un asistente de ciberseguridad ofensiva y defensiva.\n\n"
                "Capacidades:\n"
                "- Ejecucion de comandos via <cmd>etiquetas</cmd>\n"
                "- Escaneo de red con nmap\n"
                "- Enumeracion web con gobuster/ffuf\n"
                "- Analisis de vulnerabilidades\n"
                "- Explotacion y post-explotacion\n"
                "- Active Directory attacks\n"
                "- Generacion de informes\n\n"
                "Usa /help para ver todos los comandos disponibles."
            )

        if any(kw in prompt_lower for kw in ["nmap", "escaneo", "scan", "puerto"]):
            return (
                "Para escaneo de puertos recomiendo:\n\n"
                "1. Discovery: `nmap -sn 192.168.1.0/24`\n"
                "2. Puertos comunes: `nmap -sV -sC -p 22,80,443,445,3389 <target>`\n"
                "3. Todos los puertos: `nmap -sV -sC -p- <target>`\n"
                "4. Agresivo: `nmap -A -T4 <target>`\n\n"
                "Dime el target y ejecuto el escaneo."
            )

        if any(kw in prompt_lower for kw in ["sqli", "sql injection", "sqlmap"]):
            return (
                "SQL Injection - Pasos recomendados:\n\n"
                "1. Deteccion manual: `' OR 1=1--` en parametros\n"
                "2. Automatizado: `sqlmap -u 'http://target/page?id=1' --dbs`\n"
                "3. Enumerar tablas: `sqlmap -u '...' -D dbname --tables`\n"
                "4. Dump: `sqlmap -u '...' -D dbname -T tablename --dump`\n\n"
                "Proporciona la URL objetivo para proceder."
            )

        if any(kw in prompt_lower for kw in ["xss", "cross site"]):
            return (
                "XSS - Payloads comunes:\n\n"
                "- Reflected: `<script>alert(1)</script>`\n"
                "- Stored: mismo payload en campos persistentes\n"
                "- DOM-based: `javascript:alert(document.cookie)`\n"
                "- Bypass basico: `<img src=x onerror=alert(1)>`\n\n"
                "Necesito la URL y parametro vulnerable para testear."
            )

        if any(kw in prompt_lower for kw in ["directory", "dirb", "gobuster", "fuzz"]):
            return (
                "Directory enumeration:\n\n"
                "1. Gobuster: `gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt`\n"
                "2. FFUF: `ffuf -w wordlist.txt -u http://target/FUZZ`\n"
                "3. Dirsearch: `dirsearch -u http://target -e php,html,txt`\n\n"
                "Dime el target y ejecuto la enumeracion."
            )

        if any(kw in prompt_lower for kw in ["active directory", "ad ", "kerberos", "domain"]):
            return (
                "Active Directory - Tecnicas principales:\n\n"
                "1. LDAP enum: `ldapsearch -H ldap://dc -D user@domain -w pass -b 'DC=domain'`\n"
                "2. BloodHound: `bloodhound-python -d domain -u user -p pass -c All`\n"
                "3. Kerberoasting: `GetUserSPNs.py domain/user:pass -dc-ip DC -request`\n"
                "4. AS-REP Roasting: `GetNPUsers.py domain/user -dc-ip DC -request`\n\n"
                "Proporciona credenciales y dominio para proceder."
            )

        if any(kw in prompt_lower for kw in ["privilege escalation", "priv esc", "escalada"]):
            return (
                "Privilege Escalation:\n\n"
                "Linux:\n"
                "- LinPEAS: `./linpeas.sh -a`\n"
                "- SUID: `find / -perm -4000 2>/dev/null`\n"
                "- Capabilities: `getcap -r / 2>/dev/null`\n"
                "- Cron jobs: `cat /etc/crontab`\n\n"
                "Windows:\n"
                "- WinPEAS: `winPEASx64.exe`\n"
                "- AlwaysInstallElevated check\n"
                "- Unquoted service paths\n\n"
                "Que sistema objetivo tenemos?"
            )

        if any(kw in prompt_lower for kw in ["report", "informe", "resultado"]):
            return (
                "Para generar un informe usa `/report` o `/report session`.\n\n"
                "El informe incluye:\n"
                "- Resumen ejecutivo\n"
                "- Hallazgos por severidad\n"
                "- Evidencias y PoCs\n"
                "- Recomendaciones\n"
                "- Mapeo MITRE ATT&CK"
            )

        return (
            f"Entendido: '{prompt}'\n\n"
            "No tengo una respuesta predefinida para esta consulta. "
            "Intenta ser mas especifico o usa comandos como /help para ver opciones disponibles. "
            "Tambien puedes pedir un escaneo, enumeracion, o analisis de vulnerabilidades."
        )

    def _get_cached(self, key: str) -> Optional[str]:
        """Get cached response if valid."""
        if key in self._cache:
            if time.time() - self._cache_timestamps.get(key, 0) < self._cache_ttl:
                return self._cache[key]
            del self._cache[key]
            del self._cache_timestamps[key]
        return None

    def _set_cached(self, key: str, value: str) -> None:
        """Cache a response."""
        self._cache[key] = value
        self._cache_timestamps[key] = time.time()

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._cache.clear()
        self._cache_timestamps.clear()
