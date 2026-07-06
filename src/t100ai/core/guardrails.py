"""LLM Guardrails - Validacion de comandos generados por el LLM.

Problema: El LLM puede inventar flags, CVEs, o sintaxis incorrecta.
Solucion: Validar comandos antes de ejecutarlos contra reglas conocidas.
"""

import re
import shutil
from dataclasses import dataclass
from typing import Optional


@dataclass
class ValidationResult:
    """Resultado de la validacion de un comando."""
    is_valid: bool
    command: str
    errors: list[str]
    warnings: list[str]
    binary_exists: bool = True
    confidence: float = 1.0


# Flags validos por herramienta (subset comun)
_VALID_FLAGS: dict[str, set[str]] = {
    "nmap": {
        "-sS", "-sT", "-sU", "-sV", "-sC", "-A", "-O", "-p", "-p-",
        "-Pn", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        "--script", "-oN", "-oX", "-oG", "-oA",
        "-v", "-vv", "-d", "-dd",
        "--top-ports", "--min-rate", "--max-rate",
        "-iL", "-iR", "--exclude", "--excludefile",
        "-sA", "-sW", "-sM", "-sN", "-sF", "-sX",
        "--traceroute", "--reason",
        "-6", "-D", "-S", "-e", "-g", "--source-port",
        "--data-length", "--randomize-hosts",
    },
    "gobuster": {
        "dir", "dns", "vhost", "fuzz", "gcs", "s3",
        "-u", "-w", "-t", "-o", "-x", "-e", "-k",
        "-n", "-q", "--no-error", "-z", "-r",
        "-c", "-H", "-F", "-S", "-d", "-p",
        "--delay", "--timeout", "--status-codes",
        "--status-codes-blacklist", "--user-agent",
        "--url-suffix", "--wildcard",
    },
    "ffuf": {
        "-u", "-w", "-H", "-X", "-d", "-c", "-b",
        "-t", "-r", "-p", "-v", "-s", "-json",
        "-fc", "-fl", "-fw", "-fs", "-ft",
        "-mc", "-ml", "-mw", "-ms", "-mt",
        "-of", "-o", "-recursion", "-recursion-depth",
        "-e", "-sf", "-se", "-sa", "-ac",
        "-timeout", "-rate",
    },
    "nikto": {
        "-h", "-p", "-ssl", "-id", "-Tuning",
        "-o", "-Format", "-F", "-e", "-nointeractive",
        "-config", "-update", "-Plugins", "-list-plugins",
        "-Cgidirs", "-maxtime", "-Display",
        "-ask", "-Version", "-Help",
    },
    "sqlmap": {
        "-u", "-d", "-l", "-m", "-r", "-g",
        "-p", "--dbms", "--os", "--tamper",
        "--level", "--risk", "--threads",
        "--batch", "--crawl", "--forms",
        "--dbs", "--tables", "--columns", "--dump",
        "--users", "--passwords", "--privileges",
        "--os-shell", "--os-pwn",
        "--technique", "--time-sec",
        "--proxy", "--tor", "--check-tor",
        "--random-agent", "--user-agent",
        "--cookie", "--referer",
    },
    "hydra": {
        "-l", "-L", "-p", "-P", "-t", "-w", "-f",
        "-s", "-o", "-v", "-V", "-d", "-b",
        "-x", "-e", "-M", "-C",
    },
    "hashcat": {
        "-m", "-a", "-o", "-r", "-w", "-n", "-u",
        "-O", "-S", "-d", "-D", "-p", "--force",
        "--status", "--status-timer", "--session",
    },
    "curl": {
        "-X", "-H", "-d", "-o", "-O", "-L", "-s",
        "-S", "-v", "-k", "-b", "-c", "-A",
        "-e", "-u", "--data-urlencode", "--form",
        "-w", "--max-time", "--connect-timeout",
    },
    "wget": {
        "-O", "-o", "-P", "-r", "-l", "-p", "-k",
        "-N", "-c", "-q", "-v", "--no-check-certificate",
        "--user-agent", "--header", "--post-data",
    },
    "dig": {
        "@", "-t", "-x", "+short", "+trace", "+noall",
        "+answer", "+authority", "+additional",
        "+norecurse", "+recurse", "-f",
    },
    "nuclei": {
        "-u", "-l", "-t", "-tags", "-exclude-tags",
        "-severity", "-exclude-severity",
        "-o", "-json", "-silent", "-v", "-vv",
        "-c", "-rate-limit", "-bulk-size",
        "-retries", "-timeout", "-proxy",
        "-H", "-header", "-var",
    },
    "whatweb": {
        "-a", "-v", "-q", "-U", "-C", "-p",
        "--max-threads", "--follow-redirect",
        "--user-agent", "--cookie",
    },
    "wpscan": {
        "--url", "--enumerate", "-e", "--api-token",
        "--passwords", "--usernames", "--threads",
        "--max-threads", "--request-timeout",
        "--user-agent", "--cookie", "--force",
        "--disable-tls-checks",
    },
}

# Patrones de flags inventados comunes del LLM
_FAKE_FLAG_PATTERNS = [
    r"--\w{20,}",  # flags absurdamente largos
    r"-\d{3,}",    # flags numericos absurdos
    r"--[a-z]{15,}",  # flags muy largos que probablemente no existen
]

# Versiones de herramientas para referencia
_KNOWN_VERSIONS = {
    "nmap": "7.x",
    "gobuster": "3.x",
    "ffuf": "2.x",
    "nikto": "2.x",
    "sqlmap": "1.x",
}


class LLMCommandValidator:
    """
    Valida comandos generados por el LLM antes de ejecutarlos.

    Capas de validacion:
    1. Binario existe en PATH
    2. Flags conocidos (no inventados)
    3. Sintaxis basica correcta
    4. Valores de flags razonables
    5. Deteccion de alucinaciones (CVEs inventados, etc.)
    """

    def __init__(self, strict: bool = False):
        """
        Args:
            strict: Si True, bloquea comandos con flags desconocidos.
                   Si False, solo advierte pero permite ejecutar.
        """
        self.strict = strict
        self._cache: dict[str, bool] = {}

    def validate(self, command: str) -> ValidationResult:
        """Valida un comando completo."""
        command = command.strip()
        if not command:
            return ValidationResult(
                is_valid=False, command=command,
                errors=["Comando vacio"], warnings=[], confidence=0.0,
            )

        errors = []
        warnings = []
        confidence = 1.0

        parts = command.split()
        binary = parts[0]

        # Capa 1: Binario existe
        binary_exists = shutil.which(binary) is not None
        if not binary_exists:
            if self.strict:
                errors.append(f"Binario '{binary}' no encontrado en PATH")
            else:
                warnings.append(f"Binario '{binary}' no encontrado en PATH")
            confidence -= 0.3

        # Capa 2: Flags validos
        if binary in _VALID_FLAGS:
            valid_flags = _VALID_FLAGS[binary]
            for part in parts[1:]:
                # Saltar valores de flags (no empiezan con -)
                if not part.startswith("-"):
                    continue
                # Flag con valor (--flag=value o -f value)
                flag_base = part.split("=")[0]
                if flag_base not in valid_flags:
                    # Verificar si es un patron de flag inventado
                    for pattern in _FAKE_FLAG_PATTERNS:
                        if re.match(pattern, part):
                            errors.append(f"Flag sospechoso/inventado: {part}")
                            confidence -= 0.2
                            break
                    else:
                        if self.strict:
                            errors.append(f"Flag desconocido: {part}")
                            confidence -= 0.1
                        else:
                            warnings.append(f"Flag no verificado: {part}")
                            confidence -= 0.05

        # Capa 3: Sintaxis basica
        syntax_errors = self._check_syntax(binary, parts)
        errors.extend(syntax_errors)
        confidence -= len(syntax_errors) * 0.1

        # Capa 4: Valores razonables
        value_warnings = self._check_values(binary, parts)
        warnings.extend(value_warnings)
        confidence -= len(value_warnings) * 0.05

        # Capa 5: Deteccion de alucinaciones
        hallucination = self._detect_hallucinations(command)
        if hallucination:
            errors.append(hallucination)
            confidence -= 0.3

        confidence = max(0.0, min(1.0, confidence))
        is_valid = len(errors) == 0 and confidence >= 0.3

        return ValidationResult(
            is_valid=is_valid,
            command=command,
            errors=errors,
            warnings=warnings,
            binary_exists=binary_exists,
            confidence=round(confidence, 2),
        )

    def _check_syntax(self, binary: str, parts: list[str]) -> list[str]:
        """Verifica sintaxis basica del comando."""
        errors = []
        if binary == "nmap":
            # nmap necesita al menos un target
            targets = [p for p in parts[1:] if not p.startswith("-")]
            if not targets:
                errors.append("nmap requiere al menos un target")
        elif binary == "gobuster":
            # gobuster necesita subcomando y -u
            if len(parts) < 2 or parts[1] not in ("dir", "dns", "vhost", "fuzz"):
                errors.append("gobuster requiere subcomando (dir/dns/vhost/fuzz)")
            has_url = any(p == "-u" for p in parts)
            if not has_url:
                errors.append("gobuster requiere flag -u <url>")
        elif binary == "ffuf":
            has_url = any(p == "-u" for p in parts)
            has_wordlist = any(p == "-w" for p in parts)
            if not has_url:
                errors.append("ffuf requiere flag -u <url>")
            if not has_wordlist:
                errors.append("ffuf requiere flag -w <wordlist>")
        elif binary == "nikto":
            has_host = any(p == "-h" for p in parts)
            if not has_host:
                errors.append("nikto requiere flag -h <host>")
        elif binary == "sqlmap":
            has_url = any(p == "-u" for p in parts)
            has_req = any(p == "-r" for p in parts)
            if not has_url and not has_req:
                errors.append("sqlmap requiere -u <url> o -r <request>")
        elif binary == "curl":
            has_target = len(parts) >= 2 and not parts[1].startswith("-")
            has_url_flag = any(p.startswith("http") for p in parts)
            if not has_target and not has_url_flag:
                errors.append("curl requiere una URL")
        return errors

    def _check_values(self, binary: str, parts: list[str]) -> list[str]:
        """Verifica que los valores de flags sean razonables."""
        warnings = []
        for i, part in enumerate(parts):
            # Puertos fuera de rango
            if part == "-p" and i + 1 < len(parts):
                port_str = parts[i + 1]
                if port_str != "-":
                    try:
                        if "-" in port_str:
                            start, end = port_str.split("-", 1)
                            if int(end) > 65535:
                                warnings.append(f"Puerto {end} fuera de rango (max 65535)")
                        elif int(port_str) > 65535:
                            warnings.append(f"Puerto {port_str} fuera de rango")
                    except ValueError:
                        pass
            # Threads excesivos
            if part in ("-t", "--threads", "-c") and i + 1 < len(parts):
                try:
                    threads = int(parts[i + 1])
                    if threads > 100:
                        warnings.append(f"{threads} threads puede ser excesivo")
                except ValueError:
                    pass
        return warnings

    def _detect_hallucinations(self, command: str) -> Optional[str]:
        """Detecta posibles alucinaciones del LLM."""
        # CVEs inventados (formato CVE-YYYY-NNNNN)
        cve_matches = re.findall(r"CVE-(\d{4})-(\d{4,})", command)
        for year, num in cve_matches:
            year_int = int(year)
            if year_int < 2000 or year_int > 2026:
                return f"CVE con ano sospechoso: CVE-{year}-{num}"
            if len(num) > 6:
                return f"CVE con numero sospechosamente largo: CVE-{year}-{num}"
        # IPs invalidas
        ip_matches = re.findall(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", command)
        for octets in ip_matches:
            for o in octets:
                if int(o) > 255:
                    return f"IP invalida detectada: {'.'.join(octets)}"
        return None
