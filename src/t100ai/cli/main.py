"""T-100AI CLI - Main Entry Point"""

import asyncio
import platform
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.markdown import Markdown

from t100ai.core import T100AIEngine, Session
from t100ai.core.permissions import PermissionManager, PermissionLevel
from t100ai.utils.history import CommandHistory
import os
import re
from pathlib import Path

prompt_toolkit_available = False
PromptSession = None
Completer = object

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    prompt_toolkit_available = True
except ImportError:
    pass


class ContextAwareCompleter:
    """Autocompletado inteligente con contexto"""
    
    CONTEXT_SUGGESTIONS = {
        "ip": ["nmap", "ping", "rustscan", "masscan"],
        "domain": ["whois", "dig", "nslookup", "subfinder"],
        "url": ["gobuster", "sqlmap", "nikto", "nuclei", "ffuf"],
        "port": ["nmap -p", "netstat"],
        "hash": ["hashid", "hashcat", "john"],
        "cve": ["searchsploit", "nuclei"],
        "email": ["theHarvester", "hunter", "emailrep"],
    }
    
    def __init__(self, session: Optional["Session"] = None, engine: Optional["T100AIEngine"] = None):
        self.session = session
        self.engine = engine
    
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text:
            return
        
        parts = text.split()
        if len(parts) == 1:
            last = parts[0]
            if last.startswith("/"):
                for cmd in self._get_context_commands():
                    if cmd.startswith(last[1:]):
                        yield Completion(f"/{cmd}", start_position=-len(last))
            elif not last.startswith("/"):
                natural_suggestions = self._get_natural_suggestions()
                for suggestion in natural_suggestions:
                    if suggestion.startswith(last.lower()):
                        yield Completion(suggestion, start_position=-len(last))
        elif len(parts) > 1:
            cmd = parts[0]
            if cmd in ("/scope", "scope") and "set" in parts:
                target = parts[-1] if parts[-1] != "set" else ""
                yield Completion(f"/scope set {target}")
            elif cmd == "/history":
                query = " ".join(parts[1:])
                for item in command_history.search(query):
                    yield Completion(item, start_position=-len(text))
    
    def _get_context_commands(self) -> list:
        commands = [
            "help", "scope", "role", "skills", "skill", "tools", "tool",
            "findings", "finding", "report", "workflow", "mode", "model",
            "context", "session", "log", "clear", "exit", "history"
        ]
        if self.session:
            if self.session.scope:
                commands.extend(["nmap", "scan"])
            if self.session.current_skill:
                commands.append(f"/skill {self.session.current_skill}")
        return sorted(set(commands))
    
    def _get_natural_suggestions(self) -> list:
        suggestions = []
        if self.session and self.session.scope:
            for entry in self.session.scope:
                target = entry.target
                if entry.type == "ip" or re.match(r"\d+\.\d+\.\d+\.\d+", target):
                    suggestions.extend([f"escanea {target}", f"nmap {target}"])
                elif entry.type == "domain":
                    suggestions.extend([f"enumera DNS de {target}", f"whois {target}"])
        suggestions.extend([
            "escanea puertos", "busca vulnerabilidades", "genera informe",
            "muestra hallazgos", "modifica scope"
        ])
        if self.engine and hasattr(self.engine, 'skill_manager'):
            parallel_tasks = self.engine.skill_manager.detect_parallel_tasks("")
            if parallel_tasks:
                suggestions.append("ejecutar todo en paralelo")
        return suggestions
    
    def update_context(self, session, engine) -> None:
        self.session = session
        self.engine = engine

# NOTE: prompt_toolkit requires proper async context to avoid coroutine warnings.
# For now, we use the standard input() function which works reliably across all platforms.
from t100ai.core.config import T100AIConfig
import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
console = Console(force_terminal=True, file=sys.stdout)

# Persistent command history
command_history = CommandHistory()

app = typer.Typer(
    name="t100ai",
    help="T-100AI - AI-Powered Offensive Security Terminal",
    add_completion=False,
    invoke_without_command=True,
)


def _apply_config_and_confirm(cfg: T100AIConfig, config_path: Optional[str], debug: bool, model: Optional[str], no_llm: bool) -> T100AIConfig:
    """Load config, apply CLI overrides, and confirm ethical use."""
    cfg = T100AIConfig.load(config_path=config_path)
    if debug:
        cfg.log_level = "DEBUG"
    if model:
        cfg.ollama_model = model
    if no_llm:
        cfg.llm_enabled = False
        console.print("[yellow]Modo sin LLM activado[/]")

    sys.stdout.flush()

    if not Confirm.ask(
        "[yellow]!! CONFIRMACION DE USO ETICO !!\n"
        "Este software esta disenado exclusivamente para uso profesional etico autorizado.\n"
        "Solo debe usarse en sistemas donde tengas autorizacion explicita.\n\n"
        "Confirmas que tienes autorizacion para operar en estos sistemas?",
        default=False
    ):
        console.print("[red]Operacion cancelada. T-100AI requiere autorizacion expliita.[/]")
        raise typer.Exit(code=1)

    return cfg


@app.callback()
def cli_callback(
    ctx: typer.Context,
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Modelo Ollama (ej: devstral-small-2:latest)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Ruta a config.toml"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Modo debug"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Modo sin LLM"),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Objetivo inicial (IP/dominio)"),
) -> None:
    """T-100AI - AI-Powered Offensive Security Terminal

Usa: python -m t100ai.cli.main --help
    """
    if ctx.invoked_subcommand is None:
        show_banner()
        cfg = _apply_config_and_confirm(T100AIConfig(), config, debug, model, no_llm)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_t100ai(cfg, scope))


@app.command("main")
def main_entry(
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Modelo Ollama (ej: devstral-small-2:latest)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Ruta a config.toml"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Modo debug"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Modo sin LLM"),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Objetivo inicial (IP/dominio)"),
) -> None:
    """Inicia T-100AI - AI-Powered Offensive Security Terminal

Ejemplos:
  python -m t100ai.cli.main
  python -m t100ai.cli.main -s 192.168.1.1
  python -m t100ai.cli.main -m llama3.2 -s example.com
  python -m t100ai.cli.main --no-llm

Comandos: /scope, /role, /skills, /tools, /wordlist, /agent, /read, /finding, /report, /mode, /help, /clear
    """
    show_banner()
    cfg = _apply_config_and_confirm(T100AIConfig(), config, debug, model, no_llm)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_t100ai(cfg, scope))


def _system_command_list() -> list[str]:
    """Return a list of system commands (non-slash built-ins)."""
    return [
        "help", "version", "info", "workflow", "skill", "tool", "finding", "report", "mode", "clear", "history",
        "exit", "quit", "salir",
    ]


def _discover_names() -> dict:
    """Discover tool/skill/workflow names from the filesystem when available."""
    names = {"tools": [], "skills": [], "workflows": []}
    t100ai_root = Path(__file__).resolve().parent.parent
    # Tools
    for p in [t100ai_root / "tools"]:
        if p.exists():
            for child in p.iterdir():
                if child.is_dir():
                    names["tools"].append(child.name)
                elif child.is_file():
                    names["tools"].append(child.stem)
            break
    # Skills
    for p in [t100ai_root / "skills"]:
        if p.exists():
            for child in p.iterdir():
                if child.is_dir():
                    names["skills"].append(child.name)
                elif child.is_file():
                    names["skills"].append(child.stem)
            break
    # Workflows
    for p in [t100ai_root / "workflows"]:
        if p.exists():
            for child in p.iterdir():
                if child.is_file():
                    names["workflows"].append(child.stem)
            break
    return names


def _show_help() -> None:
    """Display comprehensive help with all commands."""
    help_md = markdown_help()
    console.print(Markdown(help_md))


def markdown_help() -> str:
    return """
# ◈ T-100AI — Ayuda de Comandos

**T-100AI** · AI-Powered Offensive Security Terminal · *Unseen. Unconstrained. Unstoppable.*

---

## SESIÓN Y ALCANCE
| Comando | Descripción |
|---|---|
| `/session new [nombre]` | Iniciar nueva sesión de operación |
| `/session load [id]` | Cargar sesión guardada |
| `/session export` | Exportar sesión actual |
| `/scope set [ip/cidr/domain]` | Definir el scope de la operación |
| `/scope show` | Mostrar scope actual |
| `/scope clear` | Limpiar scope |

## ROLES DEL OPERADOR
| Comando | Descripción |
|---|---|
| `/role set [nombre]` | Cambiar rol activo |
| `/role show` | Mostrar rol actual y skills activos |
| `/role list` | Listar todos los roles disponibles |

Roles disponibles: `pentester` · `red-teamer` · `blue-teamer` · `ctf-player` · `forensic`

## SKILLS
| Comando | Descripción |
|---|---|
| `/skill use [nombre]` | Activar skill específico |
| `/skill list` | Listar skills disponibles |
| `/skill info [nombre]` | Info detallada de un skill |

Skills: `recon` · `osint` · `web` · `exploit` · `postex` · `forense` · `ad` · `report`

## HERRAMIENTAS
| Comando | Descripción |
|---|---|
| `/tool run [herramienta] [args]` | Ejecutar herramienta directamente |
| `/tool list` | Listar herramientas disponibles |

## WORKFLOWS
| Comando | Descripción |
|---|---|
| `/workflow run [nombre]` | Ejecutar workflow completo |
| `/workflow list` | Listar workflows disponibles |
| `/workflow status` | Estado del workflow en curso |

Workflows: `full_pentest` · `web_audit` · `ir_response` · `ad_attack` · `quick_scan` · `report_gen`

## MODELO DE IA
| Comando | Descripción |
|---|---|
| `/model switch [nombre]` | Cambiar modelo Ollama |
| `/model info` | Info del modelo activo |
| `/context show` | Ver historial conversacional en memoria |
| `/context clear` | Limpiar historial (mantiene hallazgos) |

## HALLAZGOS
| Comando | Descripción |
|---|---|
| `/findings show` | Ver todos los hallazgos registrados |
| `/findings add [descripción]` | Añadir hallazgo manual |
| `/finding score [id] [cvss]` | Asignar score CVSS a un hallazgo |

## REPORTS
| Comando | Descripción |
|---|---|
| `/report generate` | Generar informe final |
| `/report preview` | Vista previa del informe |
| `/report export [format]` | Exportar (md/html/pdf) |

## PERMISOS
| Comando | Descripción |
|---|---|
| `/mode paranoid` | Confirmación en TODAS las acciones |
| `/mode standard` | Modo estándar (por defecto) |
| `/mode expert` | Auto-ejecución sin confirmaciones |

## UTILIDADES
| Comando | Descripción |
|---|---|
| `help` / `/help` | Mostrar esta ayuda |
| `/log show` | Ver log de acciones de sesión |
| `/log export` | Exportar log completo a JSON |
| `/context show` | Ver historial conversacional en memoria |
| `/context clear` | Limpiar historial (mantiene hallazgos) |
| `/model info` | Ver modelo LLM activo y host |
| `/history` | Historial de comandos del terminal |
| `/clear` | Limpiar pantalla |
| `exit` / `quit` | Cerrar T-100AI |

---

## CONTROL DE SISTEMA (LLM)

El LLM puede ejecutar comandos reales usando la sintaxis:

```
<cmd>nmap -sV 192.168.1.1</cmd>
```

Se pedirá confirmación antes de ejecutar cada comando (excepto en modo `expert`).
El output se analiza automáticamente y el LLM propone los siguientes pasos.

---

## ENTRADA NATURAL

Todo lo que no sea un comando `/cmd` se procesa como lenguaje natural:

```
escanea los puertos de 192.168.1.1
tengo este hash: $2y$10$abc...
explícame el ataque Kerberoasting
inicia un pentest completo contra 10.0.0.0/24
```
"""



# ─────────────────────────────────────────────────────────────────────────────
# Paleta de Colores T-100AI con ANSI extendido
# ─────────────────────────────────────────────────────────────────────────────
class T100AI_COLORS:
    """Paleta de colores del tema T-100AI"""
    BG_PRIMARY = "#080C14"
    GREEN_PRIMARY = "#00FF88"
    CYAN_PRIMARY = "#00D4FF"
    RED_CRITICAL = "#FF3366"
    ORANGE_HIGH = "#FF6B35"
    YELLOW_MEDIUM = "#FFD60A"
    GRAY_MUTED = "#8B949E"
    
    SEVERITY_COLORS = {
        "CRIT": RED_CRITICAL,
        "HIGH": ORANGE_HIGH,
        "MED": YELLOW_MEDIUM,
        "LOW": GREEN_PRIMARY,
        "INFO": GRAY_MUTED,
    }
    
    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        return cls.SEVERITY_COLORS.get(severity.upper(), cls.GRAY_MUTED)


class ANSIColors:
    """Códigos ANSI extendidos para terminal"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"
    
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    @classmethod
    def rgb(cls, r: int, g: int, b: int) -> str:
        return f"\033[38;2;{r};{g};{b}m"
    
    @classmethod
    def bg_rgb(cls, r: int, g: int, b: int) -> str:
        return f"\033[48;2;{r};{g};{b}m"
    
    @classmethod
    def cursor_hide(cls) -> str:
        return "\033[?25l"
    
    @classmethod
    def cursor_show(cls) -> str:
        return "\033[?25h"
    
    @classmethod
    def clear_screen(cls) -> str:
        return "\033[2J\033[H"
    
    @classmethod
    def clear_line(cls) -> str:
        return "\033[2K"


class KeyboardShortcuts:
    """Keyboard shortcuts support"""
    
    CTRL_C = "\x03"
    CTRL_L = "\x0c"
    CTRL_D = "\x04"
    
    @staticmethod
    def handle_input(char: str, console) -> bool:
        """Procesa atajos de teclado. Retorna True si se manejó."""
        if char == KeyboardShortcuts.CTRL_L:
            console.clear()
            return True
        elif char == KeyboardShortcuts.CTRL_D:
            console.print("[yellow]Usa 'exit' para salir[/]")
            return True
        return False


def _get_input_with_esc() -> Optional[str]:
    """Lee input del usuario detectando Esc para cancelar"""
    try:
        import sys
        import os
        
        if sys.platform == "win32":
            import msvcrt
            
            buffer = ""
            while True:
                if msvcrt.kbhit():
                    char = msvcrt.getch()
                    if char == b'\x1b':
                        return None
                    if char == b'\r':
                        print()
                        return buffer
                    if char == b'\x08':
                        if buffer:
                            buffer = buffer[:-1]
                            sys.stdout.write('\b \b')
                            sys.stdout.flush()
                    else:
                        try:
                            buffer += char.decode('utf-8')
                            sys.stdout.write(char.decode('utf-8'))
                            sys.stdout.flush()
                        except:
                            pass
        else:
            import select
            import tty
            import termios
            
            old_settings = termios.tcgetattr(sys.stdin)
            try:
                tty.setcbreak(sys.stdin.fileno())
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1)
                    if char == '\x1b':
                        return None
                return input()
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    except:
        return input()


def get_enhanced_prompt(session, config) -> str:
    """Genera prompt mejorado con colores ANSI"""
    role_tag = f"|{session.role.name}|" if session.role else ""
    model_tag = config.ollama_model
    
    cyan = ANSIColors.CYAN
    green = ANSIColors.BRIGHT_GREEN
    gray = ANSIColors.BRIGHT_BLACK
    bold = ANSIColors.BOLD
    reset = ANSIColors.RESET
    
    return (
        f"\n{green}⟩{reset} "
        f"{gray}[{reset}"
        f"{cyan}{model_tag}{reset}"
        f"{green}{role_tag}{reset}"
        f"{gray}@t100ai]{reset} "
        f"{green}▶{reset} "
    )


# ─────────────────────────────────────────────────────────────────────────────
# Banner — Ghost-ship ASCII art
# ─────────────────────────────────────────────────────────────────────────────

T100AI_LOGO = r"""         ^
       _-^-_
    _-',^. `-_.
 ._-' ,'   `.   `-_
!`-_._________`-':::
!   /\        /\::::
;  /  \      /..\ :::
! /    \    /....\::
!/      \  /......\:
;--.___. \/_.__.--;;
 '-_    `:!;;;;;;;'
     `-_, :!;;;''
         `-!'"""

SUBTITLE = "[#8B949E]Security | Pentesting | Exploitation | Control | Terminal[/]"
TAGLINE = "[#00D4FF italic]Unseen. Unconstrained. Unstoppable.[/]"


def show_banner() -> None:
    """Muestra el banner de T-100AI"""
    console.print(f"[bold #00FF88]{T100AI_LOGO}[/bold #00FF88]")
    console.print()
    console.print(SUBTITLE)
    console.print(TAGLINE)
    console.print()
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
# Comandos
# ─────────────────────────────────────────────────────────────────────────────
def _create_and_run_event_loop(coro):
    """Create a new event loop for Windows compatibility."""
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# Console with cross-platform support


async def run_t100ai(cfg: T100AIConfig, initial_scope: Optional[str] = None) -> None:
    """Ejecuta la sesión principal de T-100AI"""
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

    session = Session()
    session.set_config(cfg)
    
    if initial_scope:
        session.add_to_scope(initial_scope)
    
    engine = T100AIEngine(session=session, config=cfg)

    print("Inicializando motor T-100AI...")
    await engine.initialize()
    print("OK: Motor inicializado")

    if initial_scope:
        print(f"Scope: {initial_scope}")

    # Initialize permission manager for interactive confirmations
    permission_manager = PermissionManager(current_level=PermissionLevel.OBSERVATION)

    console.print(Panel.fit(
        "[#00FF88]T-100AI iniciado correctamente[/]\n"
        f"Modelo: [#00D4FF]{cfg.ollama_model}[/]\n"
        f"Scope: [#FFD60A]{', '.join(s.target for s in session.scope) if session.scope else 'None'}[/]\n"
        f"Modo: [#00FF88]{'CLI Interactivo' if cfg.llm_enabled else 'Herramientas'}[/]\n"
        f"Permisos: [#FFD60A]{cfg.permission_mode}[/]",
        border_style="#00FF88"
    ))

    console.print("\n[#8B949E]Escribe 'help' para ver comandos disponibles o 'exit' para salir.[/]\n")
    sys.stdout.flush()
    
    # Autocompletado opcional con prompt_toolkit (si está disponible)
    completer = None
    prompt_session = None
    if prompt_toolkit_available:
        try:
            from prompt_toolkit.completion import Completion
            
            class SystemCompleter(Completer if prompt_toolkit_available else object):
                def __init__(self, ctx_completer):
                    self.ctx = ctx_completer
                
                def get_completions(self, document, complete_event):
                    text = document.text_before_cursor
                    if not text:
                        for c in _system_command_list():
                            yield Completion(c, start_position=0)
                        return
                    last = text.split()[-1]
                    pool = set(_system_command_list())
                    names = _discover_names()
                    for t in names.get("tools", []):
                        pool.add(f"tool run {t}")
                    for s in names.get("skills", []):
                        pool.add(f"skill use {s}")
                    for w in names.get("workflows", []):
                        pool.add(f"workflow run {w}")
                    for item in sorted(pool):
                        if item.startswith(last):
                            yield Completion(item, start_position=-len(last))
            
            ctx_completer = ContextAwareCompleter(session=session, engine=engine)
            completer = SystemCompleter(ctx_completer)
            prompt_session = PromptSession(completer=completer)
        except Exception:
            pass
    
    # Loop principal
    consecutive_cancel = 0
    while True:
        try:
            if engine.interactive_mode:
                prompt = "\033[1;33m⟩ \033[0m"
            else:
                prompt = get_enhanced_prompt(session, session.config)
            sys.stdout.write(prompt)
            sys.stdout.flush()

            try:
                user_input = input()
            except EOFError:
                console.print("\n[yellow]Entrada cerrada.[/]")
                break
            
            consecutive_cancel = 0
            
            if not user_input or not user_input.strip():
                continue
            
            if user_input.lower() in ("exit", "quit", "salir"):
                break
            
            command_history.add(user_input, session_id=session.id)

            if user_input.strip() in ("/help", "help"):
                _show_help()
                continue

            if user_input.strip() == "/clear":
                console.clear()
                continue

            was_interactive = engine.interactive_mode
            engine.interactive_mode = False
            
            if was_interactive:
                await engine.process_interactive_input(user_input)
            else:
                await engine.process_input(user_input)

        except KeyboardInterrupt:
            consecutive_cancel += 1
            if consecutive_cancel >= 2:
                console.print("\n[bold #FF3366]Saliendo de T-100AI...[/]")
                break
            engine._cancel_requested = True
            console.print("\n[yellow]Cancelando... (Ctrl+C de nuevo para salir)[/]")
        except EOFError:
            console.print("\n[yellow]Entrada cerrada. Saliendo...[/]")
            break
        except Exception as e:
            from t100ai.utils.errors import ErrorHandler, format_error
            ErrorHandler.register_defaults()
            console.print(format_error(e))


@app.command()
def version() -> None:
    """Muestra la versión de T-100AI"""
    console.print("[#00FF88]T-100AI v0.1.0[/]")
    console.print("[#8B949E]AI-Powered Offensive Security Terminal[/]")


@app.command()
def info() -> None:
    """Muestra informacion del sistema"""
    table = Table(title="Informacion del Sistema T-100AI")
    table.add_column("Componente", style="#00D4FF")
    table.add_column("Estado", style="#00FF88")
    table.add_column("Detalles", style="#8B949E")
    
    table.add_row("Version", "[OK]", "0.1.0")
    table.add_row("Python", "[OK]", f"{sys.version.split()[0]}")
    table.add_row("LLM", "[--]", "No conectado")
    table.add_row("Herramientas", "[--]", "0 cargadas")
    
    console.print(table)


if __name__ == "__main__":
    app()
