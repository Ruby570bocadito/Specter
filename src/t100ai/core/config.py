"""T-100AI Configuration"""

from pathlib import Path
from typing import Optional, Literal
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
import os


class T100AIConfig(BaseSettings):
    """Configuración principal de T-100AI"""
    
    # LLM Configuration
    ollama_host: str = Field(default="http://localhost:11434", alias="OLLAMA_HOST")
    ollama_model: str = Field(default="devstral-small-2:latest", alias="OLLAMA_MODEL")
    llm_enabled: bool = Field(default=True, alias="LLM_ENABLED")
    llm_temperature: float = Field(default=0.7, alias="LLM_TEMPERATURE")
    llm_context_window: int = Field(default=4096, alias="LLM_CONTEXT_WINDOW")
    
    # Session Configuration
    session_dir: Path = Field(default=Path("./sessions"), alias="SESSION_DIR")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO", alias="LOG_LEVEL")
    audit_log_enabled: bool = Field(default=True, alias="AUDIT_LOG_ENABLED")
    
    # Permission System
    permission_mode: Literal["paranoid", "standard", "expert"] = Field(
        default="standard", 
        alias="PERMISSION_MODE"
    )
    
    # Skills Configuration
    skills_dir: Path = Field(default=Path("./skills"), alias="SKILLS_DIR")
    
    # Scope Configuration
    scope: list[str] = Field(default_factory=list, alias="SCOPE")
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "populate_by_name": True,
    }
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "T100AIConfig":
        """Carga configuración desde archivo o variables de entorno"""
        if config_path:
            # Load from TOML if provided
            import tomllib
            config_data = {}
            config_file = Path(config_path)
            if config_file.exists():
                with open(config_file, "rb") as f:
                    config_data = tomllib.load(f)
            return cls(**config_data)
        
        return cls()
    
    def get_permission_level(self, action: str) -> int:
        """Obtiene el nivel de permiso requerido para una acción"""
        levels = {
            "paranoid": {"observation": 0, "active": 0, "intrusive": 0},
            "standard": {"observation": 0, "active": 1, "intrusive": 2},
            "expert": {"observation": 0, "active": 1, "intrusive": 2},
        }
        return levels.get(self.permission_mode, {}).get(action, 0)
    
    @property
    def is_paranoid_mode(self) -> bool:
        return self.permission_mode == "paranoid"
