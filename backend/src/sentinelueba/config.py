from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinelueba.runtime.paths import resolve_runtime_paths


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELUEBA_", env_file=".env")

    data_dir: Path = Field(default=Path("data"))
    database_path: Path = Field(default=Path("data/sentinelueba.sqlite3"))
    model_dir: Path = Field(default=Path("artifacts/model"))
    log_level: str = Field(default="INFO")
    identity_mode: str = Field(default="pseudonymous")

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.model_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    from sentinelueba.runtime.state import get_runtime_context

    context = get_runtime_context()
    if context.mode in {"desktop", "service"} and context.database_path is not None:
        return Settings(
            data_dir=context.data_dir or context.database_path.parent,
            database_path=context.database_path,
            model_dir=context.model_dir or context.database_path.parent.parent / "models",
            log_level=context.log_level,
        )
    runtime = resolve_runtime_paths()
    if runtime.mode == "development":
        return Settings()
    return Settings(
        data_dir=runtime.data_dir,
        database_path=runtime.database_path,
        model_dir=runtime.model_dir,
    )
