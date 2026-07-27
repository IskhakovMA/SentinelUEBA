from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINELUEBA_", env_file=".env")

    data_dir: Path = Field(default=Path("data"))
    database_path: Path = Field(default=Path("data/sentinelueba.sqlite3"))
    model_dir: Path = Field(default=Path("artifacts/model"))
    log_level: str = Field(default="INFO")

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.model_dir.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    return Settings()

