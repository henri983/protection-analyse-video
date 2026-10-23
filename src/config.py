"""
Configuration centrale et variables d'environnement du service vidéo.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Protection Analyse Vidéo Tactique"
    APP_ENV: str = "development"
    LOG_LEVEL: str = "INFO"

    # Clé maître de chiffrement des segments vidéo (AES-256-GCM hex)
    VIDEO_STREAM_MASTER_KEY_HEX: str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    # Clé HMAC de signature des jetons éphémères de streaming
    STREAM_TOKEN_HMAC_KEY_HEX: str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

    # Durée de validité des jetons éphémères de lecture (secondes)
    STREAM_TOKEN_TTL_SECONDS: int = 30

    # Seuil d'anomalie IA pour déclenchement d'alerte et blocage
    INTRUSION_DETECTION_THRESHOLD: float = 0.75

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
