"""
Fixtures pytest pour la protection des flux d'analyse vidéo.
"""

import pytest
import pytest_asyncio
import httpx
from fastapi import FastAPI

from src.config import Settings
from src.main import create_app
from src.streaming.segment_crypto import VideoSegmentCryptoEngine
from src.streaming.token_service import StreamTokenService
from src.watermark.forensic_watermarker import ForensicWatermarker
from src.ai.intrusion_detector import VideoIntrusionDetectionEngine


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        APP_ENV="test",
        LOG_LEVEL="DEBUG",
        VIDEO_STREAM_MASTER_KEY_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        STREAM_TOKEN_HMAC_KEY_HEX="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        STREAM_TOKEN_TTL_SECONDS=30,
        INTRUSION_DETECTION_THRESHOLD=0.75,
    )


@pytest.fixture
def crypto_engine(test_settings: Settings) -> VideoSegmentCryptoEngine:
    return VideoSegmentCryptoEngine(master_key_hex=test_settings.VIDEO_STREAM_MASTER_KEY_HEX)


@pytest.fixture
def token_service(test_settings: Settings) -> StreamTokenService:
    return StreamTokenService(
        hmac_key_hex=test_settings.STREAM_TOKEN_HMAC_KEY_HEX,
        ttl_seconds=test_settings.STREAM_TOKEN_TTL_SECONDS,
    )


@pytest.fixture
def watermarker() -> ForensicWatermarker:
    return ForensicWatermarker()


@pytest.fixture
def intrusion_engine(test_settings: Settings) -> VideoIntrusionDetectionEngine:
    return VideoIntrusionDetectionEngine(intrusion_threshold=test_settings.INTRUSION_DETECTION_THRESHOLD)


@pytest.fixture
def test_app(test_settings: Settings) -> FastAPI:
    return create_app(settings=test_settings)


@pytest_asyncio.fixture
async def async_client(test_app: FastAPI):
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
