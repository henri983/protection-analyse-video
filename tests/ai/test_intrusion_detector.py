"""
Tests du moteur IA de Détection d'Intrusion sur les flux vidéo.
"""

import pytest
from src.ai.intrusion_detector import (
    IntrusionAction,
    IntrusionType,
    VideoIntrusionDetectionEngine,
)


@pytest.mark.ai
def test_normal_stream_access_low_risk(intrusion_engine: VideoIntrusionDetectionEngine):
    """Lecture vidéo normale via lecteur agréé : score de risque très faible, accès autorisé."""
    user_id = "COACH-01"
    score, action, reasons, cat = intrusion_engine.evaluate_stream_access(
        user_id=user_id,
        video_id="MATCH-01",
        client_ip="82.64.1.10",
        user_agent="TacticalAnalystPro/3.2 (Windows 11)",
        segment_index=1,
    )

    assert score < 0.30
    assert action == IntrusionAction.ALLOW
    assert len(reasons) == 0
    assert cat is None


@pytest.mark.ai
def test_headless_grabber_tool_detected(intrusion_engine: VideoIntrusionDetectionEngine):
    """Détection immédiate d'un outil de capture/scraping automatisé (yt-dlp, curl, ffmpeg)."""
    user_id = "HACKER-BOT"

    score, action, reasons, cat = intrusion_engine.evaluate_stream_access(
        user_id=user_id,
        video_id="MATCH-01",
        client_ip="185.220.101.5",
        user_agent="yt-dlp/2026.01.15 ffmpeg/6.0",
        segment_index=1,
    )

    assert score >= 0.75
    assert action == IntrusionAction.DROP_AND_BLOCK
    assert cat == IntrusionType.HEADLESS_GRABBER
    assert any("automatisé" in r.lower() for r in reasons)


@pytest.mark.ai
def test_high_speed_stream_scraping_burst(intrusion_engine: VideoIntrusionDetectionEngine):
    """Détection de rafale anormale de segments (dump vidéo massif en < 2 secondes)."""
    user_id = "SCRAPER-FAST"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"

    # Envoi de 5 requêtes ultra-rapides
    for i in range(5):
        score, action, reasons, cat = intrusion_engine.evaluate_stream_access(
            user_id=user_id,
            video_id="MATCH-CLASSIFIED",
            client_ip="100.1.2.3",
            user_agent=ua,
            segment_index=i,
        )

    assert score >= 0.75
    assert action == IntrusionAction.DROP_AND_BLOCK
    assert cat == IntrusionType.STREAM_SCRAPING
    assert any("aspiration accélérée" in r.lower() for r in reasons)


@pytest.mark.ai
def test_repeated_unauthorized_probe_brute_force(intrusion_engine: VideoIntrusionDetectionEngine):
    """Détection de sondages répétés non autorisés sur des vidéos classifiées."""
    client_ip = "192.168.1.99"

    for _ in range(3):
        score, action, reasons = intrusion_engine.evaluate_unauthorized_probe(
            user_id="GUEST-SCOUT",
            client_ip=client_ip,
            target_video_id="SECRET-TACTICAL-SETPIECE",
        )

    assert score >= 0.75
    assert action == IntrusionAction.DROP_AND_BLOCK
    assert any("Multiples tentatives" in r for r in reasons)
    assert len(intrusion_engine.alert_history) >= 1
