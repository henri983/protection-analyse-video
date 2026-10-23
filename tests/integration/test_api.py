"""
Tests d'intégration end-to-end de l'API FastAPI de protection vidéo tactique.
"""

import base64
import pytest
import httpx


@pytest.mark.asyncio
async def test_health_check(async_client: httpx.AsyncClient):
    """Vérifie l'endpoint de supervision de l'API vidéo."""
    res = await async_client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["service"] == "protection-analyse-video"


@pytest.mark.asyncio
async def test_complete_tactical_video_pipeline_and_intrusion_defense(async_client: httpx.AsyncClient):
    """
    Scénario d'intégration complet :
    1. Enregistrement d'une vidéo tactique confidentielle
    2. Ingestion de segments chiffrés en AES-256-GCM
    3. Refus d'accès pour un profil non habilité (guest_scout)
    4. Émission d'un jeton éphémère pour l'entraîneur (head_coach)
    5. Lecture du flux vidéo avec insertion du filigrane médico-légal
    6. Analyse d'une fuite vidéo et traçabilité formelle de l'auteur
    7. Blocage immédiat d'une intrusion par aspirateur de flux automatisé (yt-dlp)
    8. Vérification des alertes d'intrusion IA enregistrées
    """
    video_id = "VID-TACTIC-DERBY-2026"

    # 1. Enregistrement d'une vidéo tactique
    reg_payload = {
        "video_id": video_id,
        "title": "Schémas Tactiques Défensifs - Bloc Médian",
        "match_or_training_ref": "MATCH-REAL-2026",
        "confidentiality": "restricted_tactical",
        "duration_seconds": 120.0,
        "total_segments": 1,
    }
    reg_res = await async_client.post("/api/v1/tactical-videos", json=reg_payload)
    assert reg_res.status_code == 201

    # 2. Ingestion d'un segment vidéo
    raw_video_sample = b"MP4_HEADER_TACTICAL_FRAME_DATA_123456"
    seg_payload = {
        "segment_index": 0,
        "duration_seconds": 3.0,
        "raw_content_b64": base64.b64encode(raw_video_sample).decode("ascii"),
    }
    seg_res = await async_client.post(f"/api/v1/tactical-videos/{video_id}/segments", json=seg_payload)
    assert seg_res.status_code == 201
    seg_id = seg_res.json()["segment_id"]

    # 3. Tentative d'accès non autorisée par un scout externe
    scout_token_payload = {
        "user_id": "SCOUT-EXTERNAL",
        "video_id": video_id,
        "client_ip": "194.25.1.1",
        "user_agent": "Mozilla/5.0 Chrome/120.0",
    }
    unauth_res = await async_client.post(
        "/api/v1/streaming/token",
        json=scout_token_payload,
        headers={"X-User-Role": "guest_scout"},
    )
    assert unauth_res.status_code == 403

    # 4. Émission du jeton éphémère pour le coach principal
    coach_token_payload = {
        "user_id": "COACH-ANALYST-1",
        "video_id": video_id,
        "client_ip": "82.64.12.34",
        "user_agent": "TacticalPlayer/2.0",
    }
    token_res = await async_client.post(
        "/api/v1/streaming/token",
        json=coach_token_payload,
        headers={"X-User-Role": "head_coach"},
    )
    assert token_res.status_code == 200
    token = token_res.json()["token"]

    # 5. Lecture du flux vidéo avec jeton valide (tatoué à la volée)
    read_headers = {
        "User-Agent": "TacticalPlayer/2.0",
        "X-Client-IP": "82.64.12.34",
    }
    stream_res = await async_client.get(
        f"/api/v1/streaming/segments/{seg_id}?token={token}",
        headers=read_headers,
    )
    assert stream_res.status_code == 200
    watermarked_video_content = stream_res.content
    assert watermarked_video_content.startswith(raw_video_sample)
    assert len(watermarked_video_content) > len(raw_video_sample)

    # 6. Traçabilité médico-légale : si ce flux se retrouve fuité en ligne, on extrait la preuve
    leak_payload = {
        "leaked_chunk_b64": base64.b64encode(watermarked_video_content).decode("ascii")
    }
    trace_res = await async_client.post("/api/v1/forensics/trace-leak", json=leak_payload)
    assert trace_res.status_code == 200
    trace_data = trace_res.json()
    assert trace_data["status"] == "LEAK_IDENTIFIED"
    assert trace_data["culprit_user_id"] == "COACH-ANALYST-1"
    assert trace_data["source_ip"] == "82.64.12.34"

    # 7. Tentative d'intrusion par un scraper / grabber automatisé (ex: yt-dlp)
    hacker_headers = {
        "User-Agent": "yt-dlp/2026.01.10 (automated scraper)",
        "X-Client-IP": "82.64.12.34",
    }
    hack_res = await async_client.get(
        f"/api/v1/streaming/segments/{seg_id}?token={token}",
        headers=hacker_headers,
    )
    assert hack_res.status_code == 403
    hack_detail = hack_res.json()["detail"]
    assert hack_detail["risk_score"] >= 0.75
    assert any("automatisé" in r.lower() for r in hack_detail["reasons"])

    # 8. Consultation du registre d'alertes d'intrusion IA
    alerts_res = await async_client.get("/api/v1/ai/intrusion/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 1
    assert any(a["intrusion_type"] in ["headless_grabber", "credential_stuffing"] for a in alerts)
