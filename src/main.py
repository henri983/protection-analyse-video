"""
Application FastAPI - Protection des Flux Vidéo et Systèmes d'Analyse Tactique Sportive
avec Détection d'Intrusion par IA.
"""

import base64
import time
from typing import Dict, List, Optional
from fastapi import FastAPI, Header, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from src.ai.intrusion_detector import IntrusionAction, VideoIntrusionDetectionEngine
from src.config import Settings, get_settings
from src.models.intrusion_alert import IntrusionAlertRecord
from src.models.token import StreamTokenRequest, StreamTokenResponse
from src.models.video import (
    TacticalConfidentiality,
    TacticalVideoRegistration,
    VideoSegmentChunk,
)
from src.security.rbac import VideoAccessRole, VideoSecurityPolicy
from src.streaming.segment_crypto import VideoSegmentCryptoEngine
from src.streaming.token_service import StreamTokenService
from src.watermark.forensic_watermarker import ForensicWatermarker


class IngestSegmentPayload(BaseModel):
    segment_index: int = Field(..., ge=0)
    duration_seconds: float = Field(default=3.0, gt=0)
    raw_content_b64: str = Field(..., description="Contenu brut du segment encodé en base64")


class TraceLeakPayload(BaseModel):
    leaked_chunk_b64: str = Field(..., description="Extrait vidéo intercepté sur le web en base64")


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    current_settings = settings or get_settings()

    app = FastAPI(
        title="Protection des Flux et Systèmes d'Analyse Vidéo Tactique",
        description="Chiffrement granulaire des segments vidéo, tatouage médico-légal anti-fuite (Forensic Watermarking), jetons éphémères et Détection d'Intrusion IA.",
        version="1.0.0",
    )

    # Composants de sécurité vidéo et IA
    crypto = VideoSegmentCryptoEngine(master_key_hex=current_settings.VIDEO_STREAM_MASTER_KEY_HEX)
    token_service = StreamTokenService(
        hmac_key_hex=current_settings.STREAM_TOKEN_HMAC_KEY_HEX,
        ttl_seconds=current_settings.STREAM_TOKEN_TTL_SECONDS,
    )
    watermarker = ForensicWatermarker()
    intrusion_engine = VideoIntrusionDetectionEngine(
        intrusion_threshold=current_settings.INTRUSION_DETECTION_THRESHOLD
    )

    # Référentiels en mémoire
    videos_db: Dict[str, TacticalVideoRegistration] = {}
    # segment_id -> VideoSegmentChunk
    segments_db: Dict[str, VideoSegmentChunk] = {}
    # segment_id -> raw_decrypted_content (pour simulation de délivrance en direct)
    raw_segments_cache: Dict[str, bytes] = {}

    @app.get("/health", tags=["Monitoring"])
    async def health() -> dict:
        return {
            "status": "healthy",
            "service": "protection-analyse-video",
            "videos_catalog_count": len(videos_db),
            "segments_stored": len(segments_db),
            "intrusion_alerts_count": len(intrusion_engine.alert_history),
        }

    @app.post(
        "/api/v1/tactical-videos",
        status_code=status.HTTP_201_CREATED,
        tags=["Gestion des Vidéos Tactiques"],
    )
    async def register_tactical_video(
        payload: TacticalVideoRegistration,
        x_user_role: str = Header("head_coach", alias="X-User-Role"),
    ) -> dict:
        """Enregistre un actif vidéo tactique avec son niveau de confidentialité."""
        if payload.video_id in videos_db:
            raise HTTPException(status_code=400, detail="Vidéo tactique déjà référencée.")

        videos_db[payload.video_id] = payload
        return {
            "message": "Actif vidéo tactique classifié et enregistré.",
            "video_id": payload.video_id,
            "confidentiality": payload.confidentiality.value,
        }

    @app.post(
        "/api/v1/tactical-videos/{video_id}/segments",
        status_code=status.HTTP_201_CREATED,
        tags=["Ingestion de Flux"],
    )
    async def ingest_segment(video_id: str, payload: IngestSegmentPayload) -> dict:
        """Ingère un segment vidéo découpé, le chiffre en AES-256-GCM avec AAD séquentiel."""
        if video_id not in videos_db:
            raise HTTPException(status_code=404, detail="Vidéo tactique introuvable.")

        raw_bytes = base64.b64decode(payload.raw_content_b64)
        encrypted_bytes = crypto.encrypt_segment(raw_bytes, video_id, payload.segment_index)
        checksum = crypto.compute_checksum(raw_bytes)

        segment_id = f"{video_id}_seg_{payload.segment_index:04d}"
        chunk = VideoSegmentChunk(
            segment_id=segment_id,
            video_id=video_id,
            segment_index=payload.segment_index,
            duration_seconds=payload.duration_seconds,
            encrypted_payload_b64=base64.b64encode(encrypted_bytes).decode("ascii"),
            checksum_sha256=checksum,
        )
        segments_db[segment_id] = chunk
        raw_segments_cache[segment_id] = raw_bytes

        return {
            "message": "Segment vidéo chiffré en AES-256-GCM et stocké.",
            "segment_id": segment_id,
            "checksum_sha256": checksum,
        }

    @app.post(
        "/api/v1/streaming/token",
        response_model=StreamTokenResponse,
        tags=["Autorisation & Jetons"],
    )
    async def generate_stream_token(
        payload: StreamTokenRequest,
        x_user_role: str = Header(..., alias="X-User-Role"),
    ) -> StreamTokenResponse:
        """Délivre un jeton de streaming éphémère après vérification RBAC du niveau de confidentialité."""
        try:
            role = VideoAccessRole(x_user_role.lower())
        except ValueError:
            raise HTTPException(status_code=403, detail="Rôle utilisateur invalide.")

        if payload.video_id not in videos_db:
            raise HTTPException(status_code=404, detail="Vidéo introuvable.")

        video = videos_db[payload.video_id]

        # Vérification RBAC
        if not VideoSecurityPolicy.can_access_video(role, video.confidentiality):
            # Enregistrement pour l'IA d'intrusion (tentative de probing non autorisée)
            intrusion_engine.evaluate_unauthorized_probe(
                payload.user_id, payload.client_ip, payload.video_id
            )
            raise HTTPException(
                status_code=403,
                detail=f"Accès refusé : privilèges insuffisants pour la vidéo classifiée '{video.confidentiality.value}'.",
            )

        token, expires_at = token_service.generate_token(
            payload.user_id, payload.video_id, payload.client_ip
        )

        return StreamTokenResponse(
            token=token,
            video_id=payload.video_id,
            user_id=payload.user_id,
            expires_at=expires_at,
            ttl_seconds=current_settings.STREAM_TOKEN_TTL_SECONDS,
        )

    @app.get(
        "/api/v1/streaming/segments/{segment_id}",
        tags=["Diffusion Sécurisée"],
    )
    async def get_stream_segment(
        segment_id: str,
        token: str = Query(..., description="Jeton éphémère de streaming"),
        user_agent: str = Header("TacticalPlayer/1.0", alias="User-Agent"),
        x_client_ip: str = Header("127.0.0.1", alias="X-Client-IP"),
    ) -> Response:
        """
        Délivre un segment vidéo avec insertion d'un filigrane médico-légal personnalisé.
        Intercepte les attaques et scrapers via l'IA de détection d'intrusion.
        """
        # 1. Vérification du jeton éphémère
        is_valid, user_id, video_id, error = token_service.verify_token(token, x_client_ip)
        if not is_valid:
            intrusion_engine.evaluate_unauthorized_probe(user_id or "ANONYMOUS", x_client_ip, segment_id)
            raise HTTPException(status_code=401, detail=f"Accès non autorisé : {error}")

        if segment_id not in segments_db:
            raise HTTPException(status_code=404, detail="Segment vidéo introuvable.")

        chunk = segments_db[segment_id]
        if chunk.video_id != video_id:
            raise HTTPException(status_code=403, detail="Le jeton ne correspond pas à ce flux vidéo.")

        # 2. Analyse IA de Détection d'Intrusion (Scraping à haute vitesse, Grabber, Bot)
        score, action, reasons, detected_type = intrusion_engine.evaluate_stream_access(
            user_id=user_id,
            video_id=video_id,
            client_ip=x_client_ip,
            user_agent=user_agent,
            segment_index=chunk.segment_index,
        )

        if action == IntrusionAction.DROP_AND_BLOCK:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Intrusion détectée sur le flux vidéo tactique. Connexion interrompue.",
                    "risk_score": score,
                    "reasons": reasons,
                },
            )

        # 3. Récupération et déchiffrement du segment
        encrypted_raw = base64.b64decode(chunk.encrypted_payload_b64)
        decrypted_raw = crypto.decrypt_segment(encrypted_raw, video_id, chunk.segment_index)

        # 4. Tatouage médico-légal imperceptible (Forensic Watermarking)
        watermarked_chunk = watermarker.embed_watermark(
            raw_video_chunk=decrypted_raw,
            viewer_user_id=user_id,
            viewer_ip=x_client_ip,
            video_id=video_id,
        )

        return Response(content=watermarked_chunk, media_type="video/mp4")

    @app.post(
        "/api/v1/forensics/trace-leak",
        tags=["Forensics & Traçabilité"],
    )
    async def trace_video_leak(payload: TraceLeakPayload) -> dict:
        """Extrait l'empreinte médico-légale dissimulée dans un extrait fuité pour identifier l'auteur de la fuite."""
        chunk_bytes = base64.b64decode(payload.leaked_chunk_b64)
        extracted = watermarker.extract_watermark(chunk_bytes)

        if not extracted:
            raise HTTPException(
                status_code=404,
                detail="Aucun filigrane médico-légal détecté ou filigrane corrompu.",
            )

        return {
            "status": "LEAK_IDENTIFIED",
            "culprit_user_id": extracted.get("viewer_user_id"),
            "source_ip": extracted.get("viewer_ip"),
            "video_id": extracted.get("video_id"),
            "leak_timestamp": extracted.get("streamed_at"),
            "message": "Source de la fuite identifiée formellement par signature stéganographique.",
        }

    @app.get(
        "/api/v1/ai/intrusion/alerts",
        response_model=List[IntrusionAlertRecord],
        tags=["Supervision IA & Alertes"],
    )
    async def get_intrusion_alerts() -> List[IntrusionAlertRecord]:
        """Consulte les alertes d'intrusion et d'exfiltration tactique enregistrées par l'IA."""
        return intrusion_engine.alert_history

    return app


app = create_app()
