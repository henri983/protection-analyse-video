"""
Modèles liés aux enregistrements vidéo tactiques et segments découpés.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class TacticalConfidentiality(str, Enum):
    PUBLIC_BROADCAST = "public_broadcast"          # Extraits grand public / presse
    INTERNAL_STAFF = "internal_staff"              # Débriefing collectif d'après-match
    RESTRICTED_TACTICAL = "restricted_tactical"    # Schémas sur coups de pied arrêtés, combinaisons secrètes
    HIGH_CONFIDENTIAL_SCOUT = "high_confidential"  # Rapport d'espionnage tactique adverse


class TacticalVideoRegistration(BaseModel):
    video_id: str = Field(..., examples=["VID-TACTIC-2026-001"])
    title: str = Field(..., examples=["Combinaisons Corners & Coups Francs - Phase Offensive"])
    match_or_training_ref: str = Field(..., examples=["ENTRAINEMENT-2026-10-23"])
    confidentiality: TacticalConfidentiality = TacticalConfidentiality.RESTRICTED_TACTICAL
    duration_seconds: float = Field(..., gt=0)
    total_segments: int = Field(default=10, ge=1)


class VideoSegmentChunk(BaseModel):
    segment_id: str
    video_id: str
    segment_index: int
    duration_seconds: float
    encrypted_payload_b64: str
    checksum_sha256: str
