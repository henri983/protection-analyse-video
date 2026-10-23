"""
Modèles d'alertes d'intrusion sur les flux vidéo.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class IntrusionType(str, Enum):
    STREAM_SCRAPING = "stream_scraping"            # Aspiration automatisée rapide des segments
    HEADLESS_GRABBER = "headless_grabber"          # Utilisation d'outils comme yt-dlp, curl, ffmpeg
    CREDENTIAL_STUFFING = "credential_stuffing"    # Tentative d'accès en force brute sur les sessions
    WATERMARK_TAMPERING = "watermark_tampering"    # Tentative d'altération ou suppression du filigrane
    IMPOSSIBLE_VELOCITY = "impossible_velocity"    # Accès distant concurrent d'un même compte


class IntrusionAction(str, Enum):
    ALLOW = "allow"
    THROTTLE = "throttle"
    DROP_AND_BLOCK = "drop_and_block"


class IntrusionAlertRecord(BaseModel):
    alert_id: str
    user_id: str
    client_ip: str
    intrusion_type: IntrusionType
    risk_score: float
    action: IntrusionAction
    reasons: List[str]
    timestamp: float
    target_video_id: Optional[str] = None
