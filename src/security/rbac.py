"""
Contrôle d'accès basé sur les rôles (RBAC) pour les archives vidéo tactiques des clubs.
"""

from enum import Enum
from typing import Dict, Set
from src.models.video import TacticalConfidentiality


class VideoAccessRole(str, Enum):
    HEAD_COACH = "head_coach"
    TACTICAL_ANALYST = "tactical_analyst"
    VIDEO_EDITOR = "video_editor"
    CLUB_DIRECTOR = "club_director"
    GUEST_SCOUT = "guest_scout"


ROLE_CONFIDENTIALITY_PERMISSIONS: Dict[VideoAccessRole, Set[TacticalConfidentiality]] = {
    VideoAccessRole.HEAD_COACH: {
        TacticalConfidentiality.PUBLIC_BROADCAST,
        TacticalConfidentiality.INTERNAL_STAFF,
        TacticalConfidentiality.RESTRICTED_TACTICAL,
        TacticalConfidentiality.HIGH_CONFIDENTIAL_SCOUT,
    },
    VideoAccessRole.TACTICAL_ANALYST: {
        TacticalConfidentiality.PUBLIC_BROADCAST,
        TacticalConfidentiality.INTERNAL_STAFF,
        TacticalConfidentiality.RESTRICTED_TACTICAL,
        TacticalConfidentiality.HIGH_CONFIDENTIAL_SCOUT,
    },
    VideoAccessRole.VIDEO_EDITOR: {
        TacticalConfidentiality.PUBLIC_BROADCAST,
        TacticalConfidentiality.INTERNAL_STAFF,
        # Interdit formellement : RESTRICTED_TACTICAL, HIGH_CONFIDENTIAL_SCOUT
    },
    VideoAccessRole.CLUB_DIRECTOR: {
        TacticalConfidentiality.PUBLIC_BROADCAST,
        TacticalConfidentiality.INTERNAL_STAFF,
        TacticalConfidentiality.HIGH_CONFIDENTIAL_SCOUT,
    },
    VideoAccessRole.GUEST_SCOUT: {
        TacticalConfidentiality.PUBLIC_BROADCAST,
    },
}


class VideoSecurityPolicy:
    """Moteur de vérification des droits d'accès aux flux vidéo."""

    @staticmethod
    def can_access_video(role: VideoAccessRole, confidentiality: TacticalConfidentiality) -> bool:
        allowed = ROLE_CONFIDENTIALITY_PERMISSIONS.get(role, set())
        return confidentiality in allowed
