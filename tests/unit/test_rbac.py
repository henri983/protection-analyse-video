"""
Tests unitaires des politiques de confidentialité et RBAC vidéo.
"""

import pytest
from src.models.video import TacticalConfidentiality
from src.security.rbac import VideoAccessRole, VideoSecurityPolicy


@pytest.mark.unit
def test_head_coach_access_all():
    """L'entraîneur principal a accès à tous les niveaux de vidéos tactiques."""
    role = VideoAccessRole.HEAD_COACH
    assert VideoSecurityPolicy.can_access_video(role, TacticalConfidentiality.HIGH_CONFIDENTIAL_SCOUT) is True
    assert VideoSecurityPolicy.can_access_video(role, TacticalConfidentiality.RESTRICTED_TACTICAL) is True
    assert VideoSecurityPolicy.can_access_video(role, TacticalConfidentiality.INTERNAL_STAFF) is True


@pytest.mark.unit
def test_video_editor_restricted_access():
    """Le monteur vidéo n'a pas accès aux combinaisons secrètes ni à l'espionnage adverse."""
    role = VideoAccessRole.VIDEO_EDITOR
    assert VideoSecurityPolicy.can_access_video(role, TacticalConfidentiality.INTERNAL_STAFF) is True
    assert VideoSecurityPolicy.can_access_video(role, TacticalConfidentiality.RESTRICTED_TACTICAL) is False
    assert VideoSecurityPolicy.can_access_video(role, TacticalConfidentiality.HIGH_CONFIDENTIAL_SCOUT) is False


@pytest.mark.unit
def test_guest_scout_minimal_access():
    """Un recruteur externe invité n'a accès qu'aux rediffusions publiques."""
    role = VideoAccessRole.GUEST_SCOUT
    assert VideoSecurityPolicy.can_access_video(role, TacticalConfidentiality.PUBLIC_BROADCAST) is True
    assert VideoSecurityPolicy.can_access_video(role, TacticalConfidentiality.INTERNAL_STAFF) is False
