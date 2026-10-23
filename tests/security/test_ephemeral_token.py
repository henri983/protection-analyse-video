"""
Tests de sécurité des jetons de streaming éphémères.
"""

import time
import pytest
from src.streaming.token_service import StreamTokenService


@pytest.mark.security
def test_valid_ephemeral_token(token_service: StreamTokenService):
    """Vérifie la génération et validation conforme d'un jeton éphémère."""
    user_id = "ANALYST-1"
    video_id = "MATCH-01"
    client_ip = "82.64.1.20"

    token, expires_at = token_service.generate_token(user_id, video_id, client_ip)
    is_valid, ret_user, ret_vid, err = token_service.verify_token(token, client_ip)

    assert is_valid is True
    assert ret_user == user_id
    assert ret_vid == video_id
    assert err is None


@pytest.mark.security
def test_ephemeral_token_expiration():
    """Un jeton ayant dépassé son TTL de validité est immédiatement rejeté."""
    short_service = StreamTokenService(
        hmac_key_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ttl_seconds=1,
    )
    token, _ = short_service.generate_token("USR-SHORT", "VID-1", "10.0.0.1")

    # Attente de l'expiration
    time.sleep(1.2)

    is_valid, _, _, err = short_service.verify_token(token, "10.0.0.1")
    assert is_valid is False
    assert "expiré" in err.lower()


@pytest.mark.security
def test_ephemeral_token_ip_binding():
    """Un jeton utilisé depuis une adresse IP différente de celle d'émission est rejeté (anti-partage de session)."""
    service = StreamTokenService(
        hmac_key_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ttl_seconds=30,
    )
    token, _ = service.generate_token("USR-LEGIT", "VID-1", "82.64.1.20")

    # Tentative d'utilisation depuis une autre IP
    is_valid, _, _, err = service.verify_token(token, "194.25.1.99")
    assert is_valid is False
    assert "invalide" in err.lower() or "non concordante" in err.lower()


@pytest.mark.security
def test_tampered_token_signature_rejected(token_service: StreamTokenService):
    """Toute altération de la signature cryptographique du jeton éphémère est rejetée."""
    token, _ = token_service.generate_token("USR-1", "VID-1", "127.0.0.1")
    tampered_token = token[:-4] + "ffff"

    is_valid, _, _, err = token_service.verify_token(tampered_token, "127.0.0.1")
    assert is_valid is False
    assert "invalide" in err.lower()
