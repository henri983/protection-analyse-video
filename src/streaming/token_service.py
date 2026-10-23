"""
Gestionnaire de jetons de streaming éphémères (Signed Ephemeral Stream Tokens).
Garantit que chaque segment n'est accessible que pendant une fenêtre temporelle ultra-courte (ex: 30s).
"""

import hashlib
import hmac
import time
from typing import Optional, Tuple


class StreamTokenService:
    """Générateur et vérificateur de jetons cryptographiques éphémères de lecture."""

    def __init__(self, hmac_key_hex: str, ttl_seconds: int = 30) -> None:
        self.hmac_key = bytes.fromhex(hmac_key_hex)
        self.ttl_seconds = ttl_seconds

    def generate_token(self, user_id: str, video_id: str, client_ip: str) -> Tuple[str, float]:
        """Génère un jeton signé éphémère scellant l'identité du spectateur, la vidéo et son IP."""
        expires_at = time.time() + self.ttl_seconds
        payload = f"{user_id}:{video_id}:{client_ip}:{expires_at:.2f}"
        signature = hmac.new(self.hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        token = f"{user_id}:{video_id}:{expires_at:.2f}:{signature[:32]}"
        return token, expires_at

    def verify_token(self, token: str, client_ip: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """
        Vérifie le jeton éphémère :
        Retourne (is_valid, user_id, video_id, error_reason).
        """
        parts = token.split(":")
        if len(parts) != 4:
            return False, None, None, "Format de jeton invalide."

        user_id, video_id, expires_at_str, signature = parts
        try:
            expires_at = float(expires_at_str)
        except ValueError:
            return False, None, None, "Horodatage de jeton non numérique."

        if time.time() > expires_at:
            return False, user_id, video_id, "Jeton de streaming éphémère expiré."

        payload = f"{user_id}:{video_id}:{client_ip}:{expires_at:.2f}"
        expected_sig = hmac.new(self.hmac_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

        if not hmac.compare_digest(expected_sig, signature):
            return False, user_id, video_id, "Signature cryptographique de jeton invalide ou IP non concordante."

        return True, user_id, video_id, None
