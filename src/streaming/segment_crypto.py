"""
Chiffrement symétrique authentifié AES-256-GCM des segments de flux vidéo tactique.
"""

import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VideoSegmentCryptoEngine:
    """Moteur de chiffrement granulaire par segment vidéo."""

    def __init__(self, master_key_hex: str) -> None:
        self.master_key = bytes.fromhex(master_key_hex)
        if len(self.master_key) != 32:
            raise ValueError("La clé maître de flux vidéo doit faire exactement 32 octets (64 hex).")
        self.aesgcm = AESGCM(self.master_key)

    def encrypt_segment(self, raw_chunk_bytes: bytes, video_id: str, segment_index: int) -> bytes:
        """Chiffre un segment vidéo avec le couple (video_id, segment_index) comme AAD."""
        nonce = os.urandom(12)
        aad = f"{video_id}:{segment_index}".encode("utf-8")
        ciphertext = self.aesgcm.encrypt(nonce, raw_chunk_bytes, aad)
        return nonce + ciphertext

    def decrypt_segment(self, encrypted_chunk: bytes, video_id: str, segment_index: int) -> bytes:
        """Déchiffre un segment vidéo en vérifiant l'intégrité et le chaînage séquentiel AAD."""
        if len(encrypted_chunk) < 28:
            raise ValueError("Segment vidéo chiffré trop court ou corrompu.")
        nonce = encrypted_chunk[:12]
        ciphertext = encrypted_chunk[12:]
        aad = f"{video_id}:{segment_index}".encode("utf-8")
        return self.aesgcm.decrypt(nonce, ciphertext, aad)

    @staticmethod
    def compute_checksum(chunk_bytes: bytes) -> str:
        """Calcule l'empreinte SHA-256 du segment pour vérification d'intégrité de transport."""
        return hashlib.sha256(chunk_bytes).hexdigest()
