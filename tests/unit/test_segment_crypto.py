"""
Tests unitaires du chiffrement de segments vidéo (AES-256-GCM + AAD).
"""

import pytest
from src.streaming.segment_crypto import VideoSegmentCryptoEngine


@pytest.mark.unit
def test_video_segment_encrypt_decrypt_roundtrip(crypto_engine: VideoSegmentCryptoEngine):
    """Vérifie le cycle complet de chiffrement / déchiffrement d'un segment vidéo."""
    video_id = "MATCH-DERBY-2026"
    seg_idx = 4
    raw_video_bytes = b"\x00\x00\x00\x1cftypisom\x00\x00\x02\x00isomiso2avc1mp41"

    encrypted_segment = crypto_engine.encrypt_segment(raw_video_bytes, video_id, seg_idx)
    assert isinstance(encrypted_segment, bytes)
    assert len(encrypted_segment) > len(raw_video_bytes)

    decrypted = crypto_engine.decrypt_segment(encrypted_segment, video_id, seg_idx)
    assert decrypted == raw_video_bytes


@pytest.mark.unit
def test_wrong_segment_index_rejection(crypto_engine: VideoSegmentCryptoEngine):
    """Tenter de déchiffrer un segment avec un index AAD incorrect doit échouer (attaque par réordonnancement)."""
    video_id = "MATCH-DERBY-2026"
    raw_video_bytes = b"fake_mp4_video_content"
    encrypted = crypto_engine.encrypt_segment(raw_video_bytes, video_id, 1)

    with pytest.raises(Exception):
        crypto_engine.decrypt_segment(encrypted, video_id, 2)


@pytest.mark.unit
def test_tampered_segment_rejection(crypto_engine: VideoSegmentCryptoEngine):
    """Toute altération de flux chiffré doit lever une exception d'intégrité."""
    video_id = "MATCH-DERBY-2026"
    encrypted = crypto_engine.encrypt_segment(b"payload_video_h265", video_id, 0)

    tampered = bytearray(encrypted)
    tampered[-1] ^= 0xFF

    with pytest.raises(Exception):
        crypto_engine.decrypt_segment(bytes(tampered), video_id, 0)


@pytest.mark.unit
def test_checksum_computation(crypto_engine: VideoSegmentCryptoEngine):
    """Vérifie l'empreinte de contrôle SHA-256 du segment."""
    chunk = b"video_frame_data"
    checksum = crypto_engine.compute_checksum(chunk)
    assert len(checksum) == 64
    assert checksum == crypto_engine.compute_checksum(chunk)
