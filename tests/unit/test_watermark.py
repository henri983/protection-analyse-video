"""
Tests unitaires du tatouage médico-légal (Forensic Steganographic Watermarking).
"""

import pytest
from src.watermark.forensic_watermarker import ForensicWatermarker


@pytest.mark.unit
def test_embed_and_extract_forensic_watermark(watermarker: ForensicWatermarker):
    """Vérifie l'insertion du filigrane et l'extraction de l'identité du spectateur."""
    raw_video = b"RAW_H264_VIDEO_STREAM_BYTES"
    viewer_id = "ANALYST-MARTIN"
    viewer_ip = "194.25.1.100"
    video_id = "VID-TACTIC-CORNER-01"

    watermarked_chunk = watermarker.embed_watermark(
        raw_video_chunk=raw_video,
        viewer_user_id=viewer_id,
        viewer_ip=viewer_ip,
        video_id=video_id,
    )

    assert watermarked_chunk.startswith(raw_video)
    assert len(watermarked_chunk) > len(raw_video)

    # Extraction médico-légale
    extracted_info = watermarker.extract_watermark(watermarked_chunk)
    assert extracted_info is not None
    assert extracted_info["viewer_user_id"] == viewer_id
    assert extracted_info["viewer_ip"] == viewer_ip
    assert extracted_info["video_id"] == video_id


@pytest.mark.unit
def test_unwatermarked_chunk_returns_none(watermarker: ForensicWatermarker):
    """Un flux sans filigrane ne retourne aucune information d'extraction."""
    raw_chunk = b"REGULAR_VIDEO_STREAM_NO_WATERMARK"
    assert watermarker.extract_watermark(raw_chunk) is None


@pytest.mark.unit
def test_watermark_preserves_underlying_video_data(watermarker: ForensicWatermarker):
    """L'insertion du filigrane préserve fidèlement les octets vidéo d'origine sans altération."""
    original_video = b"\x00\x00\x00\x20ftypmp42\x00\x00\x00\x00isommp42"
    watermarked = watermarker.embed_watermark(original_video, "COACH-1", "127.0.0.1", "VID-01")

    assert watermarked[:len(original_video)] == original_video
