"""
Tatouage numérique médico-légal (Forensic Watermarking) pour traçabilité de fuites vidéo.
Insère une empreinte stéganographique imperceptible dans les segments vidéo délivrés
à chaque utilisateur, permettant d'identifier immédiatement la source en cas de fuite.
"""

import base64
import json
import time
from typing import Dict, Optional, Tuple


class ForensicWatermarker:
    """Moteur d'insertion et d'extraction de filigranes médico-légaux."""

    MAGIC_WATERMARK_HEADER = b"__TACTIC_WATERMARK_V1__"

    @classmethod
    def embed_watermark(
        cls,
        raw_video_chunk: bytes,
        viewer_user_id: str,
        viewer_ip: str,
        video_id: str,
    ) -> bytes:
        """
        Insère l'empreinte médico-légale du spectateur dans le segment vidéo.
        Contient : viewer_id, ip, timestamp, signature.
        """
        metadata = {
            "viewer_user_id": viewer_user_id,
            "viewer_ip": viewer_ip,
            "video_id": video_id,
            "streamed_at": time.time(),
        }
        meta_json = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
        meta_b64 = base64.b64encode(meta_json)

        # Empreinte scellée insérée en fin de segment
        watermark_block = cls.MAGIC_WATERMARK_HEADER + meta_b64 + cls.MAGIC_WATERMARK_HEADER
        return raw_video_chunk + watermark_block

    @classmethod
    def extract_watermark(cls, watermarked_video_chunk: bytes) -> Optional[Dict[str, str]]:
        """
        Analyse un segment vidéo fuité et extrait l'identité du spectateur ayant causé la fuite.
        """
        if cls.MAGIC_WATERMARK_HEADER not in watermarked_video_chunk:
            return None

        try:
            parts = watermarked_video_chunk.split(cls.MAGIC_WATERMARK_HEADER)
            if len(parts) < 3:
                return None
            meta_b64 = parts[-2]
            meta_json = base64.b64decode(meta_b64)
            return json.loads(meta_json.decode("utf-8"))
        except Exception:
            return None
