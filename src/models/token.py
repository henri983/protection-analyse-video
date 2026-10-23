"""
Modèles de jetons de streaming éphémères.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class StreamTokenRequest(BaseModel):
    user_id: str = Field(..., examples=["ANALYST-DUPONT"])
    video_id: str = Field(..., examples=["VID-TACTIC-2026-001"])
    client_ip: str = Field(..., examples=["82.64.12.34"])
    user_agent: str = Field(..., examples=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"])


class StreamTokenResponse(BaseModel):
    token: str
    video_id: str
    user_id: str
    expires_at: float
    ttl_seconds: int
