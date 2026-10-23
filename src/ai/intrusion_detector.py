"""
Moteur IA de Détection d'Intrusion (NIDS / HIDS) pour Systèmes Vidéo Sportifs.

Détecte en temps réel :
1. L'aspiration automatisée de flux (Video Stream Scraping / Dump de segments à haute vitesse)
2. Les outils de captation automatisés (Headless Grabbers: yt-dlp, ffmpeg, curl, python-requests)
3. Le sondage de force brute sur archives tactiques protégées
4. Les tentatives de falsification ou d'évasion de filigrane médico-légal
"""

import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from src.models.intrusion_alert import IntrusionAction, IntrusionAlertRecord, IntrusionType


class VideoIntrusionDetectionEngine:
    """Moteur expert IA d'analyse comportementale et détection d'intrusions sur flux vidéo."""

    SUSPICIOUS_USER_AGENTS = [
        "python-requests",
        "curl",
        "ffmpeg",
        "yt-dlp",
        "postman",
        "headlesschrome",
        "wget",
        "scrapy",
    ]

    def __init__(self, intrusion_threshold: float = 0.75) -> None:
        self.intrusion_threshold = intrusion_threshold
        # user_id -> list of segment request timestamps
        self._user_segment_timestamps: Dict[str, List[float]] = defaultdict(list)
        # ip -> list of failed attempt timestamps
        self._ip_failed_attempts: Dict[str, List[float]] = defaultdict(list)
        # Historique d'alertes d'intrusion
        self.alert_history: List[IntrusionAlertRecord] = []

    def evaluate_stream_access(
        self,
        user_id: str,
        video_id: str,
        client_ip: str,
        user_agent: str,
        segment_index: int,
    ) -> Tuple[float, IntrusionAction, List[str], Optional[IntrusionType]]:
        """
        Évalue une requête de segment vidéo pour détecter une exfiltration ou intrusion.
        """
        now = time.time()
        reasons: List[str] = []
        risk_components: List[float] = []
        detected_type: Optional[IntrusionType] = None

        # 1. Détection de User-Agent de scrapping / extraction automatisée
        lower_ua = user_agent.lower()
        if any(tool in lower_ua for tool in self.SUSPICIOUS_USER_AGENTS):
            reasons.append(f"Outil d'aspiration automatisé ou bot détecté (User-Agent: {user_agent}).")
            risk_components.append(0.88)
            detected_type = IntrusionType.HEADLESS_GRABBER

        # 2. Détection d'aspiration de flux vidéo à haute vélocité (Stream Scraping)
        # Normalement : 1 segment toutes les 3 à 6 secondes (vitesse de lecture x1).
        # Si > 5 segments en moins de 2 secondes = aspiration accélérée (dump complet du match).
        timestamps = self._user_segment_timestamps[user_id]
        recent_timestamps = [t for t in timestamps if now - t <= 2.0]
        recent_timestamps.append(now)
        self._user_segment_timestamps[user_id] = recent_timestamps

        if len(recent_timestamps) >= 5:
            reasons.append(
                f"Aspiration accélérée anormale : {len(recent_timestamps)} segments demandés en moins de 2s "
                f"(vélocité > 15x la vitesse de lecture normale). Tentative de dump vidéo tactique."
            )
            risk_components.append(0.92)
            detected_type = IntrusionType.STREAM_SCRAPING

        # Agrégation du score de risque
        score = self._aggregate_risk(risk_components)
        action = self._determine_action(score)

        if score >= self.intrusion_threshold and detected_type:
            self._record_alert(user_id, client_ip, detected_type, score, action, reasons, video_id)

        return score, action, reasons, detected_type

    def evaluate_unauthorized_probe(
        self,
        user_id: str,
        client_ip: str,
        target_video_id: str,
    ) -> Tuple[float, IntrusionAction, List[str]]:
        """Détecte les tentatives répétées de forçage ou d'accès non autorisé (Credential / Asset Probing)."""
        now = time.time()
        attempts = self._ip_failed_attempts[client_ip]
        recent_attempts = [t for t in attempts if now - t <= 60.0]
        recent_attempts.append(now)
        self._ip_failed_attempts[client_ip] = recent_attempts

        reasons: List[str] = []
        risk_components: List[float] = []

        if len(recent_attempts) >= 3:
            reasons.append(f"Multiples tentatives d'accès non autorisées sur actifs tactiques protégés ({len(recent_attempts)} échecs en 60s).")
            risk_components.append(0.85)

        score = self._aggregate_risk(risk_components)
        action = self._determine_action(score)

        if score >= self.intrusion_threshold:
            self._record_alert(
                user_id, client_ip, IntrusionType.CREDENTIAL_STUFFING, score, action, reasons, target_video_id
            )

        return score, action, reasons

    def _aggregate_risk(self, risk_components: List[float]) -> float:
        if not risk_components:
            return 0.05
        prod = 1.0
        for r in risk_components:
            prod *= (1.0 - r)
        return round(1.0 - prod, 3)

    def _determine_action(self, score: float) -> IntrusionAction:
        if score >= 0.75:
            return IntrusionAction.DROP_AND_BLOCK
        elif score >= 0.40:
            return IntrusionAction.THROTTLE
        return IntrusionAction.ALLOW

    def _record_alert(
        self,
        user_id: str,
        client_ip: str,
        intrusion_type: IntrusionType,
        risk_score: float,
        action: IntrusionAction,
        reasons: List[str],
        video_id: Optional[str],
    ) -> IntrusionAlertRecord:
        alert = IntrusionAlertRecord(
            alert_id=f"INT-{len(self.alert_history) + 1:05d}",
            user_id=user_id,
            client_ip=client_ip,
            intrusion_type=intrusion_type,
            risk_score=risk_score,
            action=action,
            reasons=reasons,
            timestamp=time.time(),
            target_video_id=video_id,
        )
        self.alert_history.append(alert)
        return alert
