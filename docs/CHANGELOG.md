# Changelog

Toutes les modifications notables apportées à ce projet sont consignées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et adhère au [Versionnage Sémantique (SemVer)](https://semver.org/).

## [1.0.0] - 2026-10-23

### Ajouts Initiaux (v1.0.0 Release)
- **Chiffrement Granulaire des Segments Vidéo :**
  - Chiffrement symétrique authentifié AES-256-GCM par segment chunk.
  - Données associées authentifiées (AAD) liant l'identifiant vidéo et l'index de segment.
  - Calcul d'empreinte SHA-256 pour intégrité de transport.
- **Service de Jetons Éphémères de Streaming :**
  - Signature HMAC-SHA256 avec durée de vie ultra-courte (TTL 30 secondes).
  - Verrouillage par adresse IP cliente (IP-Binding).
- **Tatouage Médico-Légal (Forensic Watermarking) :**
  - Insertion stéganographique de l'identité du spectateur à la volée.
  - Endpoint de traçabilité de fuites permettant d'identifier formellement les auteurs de divulgations.
- **Contrôle d'Accès Tactique RBAC :**
  - 4 niveaux de confidentialité (Public, Staff Interne, Tactique Restreint, Espionnage Adverse).
- **Variante Intelligence Artificielle - Moteur de Détection d'Intrusion :**
  - Détection du dump / scraping vidéo accéléré (> 15x la vitesse de lecture normale).
  - Détection des outils automatisés headless (yt-dlp, curl, ffmpeg, python-requests).
  - Détection de forçage et sondage répété d'actifs protégés.
  - Blocage automatique immédiat à partir d'un score de risque >= 0.75.
- **Assurance Qualité & Tests :**
  - Suite complète de 20 tests automatisés avec 100% de réussite.
  - Workflow GitHub Actions CI pour linter, tests continus et scan Bandit.
