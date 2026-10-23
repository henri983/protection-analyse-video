# Politique de Sécurité & Modèle de Menace - Systèmes Vidéo Sportifs

## 1. Modèle de Menace Multimédia

| Vecteur d'Attaque | Risque Stratégique | Contre-Mesure Implémentée |
|---|---|---|
| **Interception de Flux en Direct (Man-In-The-Middle)** | Espionnage en temps réel du plan de jeu par un club rival | Chiffrement symétrique authentifié AES-256-GCM par segment individuel. |
| **Aspiration Massive par Outil Automatisé (yt-dlp, ffmpeg)** | Exfiltration de la totalité des archives d'entraînement | Détection d'intrusion IA bloquant immédiatement les User-Agents et les rafales de requêtes. |
| **Partage Illicite d'Identifiants (Credential Sharing)** | Fuite d'accès vers des journalistes ou agents externes | Jetons éphémères de 30 secondes verrouillés sur l'adresse IP cliente (`IP-binding`). |
| **Fuite Anonyme sur Réseaux Sociaux (Screen Grab / Leak)** | Divulgation publique des coups de pied arrêtés secrets | Tatouage médico-légal imperceptible permettant l'identification rétroactive de l'auteur. |
| **Élévation de Privilèges sur Vidéos Classifiées** | Accès non autorisé par des scouts externes invités | Isolation stricte RBAC basée sur les niveaux de confidentialité de l'actif vidéo. |

## 2. Procédure de Signalement & Contact Sécurité

Pour tout incident lié à la sécurité des flux ou à une tentative d'intrusion :
- **Responsable Sécurité :** `henrinyame2001@gmail.com`
- **Engagement :** Prise en charge immédiate.
