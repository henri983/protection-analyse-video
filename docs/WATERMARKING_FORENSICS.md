# Tatouage Numérique Médico-Légal (Forensic Watermarking)

## 1. Principes et Utilité dans le Sport Professionnel

Dans le sport de très haut niveau, les fuites de séances tactiques ou de vidéos d'analyse d'adversaires causent des préjudices sportifs et financiers irréversibles. 

Le **Forensic Watermarking** permet de personnaliser imperceptiblement chaque flux vidéo délivré à chaque membre du staff (entraîneur, analyste, joueur, dirigeant).

## 2. Structure de l'Empreinte Médico-Légale

Chaque segment délivré via `/api/v1/streaming/segments/{segment_id}` intègre un bloc stéganographique scellé :

```
[ DONNÉES VIDÉO MP4 / H.264 ] + [ __TACTIC_WATERMARK_V1__ ] + [ BASE64(JSON_METADATA) ] + [ __TACTIC_WATERMARK_V1__ ]
```

Les métadonnées scellées contiennent :
- **`viewer_user_id` :** Identifiant unique de l'utilisateur ayant reçu le flux
- **`viewer_ip` :** Adresse IP publique lors de la lecture
- **`video_id` :** Référence de la vidéo tactique
- **`streamed_at` :** Horodatage précis Unix de diffusion

## 3. Procédure d'Investigation et Traçabilité (Leak Tracing)

Lorsqu'un extrait vidéo ou une photo de séance tactique circule publiquement :
1. L'extrait est transmis à l'endpoint `/api/v1/forensics/trace-leak`.
2. Le moteur extrait le bloc cryptographique sans dépendance visuelle.
3. Le rapport fournit le nom du compte à l'origine de la fuite, l'heure exacte et l'adresse IP pour poursuites internes ou disciplinaires.
