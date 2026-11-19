# Console SOC d'analyse d'offences QRadar

Application web qui analyse une offence QRadar et présente, dans une console par onglets :
décision indicative (P2 à P5) avec signaux explicables, acteurs et zones réseau, événements,
flux, IOC, MITRE ATT&CK, cyber kill chain, offences liées, réputation IP et qualité des données.

## Installation

```bash
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # puis renseigner les valeurs
chmod 600 .env
python app.py
```

Ouvrir `http://<IP_du_serveur>:5000` (ou le port défini par `APP_PORT`).

## Configuration

Toutes les valeurs sensibles sont lues depuis `.env`. Voir `.env.example`.
Le token QRadar doit appartenir à un compte en lecture seule.

## Sécurité

- Aucune authentification intégrée : placer l'application derrière un reverse proxy avec SSO,
  ou restreindre l'accès par pare-feu à quelques postes.
- Les IP internes ne sont jamais envoyées aux services de réputation externes.
- Ne jamais versionner `.env`.
- Le serveur Flask est un serveur de développement. En production, utiliser gunicorn :
  `gunicorn -w 2 -b 0.0.0.0:5000 app:app`.

## Avertissement

Les décisions affichées sont indicatives. Elles doivent être validées par un analyste,
et la justification doit être documentée dans l'offence.
