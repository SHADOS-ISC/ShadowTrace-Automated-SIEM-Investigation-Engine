# ShadowTrace: QRadar Offence Investigation Console

A web console that analyses a QRadar offence and presents the results in tabbed views:
an indicative decision (P2 to P5) with explainable signals, actors and network zones,
events, flows, IOCs, MITRE ATT&CK, Cyber Kill Chain, related offences, IP reputation,
and data quality.

## Installation

```bash
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then fill in the values
chmod 600 .env
python app.py
```

Open `http://<server_IP>:5000` (or the port defined by `APP_PORT`).

## Configuration

All sensitive values are read from `.env`. See `.env.example`.
The QRadar token should belong to a read-only account.

## Security

- No built-in authentication. Place the application behind a reverse proxy with SSO,
  or restrict access by firewall to a few workstations.
- Internal IP addresses are never sent to external reputation services.
- Never commit `.env` to version control.
- The Flask server is a development server. In production, use gunicorn:
  `gunicorn -w 2 -b 0.0.0.0:5000 app:app`.

## Disclaimer

The decisions shown are indicative. They must be validated by an analyst,
and the justification must be documented in the offence.
