import logging
import os

import requests
from flask import Flask, abort, jsonify, render_template

from decision import build_report
import ti as TI
from qradar_client import QRadarClient, QRadarError

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cert")

app = Flask(__name__)
client = QRadarClient()


@app.get("/")
def index():
    return render_template("soc.html")


@app.get("/api/health")
def health():
    ok = client.get_safe("system/about") is not None
    return jsonify(qradar="ok" if ok else "ko")


@app.get("/api/offence/<int:oid>")
def api_offence(oid):
    if oid < 1:
        abort(400)
    try:
        return jsonify(build_report(client, oid))
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else 502
        if code == 404:
            return jsonify(error="Offence #{} introuvable".format(oid)), 404
        log.exception("Erreur HTTP QRadar")
        return jsonify(error="Erreur QRadar (HTTP {})".format(code)), 502
    except requests.RequestException:
        log.exception("QRadar injoignable")
        return jsonify(error="QRadar injoignable (réseau, TLS ou délai)"), 502
    except QRadarError as e:
        return jsonify(error=str(e)), 504
    except Exception:
        log.exception("Analyse échouée pour l'offence %s", oid)
        return jsonify(error="Erreur interne lors de l'analyse, voir le journal serveur"), 500


@app.get("/api/ip/<path:ip>")
def api_ip(ip):
    if not TI.is_checkable(ip):
        return jsonify(error="IP invalide"), 400
    return jsonify(TI.ip_profile(client, ip))


if __name__ == "__main__":
    host = os.environ.get("APP_HOST", "0.0.0.0")
    port = int(os.environ.get("APP_PORT", "5000"))
    print("Console SOC : http://<IP_de_cette_machine>:{}".format(port))
    app.run(host=host, port=port, debug=False, threaded=True)
