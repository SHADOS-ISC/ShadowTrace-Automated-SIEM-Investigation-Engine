"""Réputation des IP : répétition dans QRadar et enrichissement CTI externe."""
import os
import time
from collections import Counter

import requests

import analyzer as A

CTI_TIMEOUT = 15
CACHE_TTL = 3600          # secondes
THRESH_REPEAT = 5         # offences sur 30 jours
THRESH_ABUSE = 50         # score AbuseIPDB (0-100)
THRESH_VT = 3             # moteurs VirusTotal qui détectent l'IP comme malveillante
_cache = {}


def is_checkable(ip):
    return A.is_valid_ip(ip)


def _cached(key, fn):
    now = time.time()
    if key in _cache and now - _cache[key][0] < CACHE_TTL:
        return _cache[key][1]
    val = fn()
    _cache[key] = (now, val)
    return val


# ══ Répétition interne (QRadar) ═════════════════════════════════════════════

def _addr_ids(client, ip):
    """Retourne les identifiants QRadar internes de l'IP, avec leur rôle."""
    found = []
    for endpoint, field, role in (
        ("siem/source_addresses", "source_ip", "source"),
        ("siem/local_destination_addresses", "local_destination_ip", "destination"),
    ):
        rows = client.get_safe(endpoint, {"filter": '{}="{}"'.format(field, ip)}, []) or []
        for a in rows:
            if a.get("id") is not None:
                found.append((role, a["id"]))
    return found


def offences_for_ip(client, ip, days=30):
    base = {"days": days, "total": 0, "open": 0, "closed": 0, "first": None,
            "last": None, "roles": [], "examples": []}
    if not is_checkable(ip):
        return base
    since = int((time.time() - days * 86400) * 1000)
    seen = {}
    for role, aid in _addr_ids(client, ip):
        fld = "source_address_ids" if role == "source" else "local_destination_address_ids"
        rows = client.get_safe("siem/offenses", {
            "filter": "{} contains {} and start_time > {}".format(fld, aid, since),
            "fields": "id,status,start_time,description",
        }, []) or []
        for o in rows:
            if o.get("id") is not None:
                seen[o["id"]] = o
                if role not in base["roles"]:
                    base["roles"].append(role)
    items = sorted(seen.values(), key=lambda o: o.get("start_time") or 0)
    base["total"] = len(items)
    base["open"] = sum(1 for o in items if o.get("status") == "OPEN")
    base["closed"] = sum(1 for o in items if o.get("status") == "CLOSED")
    if items:
        base["first"] = A.ts(items[0].get("start_time"))
        base["last"] = A.ts(items[-1].get("start_time"))
    base["examples"] = [{
        "id": o["id"], "status": o.get("status"), "start": A.ts(o.get("start_time")),
        "description": str(o.get("description") or "").replace("\n", " ")[:90],
    } for o in items[-5:][::-1]]
    return base


def events_for_ip(client, ip, days=7):
    base = {"days": days, "events": 0, "destinations": 0, "ports": [], "error": None}
    if not is_checkable(ip):
        return base
    since = int((time.time() - days * 86400) * 1000)
    q = ("SELECT destinationip, destinationport, starttime FROM events "
         "WHERE sourceip='{}' AND starttime > {} ORDER BY starttime DESC LIMIT 1000"
         ).format(ip, since)
    try:
        rows = client.aql(q, "events")
    except Exception as e:
        base["error"] = str(e)[:200]
        return base
    base["events"] = len(rows)
    base["destinations"] = len({r.get("destinationip") for r in rows})
    base["ports"] = [p for p, _ in Counter(str(r.get("destinationport")) for r in rows).most_common(5)]
    return base


# ══ Réputation externe (CTI) ════════════════════════════════════════════════

def _abuseipdb(ip):
    key = os.environ.get("ABUSEIPDB_KEY", "").strip()
    if not key:
        return None
    r = requests.get("https://api.abuseipdb.com/api/v2/check",
                     headers={"Key": key, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=CTI_TIMEOUT)
    r.raise_for_status()
    d = r.json().get("data", {})
    return {"source": "AbuseIPDB", "score": d.get("abuseConfidenceScore"),
            "reports": d.get("totalReports"), "pays": d.get("countryCode"),
            "fai": d.get("isp"), "usage": d.get("usageType"), "dernier_signalement": d.get("lastReportedAt")}


def _virustotal(ip):
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        return None
    r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/" + ip,
                     headers={"x-apikey": key}, timeout=CTI_TIMEOUT)
    r.raise_for_status()
    a = r.json().get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {}) or {}
    return {"source": "VirusTotal", "malveillant": st.get("malicious", 0),
            "suspect": st.get("suspicious", 0), "inoffensif": st.get("harmless", 0),
            "as_owner": a.get("as_owner"), "pays": a.get("country")}


def _otx(ip):
    key = os.environ.get("OTX_API_KEY", "").strip()
    if not key:
        return None
    r = requests.get("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general" % ip,
                     headers={"X-OTX-API-KEY": key}, timeout=CTI_TIMEOUT)
    r.raise_for_status()
    d = r.json()
    return {"source": "OTX", "pulses": (d.get("pulse_info") or {}).get("count", 0),
            "pays": d.get("country_name"), "reputation": d.get("reputation")}


def cti_lookup(ip):
    if not is_checkable(ip):
        return {"skipped": "IP invalide."}
    if A.is_private(ip):
        return {"skipped": "IP interne : non transmise aux services externes."}

    def run():
        out = []
        for fn in (_abuseipdb, _virustotal, _otx):
            try:
                res = fn(ip)
            except Exception as e:
                res = {"source": fn.__name__.lstrip("_"), "error": str(e)[:150]}
            if res:
                out.append(res)
        return out

    results = _cached("cti:" + ip, run)
    if not results:
        return {"skipped": "Aucune clé CTI configurée (ABUSEIPDB_KEY, VT_API_KEY, OTX_API_KEY)."}
    return {"results": results}


def cti_verdict(results):
    bad = []
    for r in results:
        if (r.get("score") or 0) >= THRESH_ABUSE:
            bad.append("AbuseIPDB score {}".format(r["score"]))
        if (r.get("malveillant") or 0) >= THRESH_VT:
            bad.append("VirusTotal {} moteurs".format(r["malveillant"]))
        if (r.get("pulses") or 0) >= 1:
            bad.append("OTX {} pulse(s)".format(r["pulses"]))
    return bad


# ══ Profil et signaux ═══════════════════════════════════════════════════════

def ip_profile(client, ip):
    internal = A.is_private(ip)
    return {
        "ip": ip,
        "scope": "INTERNE" if internal else "EXTERNE",
        "qradar": {"offences": offences_for_ip(client, ip), "events": events_for_ip(client, ip)},
        "cti": {"skipped": "IP interne : non transmise aux services externes."} if internal else cti_lookup(ip),
    }


def ti_signals(profiles):
    S = []
    for p in profiles:
        ip = p["ip"]
        q = p["qradar"]["offences"]
        if q["total"] >= THRESH_REPEAT:
            S.append({
                "key": "rep_" + ip, "level": "warn", "title": "IP récurrente dans QRadar",
                "evidence": "{} : {} offences sur {} jours ({} ouvertes, {} fermées)".format(
                    ip, q["total"], q["days"], q["open"], q["closed"]),
                "why": "Une IP qui revient souvent doit être identifiée : scanner autorisé, serveur de "
                       "supervision, ou activité persistante non corrigée.",
            })
        results = (p.get("cti") or {}).get("results") or []
        bad = cti_verdict(results)
        if bad:
            S.append({
                "key": "cti_" + ip, "level": "high", "title": "Réputation défavorable (CTI)",
                "evidence": "{} : {}".format(ip, ", ".join(bad)),
                "why": "L'IP est signalée par des sources de menace externes. Vérifier la connexion "
                       "avant toute conclusion.",
            })
    return S
