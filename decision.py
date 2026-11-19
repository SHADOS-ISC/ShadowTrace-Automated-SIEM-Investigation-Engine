"""Moteur de décision SOC : signaux explicables, verdict, questions et actions."""
import time
from collections import Counter, defaultdict

import analyzer as A
from collector import Collector
import ti as TI

PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
HIGH_IOC = {"Offensive tool", "Exposed credential", "Remote download",
            "PowerShell encoded", "SQL Injection", "JWT"}
LARGE_BYTES = 100 * 1024 * 1024

ACTIONS = {
    "P2": ["Isoler le poste source après validation rapide avec le propriétaire (EDR ou quarantaine réseau).",
           "Escalader au SOC Lead et au niveau T3 dans les 15 minutes.",
           "Préserver les logs et la mémoire des postes concernés, sans redémarrage.",
           "Bloquer les destinations sortantes suspectes au pare-feu."],
    "P3": ["Obtenir la confirmation du propriétaire de l'actif source sous 4 heures.",
           "Vérifier les connexions réussies et les comptes utilisés.",
           "Contrôler les événements dans l'interface QRadar si la collecte API est incomplète."],
    "P4": ["Faire valider la légitimité du trafic par le propriétaire de l'actif.",
           "Si légitime, créer une exception documentée plutôt que de refermer chaque occurrence."],
    "P5": ["Clôturer avec une justification écrite.",
           "Régler la règle si le faux positif est confirmé."],
}


def _mb(b):
    return round(float(b or 0) / 1048576, 2)


def _count(rows, key, cast=str, n=10):
    c = Counter(cast(r.get(key)) for r in rows if r.get(key) not in (None, ""))
    return [{"value": k, "count": v} for k, v in c.most_common(n)]


def _actor(client, ref, networks):
    if not A.is_valid_ip(ref):
        return {"ip": ref, "scope": "NON RÉSOLU", "zone": "Inconnue", "asset": None}
    info = {"ip": ref, "scope": "INTERNE" if A.is_private(ref) else "EXTERNE",
            "zone": A.zone_of(ref, networks), "asset": None}
    raw = client.asset_by_ip(ref)
    if raw:
        info["asset"] = A._asset_summary(raw)
    return info


def _events_block(events, announced):
    base = {"announced": announced or 0, "retrieved": bool(events), "total": len(events or [])}
    if not events:
        return {**base, "categories": [], "event_names": [], "dst_ports": [], "dst_hosts": [],
                "users": [], "sources": [], "sweeps": [],
                "logins": {"count": 0, "users": [], "sources": []}, "timeline": []}

    by_src = defaultdict(lambda: {"dst": set(), "ports": set(), "n": 0})
    for e in events:
        v = by_src[str(e.get("sourceip"))]
        v["dst"].add(str(e.get("destinationip")))
        v["ports"].add(str(e.get("destinationport")))
        v["n"] += 1
    sweeps = []
    for src, v in by_src.items():
        if len(v["dst"]) >= 10:
            sweeps.append({"src": src, "kind": "Balayage horizontal",
                           "detail": "{} hôtes destination, {} ports".format(len(v["dst"]), len(v["ports"])),
                           "events": v["n"]})
        elif len(v["ports"]) >= 20:
            sweeps.append({"src": src, "kind": "Balayage de ports",
                           "detail": "{} ports distincts".format(len(v["ports"])), "events": v["n"]})

    def txt(e):
        return (str(e.get("event_name") or "") + " " + str(e.get("cat_name") or "")).lower()

    logins = [e for e in events if "login" in txt(e) and "fail" not in txt(e)]
    ports = _count(events, "destinationport")
    for p in ports:
        n = int(p["value"]) if p["value"].isdigit() else -1
        p["service"] = A.DANGEROUS_PORTS.get(n, "")
        p["suspicious"] = n in A.DANGEROUS_PORTS
    ordered = sorted(events, key=lambda e: e.get("starttime") or 0)
    timeline = [{
        "time": A.ts(e.get("starttime")), "src": e.get("sourceip"), "dst": e.get("destinationip"),
        "port": e.get("destinationport"), "event": e.get("event_name") or e.get("qid"),
        "user": e.get("username") or "",
    } for e in ordered[:100]]
    return {**base,
            "categories": _count(events, "cat_name"),
            "event_names": _count(events, "event_name"),
            "dst_ports": ports,
            "dst_hosts": _count(events, "destinationip"),
            "users": _count(events, "username"),
            "sources": _count(events, "log_source"),
            "sweeps": sweeps,
            "logins": {"count": len(logins), "users": _count(logins, "username", n=5),
                       "sources": _count(logins, "sourceip", n=5)},
            "timeline": timeline}


def _flows_block(rows):
    if not rows:
        return {"retrieved": False, "flows": 0, "sent_mb": 0, "recv_mb": 0,
                "large": False, "protocols": [], "top": []}
    flows = sum(int(r.get("nb") or 0) for r in rows)
    sent = sum(int(r.get("sent") or 0) for r in rows)
    recv = sum(int(r.get("recv") or 0) for r in rows)
    proto = Counter()
    for r in rows:
        proto[PROTO.get(int(r.get("protocolid") or 0), str(r.get("protocolid")))] += int(r.get("nb") or 0)
    top = sorted(rows, key=lambda r: int(r.get("sent") or 0) + int(r.get("recv") or 0), reverse=True)[:15]
    return {
        "retrieved": True, "flows": flows, "sent_mb": _mb(sent), "recv_mb": _mb(recv),
        "large": sent > LARGE_BYTES,
        "protocols": [{"value": k, "count": v} for k, v in proto.most_common()],
        "top": [{"src": r.get("sourceip"), "dst": r.get("destinationip"), "port": r.get("destinationport"),
                 "protocol": PROTO.get(int(r.get("protocolid") or 0), r.get("protocolid")),
                 "flows": int(r.get("nb") or 0), "sent_mb": _mb(r.get("sent")),
                 "recv_mb": _mb(r.get("recv"))} for r in top],
    }


def _signals(c):
    S, off, ev, fl = [], c["off"], c["ev"], c["fl"]

    def add(key, level, title, evidence, why):
        S.append({"key": key, "level": level, "title": title, "evidence": evidence, "why": why})

    if off.get("event_count") and not ev["retrieved"]:
        add("no_ev", "warn", "Événements non récupérés",
            "{} événements annoncés par QRadar, aucun récupéré par l'API".format(off.get("event_count")),
            "Le contenu réel n'est pas vérifié. Ne pas clôturer sans contrôle dans l'interface QRadar.")
    if off.get("flow_count") and not fl["retrieved"]:
        add("no_fl", "warn", "Flux non récupérés",
            "{} flux annoncés, aucun agrégat récupéré".format(off.get("flow_count")),
            "Volumes et protocoles (dont une éventuelle exfiltration) non vérifiés.")
    for sw in ev["sweeps"][:3]:
        add("sweep", "warn", sw["kind"],
            "Source {} : {}, {} événements".format(sw["src"], sw["detail"], sw["events"]),
            "Un poste qui sonde de nombreuses cibles peut être un scanner autorisé ou un poste en "
            "phase de découverte après compromission.")
    if ev["logins"]["count"]:
        users = ", ".join(u["value"] for u in ev["logins"]["users"]) or "non renseignés"
        add("login", "warn", "Connexions réussies observées",
            "{} connexion(s) réussie(s). Comptes : {}".format(ev["logins"]["count"], users),
            "Un succès d'authentification après une phase de sondage peut indiquer un accès obtenu. "
            "Le compte et la source doivent être validés.")
    suspicious_ports = [p for p in ev["dst_ports"] if p.get("suspicious")]
    if suspicious_ports:
        add("ports", "warn", "Ports associés à des outils d'attaque",
            "Ports observés : " + ", ".join(str(p["value"]) for p in suspicious_ports),
            "Ces ports sont fréquemment utilisés par des outils de post-exploitation ou des C2.")
    if len(c["zones"]) >= 3:
        add("zones", "warn", "Destinations dans plusieurs zones réseau",
            "{} zones : {}".format(len(c["zones"]), ", ".join(c["zones"])),
            "Un même poste qui atteint serveurs applicatifs, bases de données et proxy dépasse un usage "
            "courant. Vérifier l'existence d'une règle de flux documentée.")
    if c["related_total"] >= 10:
        add("recur", "warn", "Détection récurrente",
            "{} offences liées, dont {} fermées".format(c["related_total"], c["related_closed"]),
            "Une répétition sur plusieurs jours sans correction indique soit un outil autorisé non déclaré, "
            "soit un comportement persistant. Un tuning de règle est probablement nécessaire.")
    if "icmp" in c["text"]:
        add("icmp", "info", "Trafic ICMP (Echo-Reply)", "Catégorie ou description ICMP présente",
            "Typique d'un ping sweep ou d'un outil de supervision. À confirmer.")
    for name in sorted(HIGH_IOC & set(c["iocs"])):
        add("ioc_" + name, "high", "Indicateur d'attaque : " + name,
            "Motif détecté dans les payloads : " + str(c["iocs"][name][0])[:120],
            "Motif associé à une activité malveillante. Examiner le contexte avant toute conclusion.")
    if "CVE" in c["iocs"]:
        add("cve", "warn", "Référence CVE dans les payloads", ", ".join(c["iocs"]["CVE"][:5]),
            "Vérifier si le système est vulnérable et si l'exploitation est confirmée.")
    if any(b["suspicious"] for b in c["b64"]):
        add("b64", "high", "Commande encodée suspecte",
            "Payload Base64 décodé contenant des mots-clés d'exécution",
            "Technique de dissimulation fréquente en post-exploitation.")
    if fl["large"]:
        add("exfil", "high", "Transfert sortant volumineux", "{} Mo envoyés".format(fl["sent_mb"]),
            "Volume sortant élevé : exfiltration possible. Vérifier la destination.")
    for r in c["rules"]:
        if r.get("enabled") is False:
            add("rule_" + str(r.get("id")), "info",
                "Règle désactivée : « {} »".format(r.get("name")),
                "Règle {} marquée désactivée (propriétaire : {})".format(r.get("id"), r.get("owner")),
                "Une offence peut rester active alors que la règle est désactivée. "
                "Vérifier la cohérence de la configuration.")
    S.extend(TI.ti_signals(c.get("ti", [])))
    order = {"high": 0, "warn": 1, "info": 2}
    S.sort(key=lambda s: order[s["level"]])
    return S


def _decide(sig, off, ev, fl):
    highs = [s for s in sig if s["level"] == "high"]
    warns = [s for s in sig if s["level"] == "warn"]
    score = A.risk_score(off)
    if highs:
        code, label, color = "P2", "ESCALADE P2 : investigation immédiate", "#ef4444"
    elif len(warns) >= 3 or score >= 6:
        code, label, color = "P3", "INVESTIGATION : priorité moyenne (≤ 4 h)", "#f97316"
    elif warns:
        code, label, color = "P4", "VALIDATION : priorité basse (≤ 24 h)", "#eab308"
    else:
        code, label, color = "P5", "FAUX POSITIF PROBABLE : clôture après contrôle", "#22c55e"

    if ev["retrieved"] and fl["retrieved"]:
        conf, why = "Élevée", "Événements et flux récupérés."
    elif ev["retrieved"] or fl["retrieved"]:
        conf, why = "Moyenne", "Une seule source de détails disponible."
    else:
        conf, why = "Faible", "Aucun détail d'événement ni de flux : décision fondée sur les métadonnées."
    return {"code": code, "label": label, "color": color, "confidence": conf,
            "confidence_reason": why, "score": score, "heuristic_verdict": A.verdict(score)}


def _questions(sig, c):
    keys = {s["key"] for s in sig}
    Q = []
    for sw in c["ev"]["sweeps"][:2]:
        Q.append("Le poste {} est-il un scanner autorisé (vulnérabilités, supervision, inventaire) ? "
                 "Confirmer auprès du propriétaire de l'actif.".format(sw["src"]))
    if "login" in keys:
        Q.append("Quels comptes ont réussi une connexion, depuis quelle source et à quelle heure ? "
                 "Ces comptes sont-ils attendus sur ces serveurs ?")
    if "zones" in keys:
        Q.append("Pourquoi ce poste atteint-il des serveurs de bases de données et de proxy ? "
                 "Une règle de flux documentée existe-t-elle ?")
    if "recur" in keys:
        Q.append("Pourquoi cette détection se répète-t-elle ({} offences liées) alors que les précédentes "
                 "sont fermées ? Faut-il ajuster la règle ou créer une exception documentée ?"
                 .format(c["related_total"]))
    if "no_ev" in keys:
        Q.append("Les événements apparaissent-ils dans l'onglet Events de QRadar pour cette offence ? "
                 "Si oui, la collecte API doit être corrigée avant toute conclusion.")
    if any(k.startswith("ioc_") or k in ("b64", "exfil") for k in keys):
        Q.append("Faut-il isoler le poste immédiatement ? Examiner en priorité les payloads et les hashes.")
    for s in sig:
        if s["key"].startswith("rule_"):
            Q.append("Pourquoi la règle est-elle désactivée alors que l'offence reste active ? "
                     "Depuis quand et par qui ? (" + s["title"] + ")")
    if "icmp" in keys:
        Q.append("Les réponses ICMP proviennent-elles d'un outil de supervision connu ?")
    return Q or ["Aucune question spécifique : confirmer la décision et documenter la justification."]


def _summary(off, src, dst, zones, ev, dec):
    srcs = ", ".join(a["ip"] for a in src) or "inconnue"
    desc = str(off.get("description") or "").replace("\n", " ").strip()
    parts = ["Offence #{} : {}.".format(off.get("id"), desc),
             "Source(s) : {}. Destinations : {} hôte(s) dans {} zone(s).".format(srcs, len(dst), len(zones))]
    if ev["retrieved"]:
        parts.append("{} événements analysés.".format(ev["total"]))
    else:
        parts.append("Événements non récupérés ({} annoncés) : analyse partielle.".format(ev["announced"]))
    parts.append("Décision suggérée : {} (confiance {}).".format(dec["label"], dec["confidence"]))
    return " ".join(parts)


def build_report(client, oid):
    off = client.offence(oid)
    networks = client.network_hierarchy()
    src_ids = (off.get("source_address_ids") or [])[:10]
    dst_ids = (off.get("local_destination_address_ids") or [])[:10]
    cats = off.get("categories") or []

    src = [_actor(client, client.resolve_address(i), networks) for i in src_ids]
    dst = [_actor(client, client.resolve_address(i), networks) for i in dst_ids]
    ips = sorted({a["ip"] for a in src + dst if a["scope"] != "NON RÉSOLU"})
    zones = sorted({a["zone"] for a in dst if a["zone"]})

    col = Collector(client)
    raw = col.collect(oid, off, ips)
    ev = _events_block(raw["events"], off.get("event_count"))
    fl = _flows_block(raw["flows"])

    rules = []
    for r in (off.get("rules") or [])[:20]:
        d = client.rule(r["id"]) if r.get("id") else {}
        rules.append({"id": r.get("id"), "type": r.get("type"), "name": d.get("name", "N/A"),
                      "enabled": d.get("enabled"), "owner": d.get("owner")})

    rel_raw = [r for r in client.related(src_ids, dst_ids, cats[0] if cats else None) if r.get("id") != oid]
    related = {
        "total": len(rel_raw),
        "closed": sum(1 for r in rel_raw if r.get("status") == "CLOSED"),
        "open": sum(1 for r in rel_raw if r.get("status") == "OPEN"),
        "items": [{"id": r.get("id"), "magnitude": r.get("magnitude"), "status": r.get("status"),
                   "events": r.get("event_count"), "relation": r.get("_relation"),
                   "description": str(r.get("description") or "").replace("\n", " ")} for r in rel_raw],
    }

    payload, top_payloads = A.build_payload_text(raw["events"], [])
    iocs = A.extract_iocs(payload)
    b64 = A.decode_base64(payload)
    cmds = A.extract_commands(payload)
    entropy = A.shannon_entropy(payload)
    text = " ".join([str(off.get("description") or ""), " ".join(map(str, cats)), payload]).lower()
    mitre = A.map_mitre(text, iocs, bool(b64))
    chain = A.map_killchain(text)

    c = {"off": off, "ev": ev, "fl": fl, "iocs": iocs, "b64": b64, "zones": zones,
         "rules": rules, "related_total": related["total"], "related_closed": related["closed"],
         "text": text}
    targets = [a["ip"] for a in src + dst if TI.is_checkable(a["ip"])]
    targets = list(dict.fromkeys(targets))[:6]
    c["ti"] = [TI.ip_profile(client, ip) for ip in targets]
    sig = _signals(c)
    dec = _decide(sig, off, ev, fl)
    dec["summary"] = _summary(off, src, dst, zones, ev, dec)
    dec["questions"] = _questions(sig, c)
    dec["actions"] = ACTIONS[dec["code"]] + [
        "Documenter la décision dans les notes de l'offence (décision, justification, preuves)."]

    sev, sev_desc = A.severity_label(off.get("magnitude"))
    notes = [{"user": n.get("username"), "time": A.ts(n.get("create_time")),
              "text": (n.get("note_text") or "")[:300]} for n in client.notes(oid)]

    return {
        "generated": A.ts(int(time.time() * 1000)),
        "offence": {
            "id": off.get("id"), "description": str(off.get("description") or "").replace("\n", " ").strip(),
            "status": off.get("status"), "assigned_to": off.get("assigned_to") or "Non assignée",
            "start": A.ts(off.get("start_time")), "last_updated": A.ts(off.get("last_updated_time")),
            "categories": cats, "event_count": off.get("event_count"), "flow_count": off.get("flow_count"),
            "log_source_count": len(off.get("log_sources") or []),
            "magnitude": off.get("magnitude"), "severity": off.get("severity"),
            "credibility": off.get("credibility"), "relevance": off.get("relevance"),
            "severity_label": sev, "severity_desc": sev_desc,
        },
        "decision": dec,
        "signals": sig,
        "reputation": c["ti"],
        "actors": {"sources": src, "destinations": dst, "zones": zones},
        "rules": rules,
        "events": ev,
        "flows": fl,
        "payload": {"chars": len(payload), "entropy": entropy, "high_entropy": entropy > 5.5,
                    "base64": b64, "commands": cmds, "top": top_payloads},
        "iocs": iocs,
        "mitre": mitre,
        "killchain": chain,
        "related": related,
        "notes": notes,
        "quality": {"log": col.log, "used": col.used, "resolved_ips": ips,
                    "window": {"start": A.ts(raw["window"]["start"]), "end": A.ts(raw["window"]["end"])}},
    }
