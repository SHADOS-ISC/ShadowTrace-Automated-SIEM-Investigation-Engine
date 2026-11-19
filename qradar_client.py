import time
import urllib3
import requests
from config import Config

if Config.VERIFY_SSL is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class QRadarError(Exception):
    """Erreur métier : recherche AQL en échec ou délai dépassé."""


class QRadarClient:
    def __init__(self):
        self.base = Config.QRADAR_HOST.rstrip("/") + "/api/"
        self.timeout = Config.REQUEST_TIMEOUT
        self.lookback = Config.AQL_LOOKBACK
        self.session = requests.Session()
        self.session.headers.update({
            "SEC": Config.QRADAR_TOKEN,
            "Version": Config.API_VERSION,
            "Accept": "application/json",
        })
        self.session.verify = Config.VERIFY_SSL

    def get(self, endpoint, params=None):
        r = self.session.get(self.base + endpoint, params=params, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_safe(self, endpoint, params=None, default=None):
        try:
            return self.get(endpoint, params)
        except (requests.RequestException, ValueError):
            return default

    # ── Offence & adresses ───────────────────────────────────────────────
    def offence(self, oid):
        return self.get("siem/offenses/{}".format(int(oid)))

    def resolve_address(self, addr_id):
        d = self.get_safe("siem/source_addresses/{}".format(int(addr_id)), default={}) or {}
        if d.get("source_ip"):
            return d["source_ip"]
        d = self.get_safe("siem/local_destination_addresses/{}".format(int(addr_id)), default={}) or {}
        return d.get("local_destination_ip", str(addr_id))

    def notes(self, oid):
        return self.get_safe("siem/offenses/{}/notes".format(int(oid)), default=[]) or []

    def rule(self, rule_id):
        return self.get_safe("analytics/rules/{}".format(int(rule_id)), default={}) or {}

    def asset_by_ip(self, ip):
        res = self.get_safe("asset_model/assets",
                            {"filter": 'interfaces contains ip_addresses "{}"'.format(ip)}, [])
        return res[0] if res else None

    def network_hierarchy(self):
        return self.get_safe("config/network_hierarchy/networks", default=[]) or []

    def related(self, src_ids, dst_ids, category=None):
        fields = "id,description,magnitude,status,event_count,categories"
        queries = [("source_address_ids contains {}".format(int(i)), "Shared source address")
                   for i in src_ids[:5]]
        queries += [("local_destination_address_ids contains {}".format(int(i)), "Shared destination address")
                    for i in dst_ids[:3]]
        if category:
            safe_cat = str(category).replace('"', "")
            queries.append(('categories contains "{}" and status="OPEN"'.format(safe_cat),
                            "Same category: " + safe_cat))
        seen, out = set(), []
        for flt, label in queries:
            for o in self.get_safe("siem/offenses", {"filter": flt, "fields": fields}, []) or []:
                oid = o.get("id")
                if oid and oid not in seen:
                    seen.add(oid)
                    o["_relation"] = label
                    out.append(o)
        return out[:30]

    # ── AQL ──────────────────────────────────────────────────────────────
    def aql(self, query, key, timeout_s=240):
        r = self.session.post(self.base + "ariel/searches",
                              params={"query_expression": query}, timeout=self.timeout)
        r.raise_for_status()
        sid = r.json()["search_id"]
        deadline = time.time() + timeout_s
        while True:
            status = self.get("ariel/searches/{}".format(sid)).get("status")
            if status == "COMPLETED":
                break
            if status in ("ERROR", "CANCELED"):
                raise QRadarError("Recherche AQL en échec : {}".format(status))
            if time.time() > deadline:
                raise QRadarError("Délai AQL dépassé")
            time.sleep(2)
        return self.get("ariel/searches/{}/results".format(sid)).get(key, [])

    def _since_ms(self, hours):
        """Epoch en millisecondes, il y a `hours` heures (format attendu par AQL)."""
        return int((time.time() - hours * 3600) * 1000)

    def events(self, oid, limit=500, since_ms=None):
        if since_ms is None:
            since_ms = self.offence(oid).get("start_time", 0) - 3600 * 1000
        q = ("SELECT sourceip, destinationip, sourceport, destinationport, username, "
             "qid, qidname(qid) AS event_name, CATEGORYNAME(category) AS cat_name, "
             "logsourcename(logsourceid) AS log_source, protocolname(protocolid) AS protocol, "
             "utf8(payload) AS payload_text, starttime "
             "FROM events WHERE INOFFENSE({oid}) AND starttime > {since} "
             "LIMIT {limit}").format(oid=int(oid), since=int(since_ms), limit=int(limit))
        return self.aql(q, "events")

    def flows(self, oid, limit=200, hours=72):
        q = ("SELECT sourceip, destinationip, sourceport, destinationport, "
             "protocolname(protocolid) AS protocol, sourcebytes, destinationbytes, "
             "applicationname(applicationid) AS application, starttime "
             "FROM flows WHERE INOFFENSE({oid}) AND starttime > {since} "
             "LIMIT {limit}").format(oid=int(oid), since=self._since_ms(hours), limit=int(limit))
        return self.aql(q, "flows")
