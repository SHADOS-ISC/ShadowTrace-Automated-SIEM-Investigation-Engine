"""Collecte des données d'une offence avec stratégies de repli et journal de traçabilité."""
import time

EVENT_COLS = ("sourceip, destinationip, sourceport, destinationport, username, qid, "
              "qidname(qid) AS event_name, CATEGORYNAME(category) AS cat_name, "
              "logsourcename(logsourceid) AS log_source, protocolname(protocolid) AS protocol, "
              "utf8(payload) AS payload_text, starttime")

FLOW_COLS = ("sourceip, destinationip, destinationport, protocolid, "
             "COUNT(*) AS nb, SUM(sourcebytes) AS sent, SUM(destinationbytes) AS recv")

FLOW_TAIL = " GROUP BY sourceip, destinationip, destinationport, protocolid LIMIT 500"


def _ip_cond(ips):
    return " OR ".join("sourceip='{0}' OR destinationip='{0}'".format(ip) for ip in ips)


class Collector:
    def __init__(self, client):
        self.c = client
        self.log = []
        self.used = {}

    def _run(self, source, label, query, key):
        try:
            rows = self.c.aql(query, key)
            self.log.append({"source": source, "strategie": label, "ok": True, "lignes": len(rows)})
            return rows
        except Exception as e:
            self.log.append({"source": source, "strategie": label, "ok": False, "erreur": str(e)[:300]})
            return None

    def _first(self, source, attempts, key):
        for label, query in attempts:
            rows = self._run(source, label, query, key)
            if rows:
                self.used[source] = label
                return rows
        self.used[source] = None
        return []

    def events(self, oid, ips, start, end, limit=2000):
        win = "starttime BETWEEN {} AND {}".format(start, end)
        attempts = [
            ("INOFFENSE + fenêtre",
             "SELECT {} FROM events WHERE INOFFENSE({}) AND {} LIMIT {}".format(EVENT_COLS, oid, win, limit)),
            ("INOFFENSE seul",
             "SELECT {} FROM events WHERE INOFFENSE({}) LIMIT {}".format(EVENT_COLS, oid, limit)),
        ]
        if ips:
            attempts.append(("IP + fenêtre",
                             "SELECT {} FROM events WHERE ({}) AND {} LIMIT {}".format(
                                 EVENT_COLS, _ip_cond(ips), win, limit)))
        return self._first("events", attempts, "events")

    def flows(self, oid, ips, start, end):
        win = "starttime BETWEEN {} AND {}".format(start, end)
        attempts = [
            ("INOFFENSE agrégé",
             "SELECT {} FROM flows WHERE INOFFENSE({}) AND {}{}".format(FLOW_COLS, oid, win, FLOW_TAIL)),
        ]
        if ips:
            attempts.append(("IP agrégé",
                             "SELECT {} FROM flows WHERE ({}) AND {}{}".format(
                                 FLOW_COLS, _ip_cond(ips), win, FLOW_TAIL)))
        return self._first("flows", attempts, "flows")

    def collect(self, oid, offence, ips):
        start = int(offence.get("start_time") or 0) - 3600 * 1000
        end = max(int(offence.get("last_updated_time") or 0), int(time.time() * 1000)) + 3600 * 1000
        ev = self.events(oid, ips, start, end)
        fl = self.flows(oid, ips, start, end)
        return {"events": ev, "flows": fl, "window": {"start": start, "end": end}}
