"""Moteur d'analyse CERT : transforme les données QRadar en dictionnaire JSON."""
import base64
import ipaddress
import logging
import math
import re
from collections import Counter
from datetime import datetime, timezone

log = logging.getLogger("cert.analyzer")

SEVERITY_LEVELS = [
    (3, "LOW", "Informational / low risk"),
    (6, "MEDIUM", "Moderate risk, monitor closely"),
    (8, "HIGH", "High risk, investigate urgently"),
    (11, "CRITICAL", "CRITICAL, immediate response required"),
]

DANGEROUS_PORTS = {
    4444: "Metasploit default", 1337: "Hacker port", 31337: "Elite port",
    6666: "IRC / C2", 9001: "Tor / C2", 4445: "C2 alt", 5555: "ADB / C2",
}

IOC_PATTERNS = {
    "IPv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "URL": r"https?://[^\s\"'<>]{4,200}",
    "Email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "MD5": r"\b[a-fA-F0-9]{32}\b",
    "SHA1": r"\b[a-fA-F0-9]{40}\b",
    "SHA256": r"\b[a-fA-F0-9]{64}\b",
    "Suspicious file": r"\b[\w\-]{1,50}\.(?:exe|dll|bat|cmd|ps1|vbs|js|jar|hta|scr|msi|wsf)\b",
    "PowerShell encoded": r"(?i)(?:powershell|pwsh).*?-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}",
    "Remote download": r"(?i)(?:iex|downloadstring|downloadfile|invoke-webrequest|wget|curl)[\s(]+['\"]?https?://",
    "SQL Injection": r"(?i)\bunion\b.{0,30}\bselect\b|\bor\b\s+1\s*=\s*1|'\s*--",
    "XSS": r"(?i)<script|javascript:|\bon(?:error|load|click)\s*=",
    "Directory traversal": r"(?:\.\.[\\/]){2,}",
    "CVE": r"CVE-\d{4}-\d{4,7}",
    "JWT": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Exposed credential": r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|bearer)[\s:=]+[^\s&\"']{4,}",
    "Offensive tool": r"(?i)\b(?:beacon|meterpreter|cobalt.?strike|mimikatz|bloodhound|sharphound|lazagne|reverse.?shell)\b",
    "Suspicious port": r"\b(?:4444|1337|31337|6666|6667|9001|4445|5555|9999)\b",
}

MITRE_KEYWORDS = {
    "brute force": ("T1110", "Brute Force"),
    "password spray": ("T1110.003", "Password Spraying"),
    "sql injection": ("T1190", "Exploit Public-Facing Application"),
    "exploit": ("T1190", "Exploit Public-Facing Application"),
    "xss": ("T1059.007", "JavaScript"),
    "scan": ("T1046", "Network Service Discovery"),
    "lateral movement": ("T1021", "Remote Services"),
    "smb": ("T1021.002", "SMB/Windows Admin Shares"),
    "rdp": ("T1021.001", "Remote Desktop Protocol"),
    "ssh": ("T1021.004", "SSH"),
    "exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
    "phishing": ("T1566", "Phishing"),
    "powershell": ("T1059.001", "PowerShell"),
    "beacon": ("T1071", "Application Layer Protocol"),
    "command and control": ("T1071", "Application Layer Protocol"),
    "mimikatz": ("T1003", "OS Credential Dumping"),
    "persistence": ("T1098", "Account Manipulation"),
    "registry": ("T1547.001", "Registry Run Keys / Startup Folder"),
    "scheduled task": ("T1053.005", "Scheduled Task"),
    "wget": ("T1105", "Ingress Tool Transfer"),
    "curl": ("T1105", "Ingress Tool Transfer"),
    "ransomware": ("T1486", "Data Encrypted for Impact"),
    "ddos": ("T1498", "Network Denial of Service"),
    "privilege escalation": ("T1068", "Exploitation for Privilege Escalation"),
    "kerberoast": ("T1558.003", "Kerberoasting"),
    "pass the hash": ("T1550.002", "Pass the Hash"),
}

KILLCHAIN = {
    "Reconnaissance": ["scan", "recon", "nmap", "enumeration", "probe"],
    "Weaponization": ["exploit", "payload", "shellcode", "malware", "obfuscat"],
    "Delivery": ["phishing", "attachment", "download", "upload"],
    "Exploitation": ["sql injection", "xss", "rce", "code execution", "vulnerability", "cve-", "zero day", "traversal"],
    "Installation": ["persistence", "registry", "scheduled task", "backdoor", "implant"],
    "Command & Control": ["beacon", "c2", "cobalt strike", "meterpreter", "reverse shell", "command and control"],
    "Actions on Target": ["exfiltration", "lateral movement", "credential dump", "mimikatz", "ransomware", "encrypt", "pivot"],
}

CMD_PATTERNS = [
    r"(?i)(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe|certutil\.exe)[^\n\r\"']{0,300}",
    r"(?i)(?:net\s+user|net\s+localgroup|whoami|systeminfo|tasklist|netstat)[^\n\r\"']{0,200}",
    r"(?i)(?:sc\s+create|reg\s+add|schtasks\s+/create)[^\n\r\"']{0,200}",
    r"(?i)(?:curl|wget|Invoke-WebRequest|Start-BitsTransfer)[^\n\r\"']{0,300}",
]

B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
SUSPICIOUS_WORDS = ("powershell", "cmd", "exec", "download", "http", "invoke",
                    "iex", "bypass", "hidden", "-enc", "wget", "curl")
PAYLOAD_FIELDS = ("payload_text", "CommandLine", "ProcessName", "ProcessPath",
                  "RegistryKey", "RegistryValue", "FileName", "FilePath",
                  "URL", "HTTP User Agent", "Post Data", "Application")


# ══ Utilitaires ═════════════════════════════════════════════════════════════

def ts(ms):
    if not ms:
        return None
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def severity_label(magnitude):
    m = int(float(magnitude or 0))
    for upper, label, desc in SEVERITY_LEVELS:
        if m < upper:
            return label, desc
    return "CRITICAL", SEVERITY_LEVELS[-1][2]


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def zone_of(ip, networks):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"
    for net in networks:
        cidr = net.get("cidr")
        try:
            if cidr and addr in ipaddress.ip_network(cidr, strict=False):
                return "{} ({})".format(net.get("name", "?"), cidr)
        except ValueError:
            continue
    return "Internal / RFC1918" if addr.is_private else "External / Internet"


def risk_score(off):
    mag = float(off.get("magnitude") or 0)
    sev = float(off.get("severity") or 0)
    cred = float(off.get("credibility") or 0)
    rel = float(off.get("relevance") or 0)
    ev = float(off.get("event_count") or 0)
    ev_factor = math.log10(min(ev, 10000) + 1) / 4.0
    score = mag * 0.35 + sev * 0.25 + cred * 0.15 + rel * 0.15 + ev_factor * 10 * 0.10
    return round(min(score, 10.0), 2)


def verdict(score):
    if score >= 8.5:
        return "CRITICAL: immediate action, escalate to CISO and T3"
    if score >= 7:
        return "HIGH: investigate within 30 minutes"
    if score >= 5:
        return "MEDIUM: investigate within 4 hours"
    if score >= 3:
        return "LOW-MEDIUM: investigate today"
    return "LOW: routine review within 24 hours"


# ══ Extraction ══════════════════════════════════════════════════════════════

def build_payload_text(events, flows):
    chunks, top = [], []
    for ev in events:
        parts = [str(ev[f]) for f in PAYLOAD_FIELDS if ev.get(f)]
        if not parts:
            continue
        txt = " ".join(parts)
        chunks.append(txt)
        if len(txt) > 50 and len(top) < 20:
            top.append({
                "time": ts(ev.get("starttime")),
                "src": ev.get("sourceip"),
                "dst": ev.get("destinationip"),
                "text": txt[:500],
            })
    for f in flows:
        for key in ("sourcepayload", "destinationpayload"):
            if f.get(key):
                chunks.append(str(f[key]))
    return "\n".join(chunks), top


def extract_iocs(text):
    found = {}
    for name, pattern in IOC_PATTERNS.items():
        values = []
        for m in re.finditer(pattern, text):
            v = m.group(0).strip()
            if v and v not in values:
                values.append(v)
            if len(values) >= 10:
                break
        if values:
            found[name] = values
    return found


def decode_base64(text, limit=15):
    results = []
    for token in B64_RE.findall(text)[:limit]:
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        except ValueError:
            continue
        if len(raw) < 20:
            continue
        enc = "utf-16-le" if raw[1::2].count(0) > len(raw) // 4 else "utf-8"
        try:
            dec = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        printable = sum(c.isprintable() or c in "\r\n\t" for c in dec)
        if not dec or printable / len(dec) < 0.9:
            continue
        low = dec.lower()
        results.append({
            "encoded": token[:80] + ("..." if len(token) > 80 else ""),
            "decoded": dec[:500],
            "suspicious": any(w in low for w in SUSPICIOUS_WORDS),
        })
    return results


def extract_commands(text):
    cmds = []
    for pattern in CMD_PATTERNS:
        for m in re.findall(pattern, text)[:3]:
            c = m.strip()[:300]
            if c and c not in cmds:
                cmds.append(c)
    return cmds


def shannon_entropy(text):
    if not text:
        return 0.0
    data = text.encode("utf-8", errors="ignore")
    n = len(data)
    counts = Counter(data)
    return round(-sum(c / n * math.log2(c / n) for c in counts.values()), 3)


# ══ MITRE / Kill chain ══════════════════════════════════════════════════════

def map_mitre(text, iocs, has_b64):
    found = {}
    for kw, (tid, name) in MITRE_KEYWORDS.items():
        if re.search(r"\b" + re.escape(kw), text):
            found[tid] = name
    if "PowerShell encoded" in iocs or "Remote download" in iocs:
        found["T1059.001"] = "PowerShell"
    if has_b64:
        found["T1027"] = "Obfuscated Files or Information"
    if "SQL Injection" in iocs or "CVE" in iocs:
        found["T1190"] = "Exploit Public-Facing Application"
    if "Exposed credential" in iocs:
        found["T1078"] = "Valid Accounts"
    if "JWT" in iocs:
        found["T1528"] = "Steal Application Access Token"
    return [{"id": t, "name": n,
             "url": "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"}
            for t, n in sorted(found.items())]


def map_killchain(text):
    out = []
    for stage, kws in KILLCHAIN.items():
        hits = sorted({k for k in kws if re.search(r"\b" + re.escape(k), text)})
        out.append({"stage": stage, "active": bool(hits), "keywords": hits})
    return out


def recommendations(score, iocs, b64, mitre_ids):
    recs = []
    if score >= 8:
        recs += [
            "Isolate source host(s) immediately (EDR / network quarantine).",
            "Escalate to CISO and SOC lead within 15 minutes.",
            "Block source IPs at perimeter firewall / WAF.",
            "Preserve logs and memory; do not reboot affected systems.",
            "Check other assets in the same subnet for lateral movement.",
        ]
    elif score >= 6:
        recs += [
            "Investigate the source host within 30 minutes.",
            "Review authentications for involved accounts.",
            "Open a P2 ticket and block source IPs if confirmed.",
        ]
    else:
        recs.append("Routine review; tune the rule if it is a confirmed false positive.")
    if "CVE" in iocs:
        recs.append("Apply patches for the CVE references found.")
    if b64:
        recs.append("Submit decoded payloads to a sandbox (ANY.RUN, VirusTotal).")
    if "Exposed credential" in iocs:
        recs.append("Rotate exposed credentials and revoke active sessions.")
    if mitre_ids:
        recs.append("Map detections to the ATT&CK techniques listed in the report to check coverage.")
    return recs


# ══ Résumés ═════════════════════════════════════════════════════════════════

def _counts(rows, key, n=8):
    c = Counter(str(r[key]) for r in rows if r.get(key) not in (None, ""))
    return [{"value": k, "count": v} for k, v in c.most_common(n)]


def summarize_events(events):
    if not events:
        return {"total": 0, "timeline": []}
    ports = []
    for item in _counts(events, "destinationport", 8):
        p = item["value"]
        item["service"] = DANGEROUS_PORTS.get(int(p)) if p.isdigit() and int(p) in DANGEROUS_PORTS else ""
        item["suspicious"] = p.isdigit() and int(p) in DANGEROUS_PORTS
        ports.append(item)
    timeline = [{
        "time": ts(e.get("starttime")), "src": e.get("sourceip"), "dst": e.get("destinationip"),
        "port": e.get("destinationport"), "event": e.get("event_name") or e.get("qid"),
        "user": e.get("username"),
    } for e in sorted(events, key=lambda e: e.get("starttime") or 0)[:50]]
    return {
        "total": len(events),
        "categories": _counts(events, "cat_name"),
        "event_names": _counts(events, "event_name"),
        "dst_ports": ports,
        "usernames": _counts(events, "username"),
        "log_sources": _counts(events, "log_source"),
        "timeline": timeline,
    }


def summarize_flows(flows):
    if not flows:
        return {"total": 0}
    sent = sum(int(f.get("sourcebytes") or 0) for f in flows)
    recv = sum(int(f.get("destinationbytes") or 0) for f in flows)
    top = sorted(flows, key=lambda f: int(f.get("sourcebytes") or 0) + int(f.get("destinationbytes") or 0),
                 reverse=True)[:10]
    return {
        "total": len(flows),
        "bytes_sent": sent,
        "bytes_received": recv,
        "large_transfer": sent > 100 * 1024 * 1024,
        "protocols": _counts(flows, "protocol"),
        "applications": _counts(flows, "application"),
        "top_flows": [{
            "src": "{}:{}".format(f.get("sourceip"), f.get("sourceport")),
            "dst": "{}:{}".format(f.get("destinationip"), f.get("destinationport")),
            "bytes": int(f.get("sourcebytes") or 0) + int(f.get("destinationbytes") or 0),
            "protocol": f.get("protocol"),
        } for f in top],
    }


def _asset_summary(a):
    props = {p.get("name"): p.get("value") for p in a.get("properties", [])}
    hostname = next((i.get("hostname") for i in a.get("interfaces", []) if i.get("hostname")), None)
    return {"name": a.get("name"), "hostname": hostname,
            "os": props.get("Operating System"), "owner": props.get("Business Owner"),
            "location": props.get("Location")}


def _safe(fn, default, label):
    try:
        return fn()
    except Exception:
        log.exception("Échec de récupération : %s", label)
        return default


# ══ Orchestrateur ═══════════════════════════════════════════════════════════

def analyse(client, oid):
    off = client.offence(oid)
    src_ids = (off.get("source_address_ids") or [])[:10]
    dst_ids = (off.get("local_destination_address_ids") or [])[:10]
    categories = off.get("categories") or []
    networks = client.network_hierarchy()

    def actor(ip):
        info = {"ip": ip, "scope": "UNKNOWN", "zone": zone_of(ip, networks), "asset": None}
        if is_valid_ip(ip):
            info["scope"] = "INTERNAL" if is_private(ip) else "EXTERNAL"
            raw = client.asset_by_ip(ip)
            if raw:
                info["asset"] = _asset_summary(raw)
        return info

    sources = [actor(client.resolve_address(i)) for i in src_ids]
    destinations = [actor(client.resolve_address(i)) for i in dst_ids]

    rules = []
    for r in (off.get("rules") or [])[:20]:
        detail = client.rule(r["id"]) if r.get("id") else {}
        rules.append({"id": r.get("id"), "type": r.get("type"),
                      "name": detail.get("name", "N/A"), "enabled": detail.get("enabled"),
                      "owner": detail.get("owner")})

    events = _safe(lambda: client.events(oid), [], "events")
    flows = _safe(lambda: client.flows(oid), [], "flows")
    related = [{
        "id": r.get("id"), "description": r.get("description"), "magnitude": r.get("magnitude"),
        "status": r.get("status"), "events": r.get("event_count"), "relation": r.get("_relation"),
    } for r in client.related(src_ids, dst_ids, categories[0] if categories else None)
        if r.get("id") != oid]

    payload, top_payloads = build_payload_text(events, flows)
    combined = " ".join([off.get("description") or "", " ".join(map(str, categories)), payload]).lower()
    iocs = extract_iocs(payload)
    b64 = decode_base64(payload)
    commands = extract_commands(payload)
    entropy = shannon_entropy(payload)
    mitre = map_mitre(combined, iocs, bool(b64))
    chain = map_killchain(combined)

    score = risk_score(off)
    sev, sev_desc = severity_label(off.get("magnitude"))

    return {
        "offence": {
            "id": off.get("id"),
            "description": off.get("description"),
            "status": off.get("status"),
            "assigned_to": off.get("assigned_to") or "Unassigned",
            "start_time": ts(off.get("start_time")),
            "last_updated": ts(off.get("last_updated_time")),
            "categories": categories,
            "event_count": off.get("event_count"),
            "flow_count": off.get("flow_count"),
            "log_source_count": len(off.get("log_sources") or []),
        },
        "risk": {
            "severity": sev,
            "severity_description": sev_desc,
            "composite_score": score,
            "verdict": verdict(score),
            "scores": {
                "magnitude": off.get("magnitude"),
                "severity": off.get("severity"),
                "credibility": off.get("credibility"),
                "relevance": off.get("relevance"),
            },
        },
        "actors": {"sources": sources, "destinations": destinations},
        "rules": rules,
        "events": summarize_events(events),
        "flows": summarize_flows(flows),
        "iocs": iocs,
        "payload": {
            "characters_analyzed": len(payload),
            "entropy": entropy,
            "high_entropy": entropy > 5.5,
            "base64": b64,
            "commands": commands,
            "top_payloads": top_payloads,
        },
        "mitre": mitre,
        "killchain": chain,
        "related": related,
        "notes": [{"user": n.get("username"), "time": ts(n.get("create_time")),
                   "text": (n.get("note_text") or "")[:300]}
                  for n in client.notes(oid)],
        "recommendations": recommendations(score, iocs, b64, mitre),
    }
