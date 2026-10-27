"""UniFi integration for Hisho (see addon.yaml). Runs inside Core. Read only: ``_http`` can only GET.

Two sources, one per kind of entry:
  - a gateway's UniFi Network Integration API (``url`` set), certificate pinned like Proxmox, plus
    the classic ``/proxy/network/api`` for WAN health and alerts when the key may read it;
  - the cloud Site Manager API (``url`` empty) for every console on the UI account.
WAN exposure: the public IP comes from the API; the ports are checked from a server outside the
network (``probe_from``, a Servers (SSH) entry), since from inside the house the gateway answers on
its own public IP through the LAN and would always look open.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
from typing import Any

CLOUD = "https://api.ui.com"
INTEGRATION = "/proxy/network/integration/v1"
CLASSIC = "/proxy/network/api/s"
PORTS = (443, 8443, 80, 22)
PROBE_TTL = 1800                       # seconds a port check is reused (summary runs after every fleet check)
MAX_PAGES = 10
_probe_cache: dict[tuple[str, str], tuple[float, dict[int, dict[str, str]]]] = {}


class UniFiError(RuntimeError):
    pass


# ── talking to UniFi (GET only) ───────────────────────────────────────────

def _fp(value: str | None) -> str:
    return str(value or "").replace(":", "").strip().lower()


def server_fingerprint(host: str, port: int) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
        digest = hashlib.sha256(tls.getpeercert(binary_form=True) or b"").hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _http(url: str, key: str, fingerprint: str | None = None, timeout: int = 15) -> Any:
    """GET ``url`` with the key; JSON back. With a fingerprint the certificate must match it."""
    u = urllib.parse.urlsplit(url)
    ctx = ssl.create_default_context()
    if fingerprint:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # checked below by fingerprint
    conn = http.client.HTTPSConnection(u.hostname or "", u.port or 443, timeout=timeout, context=ctx)
    try:
        conn.connect()
        if fingerprint and hashlib.sha256(conn.sock.getpeercert(binary_form=True) or b"").hexdigest() != _fp(fingerprint):
            raise UniFiError(f"{u.hostname}'s certificate changed since it was pinned; Hisho won't send the key. "
                             "If you replaced it on purpose, clear the fingerprint and press Test.")
        conn.request("GET", u.path + (f"?{u.query}" if u.query else ""),
                     headers={"X-API-KEY": key, "Accept": "application/json"})
        r = conn.getresponse()
        body = r.read()
    except ssl.SSLCertVerificationError:
        raise UniFiError(f"{u.hostname}'s certificate isn't publicly trusted; press Test to pin it")
    except (OSError, http.client.HTTPException) as exc:
        raise UniFiError(f"can't reach {u.hostname} ({exc})")
    finally:
        conn.close()
    if r.status in (401, 403):
        raise UniFiError("UniFi refused the key (wrong, deleted, or for another console)")
    if r.status == 429:
        raise UniFiError("UniFi says too many requests; it'll work again in a minute")
    if r.status >= 400:
        raise UniFiError(f"UniFi answered {r.status} on {u.path}")
    try:
        return json.loads(body or b"null")
    except ValueError:
        raise UniFiError(f"UniFi sent something that isn't JSON on {u.path}")


def _local(entry: dict[str, Any]) -> bool:
    return bool(str(entry.get("url") or "").strip())


def base_url(entry: dict[str, Any]) -> str:
    text = str(entry.get("url") or "").strip().rstrip("/")
    if not text:
        return CLOUD
    if text.startswith("http://"):
        raise UniFiError("the gateway's API is https only")
    return text if "://" in text else f"https://{text}"


# ── what Hisho may read, and which fields it keeps ────────────────────────
# A gateway key is admin-level: the same key could read every setting, including the devices' SSH password
# (/get/setting/mgmt returns x_ssh_password in clear). So only these endpoints are ever requested, and each
# answer is cut down to the fields below the moment it arrives: nothing else reaches the page, the caches,
# the logs or the API. A field not listed is dropped; a listed scalar field holding an object is dropped too.

def _page(item: Any) -> dict[str, Any]:
    return {"data": [item], "totalCount": None, "count": None, "nextToken": None}


_DEVICE = {k: None for k in ("id", "name", "model", "macAddress", "ipAddress", "state", "firmwareVersion",
                             "firmwareUpdatable")} | {"features": [None]}
_SEG = r"[A-Za-z0-9_.%-]+"
_LIST = r"\?offset=\d+&limit=\d+$"
ALLOWED: list[tuple[re.Pattern[str], Any]] = [(re.compile(rx), spec) for rx, spec in [
    (rf"^{INTEGRATION}/info$", {"applicationVersion": None}),
    (rf"^{INTEGRATION}/sites{_LIST}", _page({"id": None, "internalReference": None, "name": None})),
    (rf"^{INTEGRATION}/sites/{_SEG}/devices{_LIST}", _page(_DEVICE)),
    (rf"^{INTEGRATION}/sites/{_SEG}/devices/{_SEG}$", _DEVICE),
    (rf"^{INTEGRATION}/sites/{_SEG}/clients{_LIST}", _page({"id": None, "type": None})),
    (rf"^{CLASSIC}/{_SEG}/stat/health$",
     {"meta": {"rc": None}, "data": [{k: None for k in ("subsystem", "status", "wan_ip", "isp_name", "latency")}]}),
    (rf"^{CLASSIC}/{_SEG}/stat/alarm\?archived=false$",
     {"meta": {"rc": None}, "data": [{k: None for k in ("key", "msg", "datetime", "archived")}]}),
    (r"^/v1/hosts\?pageSize=100(&nextToken=[^&]+)?$",
     _page({"id": None, "type": None, "ipAddress": None, "owner": None,
            "reportedState": {"name": None, "hostname": None, "state": None, "version": None,
                              "hardware": {"name": None}}})),
    (r"^/v1/sites\?pageSize=100(&nextToken=[^&]+)?$",
     _page({"siteId": None, "hostId": None, "meta": {"desc": None, "name": None, "gatewayMac": None},
            "statistics": {"counts": {"*": None}, "ispInfo": {"name": None}, "percentages": {"wanUptime": None},
                           "internetIssues": [{"index": None}],
                           "wans": {"*": {"externalIp": None, "wanUptime": None}}}})),
    (r"^/v1/devices\?pageSize=100(&nextToken=[^&]+)?$",
     _page({"hostId": None, "hostName": None, "updatedAt": None,
            "devices": [{k: None for k in ("id", "mac", "name", "model", "ip", "status", "version",
                                           "firmwareStatus", "updateAvailable")}]})),
    (r"^/ea/isp-metrics/5m\?duration=24h$",
     {"data": [{"siteId": None, "periods": [{"data": {"wan": {"avgLatency": None, "packetLoss": None,
                                                              "downtime": None}}}]}]}),
]]


def keep(value: Any, spec: Any) -> Any:
    """``value`` cut down to ``spec``: None = a plain value, [s] = a list of s, {key: s} (``*`` = any key)."""
    if spec is None:
        return value if value is None or isinstance(value, (str, int, float, bool)) else None
    if isinstance(spec, list):
        return [keep(v, spec[0]) for v in value] if isinstance(value, list) else None
    if not isinstance(value, dict):
        return None
    if "*" in spec:
        return {str(k): keep(v, spec["*"]) for k, v in value.items()}
    return {k: keep(value[k], s) for k, s in spec.items() if k in value}


def _get(entry: dict[str, Any], ctx: Any, path: str) -> Any:
    spec = next((sp for rx, sp in ALLOWED if rx.match(path)), False)
    if spec is False:   # before the key is even looked up
        raise UniFiError(f"Hisho doesn't read {path.split('?')[0]} (not on the UniFi add-on's read list)")
    return keep(_http(base_url(entry) + path, ctx.secret(entry["api_key"]).strip(),
                      fingerprint=entry.get("fingerprint") if _local(entry) else None), spec)


def _local_pages(entry: dict[str, Any], ctx: Any, path: str) -> tuple[list[dict[str, Any]], int]:
    """(items, totalCount) of a paged Integration API list."""
    out: list[dict[str, Any]] = []
    total = 0
    for _ in range(MAX_PAGES):
        page = _get(entry, ctx, f"{INTEGRATION}{path}?offset={len(out)}&limit=200") or {}
        data = list(page.get("data") or [])
        out += data
        total = int(page.get("totalCount") or len(out))
        if not data or len(out) >= total:
            break
    return out, total


def _cloud_pages(entry: dict[str, Any], ctx: Any, path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    query = "?pageSize=100"
    for _ in range(MAX_PAGES):
        page = _get(entry, ctx, path + query) or {}
        out += list(page.get("data") or [])
        token = page.get("nextToken")
        if not token:
            break
        query = f"?pageSize=100&nextToken={urllib.parse.quote(str(token))}"
    return out


def _classic(entry: dict[str, Any], ctx: Any, site: str, path: str) -> list[dict[str, Any]] | None:
    """The classic Network API (WAN health, alerts); None when this key can't read it."""
    try:
        res = _get(entry, ctx, f"{CLASSIC}/{urllib.parse.quote(site)}/{path}") or {}
    except UniFiError:
        return None
    if (res.get("meta") or {}).get("rc", "ok") != "ok":
        return None
    return list(res.get("data") or [])


# ── reading: the gateway's own API ────────────────────────────────────────

ONLINE, OFFLINE = {"ONLINE"}, {"OFFLINE", "CONNECTION_INTERRUPTED", "ISOLATED"}


def read_local(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    version = str((_get(entry, ctx, f"{INTEGRATION}/info") or {}).get("applicationVersion") or "?")
    sites = []
    for s in _local_pages(entry, ctx, "/sites")[0]:
        devices, _ = _local_pages(entry, ctx, f"/sites/{s['id']}/devices")
        for d in devices[:60]:
            if "firmwareUpdatable" not in d:   # older Network versions list it only per device
                try:
                    d.update(_get(entry, ctx, f"{INTEGRATION}/sites/{s['id']}/devices/{d['id']}") or {})
                except UniFiError:
                    pass
        clients, n_clients = _local_pages(entry, ctx, f"/sites/{s['id']}/clients")
        ref = str(s.get("internalReference") or "default")
        sites.append({"site": s, "devices": devices, "clients": clients, "n_clients": n_clients,
                      "health": _classic(entry, ctx, ref, "stat/health"),
                      "alarms": _classic(entry, ctx, ref, "stat/alarm?archived=false")})
    return {"version": version, "sites": sites}


def _sub(health: list[dict[str, Any]] | None, name: str) -> dict[str, Any]:
    return next((h for h in health or [] if h.get("subsystem") == name), {})


def _local_device(d: dict[str, Any]) -> dict[str, Any]:
    state = str(d.get("state") or "?")
    upd = bool(d.get("firmwareUpdatable"))
    return {"id": f"dev-{d.get('id')}"[:60], "name": str(d.get("name") or d.get("model") or d.get("macAddress")).strip(),
            "state": "down" if state in OFFLINE else ("warn" if upd else "up" if state in ONLINE else "unknown"),
            "facts": [" · ".join(str(x) for x in (d.get("model"), d.get("ipAddress"), d.get("macAddress")) if x),
                      f"firmware {_fw(d.get('firmwareVersion'))}" + (" · firmware update available" if upd else "")
                      + ("" if state in ONLINE else f" · {state.lower().replace('_', ' ')}")],
            "actions": []}


def _alert_items(alarms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for a in alarms:
        groups.setdefault(str(a.get("msg") or a.get("key") or "alert"), []).append(a)
    return [{"id": f"alert-{i}", "name": msg + (f" ({len(g)}×)" if len(g) > 1 else ""), "state": "off",
             "facts": [f"latest {str(g[0].get('datetime') or '?')[:16].replace('T', ' ')} · {g[0].get('key') or ''}".rstrip(" ·"),
                       "Clear it in UniFi Network > Alarms once looked at (Hisho only reads)."],
             "actions": []} for i, (msg, g) in enumerate(groups.items())]


def _local_section(name: str, entry: dict[str, Any], s: dict[str, Any], version: str) -> dict[str, Any]:
    wan, www = _sub(s["health"], "wan"), _sub(s["health"], "www")
    items = [_local_device(d) for d in sorted(s["devices"], key=lambda d: str(d.get("name")).lower())]
    facts = [f"UniFi Network {version} on {base_url(entry).split('://', 1)[1]}"]
    if s["health"] is None:
        facts.append("WAN health and alerts aren't readable with this key (only the Integration API is).")
    else:
        facts.append(" · ".join(str(x) for x in (
            f"WAN {wan.get('status') or '?'}", wan.get("wan_ip") and f"public IP {wan['wan_ip']}", wan.get("isp_name"),
            www.get("latency") is not None and f"{www['latency']} ms") if x))
    kinds: dict[str, int] = {}
    for c in s["clients"]:
        kinds[str(c.get("type") or "?")] = kinds.get(str(c.get("type") or "?"), 0) + 1
    words = {"WIRED": "wired", "WIRELESS": "Wi-Fi", "VPN": "VPN", "TELEPORT": "Teleport"}
    facts.append(f"{s['n_clients']} clients: " + ", ".join(f"{n} {words.get(k, k.lower())}" for k, n in kinds.items()))
    if s["health"] is not None and s["alarms"] is None:
        facts.append("Alerts aren't readable with this key; see the UniFi app.")
    items += _alert_items(s["alarms"] or [])
    gw_down = any(d.get("state") in OFFLINE and "gateway" in (d.get("features") or []) for d in s["devices"])
    state = ("down" if gw_down or wan.get("status") == "error" else
             "warn" if any(d.get("state") in OFFLINE for d in s["devices"]) or wan.get("status") == "warning" else "ok")
    return {"title": str(s["site"].get("name") or "site"), "entry": name, "state": state,
            "facts": facts + ([entry["note"]] if entry.get("note") else []), "items": items}


# ── reading: Site Manager (cloud) ─────────────────────────────────────────

def read_cloud(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    hosts = _cloud_pages(entry, ctx, "/v1/hosts")
    sites = _unique_sites(_cloud_pages(entry, ctx, "/v1/sites"), hosts)
    # Site Manager also returns old device lists (seen 2026-10-19: two from 2025, every device offline, one
    # under an older hostId): keep the newest list of each console it lists now.
    current, devices, newest = {h.get("id") for h in hosts}, {}, {}
    for g in _cloud_pages(entry, ctx, "/v1/devices"):
        hid = g.get("hostId")
        if hid in current and str(g.get("updatedAt") or "") >= newest.get(hid, ""):
            newest[hid], devices[hid] = str(g.get("updatedAt") or ""), list(g.get("devices") or [])
    try:   # early-access endpoint: nice to have
        isp = {m.get("siteId"): m for m in (_get(entry, ctx, "/ea/isp-metrics/5m?duration=24h") or {}).get("data") or []}
    except UniFiError:
        isp = {}
    return {"hosts": hosts, "sites": sites, "devices": devices, "isp": isp}


def _unique_sites(sites: list[dict[str, Any]], hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Site Manager sometimes lists a site twice (seen 2026-10-19: an old copy with an old public IP and
    old counts). Keep one per siteId: the copy whose WAN IP is the console's IP now, else the last one."""
    ip = {h.get("id"): h.get("ipAddress") for h in hosts}
    best: dict[Any, dict[str, Any]] = {}
    for s in sites:
        key = s.get("siteId") or id(s)
        wans = ((s.get("statistics") or {}).get("wans") or {}).values()
        current = any(w.get("externalIp") and w.get("externalIp") == ip.get(s.get("hostId")) for w in wans)
        if key not in best or current or not best[key].get("_current"):
            best[key] = {**s, "_current": current}
    return list(best.values())


def _host_name(h: dict[str, Any]) -> str:
    rs = h.get("reportedState") or {}
    return str(rs.get("name") or rs.get("hostname") or h.get("id"))


def _connected(h: dict[str, Any]) -> bool:
    return (h.get("reportedState") or {}).get("state", "connected") == "connected"


def _g(x: Any) -> str:
    return f"{round(float(x), 2):g}"


def _fw(v: Any) -> str:
    return "?" if not v or str(v).upper() == "UNKNOWN" else str(v)


def _mac(v: Any) -> str:
    return str(v or "").replace(":", "").replace("-", "").upper()


def _internet(site: dict[str, Any], metrics: dict[str, Any] | None) -> str:
    st = site.get("statistics") or {}
    up = (st.get("percentages") or {}).get("wanUptime")
    line = f"internet: {(st.get('ispInfo') or {}).get('name') or '?'}" + (f" · up {_g(up)}%" if up is not None else "")
    wans = [(p.get("data") or {}).get("wan") or {} for p in (metrics or {}).get("periods") or []]
    lat = [w["avgLatency"] for w in wans if w.get("avgLatency") is not None]
    if lat:
        down = sum(float(w.get("downtime") or 0) for w in wans)
        line += (f" · last 24 h: {round(sum(lat) / len(lat))} ms average, "
                 f"packet loss up to {_g(max(float(w.get('packetLoss') or 0) for w in wans))}%"
                 + (f", {round(down / 60)} min down" if down else ""))
    return line


def _cloud_device(d: dict[str, Any]) -> dict[str, Any]:
    upd = d.get("updateAvailable") or (d.get("firmwareStatus") == "updateAvailable")
    off = d.get("status") != "online"
    return {"id": f"dev-{d.get('id') or d.get('mac')}"[:60], "name": str(d.get("name") or d.get("model")).strip(),
            "state": "down" if off else ("warn" if upd else "up"),
            "facts": [" · ".join(str(x) for x in (d.get("model"), d.get("ip"), d.get("mac")) if x),
                      f"firmware {_fw(d.get('version'))}"
                      + (f" · firmware update available: {d['updateAvailable']}" if d.get("updateAvailable")
                         else " · firmware update available" if upd else "")
                      + (f" · {d.get('status')}" if off else "")],
            "actions": []}


def _cloud_sections(name: str, entry: dict[str, Any], data: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for h in data["hosts"]:
        rs, hw = h.get("reportedState") or {}, (h.get("reportedState") or {}).get("hardware") or {}
        mine = [s for s in data["sites"] if s.get("hostId") == h.get("id")]
        devs = data["devices"].get(h.get("id")) or []
        for s in mine or [{}]:
            counts = ((s.get("statistics") or {}).get("counts") or {})
            title = _host_name(h) + (f" · {(s.get('meta') or {}).get('desc')}" if len(mine) > 1 else "")
            facts = [" · ".join(str(x) for x in (hw.get("name"), rs.get("version") and f"UniFi OS {rs['version']}",
                                                 h.get("ipAddress") and f"public IP {h['ipAddress']}") if x)]
            if s:
                facts.append(_internet(s, data["isp"].get(s.get("siteId"))))
                facts.append(f"{int(counts.get('wifiClient') or 0) + int(counts.get('wiredClient') or 0) + int(counts.get('guestClient') or 0)}"
                             f" clients: {counts.get('wiredClient') or 0} wired, {counts.get('wifiClient') or 0} Wi-Fi"
                             + (f", {counts['guestClient']} guests" if counts.get("guestClient") else ""))
                for wan, w in sorted(((s.get("statistics") or {}).get("wans") or {}).items()):
                    if not w.get("externalIp") and not float(w.get("wanUptime") or 0):
                        facts.append(f"{wan} not connected (down all of the last 24 h)")
                issues = (s.get("statistics") or {}).get("internetIssues") or []
                if issues:
                    facts.append(f"{len(issues)} internet issue{'s' * (len(issues) != 1)} reported (slow or dropped)")
                if counts.get("criticalNotification"):
                    facts.append(f"{counts['criticalNotification']} critical notification(s): see unifi.ui.com")
            if not _connected(h):
                facts.append(f"Not connected to the UniFi cloud ({rs.get('state')}); what's shown may be old.")
            items = [_cloud_device(d) for d in sorted(devs, key=lambda d: str(d.get("name")).lower())]
            state = ("down" if not _connected(h) or counts.get("offlineGatewayDevice") else
                     "warn" if any(i["state"] == "down" for i in items) or counts.get("criticalNotification") else "ok")
            out.append({"title": title, "entry": name, "state": state,
                        "facts": facts + ([entry["note"]] if entry.get("note") else []), "items": items})
    return out


# ── WAN exposure ──────────────────────────────────────────────────────────

def _public(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global and ip not in ipaddress.ip_network("100.64.0.0/10")


PROBE = r"""d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
p() { ip=$1; port=$2
  { echo "##$ip $port"
    if ! timeout 5 bash -c "exec 3<>/dev/tcp/$ip/$port" 2>/dev/null; then echo "S closed"; return; fi
    echo "S open"
    case $port in
      22) echo "B $(timeout 5 bash -c "exec 3<>/dev/tcp/$ip/$port; head -c 120 <&3" 2>/dev/null | head -1 | tr -cd '[:print:]')";;
      80) echo "T $(curl -skL -m 6 --max-redirs 2 "http://$ip/" | grep -io -m1 '<title>[^<]*' | cut -c8- | tr -cd '[:print:]')";;
      *) echo "T $(curl -skL -m 6 --max-redirs 2 "https://$ip:$port/" | grep -io -m1 '<title>[^<]*' | cut -c8- | tr -cd '[:print:]')"
         echo "C $(echo | timeout 6 openssl s_client -connect "$ip:$port" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | tr -cd '[:print:]')";;
    esac; } > "$d/$ip-$port"
}
for ip in IPS; do for port in PORTS; do p "$ip" "$port" & done; done; wait
cat "$d"/*
"""


def probe_script(ips: list[str]) -> str:
    if not ips or not all(_public(ip) for ip in ips):   # only addresses we checked go into the script
        raise UniFiError("only public IPv4 addresses are checked")
    return PROBE.replace("IPS", " ".join(ips)).replace("PORTS", " ".join(map(str, PORTS)))


def _probe_run(server: str, ips: list[str]) -> str:
    """Run the port check on a Servers (SSH) entry (same pinned host key as everything else)."""
    from hisho import addons
    srv = addons.get("server")
    target = addons.entries(srv).get(server)
    if target is None:
        raise UniFiError(f"no server named {server} on the Servers (SSH) page")
    mod = addons.provider(srv)
    mod._trust(target)
    res = subprocess.run(mod._ssh_args(target) + ["bash -s"], input=probe_script(ips), capture_output=True,
                         text=True, timeout=60)
    if "##" not in res.stdout:
        raise UniFiError((res.stderr.strip() or f"{server} didn't run the check")[-200:])
    return res.stdout


def parse_probe(text: str) -> dict[str, dict[int, dict[str, str]]]:
    out: dict[str, dict[int, dict[str, str]]] = {}
    for block in text.split("##")[1:]:
        head, *lines = block.strip().splitlines()
        ip, _, port = head.partition(" ")
        info = {ln[0]: ln[2:].strip() for ln in lines if len(ln) >= 2 and ln[1] == " "}
        if port.isdigit():
            out.setdefault(ip, {})[int(port)] = {"open": info.get("S") == "open", "title": info.get("T", ""),
                                                  "cert": info.get("C", ""), "banner": info.get("B", "")}
    return out


def probe(server: str, ips: list[str]) -> dict[str, dict[int, dict[str, Any]]]:
    now = time.time()
    fresh = {ip: _probe_cache[(server, ip)][1] for ip in ips
             if (server, ip) in _probe_cache and now - _probe_cache[(server, ip)][0] < PROBE_TTL}
    todo = [ip for ip in ips if ip not in fresh]
    if todo:
        found = parse_probe(_probe_run(server, todo))
        for ip in todo:
            fresh[ip] = found.get(ip, {})
            _probe_cache[(server, ip)] = (now, fresh[ip])
    return fresh


def _exposed_ok(entry: dict[str, Any]) -> set[str]:
    return {x.strip() for x in str(entry.get("exposed_ok") or "").split(",") if x.strip()}


LOGIN_HELP = ("Anyone on the internet can reach the console's login page and try passwords, and any UniFi OS "
              "security bug is reachable too. On UniFi gateways this is usually Direct Remote Connection: when it's "
              "on (UniFi's remote access settings, Remote Management; the gateway's setting direct_connect_enabled), "
              "UniFi adds the predefined firewall policy \"Allow Direct Remote Connection\" (External → Gateway, "
              "TCP 443) so the UniFi app can connect straight to the console's *.id.ui.direct address. To close it, "
              "turn Direct Remote Connection off: unifi.ui.com and the app keep working through UniFi's cloud, a "
              "little slower; for a fast way in, use a VPN (Teleport, WireGuard, Tailscale). If that's already off, "
              "look for a port forward or firewall rule that sends this port to the gateway itself. "
              "Hisho doesn't change UniFi settings: do this in UniFi, then press Refresh here.")


def _finding(ip: str, port: int, p: dict[str, Any], ok: set[str]) -> dict[str, Any]:
    unifi = "unifi" in (p.get("title", "") + " " + p.get("cert", "")).lower()
    on_purpose = f"{ip}:{port}" in ok
    if unifi:
        name, facts = f"UniFi OS login open to the internet  {ip}:{port}", [
            f"From outside, https://{ip}:{port}/ shows \"{p.get('title') or 'UniFi'}\" ({p.get('cert') or 'UniFi certificate'}).",
            LOGIN_HELP]
    elif port == 22:
        name, facts = f"SSH open to the internet  {ip}:22", [
            f"Answers {p.get('banner') or 'on SSH'}. Usually a port forward to a server; if you need it, keep "
            "passwords off (keys only). Otherwise remove the forward in UniFi Network > Settings > Routing."]
    else:
        name, facts = f"Port {port} open to the internet  {ip}:{port}", [
            f"A web page answers{(': ' + repr(p['title'])) if p.get('title') else ''}. Usually a port forward; "
            "remove it in UniFi Network if nothing should be reachable there."]
    if on_purpose:
        facts.insert(0, "You said this is on purpose.")
    return {"id": f"open-{ip}-{port}", "name": name, "state": "off" if on_purpose else "warn", "unifi": unifi,
            "facts": facts,
            "actions": [{"id": "expected", "label": "not on purpose"} if on_purpose else
                        {"id": "expected", "label": "on purpose",
                         "confirm": f"Stop warning about {ip}:{port}? It stays listed here, marked on purpose."}]}


def exposure(entry: dict[str, Any], ips: list[str], why_unknown: str = "") -> list[dict[str, Any]]:
    ips = sorted({ip for ip in ips if _public(ip)})
    if not ips:
        return [{"id": "exposure", "name": "Exposure not checked", "state": "unknown", "actions": [],
                 "facts": [why_unknown or "Not checked: the API gave no public IP for this network."]}]
    server = str(entry.get("probe_from") or "").strip()
    if not server:
        return [{"id": "exposure", "name": "Exposure not checked", "state": "unknown", "actions": [],
                 "facts": ["Not checked: in \"Check exposure from\", name a server outside this network (its entry "
                           "on the Servers (SSH) page, e.g. offsite). From inside the house the gateway answers on "
                           "its own public IP through your network, so it would always look open.",
                           "Public IP: " + ", ".join(ips)]}]
    try:
        seen = probe(server, ips)
    except Exception as exc:  # noqa: BLE001 -- a failed check shows as one
        return [{"id": "exposure", "name": "Exposure not checked", "state": "unknown", "actions": [],
                 "facts": [f"Couldn't check from {server}: {str(exc)[:200]}"]}]
    ok, items = _exposed_ok(entry), []
    for ip in ips:
        found = [_finding(ip, port, p, ok) for port, p in sorted(seen.get(ip, {}).items()) if p.get("open")]
        items += found or [{"id": f"ip-{ip}", "name": f"Nothing open  {ip}", "state": "up", "actions": [],
                            "facts": [f"Checked from {server}: nothing answers on {', '.join(map(str, PORTS))}."]}]
    return items


# ── the add-on's functions ────────────────────────────────────────────────

def _read(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    return read_local(entry, ctx) if _local(entry) else read_cloud(entry, ctx)


def _ips(entry: dict[str, Any], data: dict[str, Any]) -> list[str]:
    if _local(entry):
        return [str(_sub(s["health"], "wan").get("wan_ip")) for s in data["sites"] if _sub(s["health"], "wan").get("wan_ip")]
    return [str(h.get("ipAddress")) for h in data["hosts"] if h.get("owner", True) and h.get("ipAddress")]


def review(name: str, entry: dict[str, Any], data: dict[str, Any], many: bool) -> dict[str, Any]:
    key = str(entry.get("api_key") or "")
    local = _local(entry)
    unknown = ("Not checked: the public IP isn't known. This key can only read the Integration API, which "
               "doesn't give the WAN address; a Site Manager entry does." if local and not _ips(entry, data) else "")
    items = [{"id": "key", "name": f"key  {key if key and not key.startswith('HISHO_ADDON_') else '(typed on this page)'}",
              "state": "up", "actions": [],
              "facts": ([f"Gateway API key on {base_url(entry).split('://', 1)[1]}. It has the rights of the UniFi admin "
                         "who made it; Hisho only reads with it (GET), never changes anything."] if local else
                        ["Site Manager API key: read only by UniFi's design; sees every console on the UI account."])
              + ["Rotate: " + ("UniFi Network > Settings > Control Plane > Integrations." if local else "unifi.ui.com > API.")]}]
    items += [{k: v for k, v in i.items() if k != "unifi"} for i in exposure(entry, _ips(entry, data), unknown)]
    worry = sum(1 for i in items if i["state"] == "warn")
    return {"title": "Keys and exposure" + (f" · {name}" if many else ""), "entry": name,
            "state": "warn" if worry else "ok",
            "facts": [f"{worry} thing{'s' * (worry != 1)} to look at" if worry else "nothing to look at",
                      "Read only: Hisho never changes a UniFi setting."],
            "items": items}


def details(entries: dict[str, dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
    out = []
    for name, entry in entries.items():
        try:
            data = _read(entry, ctx)
        except (UniFiError, KeyError) as exc:
            out.append({"title": name, "entry": name, "state": "down", "facts": [str(exc)], "items": []})
            continue
        out.append(review(name, entry, data, len(entries) > 1))
        if _local(entry):
            out += [_local_section(name, entry, s, data["version"]) for s in data["sites"]]
        else:
            out += _cloud_sections(name, entry, data)
    return out


def summary(entries: dict[str, dict[str, Any]], ctx: Any) -> dict[str, Any]:
    """Both keys may see the same network: devices are counted once by MAC and a network's clients once
    (the gateway's own count wins over Site Manager's, which lags)."""
    problems: list[dict[str, Any]] = []
    n = {"sites": 0, "consoles": 0, "clients": 0}
    devices: dict[str, dict[str, Any]] = {}       # MAC -> {name, offline, update, local}

    def problem(entry: str, title: str, detail: str, severity: str = "warn") -> None:
        if title not in (p["title"] for p in problems):
            problems.append({"entry": entry, "severity": severity, "title": title, "detail": detail})

    def device(mac: str, name: str, offline: bool, update: bool, local: bool) -> None:
        if mac not in devices or (local and not devices[mac]["local"]):
            devices[mac] = {"name": name.strip(), "offline": offline, "update": update, "local": local}
    read = {}
    for name, entry in entries.items():
        try:
            read[name] = _read(entry, ctx)
        except (UniFiError, KeyError) as exc:
            problem(name, f"Can't read UniFi ({name})", str(exc))
    local_macs: set[str] = set()
    for name, data in read.items():
        if not _local(entries[name]):
            continue
        n["sites"] += len(data["sites"])
        for s in data["sites"]:
            n["clients"] += s["n_clients"]
            for d in s["devices"]:
                mac = _mac(d.get("macAddress")) or str(d.get("id"))
                local_macs.add(mac)
                device(mac, str(d.get("name")), d.get("state") in OFFLINE, bool(d.get("firmwareUpdatable")), True)
            wan = _sub(s["health"], "wan")
            if wan.get("status") not in (None, "ok"):
                problem(name, f"UniFi internet is {wan['status']} ({name})", "The gateway reports its WAN unhealthy.")
    for name, data in read.items():
        if _local(entries[name]):
            continue
        n["consoles"] += len(data["hosts"])
        names = {h.get("id"): _host_name(h) for h in data["hosts"]}
        for h in data["hosts"]:
            if not _connected(h):
                problem(name, f"UniFi console {_host_name(h)} isn't connected to the UniFi cloud",
                        "It may be off or offline, or its internet is down.")
        for devs in data["devices"].values():
            for d in devs:
                device(_mac(d.get("mac")) or str(d.get("id")), str(d.get("name")), d.get("status") != "online",
                       bool(d.get("updateAvailable") or d.get("firmwareStatus") == "updateAvailable"), False)
        for s in data["sites"]:
            st = s.get("statistics") or {}
            c = st.get("counts") or {}
            if _mac((s.get("meta") or {}).get("gatewayMac")) not in local_macs:
                n["clients"] += sum(int(c.get(k) or 0) for k in ("wifiClient", "wiredClient", "guestClient"))
            console = names.get(s.get("hostId"), s.get("hostId"))
            up = (st.get("percentages") or {}).get("wanUptime")
            # Titles are alert keys: the numbers go in the detail, or every new reading is a new alert
            # (the uptime figure alone made 130 pushes and as many "Resolved" in a day).
            if up is not None and float(up) < 99:
                isp = (st.get("ispInfo") or {}).get("name") or "the provider"
                problem(name, f"{console}: internet keeps dropping",
                        f"Internet was up {_g(up)}% of the time recently ({isp}). If it keeps happening, call {isp}.")
            if c.get("criticalNotification"):
                k = int(c["criticalNotification"])
                problem(name, f"{console}: critical notifications", f"{k} critical notification{'s' * (k != 1)}; "
                        "see unifi.ui.com.")
    for name, data in read.items():
        for i in exposure(entries[name], _ips(entries[name], data)):
            if i["state"] == "warn":
                ip, port = i["id"].removeprefix("open-").rsplit("-", 1)
                problem(name, (f"UniFi OS login answers from the internet on {ip}:{port}" if i.get("unifi")
                               else f"Port {port} answers from the internet on {ip}"), i["facts"][-1])
    off = sorted((d["name"] for d in devices.values() if d["offline"]), key=str.lower)
    if off:
        shown = ", ".join(off[:4]) + (f" and {len(off) - 4} more" if len(off) > 4 else "")
        problems.insert(0, {"entry": next(iter(entries), ""), "severity": "warn",
                            "title": f"UniFi device offline: {shown}" if len(off) == 1 else f"{len(off)} UniFi devices offline: {shown}",
                            "key": "UniFi devices offline",  # one alert while any are off, whichever they are
                            "detail": "Check their power and cable (cameras and switches are often unplugged on purpose)."})
    updates = sum(1 for d in devices.values() if d["update"])
    head = [f"{n['consoles']} console{'s' * (n['consoles'] != 1)}"] if n["consoles"] else []
    head += [f"{n['sites']} site{'s' * (n['sites'] != 1)}"] if n["sites"] else []
    head += [f"{len(devices)} devices" + (f" ({len(off)} offline)" if off else ""), f"{n['clients']} clients"]
    head += [f"{updates} update{'s' * (updates != 1)} available"] if updates else []
    return {"state": "warn" if problems else "ok", "headline": " · ".join(head), "problems": problems}


def test(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    fill: dict[str, Any] = {}
    try:
        if _local(entry):
            u = urllib.parse.urlsplit(base_url(entry))
            if not entry.get("fingerprint"):
                try:
                    fill["fingerprint"] = server_fingerprint(u.hostname or "", u.port or 443)
                except OSError as exc:
                    return {"ok": False, "error": f"can't reach {u.hostname}: {exc}"}
            data = read_local({**entry, **fill}, ctx)
            devs = sum(len(s["devices"]) for s in data["sites"])
            return {"ok": True, "fill": fill,
                    "message": f"Connected to UniFi Network {data['version']}: {len(data['sites'])} "
                               f"site{'s' * (len(data['sites']) != 1)}, {devs} devices"
                               + (" · certificate fingerprint filled in" if fill else "")}
        hosts = _cloud_pages(entry, ctx, "/v1/hosts")
    except UniFiError as exc:
        return {"ok": False, "error": str(exc), "fill": fill}
    return {"ok": True, "message": f"Connected to UniFi Site Manager: {len(hosts)} console{'s' * (len(hosts) != 1)}"
                                   + (f" ({', '.join(_host_name(h) for h in hosts[:6])})" if hosts else "")}


def describe_secret(entry: dict[str, Any], ctx: Any) -> str:
    """The 'What:' line of the key's Infisical comment."""
    if _local(entry):
        data = read_local(entry, ctx)
        return (f"UniFi Network Integration API key on {base_url(entry).split('://', 1)[1]} (UniFi Network "
                f"{data['version']}), sites {', '.join(str(s['site'].get('name')) for s in data['sites'])}. "
                "ADMIN-LEVEL: it has its admin's rights, so it can read every setting including the devices' SSH "
                "password; Hisho only reads devices, clients and WAN health with it (allow-listed endpoints).")
    hosts = _cloud_pages(entry, ctx, "/v1/hosts")
    return f"UniFi Site Manager API key (api.ui.com), consoles {', '.join(_host_name(h) for h in hosts)}. Read only."


def rotate_secret(entry: dict[str, Any]) -> str:
    """The 'Rotate:' line of the key's Infisical comment (the two kinds of key are made in different places)."""
    return ("UniFi Network > Settings > Control Plane > Integrations (delete the key and create another)" if _local(entry)
            else "unifi.ui.com > API (revoke the key and create another)")


def act(entries: dict[str, dict[str, Any]], ctx: Any, entry: str, item: str, action: str) -> dict[str, Any]:
    """Only Hisho's own note changes here ("on purpose"); nothing is sent to UniFi."""
    ent = entries.get(entry)
    if ent is None:
        return {"ok": False, "error": f"no UniFi entry {entry}"}
    if action != "expected" or not item.startswith("open-"):
        return {"ok": False, "error": "UniFi is read only in Hisho; change it in UniFi"}
    from hisho import addons
    ip, port = item.removeprefix("open-").rsplit("-", 1)
    key, ok = f"{ip}:{port}", _exposed_ok(ent)
    ok = ok - {key} if key in ok else ok | {key}
    addons.set_entry(ctx.addon, entry, {"exposed_ok": ", ".join(sorted(ok))}, merge=True)
    return {"ok": True, "message": f"{key}: " + ("on purpose, no more warning" if key in ok else "warning again")}
