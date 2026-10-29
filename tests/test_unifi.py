"""UniFi add-on tests. Run with Hisho's venv at the repository's top:
~/code/hisho/.venv/bin/python -m pytest -q"""
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from hisho import addon_store, addons, fleet_power, maintenance  # noqa: F401
from hisho.addon_testing import AUTH, TOKEN, Recorder

HERE = Path(__file__).resolve().parents[1]


def ctx_for(addon):
    return addons.Context(addon, resolve=lambda name: f"value-of-{name}")


def test_manifest_is_valid_and_readme_matches(addon):
    assert addons.validate_manifest(addon.manifest) == []
    assert addon_store.readme_problems(HERE) == []


UNIFI = Path(__file__).parent / "fixtures" / "unifi"


class FakeUniFi:
    """Both UniFi APIs from the recorded fixtures. Every call is a GET by construction (the provider's
    _http takes no method); the fake records each URL, key and certificate pin."""

    def __init__(self, key="k3y"):
        self.local = json.loads((UNIFI / "local.json").read_text())
        self.cloud = json.loads((UNIFI / "sitemanager.json").read_text())
        self.key, self.calls = key, []

    def __call__(self, url, key, fingerprint=None, timeout=15):
        mod = addons.provider(addons.get("unifi"))
        self.calls.append((url, fingerprint))
        if key != self.key:
            raise mod.UniFiError("UniFi refused the key (wrong, deleted, or for another console)")
        if url.startswith("https://api.ui.com"):
            path = url.removeprefix("https://api.ui.com")
            book = self.cloud
        else:
            assert url.startswith("https://198.51.100.1"), url
            path = url.removeprefix("https://198.51.100.1")
            book = self.local
        if path not in book:
            raise mod.UniFiError(f"UniFi answered 404 on {path.split('?')[0]}")
        return book[path]


def unifi_on(monkeypatch, **entries):
    uf = addons.get("unifi")
    for name, values in entries.items():
        addons.set_entry(uf, name, values)
    fake = FakeUniFi()
    mod = addons.provider(uf)
    monkeypatch.setattr(mod, "_http", fake)
    # the fixtures use documentation addresses (203.0.113.x, 198.51.100.x); count them as public here
    monkeypatch.setattr(mod, "_public", lambda ip: str(ip).startswith(("203.0.113.", "198.51.100.")))
    return uf, addons.Context(uf, resolve=lambda n: "k3y"), fake


HOME = {"url": "198.51.100.1", "api_key": "UNIFI_HOME_API_KEY", "fingerprint": "AB:CD"}


CLOUD = {"api_key": "UNIFI_SITEMANAGER_API_KEY"}


def test_unifi_local_gateway_shows_devices_clients_wan_and_alerts(fleet, monkeypatch):
    uf, ctx, fake = unifi_on(monkeypatch, home=HOME)
    s = addons.summarize(uf, ctx)
    assert s["headline"] == "1 site · 4 devices (1 offline) · 5 clients · 2 updates available"
    titles = [p["title"] for p in s["problems"]]
    assert titles == ["UniFi device offline: Garage AP"]              # alerts show on the page, not on the phone
    assert all(fp == "AB:CD" for _url, fp in fake.calls)            # the pinned certificate on every call
    review, site = addons.details(uf, ctx)
    assert review["title"] == "Keys and exposure"
    assert site["title"] == "Default" and site["state"] == "warn"
    assert "WAN ok · public IP 203.0.113.7 · Example Fiber · 11 ms" in site["facts"]
    assert "5 clients: 2 wired, 2 Wi-Fi, 1 VPN" in site["facts"]
    dev = {i["name"]: i for i in site["items"] if i["id"].startswith("dev-")}
    assert dev["Home Gateway"]["state"] == "warn" and "firmware update available" in dev["Home Gateway"]["facts"][1]
    assert dev["Garage AP"]["state"] == "down" and dev["Rack Switch"]["state"] == "up"
    alerts = [i for i in site["items"] if i["id"].startswith("alert-")]
    assert [a["name"] for a in alerts] == ["AP[74:ac:b9:00:00:04] was disconnected (2×)", "Gateway WAN transitioned to WAN2"]
    assert all(i["actions"] == [] for i in dev.values())             # read only: nothing to press on a device


def test_unifi_local_gateway_without_the_classic_api_still_works(fleet, monkeypatch):
    uf, ctx, fake = unifi_on(monkeypatch, home=HOME)
    for path in [p for p in fake.local if "/proxy/network/api/" in p]:
        del fake.local[path]                                         # an API key that only opens the Integration API
    review, site = addons.details(uf, ctx)
    assert "WAN health and alerts aren't readable with this key" in " ".join(site["facts"])
    pub = next(i for i in review["items"] if i["id"] == "exposure")
    assert pub["state"] == "unknown" and "public IP" in pub["facts"][0]


def test_unifi_site_manager_covers_every_console(fleet, monkeypatch):
    uf, ctx, fake = unifi_on(monkeypatch, cloud=CLOUD)
    s = addons.summarize(uf, ctx)
    assert s["headline"] == "2 consoles · 5 devices (2 offline) · 11 clients · 2 updates available"
    titles = [p["title"] for p in s["problems"]]
    assert "UniFi console Mom and Dad isn't connected to the UniFi cloud" in titles
    assert "2 UniFi devices offline: Garage AP, Manufacturer RLC-810A" in titles
    assert "Mom and Dad: internet keeps dropping" in titles
    assert not any(t.startswith("Home: internet") for t in titles)   # the stale duplicate site (50%) is ignored
    assert "Mom and Dad: critical notifications" in titles
    assert not any(ch.isdigit() for t in titles if "internet" in t or "critical" in t for ch in t)  # titles are keys
    drop = next(p for p in s["problems"] if p["title"] == "Mom and Dad: internet keeps dropping")
    assert "97.2%" in drop["detail"] and "Example Cable" in drop["detail"]
    assert next(p for p in s["problems"] if "offline:" in p["title"])["key"] == "UniFi devices offline"
    review, home, parents = addons.details(uf, ctx)
    assert (home["title"], parents["title"]) == ("Home", "Mom and Dad")
    assert "UniFi Dream Machine Pro · UniFi OS 4.3.6 · public IP 203.0.113.7" in home["facts"]
    assert "internet: Example Fiber · up 99.93% · last 24 h: 12 ms average, packet loss up to 0%" in home["facts"]
    assert "WAN2 not connected (down all of the last 24 h)" in home["facts"]
    assert "internet: Example Cable · up 97.2% · last 24 h: 180 ms average, packet loss up to 3%, 2 min down" in parents["facts"]
    assert parents["state"] == "down"                                  # console disconnected
    gw = next(i for i in home["items"] if i["name"] == "Home Gateway")
    assert gw["state"] == "warn" and "firmware update available: 4.4.1" in gw["facts"][1]
    cam = next(i for i in parents["items"] if i["name"] == "Manufacturer RLC-810A")
    assert cam["facts"][1] == "firmware ? · offline"
    assert any(c[0].endswith("nextToken=page2") for c in fake.calls)   # follows pages
    # old device lists Site Manager still returns (another hostId, or an older copy) are ignored
    assert "Rack Switch" not in [i["name"] for i in home["items"]]
    assert next(i for i in home["items"] if i["name"] == "Home Gateway")["state"] == "warn"


def test_unifi_wan_exposure_probes_from_outside_and_explains(fleet, monkeypatch):
    uf, ctx, fake = unifi_on(monkeypatch, home={**HOME, "probe_from": "offsite"})
    mod = addons.provider(uf)
    mod._probe_cache.clear()
    asked = []

    def run(server, ips):
        asked.append((server, ips))
        return ("##203.0.113.7 443\nS open\nT UniFi OS\nC subject=CN = unifi.local\n"
                "##203.0.113.7 8443\nS closed\n##203.0.113.7 80\nS closed\n"
                "##203.0.113.7 22\nS open\nB SSH-2.0-OpenSSH_9.2p1\n")
    monkeypatch.setattr(mod, "_probe_run", run)
    review = addons.details(uf, ctx)[0]
    assert asked == [("offsite", ["203.0.113.7"])]                      # the IP came from the API, not from code
    login = next(i for i in review["items"] if i["id"] == "open-203.0.113.7-443")
    assert login["state"] == "warn" and login["name"] == "UniFi OS login open to the internet  203.0.113.7:443"
    text = " ".join(login["facts"])
    assert "Remote Management" in text and "port forward" in text and "Hisho doesn't change UniFi settings" in text
    assert '"Allow Direct Remote Connection" (External → Gateway, TCP 443)' in text and "Direct Remote Connection off" in text
    ssh = next(i for i in review["items"] if i["id"] == "open-203.0.113.7-22")
    assert ssh["state"] == "warn" and "SSH-2.0-OpenSSH_9.2p1" in " ".join(ssh["facts"])
    titles = [p["title"] for p in addons.summarize(uf, ctx)["problems"]]
    assert "UniFi OS login answers from the internet on 203.0.113.7:443" in titles
    assert len(asked) == 1                                              # probed once, then cached
    # SSH there is on purpose: the warning stops, the item stays
    res = addons.act(uf, "home", "open-203.0.113.7-22", "expected", ctx=ctx)
    assert res["ok"] and addons.entries(uf)["home"]["exposed_ok"] == "203.0.113.7:22"
    ssh = next(i for i in addons.details(uf, ctx)[0]["items"] if i["id"] == "open-203.0.113.7-22")
    assert ssh["state"] == "off"


def test_unifi_wan_exposure_needs_an_outside_server(fleet, monkeypatch):
    uf, ctx, fake = unifi_on(monkeypatch, home=HOME)
    monkeypatch.setattr(addons.provider(uf), "_probe_run", lambda *a: pytest.fail("no probe without probe_from"))
    item = next(i for i in addons.details(uf, ctx)[0]["items"] if i["id"] == "exposure")
    assert item["state"] == "unknown" and "outside" in item["facts"][0]


def test_unifi_test_pins_the_gateway_certificate_and_names_the_key(fleet, monkeypatch):
    uf, ctx, fake = unifi_on(monkeypatch)
    mod = addons.provider(uf)
    monkeypatch.setattr(mod, "server_fingerprint", lambda host, port: "12:34")
    res = mod.test({"url": "198.51.100.1", "api_key": "UNIFI_HOME_API_KEY"}, ctx)
    assert res["ok"] and res["fill"] == {"fingerprint": "12:34"}
    assert res["message"] == "Connected to UniFi Network 9.4.19: 1 site, 4 devices · certificate fingerprint filled in"
    res = mod.test(CLOUD, ctx)
    assert res["ok"] and res["message"] == "Connected to UniFi Site Manager: 2 consoles (Home, Mom and Dad)"
    bad = addons.Context(uf, resolve=lambda n: "nope")
    assert "refused the key" in mod.test(CLOUD, bad)["error"]
    assert "Read only" in mod.describe_secret(CLOUD, ctx) and "Integrations" in uf.manifest["secret_rotate"]


def test_the_first_working_unifi_key_turns_the_addon_on(client, monkeypatch):
    uf = addons.get("unifi")
    monkeypatch.setattr(addons.provider(uf), "_http", FakeUniFi(key="k3y"))
    monkeypatch.setattr(addons.Context, "secret", lambda self, n: "k3y")
    assert "unifi" not in addons.enabled()
    r = client.post("/api/addons/unifi/entries/cloud", json=CLOUD, headers=AUTH).json()
    assert r["enabled"] is True and "UniFi is on." in r["message"] and "unifi" in addons.enabled()


def test_unifi_probe_script_only_takes_checked_public_addresses(fleet):
    mod = addons.provider(addons.get("unifi"))
    for bad in (["198.51.100.1"], ["100.64.0.20"], ["1.2.3.4; rm -rf ~"], []):
        with pytest.raises(mod.UniFiError):
            mod.probe_script(bad)
    script = mod.probe_script(["93.184.216.34"])
    assert "for ip in 93.184.216.34; do for port in 443 8443 80 22" in script
    seen = mod.parse_probe("##93.184.216.34 443\nS open\nT UniFi OS\nC subject=CN = unifi.local\n##93.184.216.34 22\nS closed\n")
    assert seen["93.184.216.34"][443]["open"] and not seen["93.184.216.34"][22]["open"]


def test_unifi_one_offline_device_is_one_problem_across_both_keys(fleet, monkeypatch):
    uf, ctx, fake = unifi_on(monkeypatch, home=HOME, cloud=CLOUD)
    titles = [p["title"] for p in addons.summarize(uf, ctx)["problems"]]
    assert "2 UniFi devices offline: Garage AP, Manufacturer RLC-810A" in titles
    assert sum("offline" in t for t in titles) == 1
    # the home gateway seen by both keys is one network: devices by MAC, clients once (the local count wins)
    s = addons.summarize(uf, ctx)
    assert s["headline"] == "2 consoles · 1 site · 7 devices (2 offline) · 12 clients · 2 updates available"


def test_unifi_says_when_alerts_are_not_readable(fleet, monkeypatch):
    uf, ctx, fake = unifi_on(monkeypatch, home=HOME)
    del fake.local["/proxy/network/api/s/default/stat/alarm?archived=false"]   # UniFi Network 10: 404 for API keys
    site = addons.details(uf, ctx)[1]
    assert "Alerts aren't readable with this key; see the UniFi app." in site["facts"]


def test_unifi_secret_comments_name_where_each_key_is_rotated(fleet, monkeypatch):
    from hisho import secret_notes
    uf, ctx, fake = unifi_on(monkeypatch, home=HOME, cloud=CLOUD)
    monkeypatch.setattr(addons, "Context", lambda addon, resolve=None: ctx)
    home = secret_notes.draft("UNIFI_HOME_API_KEY", added="2026-10-19").splitlines()
    cloud = secret_notes.draft("UNIFI_SITEMANAGER_API_KEY", added="2026-10-19").splitlines()
    assert home[0].startswith("What: UniFi Network Integration API key on 198.51.100.1 (UniFi Network 9.4.19)")
    assert "ADMIN-LEVEL" in home[0] and "SSH password" in home[0]
    assert home[1] == "Used by: Hisho UniFi add-on, entry home."
    assert home[2] == "Rotate: UniFi Network > Settings > Control Plane > Integrations (delete the key and create another), then update this value."
    assert cloud[0] == "What: UniFi Site Manager API key (api.ui.com), consoles Home, Mom and Dad. Read only."
    assert cloud[2] == "Rotate: unifi.ui.com > API (revoke the key and create another), then update this value."


SSH_SECRET = "hunter2-device-ssh"


def test_unifi_never_lets_device_ssh_credentials_through(fleet, monkeypatch, client, caplog):
    """A gateway key is admin-level: its answers may carry the devices' SSH password. Settings endpoints are
    never requested, and only allow-listed fields of each answer are kept (page, summary, cache, API, logs)."""
    import logging
    caplog.set_level(logging.DEBUG)
    uf, ctx, fake = unifi_on(monkeypatch, home={**HOME, "probe_from": "offsite"}, cloud=CLOUD)
    mod = addons.provider(uf)
    monkeypatch.setattr(mod, "_probe_run", lambda server, ips: "##203.0.113.7 443\nS open\nT UniFi OS\n")
    mod._probe_cache.clear()
    mgmt = {"meta": {"rc": "ok"}, "data": [{"key": "mgmt", "direct_connect_enabled": True,
                                            "x_ssh_password": SSH_SECRET, "x_ssh_sha512passwd": SSH_SECRET}]}
    fake.local["/proxy/network/api/s/default/get/setting/mgmt"] = mgmt
    leak = {"x_ssh_password": SSH_SECRET, "sshPassword": SSH_SECRET, "mgmt": mgmt}
    for path, page in fake.local.items():
        for item in (page.get("data") or []) if isinstance(page, dict) else []:
            item.update(leak)
    fake.local["/proxy/network/integration/v1/info"].update(leak)
    for path, page in fake.cloud.items():
        for item in (page.get("data") or []) if isinstance(page, dict) else []:
            item.update(leak)
            for d in item.get("devices") or []:
                d.update(leak)
            (item.get("reportedState") or {}).update(leak)
            (item.get("statistics") or {}).update(leak)
            for w in ((item.get("statistics") or {}).get("wans") or {}).values():
                w.update(leak)
    # the settings endpoint is refused before the key is looked up or anything is sent
    calls = len(fake.calls)
    with pytest.raises(mod.UniFiError):
        mod._get(addons.entries(uf)["home"], ctx, "/proxy/network/api/s/default/get/setting/mgmt")
    assert len(fake.calls) == calls
    seen = [json.dumps(addons.summarize(uf, ctx)), json.dumps(addons.details(uf, ctx)),
            json.dumps([mod.read_local(addons.entries(uf)["home"], ctx), mod.read_cloud(CLOUD, ctx)], default=str)]
    monkeypatch.setattr(addons.Context, "secret", lambda self, n: "k3y")
    addons.enable("unifi")
    addons.refresh_checks(run=Recorder())                                 # fills Core's summary and page caches
    seen += [json.dumps(addons.cached_details(uf), default=str), json.dumps(addons._summaries, default=str)]
    assert "Garage AP" in seen[3] and "UniFi OS login" in seen[4]      # the caches really hold UniFi's data
    seen.append(client.get("/api/addons/unifi").text)
    assert "Garage AP" in seen[5]
    seen.append(caplog.text)
    assert not [i for i, text in enumerate(seen) if SSH_SECRET in text or "ssh_password" in text.lower()]
    assert not any("setting" in url for url, _fp in fake.calls)            # no settings endpoint was ever requested
    assert "UniFi Network 9.4.19" in seen[1] and "Garage AP" in seen[1]  # the allowed fields still arrive


def test_found_on_your_network_finds_a_console_and_links_to_its_integrations_page(addon):
    from hisho import connect as hconnect
    assert addons.validate_manifest(addon.manifest) == []
    tcp = lambda ip, port, banner="": ip == "198.51.100.1" and port == 443
    http = lambda url, match: url == "https://198.51.100.1/" and match == "UniFi"
    got = hconnect.scan(addon, ["198.51.100.0/29"], tcp=tcp, http=http, rmcp=lambda *a: False, workers=2)
    assert got == [{"ip": "198.51.100.1", "title": "UniFi console at 198.51.100.1", "fill": {"url": "https://198.51.100.1"}}]
    # the key's help link is that console's own Integrations page, built from the address filled in
    get = addons.field_help(addon)["api_key"]["get"]
    assert get.replace("{url}", got[0]["fill"]["url"]) == "https://198.51.100.1/network/default/integrations"
    assert "connect" not in addon.manifest
