# UniFi (Hisho add-on)

## What it does

Read only, for your UniFi networks (home and family): devices, clients, internet health and alerts,
and whether the gateway is open to the internet. A gateway's own API key reads that gateway; a Site
Manager key reads every console on the UI account. "Check exposure from" names a server outside the
network (a Servers (SSH) entry): Hisho asks UniFi for the public IP and checks from there whether
443, 8443, 80 or 22 answer. Hisho never changes a UniFi setting.

## What it needs

- You need:
  - A UniFi gateway or console
  - A UniFi API key (the gateway's own, or a Site Manager key for every console)
- Runs on: the Core machine, inside Hisho Core
- One entry per UniFi key, each with:
  - `api_key` (password, kept as a local secret, required)
  - `url` (str, optional)
  - `fingerprint` (str, optional)
  - `probe_from` (str, optional)
  - `exposed_ok` (str, optional)
  - `note` (str, optional)

## How to install

On the dashboard: **Add-ons > Store > UniFi > Install**. Or from a terminal:

```bash
hisho addon install unifi
```

Hisho takes the newest version from this repository and turns it on inside Hisho Core. Updates show as **Update
available** on its Store card; **Roll back** returns to the version before.

## How to use

Its card shows a network with devices offline, internet trouble or an open gateway. Its page (**Add-ons > UniFi**) has devices, clients, internet health and alerts per network. It never changes a UniFi setting.

## Settings

One entry per API key. A gateway's key: on the page (**Add-ons > UniFi**), **Found on your network**
lists the UniFi OS consoles Hisho sees (their sign-in page); **Use this** fills in the address, and the
API key's **Make a key on this gateway** link opens that console's Integrations page
(`https://<gateway>/network/default/integrations`, i.e. UniFi Network > Settings > Control Plane >
Integrations): **Create API Key**, name it `hisho`, and paste it. UniFi has no supported way to make a key
from a login, so this one step is by hand. A Site Manager key: unifi.ui.com > API > Create
API Key, and leave the address empty. Test pins the gateway's certificate. Entries are kept in
`~/Hisho/System/Config/Addons/unifi.yaml`. To rotate: delete the key where you made it and create
another.

## How to remove

**Add-ons > Store > UniFi > Remove**, or `hisho addon remove unifi`. Its card and page go away; your settings stay in `~/Hisho/System/Config/Addons/unifi.yaml`, so installing it again picks up where you left off.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE.md): free to use, change and share,
for any purpose except offering a product that competes with Hisho (reselling it, for example).
