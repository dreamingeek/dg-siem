# GeoIP

DG SIEM adds location and network fields to public IP addresses as events arrive, so you can search and chart by country or provider across every source (Traefik/Pangolin, UniFi firewall, SSH, anything with an IP).

## Fields

For a public `source.ip` (and `destination.ip`, unless turned off):

| Field | Shortcut | Example |
|---|---|---|
| `source.geo.country_iso_code` | `country` | `US` |
| `source.geo.country_name` | | `United States` |
| `source.geo.region_name` | | `Washington` |
| `source.geo.city_name` | `city` | `Milton` |
| `source.geo.continent_code` | | `NA` |
| `source.geo.location.lat` / `.lon` | | `36.154` / `-95.993` |
| `source.as.number` | `asn` | `64500` |
| `source.as.organization.name` | `org`, `as_org` | `Example ISP` |

Destination fields are the same under `destination.*` (shortcuts `dst_country`, `dst_org`).

Private (RFC 1918), CGNAT `100.64.0.0/10` (Pangolin/newt and Tailscale tunnels), loopback, link-local, documentation, multicast and IPv6 ULA addresses are never looked up. When a parser already supplies a location (CrowdSec's country, authentik's GeoIP), that is kept; GeoIP still adds the network if it's missing.

Only events that arrive after GeoIP is working are enriched; older events keep what they had.

```
country=CN | stats count() by dataset
dataset=traefik.access | stats count() by country | sort -count
dataset=unifi.firewall action=blocked | top limit=10 org
org="*Hetzner*" | stats dc(src) by dataset
```

## Database source

**Administration → GeoIP**:

- **DB-IP Lite** (default): free, no account, updated monthly (checked every 6 hours; the new month's file appears in its first days). Its CC BY 4.0 license requires a credit, which DG SIEM shows on the GeoIP page and map panels.
- **MaxMind GeoLite2**: create a free account at maxmind.com, make a license key, and enter the account ID and key. Updated weekly.
- **My own files**: copy `city.mmdb` and/or `asn.mmdb` (MMDB format, GeoIP2/GeoLite2/DB-IP layout) into the GeoIP folder, e.g. a commercial GeoIP2 database. Replaced files are picked up within 6 hours or with **Update now**.
- **Off**.

Files live in `/var/lib/dg-siem/geoip` (setting `GeoIp:Directory`), on the `dg-siem-data` volume. The city database is about 130 MB. Downloads are checked before they replace the old files, and the swap happens without a restart. If an update fails, the last good files stay in use and the problem shows on the GeoIP page. The server needs outbound HTTPS to `download.db-ip.com` or `download.maxmind.com`.

The page's **Look up an address** box shows what an IP resolves to.
