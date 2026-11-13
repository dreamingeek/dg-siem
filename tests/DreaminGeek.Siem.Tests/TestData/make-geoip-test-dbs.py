"""Builds the small, synthetic MMDB files the GeoIP tests use (no real geolocation data).

    pip install mmdb-writer netaddr
    python make-geoip-test-dbs.py

Layouts match the GeoIP2/GeoLite2 City and ASN databases (DB-IP Lite uses the same).
"""
from mmdb_writer import MMDBWriter, MmdbF64, MmdbU32
from netaddr import IPSet

def city(code, country, name, region, lat, lon):
    return {
        "continent": {"code": "EU" if code in ("GB", "NL", "DE") else "NA" if code == "US" else "AS"},
        "country": {"iso_code": code, "names": {"en": country}},
        "city": {"names": {"en": name}},
        "subdivisions": [{"names": {"en": region}}],
        "location": {"latitude": MmdbF64(lat), "longitude": MmdbF64(lon)},
    }

w = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="DG-Test-City", languages=["en"], description="DG SIEM synthetic test data")
w.insert_network(IPSet(["81.2.69.0/24"]), city("GB", "United Kingdom", "London", "England", 51.5142, -0.0931))
w.insert_network(IPSet(["45.148.10.0/24"]), city("NL", "Netherlands", "Amsterdam", "North Holland", 52.37, 4.89))
w.insert_network(IPSet(["216.160.83.0/24"]), city("US", "United States", "Milton", "Washington", 47.2513, -122.3149))
w.insert_network(IPSet(["2001:4860::/32"]), city("US", "United States", "Mountain View", "California", 37.4, -122.08))
w.insert_network(IPSet(["1.12.0.0/14"]), {"country": {"iso_code": "CN", "names": {"en": "China"}}})  # country only
w.to_db_file("geo-city-test.mmdb")

a = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type="DG-Test-ASN", languages=["en"], description="DG SIEM synthetic test data")
a.insert_network(IPSet(["81.2.69.0/24"]), {"autonomous_system_number": MmdbU32(20712), "autonomous_system_organization": "Andrews & Arnold Ltd"})
a.insert_network(IPSet(["45.148.10.0/24"]), {"autonomous_system_number": MmdbU32(48090), "autonomous_system_organization": "Techoff SRV Limited"})
a.insert_network(IPSet(["216.160.83.0/24"]), {"autonomous_system_number": MmdbU32(64500), "autonomous_system_organization": "Example ISP"})
a.to_db_file("geo-asn-test.mmdb")
print("wrote geo-city-test.mmdb, geo-asn-test.mmdb")
