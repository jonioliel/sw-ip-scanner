"""Discover directly attached IPv4 networks, excluding container/VPN interfaces."""
import ipaddress
import json
import re
import subprocess

MAX_HOSTS = 4094
EXCLUDED = ("lo", "docker", "veth", "br-", "hassio", "virbr", "tailscale", "wg", "tun", "zt")


def usable_network(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError("יש להזין רשת תקינה בפורמט CIDR, לדוגמה 192.168.1.0/24") from exc
    if network.version != 4 or network.prefixlen > 30:
        raise ValueError("הגרסה הזו תומכת ברשתות IPv4 עד ‎/30")
    if network.num_addresses - 2 > MAX_HOSTS:
        raise ValueError("ניתן לסרוק עד 4,094 כתובות לרשת (‎/20 או טווח קטן יותר)")
    return network


def parse_interfaces(addresses, routes):
    defaults = {r.get("dev"): r.get("gateway") for r in routes if r.get("dst") == "default"}
    found = []
    seen = {}
    for interface in addresses:
        name = interface.get("ifname", "")
        if not name or name.startswith(EXCLUDED):
            continue
        if interface.get("operstate") == "DOWN":
            continue
        for item in interface.get("addr_info", []):
            if item.get("family") != "inet" or item.get("scope") != "global":
                continue
            address = ipaddress.ip_interface(f"{item['local']}/{item['prefixlen']}")
            if address.ip.is_loopback or address.ip.is_link_local or address.ip.is_multicast:
                continue
            key = (str(address.network), name)
            if key in seen:
                if str(address.ip) not in seen[key]["local_ips"]:
                    seen[key]["local_ips"].append(str(address.ip))
                continue
            mac = interface.get("address") or ""
            entry = {
                "cidr": str(address.network), "interface": name, "host_ip": str(address.ip),
                "local_ips": [str(address.ip)],
                "mac": mac.upper() if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) else "",
                "gateway": defaults.get(name), "default": name in defaults,
                "host_count": max(address.network.num_addresses - 2, 0),
                "supported": 20 <= address.network.prefixlen <= 30,
            }
            seen[key] = entry
            found.append(entry)
    return sorted(found, key=lambda n: (not n["default"], n["interface"], n["cidr"]))


def discover_networks():
    def run(*args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=10, check=True)
        return json.loads(result.stdout)
    return parse_interfaces(run("ip", "-j", "-4", "address", "show", "up"),
                            run("ip", "-j", "-4", "route", "show", "default"))


def select_network(value, networks):
    supported = [n for n in networks if n["supported"]]
    if value == "auto":
        if not supported:
            raise ValueError("לא נמצאה רשת מקומית נתמכת. בדוק את טווח הרשת ואת host_network")
        return supported[0]
    requested = usable_network(value)
    for item in networks:
        parent = ipaddress.ip_network(item["cidr"])
        if requested.subnet_of(parent):
            return {**item, "cidr": str(requested), "supported": True,
                    "host_count": requested.num_addresses - 2}
    raise ValueError("אפשר לסרוק רק רשת המחוברת ישירות לשרת Home Assistant")
