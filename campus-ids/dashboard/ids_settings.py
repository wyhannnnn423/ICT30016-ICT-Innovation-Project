"""
ids_settings.py
------------------------
Settings of the dashboard: validation, storage and IP matching.
No Flask in here, so it can be tested on its own (see tests/test_settings.py).

Settings:
  own_ips      the monitored PC itself (alerts from it are hidden)
  trusted_ips  other trusted sources, single IPs or ranges such as 192.168.50.0/28
  scan_ports, flood_flows, window, cooldown   thresholds of the Stats layer
"""

import ipaddress
import json
import re
import socket
from functools import lru_cache
from pathlib import Path

DEFAULTS = {
    "auto_own_ip": True,      # follow this PC's IP automatically (also when the network changes)
    "own_ips": [],
    "trusted_ips": [],
    "scan_ports": 15,
    "flood_flows": 150,
    "window": 10,
    "cooldown": 30,
}

LIMITS = {                      # (minimum, maximum)
    "scan_ports": (2, 1000),
    "flood_flows": (10, 100000),
    "window": (1, 300),
    "cooldown": (0, 3600),
}

LABELS = {
    "auto_own_ip": "Detect this PC's IP automatically",
    "own_ips": "This PC's IP address",
    "trusted_ips": "Trusted IPs or ranges",
    "scan_ports": "Port scan threshold",
    "flood_flows": "Flood threshold",
    "window": "Time window",
    "cooldown": "Cooldown",
}

MAX_ENTRIES = 100


# ---------------------------------------------------------------- IP matching
@lru_cache(maxsize=8192)
def _parse_ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


class IpMatcher:
    """A set of IP addresses and ranges. Different spellings of the same IPv6
    address (Suricata writes it fully expanded) match each other."""

    def __init__(self, items=()):
        self.addresses = set()
        self.networks = []
        for item in items:
            item = item.strip()
            if "/" in item:
                self.networks.append(ipaddress.ip_network(item, strict=False))
            else:
                self.addresses.add(ipaddress.ip_address(item))

    def matches(self, ip_text):
        if not ip_text:
            return False
        ip = _parse_ip(ip_text)
        if ip is None:
            return False
        if ip in self.addresses:
            return True
        return any(ip in net for net in self.networks)

    def to_list(self):
        return sorted(str(a) for a in self.addresses) + [str(n) for n in self.networks]


# ----------------------------------------------------------------- validation
def _as_list(value):
    if isinstance(value, str):
        return [x for x in re.split(r"[,;\s]+", value) if x]
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return [x.strip() for x in value if x.strip()]
    return None


def validate(data, current=None):
    """Check settings coming from the browser, the command line or the settings file.

    Returns (clean, errors). Keys missing from `data` keep their value from `current`
    (or the defaults). Entries that are not valid are reported in `errors`.
    """
    base = dict(DEFAULTS)
    if current:
        base.update(current)
    if not isinstance(data, dict):
        return dict(base), ["Settings must be a JSON object"]

    clean, errors = {}, []

    if "auto_own_ip" not in data:
        clean["auto_own_ip"] = bool(base["auto_own_ip"])
    elif isinstance(data["auto_own_ip"], bool):
        clean["auto_own_ip"] = data["auto_own_ip"]
    else:
        errors.append(f"{LABELS['auto_own_ip']}: expected true or false")

    for key in ("own_ips", "trusted_ips"):
        if key not in data:
            clean[key] = list(base[key])
            continue
        items = _as_list(data[key])
        if items is None:
            errors.append(f"{LABELS[key]}: expected a list of IP addresses")
            continue
        if len(items) > MAX_ENTRIES:
            errors.append(f"{LABELS[key]}: at most {MAX_ENTRIES} entries")
            continue
        good = []
        for item in items:
            try:
                if "/" in item:
                    if key == "own_ips":
                        errors.append(f"'{item}': only a single IP address is allowed here (put ranges under trusted IPs)")
                        continue
                    net = ipaddress.ip_network(item, strict=False)
                    smallest = 8 if net.version == 4 else 32
                    if net.prefixlen < smallest:
                        errors.append(f"'{item}' is too large a range (use /{smallest} or longer)")
                        continue
                    good.append(str(net))
                else:
                    good.append(str(ipaddress.ip_address(item)))
            except ValueError:
                what = "IP address or range" if key == "trusted_ips" else "IP address"
                errors.append(f"'{item}' is not a valid {what}")
        clean[key] = list(dict.fromkeys(good))        # remove duplicates, keep order

    for key, (low, high) in LIMITS.items():
        if key not in data:
            clean[key] = base[key]
            continue
        value = data[key]
        is_number = isinstance(value, int) and not isinstance(value, bool)
        is_digits = isinstance(value, str) and re.fullmatch(r"\d+", value.strip())
        if not (is_number or is_digits):
            errors.append(f"{LABELS[key]} must be a whole number")
            continue
        value = int(value)
        if not low <= value <= high:
            errors.append(f"{LABELS[key]} must be between {low} and {high}")
            continue
        clean[key] = value

    return clean, errors


# -------------------------------------------------------------------- storage
def load(path):
    """Read the settings file. Returns only the valid keys that are in the file."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    clean, _ = validate(data)
    return {k: clean[k] for k in data if k in DEFAULTS and k in clean}


def save(path, settings):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    tmp.replace(path)


def resolve_own_ips(clean, detected_ip):
    """In automatic mode the PC's IP always comes from detection, whatever the form sent."""
    out = dict(clean)
    if out.get("auto_own_ip") and detected_ip:
        out["own_ips"] = [detected_ip]
    return out


def startup_settings(saved, cli, detected_ip=None):
    """Combine the sources at start-up: defaults < settings file < command line.

    Automatic mode (the default) uses the detected LAN IP of this PC. It is switched off when
    --own-ip is given, or when the settings file comes from before automatic mode existed and
    already holds an own_ips value. Returns (settings, errors, auto_ip).
    """
    settings = dict(DEFAULTS)
    settings.update(saved)
    cli_clean, errors = validate(cli, settings)
    if errors:
        return None, errors, None
    settings.update({k: cli_clean[k] for k in cli})
    if "own_ips" in cli:
        settings["auto_own_ip"] = False
    elif "auto_own_ip" not in saved and "own_ips" in saved:
        settings["auto_own_ip"] = False
    auto_ip = None
    if settings["auto_own_ip"] and detected_ip:
        settings["own_ips"] = [detected_ip]
        auto_ip = detected_ip
    return settings, [], auto_ip


# ------------------------------------------------------- this PC / who may edit
def detect_lan_ip():
    """LAN IPv4 address of this PC (the one used to reach the network), or None."""
    ip = None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))        # UDP connect only picks a route, nothing is sent
        ip = s.getsockname()[0]
    except OSError:
        pass
    finally:
        s.close()
    if not ip or ip.startswith("127.") or ip == "0.0.0.0":
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = None
    if ip and (ip.startswith("127.") or ip == "0.0.0.0"):
        ip = None
    return ip


@lru_cache(maxsize=1)
def _hostname_addresses():
    try:
        return tuple(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        return ()


def local_addresses():
    """Addresses a request has when it comes from this very PC."""
    found = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}
    found.update(_hostname_addresses())
    ip = detect_lan_ip()
    if ip:
        found.add(ip)
    return found


def host_header_ok(host):
    """Accept only 'localhost' or a plain IP in the Host header (blocks DNS-rebinding tricks)."""
    if not host:
        return False
    if host.startswith("["):
        name = host[1:host.find("]")] if "]" in host else ""
    elif host.count(":") == 1:
        name = host.rsplit(":", 1)[0]
    else:
        name = host
    return name.lower() == "localhost" or _parse_ip(name) is not None
