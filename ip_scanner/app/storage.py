"""Atomic persistent state. An unanswered known address never becomes free."""
import copy
import ipaddress
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def consecutive_ranges(rows):
    ranges = []
    for row in rows:
        number = int(ipaddress.ip_address(row["ip"]))
        if ranges and ranges[-1]["status"] == row["status"] and ranges[-1]["_end"] + 1 == number:
            ranges[-1]["end"] = row["ip"]
            ranges[-1]["count"] += 1
            ranges[-1]["_end"] = number
        else:
            ranges.append({"start": row["ip"], "end": row["ip"], "count": 1,
                           "status": row["status"], "_end": number})
    return [{k: v for k, v in entry.items() if k != "_end"} for entry in ranges]


class Store:
    def __init__(self, directory):
        self.path = Path(directory) / "state.json"
        self.lock = threading.RLock()
        self.state = {"version": 1, "networks": {}, "aliases": {}}
        if self.path.exists():
            state = json.loads(self.path.read_text(encoding="utf-8"))
            if state.get("version") != 1 or not isinstance(state.get("networks"), dict):
                raise ValueError("Unsupported or damaged state.json; restore from backup")
            self.state = state

    def _write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(self.state, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def commit(self, cidr, hosts, duration, warnings):
        with self.lock:
            previous = copy.deepcopy(self.state)
            snapshot = self.state["networks"].setdefault(cidr, {"devices": {}})
            timestamp = utc_now()
            for device in snapshot["devices"].values():
                device["status"] = "known"
            for host in hosts:
                old = snapshot["devices"].get(host["ip"], {})
                # Do not carry a name across a detected MAC-address change.
                same_device = not (old.get("mac") and host.get("mac") and old["mac"] != host["mac"])
                merged = {**(old if same_device else {}), **host}
                # This role is current interface evidence, not historical device identity.
                merged["role"] = host.get("role")
                for key in ("hostname", "vendor", "mac"):
                    if not merged.get(key) and same_device:
                        merged[key] = old.get(key, "")
                merged.update(status="occupied", last_seen=timestamp,
                              first_seen=old.get("first_seen", timestamp) if same_device else timestamp)
                snapshot["devices"][host["ip"]] = merged
            snapshot.update(scanned_at=timestamp, duration=round(duration, 1), warnings=warnings)
            try:
                self._write()
            except Exception:
                self.state = previous
                raise

    def set_alias(self, cidr, ip, alias):
        with self.lock:
            key = f"{cidr}|{ip}"
            old = copy.deepcopy(self.state["aliases"])
            if alias:
                self.state["aliases"][key] = alias
            else:
                self.state["aliases"].pop(key, None)
            try:
                self._write()
            except Exception:
                self.state["aliases"] = old
                raise

    def snapshot(self, cidr):
        network = ipaddress.ip_network(cidr)
        with self.lock:
            snapshot = copy.deepcopy(self.state["networks"].get(cidr, {}))
            aliases = dict(self.state["aliases"])
        devices = snapshot.get("devices", {})
        scanned = bool(snapshot.get("scanned_at"))
        rows = []
        for ip in network.hosts():
            value = str(ip)
            device = devices.get(value, {})
            alias = aliases.get(f"{cidr}|{value}", "")
            rows.append({"ip": value, "status": device.get("status", "unobserved" if scanned else "unscanned"),
                         "name": alias or device.get("hostname") or (
                             "שרת Home Assistant" if device.get("role") == "local_host" else ""), "alias": alias,
                         "hostname": device.get("hostname", ""), "mac": device.get("mac", ""),
                         "vendor": device.get("vendor", ""), "source": device.get("source", ""),
                         "last_seen": device.get("last_seen"), "first_seen": device.get("first_seen")})
        counts = {status: sum(r["status"] == status for r in rows)
                  for status in ("occupied", "known", "unobserved", "unscanned")}
        return {"cidr": cidr, "rows": rows, "ranges": consecutive_ranges(rows), "counts": counts,
                "total": len(rows), "scanned_at": snapshot.get("scanned_at"),
                "duration": snapshot.get("duration"), "warnings": snapshot.get("warnings", []),
                "reserved": [str(network.network_address), str(network.broadcast_address)]}
