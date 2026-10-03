"""Explicit demonstration data; never enabled by the Home Assistant entrypoint."""
from scanner import ScanManager

DEMO_NETWORK = {"cidr": "192.168.1.0/24", "interface": "eth0", "host_ip": "192.168.1.10",
                "gateway": "192.168.1.1", "default": True, "supported": True, "host_count": 254}
DEVICES = [
    (1, "router.home", "Ubiquiti", "Gateway"),
    (10, "homeassistant.local", "Home Assistant", "Home Assistant"),
    (12, "nas.local", "Synology", "NAS · גיבויים"),
    (15, "office-mac.local", "Apple", "מחשב העבודה"),
    (20, "living-room-tv.local", "Samsung", "טלוויזיה · סלון"),
    (21, "chromecast.local", "Google", "Chromecast"),
    (24, "jon-iphone.local", "Apple", "iPhone"),
    (30, "hue-bridge.local", "Philips", "Hue Bridge"),
    (31, "shelly-kitchen.local", "Shelly", "תאורה · מטבח"),
    (32, "shelly-bedroom.local", "Shelly", "תריס · חדר שינה"),
    (40, "esp-living-room.local", "Espressif", "חיישן · סלון"),
    (41, "esp-office.local", "Espressif", "חיישן · משרד"),
    (50, "front-door.local", "Reolink", "מצלמה · כניסה"),
    (51, "garden.local", "Reolink", "מצלמה · גינה"),
    (65, "laserjet.local", "HP", "מדפסת"),
    (80, "vacuum.local", "Roborock", "שואב אבק"),
    (100, "access-point.local", "Ubiquiti", "נקודת גישה"),
    (120, "sonos.local", "Sonos", "רמקול · סלון"),
]


def demo_hosts():
    return [{"ip": f"192.168.1.{octet}", "hostname": name, "vendor": vendor,
             "mac": f"02:00:00:00:01:{octet:02X}", "source": "ARP/mDNS"}
            for octet, name, vendor, _ in DEVICES]


def seed_demo(store):
    if store.snapshot(DEMO_NETWORK["cidr"])["scanned_at"]:
        return
    old = [{"ip": f"192.168.1.{n}", "hostname": name, "vendor": vendor,
            "mac": f"02:00:00:00:01:{n:02X}", "source": "ARP"}
           for n, name, vendor in [(25, "tablet.local", "Apple"), (60, "laptop.local", "Lenovo"),
                                    (81, "guest-phone.local", "Samsung")]]
    store.commit(DEMO_NETWORK["cidr"], old + demo_hosts(), 8.4, [])
    store.commit(DEMO_NETWORK["cidr"], demo_hosts(), 7.8, [])
    for n, _, _, alias in DEVICES:
        store.set_alias(DEMO_NETWORK["cidr"], f"192.168.1.{n}", alias)


class DemoManager(ScanManager):
    def _run(self, selected):
        try:
            self._phase("discovery")
            if self.cancel.wait(0.8):
                return
            self._phase("names")
            if self.cancel.wait(0.6):
                return
            with self.lock:
                if not self.cancel.is_set():
                    self.store.commit(selected["cidr"], demo_hosts(), 1.4, [])
        finally:
            with self.lock:
                self.status.update(running=False, phase="cancelled" if self.cancel.is_set() else "idle")
