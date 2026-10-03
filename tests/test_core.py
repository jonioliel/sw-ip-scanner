import http.client
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ip_scanner" / "app"))
from app import Context, DEFAULTS, make_handler, load_options
from demo import DEMO_NETWORK
from http.server import ThreadingHTTPServer
from network import parse_interfaces, select_network, usable_network
from scanner import ScanManager, parse_nmap
from storage import Store

XML = '''<?xml version="1.0"?><nmaprun><host><status state="up" reason="arp-response"/>
<address addr="192.168.1.10" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Vendor"/>
<hostnames><hostname name="homeassistant.local" type="PTR"/></hostnames></host>
<host><status state="down"/><address addr="192.168.1.11" addrtype="ipv4"/></host>
<runstats><finished exit="success"/><hosts up="1" down="255" total="256"/></runstats></nmaprun>'''


def host(ip="192.168.1.10", name="homeassistant.local", mac="AA:BB:CC:DD:EE:FF"):
    return {"ip": ip, "hostname": name, "mac": mac, "vendor": "Vendor", "source": "ARP"}


class NetworkTests(unittest.TestCase):
    def test_host_and_container_interfaces(self):
        def interface(name, address, prefix=24):
            return {"ifname": name, "operstate": "UP", "addr_info": [
                {"local": address, "prefixlen": prefix, "family": "inet", "scope": "global"}]}
        networks = parse_interfaces([interface("docker0", "172.17.0.1", 16), interface("hassio", "172.30.32.1", 23),
                                     interface("eth1", "10.0.0.2"), interface("eth0", "192.168.1.10")],
                                    [{"dev": "eth0", "dst": "default", "gateway": "192.168.1.1"}])
        self.assertEqual(len(networks), 2)
        self.assertEqual(select_network("auto", networks)["cidr"], "192.168.1.0/24")
        self.assertEqual(select_network("192.168.1.128/25", networks)["interface"], "eth0")
        for value in ("8.8.8.0/24", "192.168.1.1/24", "192.168.1.0/24; touch /tmp/a"):
            with self.assertRaises(ValueError):
                select_network(value, networks)

    def test_network_limits(self):
        for value in ("10.0.0.0/8", "2001:db8::/64", "192.168.1.0/31"):
            with self.assertRaises(ValueError):
                usable_network(value)
        self.assertEqual(usable_network("192.168.0.0/20").num_addresses - 2, 4094)

    def test_all_local_addresses_on_the_interface_are_retained(self):
        addresses = [{"ifname": "eth0", "operstate": "UP", "address": "AA:BB:CC:DD:EE:FF",
                      "addr_info": [{"family": "inet", "scope": "global", "local": ip, "prefixlen": 24}
                                    for ip in ("192.168.1.10", "192.168.1.11")]}]
        networks = parse_interfaces(addresses, [])
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["local_ips"], ["192.168.1.10", "192.168.1.11"])
        self.assertEqual(networks[0]["mac"], "AA:BB:CC:DD:EE:FF")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()

    def test_unscanned_is_never_free(self):
        result = self.store.snapshot("192.168.1.0/24")
        self.assertEqual(result["total"], 254)
        self.assertEqual(result["counts"]["unobserved"], 0)
        self.assertEqual(result["counts"]["unscanned"], 254)
        self.assertEqual(result["reserved"], ["192.168.1.0", "192.168.1.255"])

    def test_history_names_and_restart(self):
        self.store.commit("192.168.1.0/24", [host(), host("192.168.1.11")], 2, [])
        self.store.set_alias("192.168.1.0/24", "192.168.1.10", "השרת שלי")
        self.store.commit("192.168.1.0/24", [host(name="")], 3, [])
        result = Store(self.temp.name).snapshot("192.168.1.0/24")
        self.assertEqual(result["counts"], {"occupied": 1, "known": 1, "unobserved": 252, "unscanned": 0})
        self.assertEqual(result["rows"][9]["name"], "השרת שלי")
        self.assertEqual(result["rows"][9]["hostname"], "homeassistant.local")
        self.assertEqual(result["rows"][10]["status"], "known")
        self.assertEqual(sum(r["count"] for r in result["ranges"]), 254)

    def test_ranges_cross_octet_and_network_isolation(self):
        self.store.commit("192.168.0.0/23", [host("192.168.0.254"), host("192.168.0.255"), host("192.168.1.0")], 2, [])
        snapshot = self.store.snapshot("192.168.0.0/23")
        ranges = [r for r in snapshot["ranges"] if r["status"] == "occupied"]
        self.assertEqual(ranges[0], {"start": "192.168.0.254", "end": "192.168.1.0", "count": 3, "status": "occupied"})
        self.assertEqual(snapshot["total"], 510)
        self.assertEqual(self.store.snapshot("10.0.0.0/24")["counts"]["unscanned"], 254)

    def test_new_mac_does_not_inherit_old_discovered_name(self):
        self.store.commit("192.168.1.0/24", [host()], 1, [])
        self.store.commit("192.168.1.0/24", [host(name="", mac="01:02:03:04:05:06")], 1, [])
        self.assertEqual(self.store.snapshot("192.168.1.0/24")["rows"][9]["name"], "")

    def test_local_host_label_is_not_kept_for_a_remote_device(self):
        self.store.commit("192.168.1.0/24", [{**host(name=""), "role": "local_host"}], 1, [])
        self.assertEqual(self.store.snapshot("192.168.1.0/24")["rows"][9]["name"], "שרת Home Assistant")
        self.store.commit("192.168.1.0/24", [host(name="")], 1, [])
        self.assertEqual(self.store.snapshot("192.168.1.0/24")["rows"][9]["name"], "")

    def test_failed_disk_write_rolls_back_memory(self):
        self.store.commit("192.168.1.0/24", [host()], 1, [])
        before = self.store.snapshot("192.168.1.0/24")
        with patch.object(self.store, "_write", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.store.commit("192.168.1.0/24", [host("192.168.1.20")], 1, [])
        self.assertEqual(before, self.store.snapshot("192.168.1.0/24"))


class ScannerTests(unittest.TestCase):
    def test_nmap_live_only(self):
        self.assertEqual(parse_nmap(XML, "192.168.1.0/24"), [host()])
        with self.assertRaises(RuntimeError):
            parse_nmap(XML.replace('exit="success"', 'exit="error"'), "192.168.1.0/24")
        with self.assertRaises(Exception):
            parse_nmap(XML[:100], "192.168.1.0/24")
        with self.assertRaises(RuntimeError):
            parse_nmap(XML.replace('total="256"', 'total="128"'), "192.168.1.0/24")

    def test_failed_scan_preserves_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            store.commit("192.168.1.0/24", [host()], 2, [])
            before = store.snapshot("192.168.1.0/24")
            manager = ScanManager(store, mdns=False)
            with self.assertLogs("scanner", level="ERROR"), patch("scanner.subprocess.Popen", side_effect=FileNotFoundError("nmap missing")):
                manager.start(DEMO_NETWORK)
                manager.thread.join(timeout=2)
            self.assertFalse(manager.state()["running"])
            self.assertTrue(manager.state()["error"])
            self.assertEqual(before, store.snapshot("192.168.1.0/24"))

    def test_successful_scan_uses_arp_without_shell_or_port_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            manager = ScanManager(store, mdns=False)
            with patch("scanner.subprocess.Popen") as launch:
                process = launch.return_value
                process.communicate.return_value = (XML, "")
                process.returncode = 0
                manager.start(DEMO_NETWORK)
                manager.thread.join(timeout=2)
                command = launch.call_args.args[0]
                self.assertIn("-sn", command)
                self.assertIn("-PR", command)
                self.assertEqual(command[-1], "192.168.1.0/24")
                self.assertFalse(launch.call_args.kwargs.get("shell", False))
            self.assertIsNone(manager.state()["error"])
            self.assertEqual(store.snapshot("192.168.1.0/24")["counts"]["occupied"], 1)

    def test_missing_local_arp_response_does_not_reject_other_results(self):
        # Reproduce a successful LAN scan where Nmap reports the router but not HA itself.
        xml = XML.replace("192.168.1.10", "192.168.1.1").replace("homeassistant.local", "router.home")
        selected = {**DEMO_NETWORK, "local_ips": ["192.168.1.10", "192.168.1.11"],
                    "mac": "12:34:56:78:9A:BC"}
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            manager = ScanManager(store, mdns=False)
            with patch("scanner.LOG"), patch("scanner.subprocess.Popen") as launch:
                launch.return_value.communicate.return_value = (xml, "")
                launch.return_value.returncode = 0
                manager.start(selected)
                manager.thread.join(timeout=2)
            self.assertIsNone(manager.state()["error"])
            snapshot = store.snapshot(selected["cidr"])
            self.assertEqual(snapshot["counts"]["occupied"], 3)
            self.assertEqual(snapshot["rows"][0]["name"], "router.home")
            for index in (9, 10):
                self.assertEqual(snapshot["rows"][index]["name"], "שרת Home Assistant")
                self.assertEqual(snapshot["rows"][index]["mac"], selected["mac"])
                self.assertEqual(snapshot["rows"][index]["source"], "Local interface")

    def test_local_addresses_outside_selected_subnet_are_not_added(self):
        xml = XML.replace("192.168.1.10", "192.168.1.1").replace("homeassistant.local", "router.home")
        selected = {**DEMO_NETWORK, "host_ip": "10.0.0.10", "local_ips": ["10.0.0.10"]}
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            manager = ScanManager(store, mdns=False)
            with patch("scanner.subprocess.Popen") as launch:
                launch.return_value.communicate.return_value = (xml, "")
                launch.return_value.returncode = 0
                manager.start(selected)
                manager.thread.join(timeout=2)
            self.assertIsNone(manager.state()["error"])
            snapshot = store.snapshot(selected["cidr"])
            self.assertEqual(snapshot["counts"]["occupied"], 1)
            self.assertEqual(snapshot["rows"][9]["status"], "unobserved")

    def test_empty_and_incomplete_scan_do_not_mark_addresses_free(self):
        for xml in (XML.replace('state="up"', 'state="down"'), XML.replace('total="256"', 'total="128"')):
            with self.subTest(xml=xml), tempfile.TemporaryDirectory() as directory:
                store = Store(directory)
                manager = ScanManager(store, mdns=False)
                with self.assertLogs("scanner", level="ERROR"), patch("scanner.subprocess.Popen") as launch:
                    process = launch.return_value
                    process.communicate.return_value = (xml, "")
                    process.returncode = 0
                    manager.start(DEMO_NETWORK)
                    manager.thread.join(timeout=2)
                self.assertTrue(manager.state()["error"])
                self.assertEqual(store.snapshot("192.168.1.0/24")["counts"]["unobserved"], 0)

    def test_cancellation_during_name_discovery_keeps_prior_results(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            store.commit("192.168.1.0/24", [host("192.168.1.11")], 2, [])
            before = store.snapshot("192.168.1.0/24")
            manager = ScanManager(store, mdns=True)
            reached_names = threading.Event()
            def wait_for_cancellation(*args):
                reached_names.set()
                manager.cancel.wait(2)
                return {}
            with patch("scanner.discover_mdns", side_effect=wait_for_cancellation), patch("scanner.subprocess.Popen") as launch:
                process = launch.return_value
                process.communicate.return_value = (XML, "")
                process.returncode = 0
                process.poll.return_value = 0
                manager.start(DEMO_NETWORK)
                self.assertTrue(reached_names.wait(2))
                manager.stop()
                manager.thread.join(timeout=2)
            self.assertEqual(before, store.snapshot("192.168.1.0/24"))
            self.assertEqual(manager.state()["phase"], "cancelled")


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.context = Context(self.temp.name, dict(DEFAULTS), demo=True)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.context))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def tearDown(self):
        self.context.scanner.stop()
        if self.context.scanner.thread:
            self.context.scanner.thread.join(timeout=2)
        self.server.shutdown()
        self.server.server_close()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        data = json.dumps(body) if body is not None else None
        connection.request(method, path, data, headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def post(self, path, body):
        return self.request("POST", path, body, {"Content-Type": "application/json", "X-IP-Scanner": "1"})

    def test_ingress_base_and_assets(self):
        code, headers, data = self.request("GET", "/", headers={"X-Ingress-Path": "/api/hassio_ingress/example"})
        self.assertEqual(code, 200)
        self.assertIn(b'<base href="/api/hassio_ingress/example/">', data)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("GET", "/app.js")[0], 200)
        self.assertEqual(self.request("GET", "/../../app.py")[0], 404)
        self.assertEqual(self.request("GET", "/", headers={"X-Ingress-Path": "//evil.test"})[0], 400)

    def test_production_does_not_trust_forwarded_for(self):
        self.context.demo = False
        self.assertEqual(self.request("GET", "/api/state", headers={"X-Forwarded-For": "172.30.32.2"})[0], 403)

    def test_alias_validation_and_csv_formula_protection(self):
        self.assertEqual(self.post("/api/alias", {"ip":"192.168.1.10","alias":"=HYPERLINK(1)"})[0], 200)
        code, _, data = self.request("GET", "/api/export.csv")
        self.assertEqual(code, 200)
        self.assertIn(b"'=HYPERLINK(1)", data)
        self.assertEqual(self.post("/api/alias", {"ip":"8.8.8.8","alias":"outside"})[0], 400)
        self.assertEqual(self.post("/api/alias", {"ip":"192.168.1.255","alias":"broadcast"})[0], 400)
        self.assertEqual(self.request("POST", "/api/alias", {})[0], 403)

    def test_scan_conflict_and_cancel(self):
        self.assertEqual(self.post("/api/scan", {})[0], 200)
        self.assertEqual(self.post("/api/scan", {})[0], 400)
        self.assertEqual(self.post("/api/network", {"cidr":"192.168.1.0/24"})[0], 400)
        self.assertEqual(self.post("/api/stop", {})[0], 200)
        self.context.scanner.thread.join(timeout=2)
        self.assertEqual(self.context.scanner.state()["phase"], "cancelled")


if __name__ == "__main__":
    unittest.main()
