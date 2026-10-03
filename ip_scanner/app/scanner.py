"""ARP host discovery via nmap; mDNS supplements hostnames and live evidence."""
import ipaddress
import logging
import queue
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

LOG = logging.getLogger(__name__)
SERVICE_TYPES = ["_http._tcp.local.", "_https._tcp.local.", "_workstation._tcp.local.",
                 "_home-assistant._tcp.local.", "_esphomelib._tcp.local.", "_hap._tcp.local.",
                 "_googlecast._tcp.local.", "_airplay._tcp.local.", "_raop._tcp.local.",
                 "_ipp._tcp.local.", "_smb._tcp.local.", "_ssh._tcp.local."]


def parse_nmap(xml, cidr):
    root = ET.fromstring(xml)
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise RuntimeError("הסריקה לא הסתיימה בהצלחה; נשמרו התוצאות הקודמות")
    network = ipaddress.ip_network(cidr)
    totals = root.find("runstats/hosts")
    if totals is None or int(totals.get("total", "0")) != network.num_addresses:
        raise RuntimeError("הסריקה לא כיסתה את כל הטווח; התוצאות הקודמות נשמרו")
    hosts = []
    for element in root.findall("host"):
        status = element.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = {a.get("addrtype"): a for a in element.findall("address")}
        address = addresses.get("ipv4")
        if address is None:
            continue
        ip = ipaddress.ip_address(address.get("addr"))
        if ip not in network or ip in (network.network_address, network.broadcast_address):
            continue
        mac = addresses.get("mac")
        hostname = element.find("hostnames/hostname")
        hosts.append({"ip": str(ip), "hostname": hostname.get("name", "") if hostname is not None else "",
                      "mac": mac.get("addr", "") if mac is not None else "",
                      "vendor": mac.get("vendor", "") if mac is not None else "",
                      "source": "ARP"})
    return hosts


def discover_mdns(host_ip, cidr, cancel, seconds=4):
    from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf
    pending = queue.Queue()
    class Listener(ServiceListener):
        def add_service(self, zc, service_type, name):
            pending.put((service_type, name))
        def update_service(self, zc, service_type, name):
            pending.put((service_type, name))
        def remove_service(self, zc, service_type, name):
            pass
    network = ipaddress.ip_network(cidr)
    results, seen = {}, set()
    zc = Zeroconf(interfaces=[host_ip], ip_version=IPVersion.V4Only)
    browser = None
    try:
        browser = ServiceBrowser(zc, SERVICE_TYPES, listener=Listener())
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not cancel.is_set():
            try:
                item = pending.get(timeout=0.15)
            except queue.Empty:
                continue
            if item in seen:
                continue
            seen.add(item)
            info = zc.get_service_info(*item, timeout=250)
            if info:
                for address in info.parsed_addresses(IPVersion.V4Only):
                    ip = ipaddress.ip_address(address)
                    if ip in network and ip not in (network.network_address, network.broadcast_address):
                        results[address] = (info.server or item[1]).rstrip(".")
    finally:
        if browser is not None:
            browser.cancel()
        zc.close()
    return results


class ScanManager:
    def __init__(self, store, timeout=180, mdns=True):
        self.store, self.timeout, self.mdns = store, timeout, mdns
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.process = None
        self.thread = None
        self.status = {"running": False, "phase": "idle", "error": None}

    def state(self):
        with self.lock:
            return dict(self.status)

    def start(self, selected):
        with self.lock:
            if self.status["running"]:
                raise ValueError("סריקה כבר מתבצעת. המתן לסיום או עצור אותה")
            self.cancel.clear()
            self.status = {"running": True, "phase": "discovery", "error": None,
                           "cidr": selected["cidr"], "started_at": time.time()}
            self.thread = threading.Thread(target=self._run, args=(dict(selected),), daemon=True)
            self.thread.start()

    def stop(self):
        with self.lock:
            self.cancel.set()
            if self.process and self.process.poll() is None:
                self.process.terminate()

    def _phase(self, phase):
        with self.lock:
            self.status["phase"] = phase

    def _run(self, selected):
        started, warnings = time.monotonic(), []
        process = None
        try:
            LOG.info("Scanning %s on %s; local address=%s", selected["cidr"],
                     selected["interface"], selected["host_ip"])
            # No shell, no user-controlled flags, no port scan. Force ARP on an attached interface.
            command = ["nmap", "-sn", "-PR", "-e", selected["interface"], "--max-retries", "2",
                       "--host-timeout", "20s", "-oX", "-", selected["cidr"]]
            with self.lock:
                if self.cancel.is_set():
                    return
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True, encoding="utf-8", errors="replace")
                self.process = process
            stdout, stderr = process.communicate(timeout=self.timeout)
            if self.cancel.is_set():
                return
            if process.returncode:
                LOG.warning("Nmap error: %s", stderr.strip()[:500])
                raise RuntimeError("הסריקה נכשלה. בדוק הרשאת NET_RAW וחיבור לרשת ביומן התוסף")
            hosts = parse_nmap(stdout, selected["cidr"])
            if not hosts:
                raise RuntimeError("לא התקבלה אף תגובה. התוצאות הקודמות נשמרו; לא סומנו כתובות כפנויות")
            arp_count = len(hosts)
            # An assigned local address is in use even when the host cannot ARP itself.
            # Add it only after a complete, nonempty scan so it cannot mask scan failures.
            network = ipaddress.ip_network(selected["cidr"])
            by_ip = {host["ip"]: host for host in hosts}
            local_ips = [selected["host_ip"], *selected.get("local_ips", [])]
            for value in dict.fromkeys(local_ips):
                ip = ipaddress.ip_address(value)
                if ip not in network or ip in (network.network_address, network.broadcast_address):
                    continue
                value = str(ip)
                if value not in by_ip:
                    by_ip[value] = {"ip": value, "hostname": "", "mac": selected.get("mac", ""),
                                   "vendor": "", "source": "Local interface"}
                by_ip[value]["role"] = "local_host"
            hosts = list(by_ip.values())
            if self.mdns:
                self._phase("names")
                try:
                    names = discover_mdns(selected["host_ip"], selected["cidr"], self.cancel)
                    by_ip = {host["ip"]: host for host in hosts}
                    for ip, name in names.items():
                        if ip not in by_ip:
                            by_ip[ip] = {"ip": ip, "mac": "", "vendor": "", "source": "mDNS"}
                        by_ip[ip].update(hostname=name, source=by_ip[ip]["source"] + "/mDNS"
                                          if by_ip[ip]["source"] != "mDNS" else "mDNS")
                    hosts = list(by_ip.values())
                except Exception as exc:
                    LOG.warning("mDNS unavailable: %s", exc)
                    warnings.append("זיהוי mDNS אינו זמין כרגע; תוצאות ARP ו־DNS מוצגות")
            with self.lock:
                if self.cancel.is_set():
                    return
                self.store.commit(selected["cidr"], hosts, time.monotonic() - started, warnings)
            LOG.info("Scan complete: %s; %s discovered hosts, %s occupied addresses; %.1fs",
                     selected["cidr"], arp_count, len(hosts), time.monotonic() - started)
        except subprocess.TimeoutExpired:
            if process:
                process.kill()
                process.communicate()
            with self.lock:
                self.status["error"] = "זמן הסריקה הסתיים; התוצאות הקודמות נשמרו"
        except Exception as exc:
            LOG.exception("Scan failed")
            with self.lock:
                self.status["error"] = str(exc)
        finally:
            with self.lock:
                if self.cancel.is_set():
                    self.status["error"] = None
                self.process = None
                self.status.update(running=False, phase="cancelled" if self.cancel.is_set() else "idle")
