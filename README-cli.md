# SelfishNet CLI (`selfishnet.py`)

A small, script-based reimplementation of SelfishNet v3's core function for
Windows: discover LAN devices, ARP-spoof selected targets to become
man-in-the-middle, and **rate-limit or block their traffic per device**.

> **Authorized use only.** Run this against your own LAN or a network you are
> explicitly permitted to test. ARP spoofing is disruptive by design.

## How it works

| Stage | Tool | Role |
|-------|------|------|
| Discover devices | Scapy + Npcap | ARP scan the subnet |
| Become MITM | Scapy | ARP-spoof each target ⟷ gateway |
| Keep victims online | Windows IP forwarding | kernel routes their traffic at line rate |
| Rate limit / block | WinDivert (`pydivert`) | per-device token bucket on forwarded packets |

The WinDivert loop runs at the **network-forward layer**: traffic *to* a target
is "download", *from* a target is "upload". Each direction has a token bucket —
packets forward while under budget and drop when over. `--block` is just a
budget of zero.

## Prerequisites (on the Windows host)

1. **[Npcap](https://npcap.com/)** installed — check "WinPcap API-compatible mode"
   during install. (This replaces the unsigned, ancient WinPcap 4.1.3 the C#
   build used.)
2. Python 3.8+ and the packages: `pip install -r requirements.txt`
   (`pydivert` bundles the WinDivert `.dll`/`.sys`).
3. Run from an **elevated** (Administrator) terminal — both drivers require it.
4. If Windows Defender/AV quarantines the WinDivert driver, add an exclusion.

## Usage

```powershell
# List devices and exit
python selfishnet.py --scan

# Cap one device to 500 kbps down / 200 kbps up until Ctrl-C
python selfishnet.py --limit 192.168.1.42:500:200

# Download-only cap (upload unlimited), block another device, run 10 minutes
python selfishnet.py --limit 192.168.1.42:500: --block 192.168.1.77 --duration 600
```

### `--limit IP:DOWN:UP`
Rates are in **kbps** (kilobits/sec). Per field:
- a number `> 0` → cap that direction
- `0` → block that direction
- empty → unlimited (e.g. `192.168.1.42:500:` = cap download, leave upload alone)

Repeat `--limit` / `--block` for multiple devices. On exit (Ctrl-C or
`--duration`) the tool heals the ARP caches and disables the forwarding it
enabled.

### Config file (multiple devices)
Keep a device list in a file so you don't retype `--limit` flags. If a
`devices.txt` exists in the current folder (or next to the script), it's loaded
**automatically** — no flag needed:

```powershell
copy devices.example.txt devices.txt   # make your list once, edit in Notepad
python selfishnet.py                    # auto-loads devices.txt and runs
```

Or point at a specific file with `--config`:
```powershell
python selfishnet.py --config guests.txt
```

One device per line — `IP DOWN UP` in kbps (see `devices.example.txt`):
```
# ip            down   up      (number=cap, 0=block dir, - or blank=unlimited)
192.168.1.42    500    200
192.168.1.50    1000   -       # download capped, upload unlimited
192.168.1.77    block          # blocked entirely
```
Fields may be separated by spaces, commas, or colons; `#` starts a comment.
Any `--limit`/`--block` flags given on the command line override file entries
for the same IP.

### Other flags
- `--config FILE` / `-c` — read targets from a device list file
- `--range CIDR` — scan range (default: local `/24`)
- `--iface "Wi-Fi"` — interface friendly name (used for `netsh` forwarding)
- `--gateway IP` — override gateway auto-detection
- `--no-forward` — don't touch Windows IP forwarding (manage it yourself)
- `-v` — live forwarded/dropped counters

## Known limitations

- **IP forwarding enablement is the fragile part on Windows.** The tool uses
  `netsh interface ipv4 set interface "<iface>" forwarding=enabled`, which is
  immediate per-interface. On some setups you may additionally need
  `IPEnableRouter=1` under
  `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` and a reboot, or the
  Routing and Remote Access service. If capped devices lose internet entirely
  (instead of being throttled), forwarding isn't taking effect.
- Subnet discovery assumes a `/24`; use `--range` for anything else.
- Rate accounting is on the IP packet size at the forward layer (close to, not
  identical to, on-wire bytes).
