#!/usr/bin/env python3
"""
ad600_discovery.py — portable, nothing-hardcoded discovery for the AD600 spectrum scanner.

Responsibilities
----------------
  • list_interfaces()          -> [{name, mac, ipv4}]  for every NIC (stdlib-first; netifaces if present).
  • derive_our_cid(mac)        -> our controller CID hex, DERIVED from the selected NIC MAC.
  • discover(iface, timeout)   -> {device_cid, device_ip, device_port, model, name, iface} | None
                                  by joining the ACN/SLP multicast group and parsing the AD600's
                                  SLPv2 AttrRply component advert (RFC2608). UDP-2201 beacon fallback.
  • probe_all()                -> quick discover() on each interface; flags which see an AD600.

The AD600 advertises itself, WWB-style, as an SLPv2 AttrRply (function 0x07) multicast to
239.255.254.253:8427 whose attribute list contains, e.g.:
    (cid=DDAC0650-0000-11DD-A000-000EDDCCCCCC),(acn-fctn=AD600),(acn-uacn=...),
    (csl-esta.dmp=esta.sdt/192.168.5.101:57383;esta.dmp/cd:...),(device-description=...)
We PULL device_cid / device_ip / device_port / model straight from that advert — nothing hardcoded.

Stdlib only. Runs as a CLI too:   python3 ad600_discovery.py [--iface en10] [--timeout 6] [--all]
"""
import os, re, sys, socket, struct, subprocess, time

SLP_GROUP = "239.255.254.253"
SLP_PORT  = 8427
BEACON_PORT = 2201            # UDP device presence beacon (…→ x.x.x.255:2201)
DEFAULT_DEV_PORT = 57383

# our_cid = <last 4 bytes of NIC MAC as hex> + this fixed ESTA/Shure suffix (CONFIRMED derivation)
CID_SUFFIX = "000011dda000000eddcccccc"


# ─────────────────────────────────────────────────────────────────────────────────────────────
# CID derivation
# ─────────────────────────────────────────────────────────────────────────────────────────────
def derive_our_cid(mac):
    """our_cid_hex from a NIC MAC. en10 34:99:71:ea:53:37 -> '71ea5337'+suffix (known-good CID)."""
    hexonly = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if len(hexonly) < 12:
        raise ValueError("MAC too short to derive CID: %r" % (mac,))
    last4 = hexonly[-8:]                      # last 4 bytes = 8 hex chars
    return last4 + CID_SUFFIX


# ─────────────────────────────────────────────────────────────────────────────────────────────
# Interface enumeration (stdlib-first; netifaces optional)
# ─────────────────────────────────────────────────────────────────────────────────────────────
def list_interfaces():
    """Return [{name, mac, ipv4}] for the machine's NICs. Only IPv4-capable, non-loopback NICs
    with a MAC (so a CID can be derived) are returned. netifaces used if importable, else ifconfig."""
    try:
        import netifaces  # type: ignore
        return _list_interfaces_netifaces(netifaces)
    except Exception:
        return _list_interfaces_ifconfig()


def _list_interfaces_netifaces(netifaces):
    out = []
    for name in netifaces.interfaces():
        if name == "lo0":
            continue
        addrs = netifaces.ifaddresses(name)
        mac = (addrs.get(netifaces.AF_LINK, [{}])[0] or {}).get("addr", "")
        ip4 = (addrs.get(netifaces.AF_INET, [{}])[0] or {}).get("addr", "")
        if mac:
            out.append({"name": name, "mac": mac, "ipv4": ip4 or ""})
    return out


def _list_interfaces_ifconfig():
    """Parse `ifconfig` output (macOS/BSD). Falls back gracefully on Linux `ip`-style hosts."""
    try:
        txt = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return _list_interfaces_socket_only()
    out, cur = [], None
    for line in txt.splitlines():
        if line and not line[0].isspace():
            name = line.split(":", 1)[0].strip()
            if name == "lo0":
                cur = None
                continue
            cur = {"name": name, "mac": "", "ipv4": ""}
            out.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r"ether\s+([0-9a-fA-F:]{17})", s)
        if m:
            cur["mac"] = m.group(1)
            continue
        m = re.match(r"inet\s+(\d+\.\d+\.\d+\.\d+)", s)
        if m and not cur["ipv4"]:
            cur["ipv4"] = m.group(1)
    # keep only NICs with a MAC (needed for CID derivation)
    return [d for d in out if d["mac"]]


def _list_interfaces_socket_only():
    """Last-resort: at least report the primary interface's IP (no MAC/name detail)."""
    ip = _primary_ipv4()
    return [{"name": "default", "mac": "", "ipv4": ip}] if ip else []


def _primary_ipv4():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 1))          # RFC5737 TEST-NET; no packet sent, just picks egress src
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def iface_by_name(name):
    for d in list_interfaces():
        if d["name"] == name:
            return d
    return None


# ─────────────────────────────────────────────────────────────────────────────────────────────
# SLPv2 AttrRply parsing (RFC2608 §10)
# ─────────────────────────────────────────────────────────────────────────────────────────────
def parse_slp_attrreply(data):
    """Parse an SLPv2 AttrRply (function 0x07) datagram -> {attr_key: value_str} or None.
    Header: ver(1) fn(1) len(3) flags(2) nextext(3) xid(2) langtaglen(2) langtag(n)
    Body(AttrRply): errcode(2) attrlistlen(2) attrlist(n) [attr-auth-count(1) ...].
    The attrlist is RFC2608 comma-separated `(key=value)` / `(key=v1,v2)` / bare `key` items."""
    try:
        if len(data) < 16 or data[0] != 0x02:
            return None
        fn = data[1]
        if fn != 0x07:                        # only AttrRply carries the attribute list
            return None
        # ver1 fn1 len3 flags2 nextext3 xid2 langtaglen2
        langtaglen = struct.unpack(">H", data[12:14])[0]
        p = 14 + langtaglen
        if p + 4 > len(data):
            return None
        # errcode(2), attrlistlen(2)
        errcode = struct.unpack(">H", data[p:p + 2])[0]
        attrlen = struct.unpack(">H", data[p + 2:p + 4])[0]
        p += 4
        attrlist = data[p:p + attrlen].decode("utf-8", "replace")
        if errcode != 0:
            return None
        return _parse_attrlist(attrlist)
    except Exception:
        return None


def _parse_attrlist(s):
    """`(cid=..),(acn-fctn=AD600),(csl-esta.dmp=esta.sdt/ip:port;..)` -> dict. Bare tags -> value ''."""
    attrs = {}
    for m in re.finditer(r"\(([^()=]+)=([^()]*)\)", s):
        attrs[m.group(1).strip().lower()] = m.group(2).strip()
    # bare (no '=') tags such as (service:...) — record presence
    for m in re.finditer(r"\(([^()=]+)\)", s):
        k = m.group(1).strip().lower()
        if k not in attrs and "=" not in k:
            attrs.setdefault(k, "")
    return attrs


def attrs_to_device(attrs, iface):
    """Turn a parsed AD600 attribute dict into the discovery record, or None if it isn't an AD600."""
    if not attrs:
        return None
    fctn = attrs.get("acn-fctn", "")
    cid = attrs.get("cid", "")
    csl = attrs.get("csl-esta.dmp", "")
    # esta.sdt/<ip>:<port>;esta.dmp/cd:<uuid>
    ip, port = None, DEFAULT_DEV_PORT
    m = re.search(r"esta\.sdt/(\d+\.\d+\.\d+\.\d+):(\d+)", csl)
    if m:
        ip, port = m.group(1), int(m.group(2))
    # Accept only device adverts: an AD600 function tag, OR any non-WWB component exposing an sdt url.
    is_ad600 = ("AD600" in fctn) or (bool(ip) and "WWB" not in fctn.upper())
    if not is_ad600 or not cid:
        return None
    return {
        "device_cid": _cid_to_hex(cid),
        "device_cid_str": cid.upper(),
        "device_ip": ip,
        "device_port": port,
        "model": fctn or "AD600",
        "name": attrs.get("acn-uacn", fctn or "AD600"),
        "iface": iface,
    }


def _cid_to_hex(cidstr):
    """'DDAC0650-0000-11DD-A000-000EDDCCCCCC' -> 'ddac0650000011dda000000eddcccccc'."""
    return re.sub(r"[^0-9a-fA-F]", "", cidstr or "").lower()


# ─────────────────────────────────────────────────────────────────────────────────────────────
# Active SLP solicitation (RFC2608 §8.1 Service Request) — nudges the device to advertise now
# ─────────────────────────────────────────────────────────────────────────────────────────────
def _build_srvrqst(xid=0x1234, srvtype="service:esta.sdt"):
    """Minimal SLPv2 SrvRqst (function 1) multicast to prompt the SA to reply promptly. Best-effort:
    the AD600 also multicasts its advert periodically, so passive capture works without this."""
    langtag = b"en"
    body = (b"\x00\x00"                                   # <PRList> length 0
            + struct.pack(">H", len(srvtype)) + srvtype.encode()
            + b"\x00\x00"                                 # <scope-list> length 0 (default scope)
            + b"\x00\x00"                                 # <predicate> length 0
            + b"\x00\x00")                                # <SLP SPI> length 0
    flags = b"\x20\x00"                                   # O flag? use MCAST flag 0x2000 per RFC (bit set)
    hdr = (b"\x02\x01"                                    # ver=2, fn=1 (SrvRqst)
           + b"\x00\x00\x00"                              # length placeholder (filled below)
           + flags
           + b"\x00\x00\x00"                              # next ext offset
           + struct.pack(">H", xid)
           + struct.pack(">H", len(langtag)) + langtag)
    pkt = hdr + body
    pkt = pkt[:2] + struct.pack(">I", len(pkt))[1:] + pkt[5:]   # patch 3-byte length
    return pkt


# ─────────────────────────────────────────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────────────────────────────────────────
def _matches_model(rec, model_filter):
    """True if the device record matches `model_filter` (case-insensitive substring of its
    model/acn-fctn or advertised name). Empty/None filter matches anything."""
    if not model_filter:
        return True
    mf = str(model_filter).upper()
    hay = ((rec.get("model") or "") + " " + (rec.get("name") or "")).upper()
    return mf in hay


def _open_group_socket(iface, active=True):
    """Join the SLP multicast group on `iface`; return (sock, mreq, ifname, src_ip).
    `iface` may be an interface record dict OR the interface NAME string. Sends the SLP
    solicitation if `active`. Caller must call _close_group_socket(sock, mreq)."""
    ifd = iface_by_name(iface) if isinstance(iface, str) else iface
    src_ip = (ifd or {}).get("ipv4") or _primary_ipv4()
    ifname = (ifd or {}).get("name") if ifd else (iface if isinstance(iface, str) else None)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass
    try:
        sock.bind(("", SLP_PORT))
    except Exception:
        sock.bind(("", 0))                                # fall back: still can recv unicast replies
    # join the multicast group on the chosen interface
    mreq = None
    try:
        if src_ip:
            mreq = socket.inet_aton(SLP_GROUP) + socket.inet_aton(src_ip)
        else:
            mreq = struct.pack("4sL", socket.inet_aton(SLP_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except Exception as e:
        sys.stderr.write("[discovery] group-join warn on %s: %r\n" % (ifname, e))
    # egress the chosen interface for our solicitation
    if active:
        try:
            if src_ip:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src_ip))
            if ifname:
                sock.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(ifname))  # IP_BOUND_IF
        except Exception:
            pass
        for st in ("service:esta.sdt", "service:acn.esta"):
            try:
                sock.sendto(_build_srvrqst(srvtype=st), (SLP_GROUP, SLP_PORT))
            except Exception:
                pass
    return sock, mreq, ifname, src_ip


def _close_group_socket(sock, mreq):
    try:
        if mreq is not None:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def _collect_adverts(iface, timeout, our_cid, active, model_filter, stop_on_match):
    """Listen on the SLP group for up to `timeout` s. Returns (match_rec | None, distinct_list).
      • distinct_list — every distinct Shure device advert seen (deduped by device_cid/ip), in
        first-seen order.
      • match_rec — the FIRST advert whose model matches `model_filter`; if `stop_on_match` we
        return as soon as that match is found, otherwise we keep collecting for the full timeout
        (so an AD4Q advertising before the AD600 never shadows it)."""
    sock, mreq, ifname, src_ip = _open_group_socket(iface, active=active)
    sock.settimeout(0.5)
    deadline = time.time() + float(timeout)
    match = None
    seen = {}                                             # key -> device record (dedup, ordered)
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            break
        attrs = parse_slp_attrreply(data)
        cand = attrs_to_device(attrs, ifname or (iface if isinstance(iface, str) else None))
        if not cand:
            continue
        if our_cid and cand["device_cid"] == _cid_to_hex(our_cid):
            continue                                      # skip our own advert
        if not cand.get("device_ip"):
            cand["device_ip"] = addr[0]                   # last-resort: source IP of the advert
        key = cand.get("device_cid") or cand.get("device_ip")
        if key not in seen:
            seen[key] = cand
        if match is None and _matches_model(cand, model_filter):
            match = cand
            if stop_on_match:
                break
    _close_group_socket(sock, mreq)
    return match, list(seen.values())


def discover(iface, timeout=6, our_cid=None, active=True, model_filter="AD600"):
    """Join the SLP multicast group ON `iface` and return the advert whose model/acn-fctn matches
    `model_filter` (default 'AD600'), IGNORING other Shure devices on the wire (e.g. an AD4Q_RX).
    Listens for up to `timeout` s and does NOT return on the first packet, so the AD600 is found
    even when the AD4Q advertises first. Returns the device record or None. `our_cid` (hex) filters
    out our own advert if present. `iface` may be an interface record dict OR the interface name."""
    match, _all = _collect_adverts(iface, timeout, our_cid, active, model_filter, stop_on_match=True)
    if match is not None:
        return match
    # fallback presence probe: UDP-2201 beacon (device -> broadcast). Presence only.
    ifd = iface_by_name(iface) if isinstance(iface, str) else iface
    src_ip = (ifd or {}).get("ipv4") or _primary_ipv4()
    ifname = (ifd or {}).get("name") if ifd else (iface if isinstance(iface, str) else None)
    bc = _beacon_probe(src_ip, timeout=min(2.0, timeout))
    if bc:
        return {"device_cid": None, "device_ip": bc, "device_port": DEFAULT_DEV_PORT,
                "model": "AD600?", "name": "AD600 (beacon)", "iface": ifname or iface,
                "beacon_only": True}
    return None


def discover_all(iface, timeout=6, our_cid=None, active=True):
    """Return ALL distinct Shure devices seen on `iface` within `timeout` s (list of device dicts,
    same shape as discover()). No model filter — AD600, AD4Q_RX, etc. are all returned — so the
    menubar can offer a device picker when more than one device is present. `iface` may be an
    interface record dict OR the interface name string."""
    _match, found = _collect_adverts(iface, timeout, our_cid, active,
                                     model_filter=None, stop_on_match=False)
    return found


def _beacon_probe(src_ip, timeout=2.0):
    """Listen briefly for the device's UDP-2201 presence beacon. Returns sender IP or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except Exception:
        pass
    try:
        s.bind(("", BEACON_PORT))
    except Exception:
        s.close()
        return None
    s.settimeout(0.5)
    deadline = time.time() + timeout
    found = None
    while time.time() < deadline:
        try:
            _data, addr = s.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception:
            break
        if addr[0] and addr[0] != src_ip:
            found = addr[0]
            break
    s.close()
    return found


def probe_all(timeout=3):
    """Quick discover() on each interface. Returns [{iface, mac, ipv4, our_cid, device|None}]."""
    results = []
    for ifd in list_interfaces():
        our_cid = None
        try:
            our_cid = derive_our_cid(ifd["mac"])
        except Exception:
            pass
        dev = None
        if ifd.get("ipv4"):
            try:
                dev = discover(ifd, timeout=timeout, our_cid=our_cid)
            except Exception as e:
                sys.stderr.write("[discovery] probe %s failed: %r\n" % (ifd["name"], e))
        results.append({"iface": ifd["name"], "mac": ifd["mac"], "ipv4": ifd.get("ipv4", ""),
                        "our_cid": our_cid, "device": dev})
    return results


# ─────────────────────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────────────────────
def _main(argv):
    import json
    iface = None
    timeout = 6
    do_all = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--iface", "-i"):
            iface = argv[i + 1]; i += 2; continue
        if a in ("--timeout", "-t"):
            timeout = float(argv[i + 1]); i += 2; continue
        if a == "--all":
            do_all = True; i += 1; continue
        i += 1
    print("interfaces:")
    for d in list_interfaces():
        cid = ""
        try:
            cid = derive_our_cid(d["mac"])
        except Exception:
            cid = "(no-mac)"
        print("  %-8s mac=%-17s ipv4=%-15s our_cid=%s" % (d["name"], d["mac"], d["ipv4"] or "-", cid))
    if do_all:
        print("\nprobe_all (this TALKS to the network):")
        print(json.dumps(probe_all(timeout=timeout), indent=2))
    elif iface:
        print("\ndiscover(%s):" % iface)
        d = iface_by_name(iface)
        cid = derive_our_cid(d["mac"]) if d and d["mac"] else None
        print(json.dumps(discover(iface, timeout=timeout, our_cid=cid), indent=2))


if __name__ == "__main__":
    _main(sys.argv[1:])
