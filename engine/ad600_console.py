#!/usr/bin/env python3
"""
ad600_console.py — an INTERACTIVE DEVICE CONSOLE for the operator's OWN Shure AD600
(ANSI E1.17 / ACN SDT+DMP, UDP 57383).  Authorized personal-use interop tooling.

WHY THIS FILE EXISTS
--------------------
Every hypothesis test so far has meant "launch a 40 s client, wait, read the log, tweak,
relaunch."  That loop is too slow to probe reply-tempo / full-subscribe-set behaviour.
This console instead holds ONE live SDT session open indefinitely and lets the operator fire
individual DMP commands at the device via a control file while watching decoded replies — and
crucially the device's live reliable-seq — stream to a log in real time.

It is NOT autonomous: it sends NOTHING on its own except the mandatory SDT keepalives/ACKs.
It only transmits DMP when a line appears in the control file.

DESIGN — SELF-CONTAINED
------------------------
The session machinery (SLP advert, SDT JOIN, proto-0x102 DECL09/ASSOC0a association, session-key
derivation, eager cumulative ACK of the device frontier, keepalives, continuous-CTR tx/rx
tracking, NAK retransmit, clean teardown) is self-contained in _SessionBase:
  • Command source: polled control file or embedded INIT_COMMANDS sequence.
  • Output: full decode of every reply + the device reliable-seq on every inbound wrapper,
    tee'd to a flushed log file.

RUN:
    python3 ad600_console.py [run_for_secs] [cmd_file] [log_file]
Env overrides: AD600_CONSOLE_SECS, AD600_CONSOLE_CMD, AD600_CONSOLE_LOG, AD600_CONSOLE_DIR,
               AD600_NO_SLP=1 (skip the SLP advert prologue).
Verify:  python3 -m py_compile ad600_console.py
Stdlib only (+ ad600_native in the same directory).
"""
import os, sys, time, base64, signal, struct as _struct

# AD600_EMIT_FRAMES=1: additionally emit one machine-parseable "FRAME ..." line per decoded
# RF_SCAN_DATA event so a supervising process (the application bridge) can consume the
# firehose off this console's stdout without re-implementing the ownership recipe. Entirely
# gated by the env flag; when unset the console behaves byte-for-byte as before.
_EMIT_FRAMES = os.environ.get("AD600_EMIT_FRAMES") == "1"

# ── Embedded session foundation & DMP primitives ──
import socket, struct, zlib
from ad600_native import (
    sk_util, aes_ctr_at, aes_ctr, skip32, find_ctr_pos, _valid_dmp_head,
    dmp_pdu, dmp_parse, parse_rf_scan_data, parse_wrapper, rewrite_scan_idx, rewrite_rt_compression,
    rewrite_scan_range, rewrite_scan_step_rbw, rewrite_curve_select, rewrite_repeat_request,
    pdu_decode, pdu_encode, root_wrap, root_parse,
    build_join, build_join_accept, build_wrapper, client_block,
    mgmt_ack, mgmt_proto,
    DMP_GET, DMP_SET, DMP_SUBSCRIBE, SDT_VEC,
)

# ── Identity & networking defaults (overridable by environment) ──
WWB_CID  = bytes.fromhex(os.environ.get("WWB_CID",  "71ea5337000011dda000000eddcccccc"))
DEV_CID  = bytes.fromhex(os.environ.get("WWB_DEVCID","ddac0650000011dda000000eddcccccc"))
DEV_IP   = os.environ.get("WWB_DEVIP",  "192.168.5.101")
DEV_PORT = int(os.environ.get("WWB_DEVPORT", "57383"))
MY_IP    = os.environ.get("WWB_MYIP",   "192.168.5.68")
SRC_PORT = int(os.environ.get("WWB_SRCPORT", "64198"))
SLP_GRP  = ("239.255.254.253", 8427)

os.environ["WWB_SEQBASE_FORCED"] = "chan"
os.environ["AD600_SEQBASE"] = "chan"

def _dmp_first_addr(blob):
    if not blob: return None
    off = 3 if (blob[0] & 0xF0) == 0xF0 else 2
    if len(blob) < off + 6: return None
    return int.from_bytes(blob[off + 2:off + 6], "big")

def _is_write(blob):
    if not blob: return False
    off = 3 if (blob[0] & 0xF0) == 0xF0 else 2
    return len(blob) > off and blob[off] == 2

# Embedded hardware scan engine initialization commands (49 command wrappers)
INIT_COMMANDS = (
    "7008070201400303",
    "7008070201400360",
    "700807020100001210060100002310060100002410060100002510060100002610060100002810060100002b100601010101100601010102100601010103",
    "7008070201010104100601010105100601010106100601010107100601070137100601070220100601070221100601070404100601070480100601070481",
    "7008070201070482100601070483100601070484100601070485100601070470100601070471100601070472100601070473100601070474100601070475",
    "70080702010704c01006010704c11006010704c21006010704c31006010704c41006010704c5100601070440100601070441100601070442100601070443",
    "70080702010704441006010704451006010704d01006010704d11006010704d21006010704d31006010704d41006010704d51006010704f41006010c0010",
    "70080702010900501006014001121006014003401006010f0100100601080003100601010046302c0700294e4554574f524b5f4554483a5354415449435f444e535f5345525645522f444e535f4944583d30102b00294e4554574f524b5f4554483a5354415449435f444e535f5345525645522f444e535f4944583d31102c002a4e4554574f524b5f4554483a43555252454e545f444e535f5345525645522f444e535f4944583d30102c002a4e4554574f524b5f4554483a43555252454e545f444e535f5345525645522f444e535f4944583d31",
    "7008010201400303100601400402100601400404100601400403100601400401100601400400100601400405100601400407100601400406",
    "7008010201400360",
    "7008010201030002100601000012100601000000100601000004100601000023100601000024100601000025100601000026100601000028100601000002",
    "700801020100005010060100002b1006010000b0100601000005100601010100100601010101100601010102100601010103100601010104100601010105",
    "7008010201010106100601010107100601070213100601070137100601070201100601070220100601070221100601070404100601070420100601070421",
    "7008010201070422100601070423100601070424100601070425100601070426100601070430100601070431100601070432100601070433100601070434",
    "7008010201070435100601070436100601070480100601070481100601070482100601070483100601070484100601070485100601070470100601070471",
    "70080102010704721006010704731006010704741006010704751006010704c01006010704c11006010704c21006010704c31006010704c41006010704c5",
    "70080102010704401006010704411006010704421006010704431006010704441006010704451006010704d01006010704d11006010704d21006010704d3",
    "70080102010704d41006010704d51006010704f41006010c001010060107021210060109005010060107040010060140011210060140034010060100007b",
    "700801020100007a10060100007c1006010f0100100601080003100601010046302c0700294e4554574f524b5f4554483a5354415449435f444e535f5345525645522f444e535f4944583d30102b00294e4554574f524b5f4554483a5354415449435f444e535f5345525645522f444e535f4944583d31102c002a4e4554574f524b5f4554483a43555252454e545f444e535f5345525645522f444e535f4944583d30102c002a4e4554574f524b5f4554483a43555252454e545f444e535f5345525645522f444e535f4944583d31",
    "7008010201201106100601201103100601201102100601201003",
    "7008070201090221100601090224100601090202100601090203100601090206100601090207100601090204100601090205100601090212100601090210",
    "700807020130101910060100002c100601090222100601090223100601090220",
    "7008010201301019",
    "7008070201201007100601201103100601201102",
    "7008010201201103100601201102",
    "7008010201201106100601201103100601201102100601201003",
    "7008010201301019",
    "7008070201090201",
    "70080102010704f0",
    "70080102010704f1",
    "7008010201070240",
    "7008010201070241",
    "7008010201070242",
    "7008010201070243",
    "7008010201070244",
    "7008010201070245",
    "7008010201070246",
    "700801020107010f",
    "7008010201070210100601070200100601070201100601070202",
    "70290707002552465f5343414e3a43555252454e545f53574545505f5354415455532f5343414e3d301023002152465f5343414e3a43555252454e545f53574545505f49442f5343414e3d301021001f52465f5343414e3a43555252454e545f5354415455532f5343414e3d30",
    "70280207002052465f5343414e3a5343414e5f53544152545f465245512f5343414e3d3000072bf01025001f52465f5343414e3a5343414e5f53544f505f465245512f5343414e3d30000f42401025001f52465f5343414e3a5343414e5f535445505f465245512f5343414e3d30000000191029002352465f5343414e3a5343414e5f5245534f4c5554494f4e5f42572f5343414e3d30000000191027002452465f5343414e3a5343414e5f5245504541545f524551554553542f5343414e3d30ff1023001d52465f5343414e3a43555256455f53454c4543542f5343414e3d300000007e1024002052465f5343414e3a5343414e5f53574545505f524154452f5343414e3d30003c102c002652465f5343414e3a5245414c5f54494d455f434f4d5052455353494f4e2f5343414e3d3000000024",
    "70400707003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d312f465245515f4944583d31313834302d3333303430103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d322f465245515f4944583d31313834302d3333303430103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d332f465245515f4944583d31313834302d3333303430103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d342f465245515f4944583d31313834302d3333303430103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d352f465245515f4944583d31313834302d3333303430103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d362f465245515f4944583d31313834302d3333303430",
    "700902020107010300",
    "700807020109002b",
    "700902020109002a017005010000",
    "7009020201010201017005010000",
    "700902020109002a027005010000",
    "700808020109002b7005010000",
    "7009020201010201007005010000",
)


class _SessionBase:
    """Core ANSI E1.17 ACN SDT & DMP protocol session controller."""

    def __init__(self, run_for=45.0):
        self.run_for = run_for
        self.cid = WWB_CID
        self.dst = (DEV_IP, DEV_PORT)
        self.our_chan = int(os.environ.get("WWB_CHAN", "0"), 16) or (0x8000 | (os.urandom(1)[0] << 4))
        self.dev_chan = None
        self.total_seq = (self.our_chan + 1) & 0xffff
        self.rel_seq   = self.our_chan & 0xffff
        self.first_rel_seq = None
        self.first_rel = True
        self.unacked = {}
        self.unrel_ct = 0
        self.key = None
        self.tx_nonce = os.urandom(8)
        self.tx_pos = 0
        self.rx_pos = 0
        self.rx_seen = {}
        self.accepted_us = False
        self.sent_accept = False
        self.joined = False
        self.proto_ok = False
        self.recip_assoc_sent = False
        self.assoc_time = None
        self.dev_rel = 0
        self.cmds = []
        self.cmd_i = 0
        self.next_send_at = 0.0
        self.sock = None
        self.slp_sock = None
        self.slp_pkt = None
        self.last_slp = 0.0
        self.last_keepalive = 0.0
        self.big_pkts = 0
        self.scan_events = 0
        self.decoded = 0
        self.undec = 0
        self.t0 = 0.0

    def _build_slp(self):
        c = self.cid
        cidstr = ("%s-%s-%s-%s-%s" % (c[0:4].hex(), c[4:6].hex(), c[6:8].hex(),
                                      c[8:10].hex(), c[10:16].hex())).upper()
        attrs = ("(cid=%s),(acn-fctn=WWB6),(acn-uacn=WWB 6X),(acn-services=esta.dmp),"
                 "(csl-esta.dmp=esta.sdt/%s:%d;esta.dmp/cd:CCDA8E0A-E139-11DF-8C7A-0015C5F3F612),"
                 "(device-description=$:tftp://%s/$.ddl),"
                 "(csl-esta.dmp.values=version:1_interfaceId:1_extVersion:1)"
                 ) % (cidstr, MY_IP, SRC_PORT, MY_IP)
        ab = attrs.encode()
        after = (b"\x00\x00" + b"\x00\x00\x00" + b"\x22\x3d" + b"\x00\x02" + b"en"
                 + b"\x00\x00" + struct.pack(">H", len(ab)) + ab + b"\x00")
        self.slp_pkt = b"\x02\x07" + (2 + 3 + len(after)).to_bytes(3, "big") + after
        return cidstr

    def _advertise(self):
        cidstr = self._build_slp()
        self.slp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.slp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.slp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        try:
            self.slp_sock.bind(("", 8427))
        except Exception as e:
            print("   SLP bind warn:", e)
        self.slp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        try:
            self.slp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(MY_IP))
            self.slp_sock.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(os.environ.get("AD600_MCAST_IF", "en10")))
        except Exception as e:
            print("   SLP egress-iface warn:", e)
        try:
            self.slp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                     socket.inet_aton(SLP_GRP[0]) + socket.inet_aton(MY_IP))
        except Exception as e:
            print("   SLP mcast-join warn:", e)
        for _ in range(3):
            self.slp_sock.sendto(self.slp_pkt, SLP_GRP)
            time.sleep(0.12)
        self.last_slp = time.time()
        print("→ SLP advert sent (cid=%s  esta.sdt/%s:%d, %dB) — waiting 3 s before JOIN (WWB gap)"
              % (cidstr, MY_IP, SRC_PORT, len(self.slp_pkt)))
        time.sleep(3.0)

    def _slp_keepalive(self):
        if self.slp_sock is not None and time.time() - self.last_slp > 4.0:
            try:
                self.slp_sock.sendto(self.slp_pkt, SLP_GRP)
            except Exception:
                pass
            self.last_slp = time.time()

    def _send_reliable(self, blocks):
        tot = self.total_seq; self.total_seq = (self.total_seq + 1) & 0xffff
        self.rel_seq = (self.rel_seq + 1) & 0xffff
        if self.first_rel_seq is None:
            self.first_rel_seq = self.rel_seq
        trailer = b"\xff\xff\x00\x00\x00\x00" if self.first_rel else b"\xff\xff\xff\xff\x00\x00"
        self.first_rel = False
        oldest = self.first_rel_seq
        self.unacked[self.rel_seq] = blocks
        self.sock.sendto(build_wrapper(self.cid, self.our_chan, tot, self.rel_seq, oldest,
                                       blocks, True, trailer), self.dst)

    def _send_unreliable(self, blocks):
        tot = self.total_seq; self.total_seq = (self.total_seq + 1) & 0xffff
        self.unrel_ct += 1
        _early = os.environ.get("AD600_EARLY_MAK") == "1"
        _fh_up = _early or self.big_pkts > 0
        trailer = (b"\x00\x01\x00\x01\x00\x00"
                   if (_fh_up and self.unrel_ct % 3 == 0)
                   else b"\xff\xff\xff\xff\x00\x00")
        oldest = self.rel_seq
        self.sock.sendto(build_wrapper(self.cid, self.our_chan, tot, self.rel_seq, oldest,
                                       blocks, False, trailer), self.dst)

    def _ack_device(self):
        assoc = self.dev_chan or 0
        self._send_unreliable([client_block(1, 1, assoc, mgmt_ack(self.dev_rel))])

    def _send_dmp(self, pdu):
        pos = self.tx_pos
        ct = aes_ctr_at(self.key, self.tx_nonce, pos, pdu)
        iv = self.tx_nonce + ((pos + 15) // 16).to_bytes(8, "big")
        self.tx_pos += len(pdu)
        cb = b"\x01\x01" + struct.pack(">H", 16 + len(pdu)) + iv + ct
        tag = skip32(self.key[:10], zlib.crc32(cb) & 0xffffffff, True).to_bytes(4, "big")
        self._send_reliable([client_block(1, 0x102, 0, cb + tag)])

    def _scan_assoc(self, blocks):
        for _proto, pl in blocks:
            if pl[:1] == b"\x70" and len(pl) >= 7 and pl[2] == 0x0e:
                self._on_our_ack(int.from_bytes(pl[-2:], "big"))
            if pl[:3] == b"\x70\x07\x09" and pl[3:7] == b"\x00\x00\x01\x02" and not self.recip_assoc_sent:
                self.recip_assoc_sent = True
                self.assoc_time = time.time()
                self._send_reliable([client_block(1, 1, self.dev_chan or 0,
                                                  pdu_encode(0x0a, None, struct.pack(">I", 0x102), 1))])
                print("  %6.2fs → reciprocal ASSOC0a (assoc=0x%04X) — FULL association up"
                      % (time.time() - self.t0, self.dev_chan or 0))
            if pl[:3] == b"\x70\x07\x0a" and pl[3:7] == b"\x00\x00\x01\x02" and not self.proto_ok:
                self.proto_ok = True
                self._proto_ok_time = time.time()
                print("  %6.2fs → device ASSOC0a — our declare accepted, DMP send enabled"
                      % (time.time() - self.t0))

    def _on_our_ack(self, ackseq):
        for sq in [q for q in list(self.unacked)
                   if ((q - ackseq) & 0xffff) == 0 or ((ackseq - q) & 0xffff) < 0x8000]:
            self.unacked.pop(sq, None)

    # ── RX DMP decode (device→controller continuous CTR, drift-robust) ──
    def _decode_dmp(self, payload):
        ln = struct.unpack(">H", payload[2:4])[0]
        nonce = payload[4:12]
        ct = payload[20:4 + ln]
        if not ct:
            return None
        if ct in self.rx_seen:
            pos = self.rx_seen[ct]
            dec = aes_ctr_at(self.key, nonce, pos, ct)
        else:
            pos = self.rx_pos
            dec = aes_ctr_at(self.key, nonce, pos, ct)
            if not _valid_dmp_head(dec, len(ct)):
                fp, fdec = find_ctr_pos(self.key, nonce, ct, self.rx_pos)
                if fdec is not None:
                    pos, dec = fp, fdec
            if dec and _valid_dmp_head(dec, len(ct)):
                self.rx_seen[ct] = pos
                self.rx_pos = max(self.rx_pos, pos + len(ct))
        if dec and (_valid_dmp_head(dec, len(ct)) or dec[0] == 0x70):
            self.decoded += 1
            return dec
        self.undec += 1
        return None

    def _handle_dmp(self, dec):
        pass

    def _drain_commands(self, now):
        pass

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        self.sock.bind(("", SRC_PORT))
        self.sock.settimeout(float(os.environ.get("AD600_SOCK_TIMEOUT", "0.1")))
        print("our CID=%s  our chan=0x%04X  src port=%d  dev=%s:%d"
              % (self.cid.hex(), self.our_chan, self.sock.getsockname()[1], DEV_IP, DEV_PORT))

        self._advertise()
        self.sock.sendto(build_join(self.cid, DEV_CID, self.our_chan), self.dst)
        print("→ JOIN sent (leader chan 0x%04X, reliable seq-base=0x%04X → first reliable=0x%04X)"
              % (self.our_chan, self.our_chan, (self.our_chan + 1) & 0xffff))

        self.t0 = time.time()
        while time.time() - self.t0 < self.run_for:
            if getattr(self, "_quit", False):
                break
            try:
                data, _addr = self.sock.recvfrom(4096)
            except socket.timeout:
                self._slp_keepalive()
                if self.joined and time.time() - self.last_keepalive > 1.4:
                    self._ack_device()
                    self.last_keepalive = time.time()
                self._drain_commands(time.time())
                continue

            if _addr[0] != DEV_IP:
                continue   # ignore anything not from our claimed device (other hosts on the LAN)

            if len(data) > 200:
                self.big_pkts += 1
                if self.big_pkts <= 3 or self.big_pkts % 50 == 0:
                    print("  ★★★ %6.2fs BIG PACKET #%d len=%d — STREAM DATA"
                          % (time.time() - self.t0, self.big_pkts, len(data)))

            # A truncated/garbled datagram can throw deep inside PDU/DMP decode (struct.unpack,
            # slicing) — catch it here so one bad packet can't kill the whole session/process.
            try:
                pr = root_parse(data)
                if not pr:
                    continue
                _src, sdt = pr

                off = 0
                while off < len(sdt):
                    r = pdu_decode(sdt, off)
                    if not r:
                        break
                    _f, ds, end = r
                    vec = sdt[ds]
                    vdata = sdt[ds + 1:end]
                    off = end
                    self._dispatch(vec, vdata, time.time())

                if self.accepted_us and self.sent_accept and self.dev_chan and not self.joined:
                    self._complete_join()
            except Exception as e:
                print("  [packet decode/dispatch error: %r len=%d]" % (e, len(data)))

            self._drain_commands(time.time())

        self._teardown()

    def _dispatch(self, vec, vdata, now):
        name = SDT_VEC.get(vec, "vec%d" % vec)
        if vec == 6:                                    # JOIN_ACCEPT (device accepts our JOIN)
            self.accepted_us = True
            self.dev_chan = struct.unpack(">H", vdata[-2:])[0]
            print("← JOIN_ACCEPT  dev chan=0x%04X" % self.dev_chan)
        elif vec == 4:                                  # device's reciprocal JOIN → we accept it
            self.dev_chan = struct.unpack(">H", vdata[18:20])[0]
            relseq = struct.unpack(">I", vdata[26:30])[0] & 0xffff
            self.dev_rel = relseq
            if not self.sent_accept:
                self.sock.sendto(build_join_accept(self.cid, DEV_CID, self.dev_chan, relseq, self.our_chan), self.dst)
                self.sent_accept = True
                print("→ JOIN_ACCEPT sent (dev chan 0x%04X, dev_rel=0x%04X)" % (self.dev_chan, relseq))
        elif vec in (1, 2):                             # reliable / unreliable SDT wrapper
            w = parse_wrapper(vdata)
            if not w:
                return
            _chan, _total, rel, _oldest, blocks = w
            r16 = rel & 0xffff
            if vec == 1:                                # reliable: advance our ack frontier + ACK EARLY
                self.dev_rel = r16
                self._scan_assoc(blocks)
                _reactive = os.environ.get("AD600_REACTIVE_ACK") == "1"
                if _reactive or os.environ.get("AD600_LAZY_ACK") != "1":
                    self._ack_device()                  # cumulative climbing ACK per device reliable wrapper
                    self.last_keepalive = now
            else:
                self._scan_assoc(blocks)
            for proto, payload in blocks:
                if proto == 0x102 and self.key and payload[:1] == b"\x01":
                    dec = self._decode_dmp(payload)
                    if dec:
                        self._handle_dmp(dec)
        elif vec == 8:                                  # NAK — device wants a retransmit of a gap
            missed = struct.unpack(">H", vdata[22:24])[0] if len(vdata) >= 24 else None
            print("← NAK missed=0x%04x" % (missed if missed is not None else 0))
            if missed is not None:
                seqs = [q for q in sorted(self.unacked, key=lambda q: (q - missed) & 0xffff)
                        if ((q - missed) & 0xffff) < 0x8000]
                for sq in seqs:
                    tot = self.total_seq; self.total_seq = (self.total_seq + 1) & 0xffff
                    old = self.first_rel_seq if self.first_rel_seq is not None else sq
                    self.sock.sendto(build_wrapper(self.cid, self.our_chan, tot, sq, old,
                                                   self.unacked[sq], True), self.dst)
                if seqs:
                    print("   → retransmitted %d reliable wrapper(s) from 0x%04x" % (len(seqs), missed))
        elif vec == 7:
            print("← LEAVING %s" % vdata.hex()[:32])
        elif vec == 5:
            _refuse_reason = {1:"NONSPECIFIC", 2:"ILLEGAL_PARAMS", 3:"LOW_RESOURCES",
                              4:"ALREADY_MEMBER", 5:"BAD_ADDR", 6:"NO_RECIPROCAL",
                              7:"CHANNEL_EXPIRED", 8:"LOST_SEQUENCE"}
            _rc = vdata[-1] if len(vdata) > 16 else None
            _leader = vdata[:16].hex()
            _mine = _leader == self.cid.hex()
            print("← JOIN_REFUSE full=%s  leaderCID=%s(%s)  reason=%s(%s)"
                  % (vdata.hex(), _leader, "OURS" if _mine else "NOT-OURS",
                     _rc, _refuse_reason.get(_rc, "?") if _rc is not None else "n/a"))
            print("   [IDENTITY IN USE] our WWB_CID=%s  DEV_CID=%s  DEV=%s:%d"
                  % (self.cid.hex(), DEV_CID.hex(), DEV_IP, DEV_PORT))

    def _complete_join(self):
        self.joined = True
        blob = self.cid + DEV_CID + struct.pack("<H", self.our_chan) + struct.pack("<H", self.dev_chan)
        self.key = sk_util(blob)[:16]
        print("*** JOINED — us=0x%04X dev=0x%04X  key=%s ***"
              % (self.our_chan, self.dev_chan, self.key.hex()))
        self._ack_device()
        self.last_keepalive = time.time()
        self._send_reliable([client_block(1, 1, 0, mgmt_proto())])
        print("→ EARLY mgmt-ack(dev_rel=0x%04X) + proto-0x102 declaration sent" % self.dev_rel)

    def _teardown(self):
        if getattr(self, "_torn_down", False):
            return
        self._torn_down = True
        if self.joined and self.dev_chan:
            try:
                for _ in range(2):
                    self._send_reliable([client_block(1, 1, 0, pdu_encode(0x0c, None, struct.pack(">I", 0x102), 1))])
                    self._send_reliable([client_block(1, 1, 0, pdu_encode(7, None, b"", 1))])
                    time.sleep(0.05)
                leave = root_wrap(self.cid, pdu_encode(8, None, DEV_CID + bytes.fromhex("b2b000010001207a06"), 1))
                self.sock.sendto(leave, self.dst)
                self.sock.sendto(leave, self.dst)
                print("→ clean disconnect sent (disassoc + LEAVING + root-leave)")
            except Exception as e:
                print("disconnect error:", e)
        try:
            self.sock.close()
        except Exception:
            pass
        print("done — decoded %d DMP blocks; %d undecryptable; %d big pkts; %d RF_SCAN_DATA events"
              % (self.decoded, self.undec, self.big_pkts, self.scan_events))


WwbMirror = _SessionBase


# ══════════════════════════ un-batch helpers (AD600_UNBATCH — winning_v2 recipe) ══════════════════════════
# The batched feed packs 10-16 subscribe addresses into one DMP PDU via ACN header-inheritance
# (a 0x70 PDU sets vector+header; following 0x10 PDUs inherit them and carry only the next
# address). The device tolerates only ~10-12 OUTSTANDING un-accepted subscriptions, so a
# reply-gate that counts WRAPPERS puts ~20 subs in flight at once → it accepts the first batched
# wrapper's ~10 + a couple singles (=12) then silently drops the rest (the whole 0x0107 scan tree)
# = the "12-cap". winning_v2 crossed the full tree in ONE pass by sending each subscribe address
# as its OWN single-address SUBSCRIBE PDU (70 08 07 02 <addr>), exactly ONE PDU per SDT reliable
# wrapper, with only ~2 subscriptions outstanding. These helpers reproduce that un-batching.
def _walk_pdus(pt):
    """Yield (vector, header_type, data_bytes) for every DMP PDU in a block, honoring ACN
    header-inheritance: a 0x70 PDU (flag bits V|H|D) carries its own vector + header (address
    mode); a following 0x10 PDU (flag bit D only) inherits the previous vector + header and
    carries only its data (the next address / string key)."""
    out = []; i = 0; iv = None; ih = None
    while i < len(pt):
        r = pdu_decode(pt, i)
        if not r:
            break
        f, ds, end = r
        j = ds; vec = iv; ht = ih
        if f & 0x4:                                # V flag: own vector
            vec = pt[j]; j += 1; iv = vec
        if f & 0x2:                                # H flag: own header (address mode)
            ht = pt[j]; j += 1; ih = ht
        out.append((vec, ht, pt[j:end]))
        i = end
    return out


def _rebuild_pdu(vec, ht, data):
    """Re-materialise ONE self-contained header PDU (flag 0x70 = V|H|D) from an inherited PDU's
    (vector, header_type, data). The address/data field is copied VERBATIM — only the inherited
    vector + header bytes are re-stamped — so the result is byte-identical to how the feed would
    have carried that same address as its own leading PDU (numeric → 70 08 07 02 <addr4>)."""
    L = 4 + len(data)                              # flag(1)+len(1)+vec(1)+ht(1)+data
    if L > 0x0FFF:
        raise ValueError("PDU too long to un-batch (%d)" % L)
    return bytes([0x70 | (L >> 8), L & 0xff, vec, ht]) + data


def flatten_subscribe_wrapper(blk):
    """Split a possibly-batched SUBSCRIBE wrapper into a list of individual single-address
    SUBSCRIBE PDUs, one per address (preserving feed order). Works for numeric (header 0x02) and
    string-key (header 0x07, e.g. RF_SCAN_DATA:RSSI/…) subscribes alike."""
    return [_rebuild_pdu(v, h, d) for (v, h, d) in _walk_pdus(blk)]


# ══════════════════ COMBINED-MODE helpers (AD600_PERSIST_UNTIL_STATUS + AD600_ARM_ON_STATUS) ══════════════════
# The three RF_SCAN status objects that gate the sweep. CURRENT_SWEEP_STATUS is THE gate: once the
# device SUB_ACCEPTs it for our session, the sweep can arm and RSSI streams. We persist the full
# fan-out (incl the deep 0x01090201-0224 scan-module tree AND these three CURRENT_* string subs)
# until CURRENT_SWEEP_STATUS is accepted, then fire the arm ONCE (config SETs → RSSI leaves → START).
_STATUS_KEYS = (b"CURRENT_SWEEP_STATUS", b"CURRENT_SWEEP_ID", b"CURRENT_STATUS")
# Order matters: CURRENT_SWEEP_STATUS is a substring-superset test target, so match the LONGEST /
# most specific key first (CURRENT_SWEEP_STATUS before CURRENT_STATUS) when classifying a block.
_STATUS_MATCH = (b"CURRENT_SWEEP_STATUS", b"CURRENT_SWEEP_ID", b"CURRENT_STATUS")


def _is_arm_block(blk):
    """True if a (flattened) wrapper belongs to the RF_SCAN ARM (fired ONCE after the gate) and NOT
    to the persisted fan-out. Arm = the 8 RF_SCAN config SETs (RF_SCAN:SCAN_*), the 6
    &RF_SCAN_DATA:RSSI subscribe leaves, and the bare numeric START (SET 0x01070103=00). The three
    CURRENT_* status subscribes are DELIBERATELY excluded — they live in the persisted fan-out (they
    ARE the gate objects), so 'RF_SCAN:CURRENT_*' must NOT count as an arm block."""
    if b"RF_SCAN:SCAN_" in blk:            # the 8 sweep-config SETs (SCAN_START_FREQ, …)
        return True
    if b"RF_SCAN_DATA:RSSI" in blk:        # the 6 RSSI curve subscribe leaves
        return True
    if len(blk) >= 9 and blk[:8].hex() == "7009020201070103":   # numeric START  SET 0x01070103
        return True
    return False


def _sub_identities(blk):
    """Identities of the SUBSCRIBE PDUs in a (flattened) wrapper, for cross-pass accept tracking.
    Returns a list of ('str', '<STATUS_KEY>') for the three CURRENT_* / RSSI string subs, or
    ('num', <addr int>) for numeric subscribes. Only vector-7 (SUBSCRIBE) PDUs are reported."""
    out = []
    for vec, ht, data in _walk_pdus(blk):
        if vec != 7:                       # only subscribes carry a subscription identity
            continue
        if ht == 0x07:                     # string key (2-byte len + ASCII in `data`)
            tag = None
            for k in _STATUS_MATCH:
                if k in data:
                    tag = k.decode(); break
            if tag is None and b"RF_SCAN_DATA:RSSI" in data:
                tag = "RF_SCAN_DATA:RSSI"
            if tag is not None:
                out.append(("str", tag))
        elif ht == 0x02 and len(data) >= 4:   # numeric address mode
            out.append(("num", int.from_bytes(data[:4], "big")))
    return out


def _strkey_event_value(dec):
    """For a decrypted vec-4 EVENT that carries a string key (header 0x07): return (key_bytes,
    value_bytes), else None. Layout: [70][len2][04][07][2B strlen][ASCII key][value…]."""
    if len(dec) < 6 or dec[2] != 0x04 or dec[3] != 0x07:
        return None
    strlen = dec[5]                        # low byte of the 2-byte strlen (keys are < 256B)
    if 6 + strlen > len(dec):
        return None
    return dec[6:6 + strlen], dec[6 + strlen:]

# DMP reply vectors → names (for readable decode lines).
DMP_VEC_NAMES = {
    1: "GET", 2: "SET", 3: "GET_REPLY", 4: "EVENT", 7: "SUBSCRIBE",
    9: "GET_FAIL", 10: "SET_FAIL", 12: "SUB_ACCEPT", 13: "SUB_REJECT",
}

# ── default control/output paths (all overridable by argv or env) ──
_DEF_DIR = os.environ.get(
    "AD600_CONSOLE_DIR",
    "/private/tmp/claude-501/-Users-nt-mbp-Wisycom-Control/"
    "528e2b42-ede5-461b-ac9f-c09ae31c061c/scratchpad")
DEF_CMD = os.environ.get("AD600_CONSOLE_CMD", os.path.join(_DEF_DIR, "console_cmd.txt"))
DEF_LOG = os.environ.get("AD600_CONSOLE_LOG", os.path.join(_DEF_DIR, "console_out.log"))


class _Tee:
    """Write to several streams at once, flushing each write — so everything the console (and its
    inherited WwbMirror prints) emit lands in BOTH stdout and the log file in real time."""
    def __init__(self, *streams):
        self.streams = [s for s in streams if s is not None]
    def write(self, s):
        for st in self.streams:
            try:
                st.write(s)
                st.flush()
            except Exception:
                pass
        return len(s)
    def flush(self):
        for st in self.streams:
            try:
                st.flush()
            except Exception:
                pass


class _TSWriter:
    """Wrap a file handle and prepend a wall-clock timestamp to each COMPLETE line.
    Used only for the LOG FILE (never stdout) so the FRAME/status stream the engine
    parses stays byte-clean, while the durable log gains 'YYYY-MM-DD HH:MM:SS.mmm ' stamps."""
    def __init__(self, fh):
        self.fh = fh
        self._buf = ""
    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            t = time.time()
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + (".%03d " % int((t % 1) * 1000))
            try:
                self.fh.write(ts + line + "\n")
            except Exception:
                pass
        return len(s)
    def flush(self):
        try:
            self.fh.flush()
        except Exception:
            pass


class Ad600Console(WwbMirror):
    """A persistent, operator-driven WWB-style session.  Inherits the whole SDT/DMP stack from
    WwbMirror; adds a control-file command channel and full real-time reply logging."""

    def __init__(self, run_for, cmd_path, log_path):
        super().__init__(run_for=run_for)         # builds counters, sockets-config, seq bases, etc.
        self.cmds = []                            # belt-and-braces: no canned replay
        self.cmd_path = cmd_path
        self.log_path = log_path
        self.cmd_fpos = 0                          # byte offset consumed in the control file
        self.pending = []                          # DMP blocks queued before proto_ok (DMP not yet enabled)
        self.vec12_accepts = 0                     # SUBSCRIBE_ACCEPT count (vec 12)
        self.app_replies = 0                       # ALL app-layer replies (accepts+get_reply+fail+reject)
        # ── strict lock-step driver state (WWB flow control: ≤1 wrapper outstanding) ──
        self.lockstep = None                       # [(block_bytes, expected_replies, kind), ...] or None
        self.lockstep_path = None                  # source feed (for AD600_HOLD_LOOP re-subscribe loop)
        self.ls_loops = 0
        # ── AD600_RT_COMPRESSION: delivered-RBW retune (comp*25kHz; 0/unset → feed default 900kHz) ──
        try:
            self._rt_comp = int(os.environ.get("AD600_RT_COMPRESSION", "0") or 0)
        except ValueError:
            self._rt_comp = 0
        # ── AD600_SCAN_START_KHZ / AD600_SCAN_STOP_KHZ: scan range (0/unset → feed default 470-1000) ──
        try:
            self._scan_start_khz = int(os.environ.get("AD600_SCAN_START_KHZ", "0") or 0)
        except ValueError:
            self._scan_start_khz = 0
        try:
            self._scan_stop_khz = int(os.environ.get("AD600_SCAN_STOP_KHZ", "0") or 0)
        except ValueError:
            self._scan_stop_khz = 0
        # ── AD600_SCAN_STEP_KHZ / AD600_RBW_KHZ: measurement step + filter BW (0/unset → 25 kHz) ──
        # These reach BELOW the 25 kHz compression floor (capability probe; freq axis is 25 kHz/idx).
        try:
            self._step_khz = int(os.environ.get("AD600_SCAN_STEP_KHZ", "0") or 0)
        except ValueError:
            self._step_khz = 0
        try:
            self._rbw_khz = int(os.environ.get("AD600_RBW_KHZ", "0") or 0)
        except ValueError:
            self._rbw_khz = 0
        # ── AD600_CURVE_SELECT: hardware curve bitmask (e.g. 0x7E = all six; 0x02 = A only) ──
        try:
            self._curve_mask = int(os.environ.get("AD600_CURVE_SELECT", "0") or 0)
        except ValueError:
            self._curve_mask = 0
        # ── AD600_REPEAT: 0xFF for continuous, 0x01 for single-shot snapshot ──
        try:
            self._repeat = int(os.environ.get("AD600_REPEAT", "0") or 0)
        except ValueError:
            self._repeat = 0
        # ── scan-ownership + auto-arm (AD600_LOOP_UNTIL_OWN + AD600_AUTO_ARM) ──
        self.scan_owned = False                    # set when GET 0x0107010f is ANSWERED
        self.scan_id = None                        # the LIVE scan-id N from the 0x0107010f reply
        self.armed = False                         # armed with /SCAN=N yet
        self.arm_blocks = []                       # RF_SCAN arm wrappers (status/config/RSSI/START) to rewrite
        self.ls_idx = 0
        self.ls_batch_end = 0                      # index AFTER the batch currently outstanding
        self.ls_waiting = False
        self.ls_target = 0                         # advance when app_replies >= this
        self.ls_min_time = 0.0                     # do not advance before this (settle floor)
        self.ls_deadline = 0.0                     # force-advance at this time (timeout)
        self.ls_hold_until = 0.0                   # pause the whole driver until this time (loop gap)
        self.ls_to_sub = float(os.environ.get("AD600_LS_SUB_TIMEOUT", "2.0"))
        self.ls_to_get = float(os.environ.get("AD600_LS_GET_TIMEOUT", "1.0"))
        self.ls_settle = float(os.environ.get("AD600_LS_SETTLE", "0.15"))
        # ── TRUE REPLY-GATING (AD600_REPLY_GATED=1): keep ≤ AD600_MAX_OUTSTANDING wrappers in
        # flight and advance the frontier ONLY when the batch's accepts/replies actually arrive
        # (the ls_to_* timeouts become a LONG anti-deadlock fallback, NOT the routine path). This
        # stops the device's small DMP input queue being overrun by a timed burst, so it keeps
        # draining and its dequeue frontier walks into the 0x0107 scan tree. Default (flag unset)
        # = legacy 1-wrapper-per-gate behaviour, so other modes are untouched.
        self.reply_gated = os.environ.get("AD600_REPLY_GATED") == "1"
        self.max_outstanding = (int(os.environ.get("AD600_MAX_OUTSTANDING", "2"))
                                if self.reply_gated else 1)
        # ── AD600_UNBATCH=1 (winning_v2 recipe): flatten the subscribe fan-out to one address per
        # wrapper and GATE ON OUTSTANDING-SUBSCRIPTION COUNT. Because each un-batched subscribe is
        # its own 1-PDU wrapper, "wrappers outstanding" == "subscriptions outstanding", so the
        # existing reply-gated batch sender enforces the subscription cap directly. Force reply-
        # gating on and size the cap from AD600_MAX_OUTSTANDING_SUBS (default 2 = WWB's measured
        # peak). Other modes (flag unset) are completely unaffected.
        self.unbatch = os.environ.get("AD600_UNBATCH") == "1"
        if self.unbatch:
            self.reply_gated = True
            self.max_outstanding = int(os.environ.get(
                "AD600_MAX_OUTSTANDING_SUBS",
                os.environ.get("AD600_MAX_OUTSTANDING", "2")))
        # ── COMBINED MODE (AD600_PERSIST_UNTIL_STATUS + AD600_ARM_ON_STATUS) ──
        # PERSIST the full fan-out (incl the deep 0x01090201-0224 scan-module tree AND the three
        # RF_SCAN:CURRENT_SWEEP_STATUS/_SWEEP_ID/_STATUS string subs) — re-sending each pass — UNTIL
        # the device SUB_ACCEPTs CURRENT_SWEEP_STATUS (the gate object). Then fire the arm ONCE.
        # Distinct from AD600_LOOP_UNTIL_OWN (exit = ownership) so other modes are untouched.
        self.persist_until_status = os.environ.get("AD600_PERSIST_UNTIL_STATUS") == "1"
        self.arm_on_status = os.environ.get("AD600_ARM_ON_STATUS") == "1"
        self.loud_sweep = self.persist_until_status or self.arm_on_status
        # ── OWNERSHIP-CLAIM MODE (AD600_OWNER_CLAIM) ─────────────────────────────────────────────
        # The producing sequence (wwb_onboard_scan, byte-verified): after the clean grant fan-out,
        # WWB waits a ~2.8s PRIMING GAP (device finishing scan-engine init), then LATE-subscribes
        # 0x01090201 (t=2.811, isolated) and reads GET 0x0107010f (t=3.401) — the SCAN-OWNERSHIP
        # claim, ANSWERED only for the boot-first slot-0 owner. The device then PUSHES EVENT
        # 0x01070137=0e (scan-ready) — the owner milestone, present ONLY for the owner. The arm
        # (config SETs → RSSI leaves → bare START) is GATED on that scan-ready EVENT. Sent EARLY or
        # as a non-owner, GET 0x0107010f draws a GFAIL and POISONS the session (→ the old 12/59), so
        # it is DEFERRED out of the early feed and re-sent ONCE, LATE, here.
        self.owner_claim = os.environ.get("AD600_OWNER_CLAIM") == "1"
        self.prime_settle = float(os.environ.get("AD600_PRIME_SETTLE", "4.5"))
        self.owner_claim_timeout = float(os.environ.get("AD600_OWNER_CLAIM_TIMEOUT", "12.0"))
        self.scanready_timeout = float(os.environ.get("AD600_SCANREADY_TIMEOUT", "12.0"))
        if self.owner_claim:
            self.loud_sweep = True
        self.oc_phase = "fanout"        # fanout → settle → claim(sent) → wait_owner → wait_scanready → armed/aborted
        self.oc_settle_until = 0.0      # wall clock to end the priming settle
        self.oc_claim_deadline = 0.0    # wall clock to give up on the ownership GET reply
        self.oc_scanready_deadline = 0.0  # wall clock to give up on the scan-ready EVENT
        self.scan_ready = False         # device PUSHED EVENT 0x01070137=0e (owner milestone) yet
        self.scan_gfail = False         # device returned GET_FAIL on 0x0107010f (non-owner)
        self.oc_aborted = False         # NOT-OWNER / no-scan-ready abort — arm suppressed
        # cross-pass acceptance ledger (persists across reloads; only per-pass counters reset).
        self.accepted_ids = set()                  # numeric addrs + string tags SUB_ACCEPTed so far
        self.status_accepted = {"CURRENT_SWEEP_STATUS": False,
                                "CURRENT_SWEEP_ID": False,
                                "CURRENT_STATUS": False}
        self.deep0109_accepted = set()             # 0x01090201-0224 addrs accepted (deep scan tree)
        self.armed_status = False                  # armed via the CURRENT_SWEEP_STATUS gate yet
        self.ls_batch_acc0 = 0                      # vec12_accepts snapshot at batch send (per-batch)
        self.max_passes = int(os.environ.get("AD600_MAX_PASSES", "25"))          # persist cap
        self.persist_budget = float(os.environ.get("AD600_PERSIST_BUDGET_S", "240"))  # ~4 min cap
        # ── AD600_WWB_EXACT=1 (the decisive verbatim-replay mode) ──────────────────────────────
        # Replay WWB's EXACT ctrl->dev SDT reliable-wrapper stream (captures/wwb_wrapper_exact.txt):
        # WWB's OWN wrapper GROUPING — 49 FAT multi-PDU DMP blocks, one 0x102 block per SDT reliable
        # wrapper, exactly as WWB packed them (NOT flattened to single-PDU wrappers, NOT re-batched) —
        # sent on WWB's OWN inter-wrapper BURST cadence and NOT reply-gated (fire the next wrapper when
        # its recorded send-time arrives, never waiting for accepts). This is the ONE delivery variable
        # every prior mode destroyed: reply-gated batching throttled to a 12-cap; AD600_UNBATCH
        # flattened the fat blocks into 91 single-PDU wrappers. ONE association, NO re-JOIN.
        self.wwb_exact = os.environ.get("AD600_WWB_EXACT") == "1"
        self.wx = None                 # [(rel_ts_s, [block_bytes,...]), ...]  loaded schedule
        self.wx_sched = None           # cumulative clamped send-offsets (s) aligned to wx
        self.wx_idx = 0
        self.wx_t0 = None              # wall-clock anchor for the burst schedule
        self.wx_done = False
        self.wx_pass = 0
        self.wx_repeat = int(os.environ.get("AD600_WWB_REPEAT", "0"))   # fallback extra full re-bursts
        self.wx_maxgap = float(os.environ.get("AD600_WWB_MAXGAP", "2.0"))  # clamp idle gaps (collapse WWB's ~18.8s operator idle; keeps the 2-145ms burst + ~1s CFL pauses intact)
        self.wx_settle = float(os.environ.get("AD600_WWB_SETTLE", "6.0"))  # wait after a pass before a repeat/finish
        self.exact_accepts = set()     # SUB_ACCEPTed numeric addrs + string keys (branch tracking)
        if self.wwb_exact:
            self.loud_sweep = True     # enable the RSSI-FIREHOSE / sweep-state EVENT prints
        self._quit = False
        self.last_poll = 0.0
        # Tee stdout → stdout + log file so EVERY event (ours and inherited) is durably logged.
        self._logfh = open(self.log_path, "a", buffering=1)   # line-buffered
        sys.stdout = _Tee(sys.__stdout__, _TSWriter(self._logfh))   # stdout raw (FRAME parse); log file gets wall-clock stamps
        print("\n" + "=" * 78)
        print("ad600_console — live session  |  cmd=%s" % self.cmd_path)
        print("                              |  log=%s" % self.log_path)
        print("=" * 78)

    # ── SLP advert is optional for the console (env AD600_NO_SLP=1 to skip) ──
    def _advertise(self):
        if os.environ.get("AD600_NO_SLP") == "1":
            print("→ SLP advert SKIPPED (AD600_NO_SLP=1)")
            return
        super()._advertise()

    # ── full real-time decode of every device DMP reply (overrides base's scan-only print) ──
    def _handle_dmp(self, dec):
        try:
            # inheritance-aware count of ALL PDUs in this block (device batches replies with
            # header-inheritance: 0x70 sets the vector, following 0x10 PDUs inherit it). Counting
            # only the first PDU (dec[2]) undercounts batched accepts — fatal for the lock-step gate.
            _i = 0; _cur = None
            while _i + 1 < len(dec):
                _fl = dec[_i]
                if _fl & 0xf0 not in (0x70, 0x10):
                    break
                _ln = ((_fl & 0x0f) << 8) | dec[_i + 1]
                if _ln < 2 or _i + _ln > len(dec):
                    break
                if _fl & 0xf0 == 0x70:
                    _cur = dec[_i + 2] if _i + 2 < len(dec) else None
                if _cur == 12:
                    self.vec12_accepts += 1
                if _cur in (3, 9, 10, 12, 13):     # get_reply, get_fail, set_fail, accept, reject
                    self.app_replies += 1
                _i += _ln
            if self.wwb_exact:                     # verbatim-mode: track which branches ACCEPT
                self._track_exact_branches(dec)
            vec = dec[2] if len(dec) > 2 else 0
            name = DMP_VEC_NAMES.get(vec, "vec%d" % vec)
            if vec == 4:                                       # EVENT — includes the RF_SCAN firehose
                rf = parse_rf_scan_data(dec)
                if rf:
                    curve, flo, fhi, amps = rf
                    f0 = 174 + flo * 0.025
                    f1 = 174 + fhi * 0.025
                    mn = min(amps) if amps else 0
                    mx = max(amps) if amps else 0
                    self.scan_events += 1
                    if self.scan_events == 1:
                        print("\n" + "=" * 68 +
                              "\n  SCAN LANDED — device is streaming RF_SCAN_DATA\n" + "=" * 68 + "\n")
                    print("  %6.2fs  RF_SCAN_DATA curve=%d  %.3f-%.3f MHz  %d bins  %d..%d dBm/10"
                          % (time.time() - self.t0, curve, f0, f1, len(amps), mn, mx))
                    if _EMIT_FRAMES:
                        # FRAME <curve> <flo> <fhi> <b64>  where <b64> = base64 of the int16-BE
                        # (dBm*10) amplitude array — a compact, lossless re-encoding of `amps`
                        # (which parse_rf_scan_data already divided by 10). The consumer inverts
                        # with struct.unpack(">%dh"%n, raw) then /10.0. One line, flushed.
                        try:
                            _q = [max(-32768, min(32767, int(round(a * 10)))) for a in amps]
                            _b64 = base64.b64encode(_struct.pack(">%dh" % len(_q), *_q)).decode("ascii")
                            sys.stdout.write("FRAME %d %d %d %s\n" % (curve, flo, fhi, _b64))
                            sys.stdout.flush()
                        except Exception:
                            pass
                    if self.loud_sweep:
                        print("  %6.2fs  ★★★ RSSI FIREHOSE EVENT len=%d (curve=%d, %d bins)"
                              % (time.time() - self.t0, len(dec), curve, len(amps)))
                    return
                # string-keyed sweep-state EVENT (CURRENT_STATUS / CURRENT_SWEEP_STATUS / _ID):
                # this is how we MEASURE the sweep arming instead of inferring it.
                if self.loud_sweep:
                    se = _strkey_event_value(dec)
                    if se is not None:
                        key, val = se
                        if b"CURRENT_SWEEP_STATUS" in key:
                            print("  %6.2fs  ★★ SWEEP-STATE EVENT CURRENT_SWEEP_STATUS=%s"
                                  % (time.time() - self.t0, val.hex()))
                            return
                        if b"CURRENT_SWEEP_ID" in key:
                            print("  %6.2fs  ★★ SWEEP-ID EVENT=%s"
                                  % (time.time() - self.t0, val.hex()))
                            return
                        if b"CURRENT_STATUS" in key:
                            print("  %6.2fs  ★★ SWEEP-STATE EVENT CURRENT_STATUS=%s"
                                  % (time.time() - self.t0, val.hex()))
                            return
            # generic reply: dispatch ALL PDUs in this block (handling both 0x70 headers and 0x10 continuations)
            _i = 0
            _cur_vec = None
            _cur_hdr = None
            dispatched = False
            while _i + 1 < len(dec):
                _fl = dec[_i]
                if _fl & 0xf0 not in (0x70, 0x10):
                    break
                _ln = ((_fl & 0x0f) << 8) | dec[_i + 1]
                if _ln < 2 or _i + _ln > len(dec):
                    break
                if _fl & 0xf0 == 0x70:
                    if _ln >= 4 and _i + 4 <= len(dec):
                        _cur_vec = dec[_i + 2]
                        _cur_hdr = dec[_i + 3]
                        if _cur_hdr == 0x02 and _ln >= 8 and _i + 8 <= len(dec):
                            _addr = int.from_bytes(dec[_i + 4 : _i + 8], "big")
                            _val = dec[_i + 8 : _i + _ln]
                            self._dispatch_pdu(_cur_vec, _addr, _val)
                            dispatched = True
                        else:
                            p = dmp_parse(dec[_i : _i + _ln])
                            if p:
                                self._dispatch_pdu(p[0], p[1], p[2])
                                dispatched = True
                elif _fl & 0xf0 == 0x10:
                    if _cur_hdr == 0x02 and _ln >= 6 and _i + 6 <= len(dec):
                        _addr = int.from_bytes(dec[_i + 2 : _i + 6], "big")
                        _val = dec[_i + 6 : _i + _ln]
                        self._dispatch_pdu(_cur_vec, _addr, _val)
                        dispatched = True
                _i += _ln
            if not dispatched:
                p = dmp_parse(dec)
                if p:
                    self._dispatch_pdu(p[0], p[1], p[2])
                else:
                    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in dec[4:40])
                    print("  %6.2fs  DMP %-11s raw=%s  |%s|"
                          % (time.time() - self.t0, name, dec[:16].hex(), asc))
        except Exception as e:
            print("  [decode-handler error: %r  raw=%s]" % (e, dec[:24].hex()))

    def _dispatch_pdu(self, vector, addr, value):
        vec_name = DMP_VEC_NAMES.get(vector, "vec%d" % (vector if vector is not None else 0))
        print("  %6.2fs  DMP %-11s addr=0x%08x  val[%d]=%s"
              % (time.time() - self.t0, vec_name, addr, len(value), value[:16].hex()))

        # ANTENNA BIAS TELEMETRY: 0x01070470..0x01070475 (ports A..F)
        # Vector 3 = GET_REPLY, Vector 4 = EVENT (state change push)
        if vector in (3, 4) and 0x01070470 <= addr <= 0x01070475:
            if len(value) == 1 and value[0] in (0, 1):
                ant_letter = chr(ord("A") + (addr - 0x01070470))
                is_on = (value[0] == 1)
                print("  %6.2fs  ★ BIAS TELEMETRY Antenna %s = %s (addr=0x%08x)"
                      % (time.time() - self.t0, ant_letter, "ON" if is_on else "OFF", addr))
                sys.stdout.write("BIAS %s %d\n" % (ant_letter, 1 if is_on else 0))
                sys.stdout.flush()

        # HARDWARE TEMPERATURE TELEMETRY
        if addr in (0x0100007b, 0x010c0010, 0x01010104) and len(value) >= 1:
            raw_temp = int.from_bytes(value, "big")
            celsius = None
            if 250 <= raw_temp <= 400:
                celsius = raw_temp - 273.15
            elif 2500 <= raw_temp <= 4000:
                celsius = (raw_temp / 10.0) - 273.15
            elif 15 <= raw_temp <= 90:
                celsius = float(raw_temp)
            if celsius is not None:
                print("  %6.2fs  ★ TEMPERATURE TELEMETRY = %.1f°C (addr=0x%08x)"
                      % (time.time() - self.t0, celsius, addr))
                sys.stdout.write("TEMP %.1f\n" % celsius)
                sys.stdout.flush()

        # ACCESS-LEVEL probe: 0x01201106=access-level name (WWB reads "Admin"), plus
        # 0x01201102/1103/1003.
        if vector == 3 and addr in (0x01201106, 0x01201102, 0x01201103, 0x01201003):
            asc = "".join(chr(c) if 32 <= c < 127 else "." for c in value)
            print("  %6.2fs  ★ ACCESS-LEVEL 0x%08x = %r"
                  % (time.time() - self.t0, addr, asc))

        # SCAN-OWNERSHIP: 0x0107010f is the scan-id / CURRENT_REQUESTER_CID read that RESERVES
        # the scan slot (WWB gets =00).
        if vector == 3 and addr == 0x0107010f:
            self.scan_owned = True
            self.scan_id = int.from_bytes(value, "big") if value else 0
            if self.scan_id > 15:
                self.scan_id = 0
            print("  %6.2fs  ★★ SCAN-OWNERSHIP 0x0107010f REPLIED val=%s (scan-id=%d) — we own the slot"
                  % (time.time() - self.t0, value.hex(), self.scan_id))
            # Poll bias and subscribe for all 6 antenna ports on ownership
            for _i in range(6):
                self._send_block(dmp_pdu(DMP_GET, 0x01070470 + _i))
                self._send_block(dmp_pdu(DMP_SUBSCRIBE, 0x01070470 + _i))
            for _taddr in (0x0100007b, 0x010c0010, 0x01010104):
                self._send_block(dmp_pdu(DMP_GET, _taddr))

        # NON-OWNER signal: GET_FAIL (vector 9) on the ownership address.
        if vector == 9 and addr == 0x0107010f:
            self.scan_gfail = True
            print("  %6.2fs  ⚠️  SCAN-OWNERSHIP 0x0107010f GET_FAIL — NOT owner (GFAIL)"
                  % (time.time() - self.t0))

        # SCAN-READY milestone: the device PUSHES EVENT 0x01070137=0e ONLY for the scan-slot
        # owner once its scan engine is armed-ready.
        if vector == 4 and addr == 0x01070137:
            self.scan_ready = True
            print("  %6.2fs  ★★★ SCAN-READY EVENT 0x01070137=%s — owner milestone (arm gate open)"
                  % (time.time() - self.t0, value.hex() if value else "∅"))

    # ── print the device reliable-seq on every inbound wrapper (the freeze-threshold watch) ──
    def _dispatch(self, vec, vdata, now):
        super()._dispatch(vec, vdata, now)                     # base updates dev_rel + eager-ACKs
        if vec in (1, 2):
            kind = "REL " if vec == 1 else "UNREL"
            print("  %6.2fs  <- %s wrapper   device reliable-seq=0x%04x   [watch ~0x72b freeze]"
                  % (now - self.t0, kind, self.dev_rel))

    # ══════════════════════════ control-file command channel ══════════════════════════
    # Overrides WwbMirror._drain_commands (called by the base run loop on every iteration, in both
    # the socket-timeout branch and after each received datagram). We repurpose it to service the
    # control file and flush any DMP queued before the association came up.
    def _drain_commands(self, now):
        # On first connection milestone (proto_ok), query hardware bias and temp immediately
        if self.proto_ok and not getattr(self, "_connect_polled", False):
            self._connect_polled = True
            print("  %6.2fs  ★ CONNECTED TO AD600 (DMP READY) — Querying Bias for Ports A-F" % (now - self.t0))
            sys.stdout.write("CONNECTED\n")
            sys.stdout.flush()
            for _i in range(6):
                self._send_block(dmp_pdu(DMP_GET, 0x01070470 + _i))
                self._send_block(dmp_pdu(DMP_SUBSCRIBE, 0x01070470 + _i))
            for _taddr in (0x0100007b, 0x010c0010, 0x01010104):
                self._send_block(dmp_pdu(DMP_GET, _taddr))

        # flush sends queued before DMP was enabled
        if self.proto_ok and self.pending:
            for blk in self.pending:
                self._send_block(blk, queued=True)
            self.pending = []
        # AD600_WWB_EXACT verbatim-burst driver runs every loop iteration (time-scheduled, not reply-gated)
        if self.wwb_exact and self.wx is not None:
            self._drive_wwb_exact(now)
        # strict lock-step driver runs every loop iteration (independent of the file poll)
        if self.lockstep is not None:
            self._drive_lockstep(now)
        # AD600_OWNER_CLAIM phase controller runs every loop (settle timer + late claim + scan-ready
        # gate); it drives the arm AFTER the lock-step fan-out drains, so it runs whether or not
        # lockstep is currently loaded.
        if self.owner_claim:
            self._drive_owner_claim(now)
        # poll the control file for new lines (interval env-tunable for smooth-burst delivery)
        if now - self.last_poll < float(os.environ.get("AD600_POLL", "0.1")):
            return
        self.last_poll = now
        for line in self._read_new_lines():
            if self._quit:
                break
            try:
                self._exec(line, now)
            except Exception as e:
                print("  [command error on %r: %r]" % (line, e))

    # ── strict lock-step: ≤1 wrapper outstanding, wait for ALL its accepts, then next (WWB flow) ──
    @staticmethod
    def _wrapper_expect(blk):
        """Count PDUs (header-inheritance aware) and read the first PDU's vector → (n_pdus, vec0)."""
        n = 0; i = 0; vec0 = None
        while i + 1 < len(blk):
            fl = blk[i]
            if fl & 0xf0 not in (0x70, 0x10):
                break
            ln = ((fl & 0x0f) << 8) | blk[i + 1]
            if ln < 2 or i + ln > len(blk):
                break
            if fl & 0xf0 == 0x70 and vec0 is None:
                vec0 = blk[i + 2] if i + 2 < len(blk) else None
            n += 1
            i += ln
        return n, vec0

    def _load_lockstep(self, path=None):
        self.lockstep_path = path
        wraps = []
        lines = INIT_COMMANDS
        if path and path not in ("BUILTIN", "DEFAULT") and os.path.isfile(path):
            try:
                lines = open(path).read().splitlines()
            except Exception:
                lines = INIT_COMMANDS
        for raw in lines:
            h = raw.strip()
            if not h or h.startswith("#"):
                continue
            h = h.split()[-1]                      # tolerate "raw <hex>" or bare hex
            try:
                blk = bytes.fromhex(h)
            except ValueError:
                continue
            # AD600_RT_COMPRESSION: retune DELIVERED resolution (RBW = comp * 25 kHz). Patches the
            # REAL_TIME_COMPRESSION value in the config-SET block only; every other block passes
            # through untouched. Unset/0 → feed verbatim (default 900 kHz). e.g. 14 → 350 kHz.
            if self._rt_comp:
                _patched = rewrite_rt_compression(blk, self._rt_comp)
                if _patched != blk and not getattr(self, "_rt_comp_logged", False):
                    print("  %6.2fs  RBW: REAL_TIME_COMPRESSION → %d (delivered RBW = %d kHz)"
                          % (time.time() - self.t0, self._rt_comp, self._rt_comp * 25))
                    self._rt_comp_logged = True
                blk = _patched
            # AD600_SCAN_START_KHZ / AD600_SCAN_STOP_KHZ: retune scan range (config-SET block only)
            if self._scan_start_khz or self._scan_stop_khz:
                _patched = rewrite_scan_range(blk, self._scan_start_khz or None,
                                              self._scan_stop_khz or None)
                if _patched != blk and not getattr(self, "_range_logged", False):
                    print("  %6.2fs  RANGE: SCAN_START/STOP → %s-%s kHz"
                          % (time.time() - self.t0, self._scan_start_khz or "·",
                             self._scan_stop_khz or "·"))
                    self._range_logged = True
                blk = _patched
            # AD600_SCAN_STEP_KHZ / AD600_RBW_KHZ: measurement step + filter BW (capability probe)
            if self._step_khz or self._rbw_khz:
                _patched = rewrite_scan_step_rbw(blk, self._step_khz or None, self._rbw_khz or None)
                if _patched != blk and not getattr(self, "_step_logged", False):
                    print("  %6.2fs  STEP/RBW: SCAN_STEP_FREQ → %s kHz, SCAN_RESOLUTION_BW → %s kHz"
                          % (time.time() - self.t0, self._step_khz or "·", self._rbw_khz or "·"))
                    self._step_logged = True
                blk = _patched
            # AD600_CURVE_SELECT: hardware curve bitmask
            if self._curve_mask:
                _patched = rewrite_curve_select(blk, self._curve_mask)
                if _patched != blk and not getattr(self, "_curve_mask_logged", False):
                    print("  %6.2fs  CURVE: CURVE_SELECT → 0x%02x"
                          % (time.time() - self.t0, self._curve_mask))
                    self._curve_mask_logged = True
                blk = _patched
            # AD600_REPEAT: continuous (0xFF/255) vs single-shot (1)
            if self._repeat:
                _patched = rewrite_repeat_request(blk, self._repeat)
                if _patched != blk and not getattr(self, "_repeat_logged", False):
                    print("  %6.2fs  REPEAT: SCAN_REPEAT_REQUEST → %d (%s)"
                          % (time.time() - self.t0, self._repeat, "single-shot" if self._repeat == 1 else "continuous"))
                    self._repeat_logged = True
                blk = _patched
            n, vec0 = self._wrapper_expect(blk)
            # ── AD600_OWNER_CLAIM: the GET 0x0107010f is the OWNERSHIP CLAIM — it must NOT ride the
            # early feed (early / non-owner draws a GFAIL and poisons the session). DEFER it out of
            # the early fan-out here; _send_owner_claim re-injects it ONCE, LATE, after the priming
            # settle (mirror WWB t≈3.4). SET 0x0109002a stays spurious (dropped, never re-sent). This
            # is a DISTINCT log from DROP-SPURIOUS so the dry-run shows 0x0107010f DEFERRED, not gone.
            if self.owner_claim and b"\x01\x07\x01\x0f" in blk:
                if not getattr(self, "_oc_defer_logged", False):
                    print("  %6.2fs  OWNER-CLAIM: deferring GET 0x0107010f out of the early feed → "
                          "re-sent LATE as the ownership claim after %.1fs priming settle"
                          % (time.time() - self.t0, self.prime_settle))
                    self._oc_defer_logged = True
                continue
            if self.owner_claim and b"\x01\x09\x00\x2a" in blk:
                if not getattr(self, "_oc_2a_logged", False):
                    print("  %6.2fs  OWNER-CLAIM: dropping SET 0x0109002a (spurious; never sent)"
                          % (time.time() - self.t0))
                    self._oc_2a_logged = True
                continue
            # ── AD600_DROP_SPURIOUS=1 (staged firehose fix): the WWB-faithful run must NOT emit the two
            # PDUs the root-cause diff flagged as spurious — GET 0x0107010f (SCAN_ID read, which
            # reserves/bumps the scan slot) and SET 0x0109002a (FREQCOMPAT module-open). Drop ANY feed
            # wrapper carrying either 4-byte DMP address. Flag unset → feed stays byte-for-byte verbatim
            # (all other modes unchanged). Distinct from SCANID_ONCE (which only drops REPEAT reads).
            if os.environ.get("AD600_DROP_SPURIOUS") == "1" and (
                    b"\x01\x07\x01\x0f" in blk or b"\x01\x09\x00\x2a" in blk):
                if not getattr(self, "_drop_spurious_logged", False):
                    print("  %6.2fs  DROP-SPURIOUS: suppressing GET 0x0107010f + SET 0x0109002a "
                          "from feed (WWB-faithful; never sent)" % (time.time() - self.t0))
                    self._drop_spurious_logged = True
                continue
            # ── AD600_SCANID_ONCE: read the SCAN_ID (0x0107010f) EXACTLY ONCE. That GET RESERVES the
            # scan slot and each RE-READ BUMPS the reservation id (0→1), de-syncing the /SCAN=N that
            # RSSI/CURRENT_* were subscribed at (the firehose_native bug). On every reload AFTER the
            # id has been answered once (self.scan_owned), DROP the repeat GET 0x0107010f so N is
            # read a single time and then HELD. Other modes (flag unset) keep the feed verbatim.
            if (os.environ.get("AD600_SCANID_ONCE") == "1" and self.scan_owned
                    and vec0 == 1 and b"\x01\x07\x01\x0f" in blk):
                if not getattr(self, "_scanid_once_logged", False):
                    print("  %6.2fs  SCANID-ONCE: suppressing repeat GET 0x0107010f "
                          "(owned scan-id=%s held; no re-read)"
                          % (time.time() - self.t0, self.scan_id))
                    self._scanid_once_logged = True
                continue
            # expected replies + which timeout: SUB(7)→n accepts; GET(1)→n replies; SET(2)/other→0 (settle)
            if vec0 == 7:
                wraps.append((blk, n, "sub"))
            elif vec0 == 1:
                wraps.append((blk, n, "get"))
            else:
                wraps.append((blk, 0, "set"))
        # ── AD600_UNBATCH=1: winning_v2's recipe. Flatten EVERY batched SUBSCRIBE wrapper into
        # individual single-address SUBSCRIBE PDUs (70 08 07 02 <addr>), ONE PDU per SDT reliable
        # wrapper, preserving the exact feed order. GET/SET wrappers pass through untouched (the
        # task requires only subscribes be un-batched). With the reply-gated driver keeping ≤
        # max_outstanding(=AD600_MAX_OUTSTANDING_SUBS) subscriptions un-accepted, the device's DMP
        # input queue is never overrun and its dequeue frontier walks the whole 0x0107 scan tree in
        # ONE pass — instead of the 12-cap the batched feed hits. Done BEFORE the arm-split so the
        # RF_SCAN string-key subscribes (sweep-status + the 6 RSSI curves) are individualised too.
        if self.unbatch:
            flat = []; n_wrap_in = 0; n_pdu_out = 0
            for blk, expected, kind in wraps:
                if kind == "sub":
                    n_wrap_in += 1
                    for pdu in flatten_subscribe_wrapper(blk):
                        flat.append((pdu, 1, "sub")); n_pdu_out += 1
                else:
                    flat.append((blk, expected, kind))
            wraps = flat
            print("  %6.2fs  UNBATCH: flattened %d subscribe wrapper(s) → %d single-address "
                  "SUBSCRIBE PDUs (1 PDU/wrapper); GET/SET wrappers unchanged; gate=OUTSTANDING-"
                  "SUBS cap=%d"
                  % (time.time() - self.t0, n_wrap_in, n_pdu_out, self.max_outstanding))
        # capture the RF_SCAN arm wrappers (status/config/RSSI string keys + the numeric START
        # 0x01070103) so AD600_AUTO_ARM can re-issue them rewritten to the live /SCAN=N once owned.
        # The arm begins at the first RF_SCAN string-key block; the fan-out (subs+gets, INCLUDING the
        # single 0x0107010f read that claims ownership) is everything BEFORE it.
        orig_wraps = list(wraps)
        _first_rf = next((i for i, (blk, _e, _k) in enumerate(orig_wraps) if b"RF_SCAN" in blk), len(orig_wraps))
        self.arm_blocks = [blk for (blk, _e, _k) in orig_wraps[_first_rf:]
                           if (b"RF_SCAN" in blk) or (len(blk) >= 9 and blk[:8].hex() == "7009020201070103")]
        # AD600_AUTO_ARM: persist ONLY the fan-out (subs+gets incl the 0x0107010f read). EXCLUDE the arm
        # (status/config/RSSI) AND the START and any post-START SETs — sending START every persistence
        # pass fires it prematurely and BUMPS the reservation id (the firehose_native bug). The arm is
        # fired ONCE by _fire_arm the instant 0x0107010f replies, at the owned /SCAN=N.
        if os.environ.get("AD600_AUTO_ARM") == "1":
            wraps = orig_wraps[:_first_rf]
            print("  %6.2fs  ARM-SPLIT: persist %d fan-out wrappers (incl 0x0107010f read); %d arm "
                  "wrappers held for one-shot /SCAN=N arm on ownership"
                  % (time.time() - self.t0, len(wraps), len(self.arm_blocks)))
        # ── COMBINED-MODE arm-split (AD600_ARM_ON_STATUS): a DIFFERENT boundary from AUTO_ARM. The
        # three RF_SCAN:CURRENT_* status subs (the gate objects) STAY in the persisted fan-out; ONLY
        # the config SETs / RSSI leaves / numeric START are held as the one-shot arm (see
        # _is_arm_block). Fan-out = every wrapper before the first arm block (that includes the three
        # CURRENT_* subs, since config SETs follow them in the feed); arm = the arm blocks only,
        # dropping the post-START CFL/SSM tail. Recomputed here so it overrides the AUTO_ARM split
        # above (the two modes are mutually exclusive in the launchers).
        if self.arm_on_status:
            _first_arm = next((i for i, (blk, _e, _k) in enumerate(orig_wraps) if _is_arm_block(blk)),
                              len(orig_wraps))
            self.arm_blocks = [blk for (blk, _e, _k) in orig_wraps[_first_arm:] if _is_arm_block(blk)]
            wraps = orig_wraps[:_first_arm]
            n_status = sum(1 for (blk, _e, _k) in wraps
                           if any(k in blk for k in _STATUS_KEYS))
            print("  %6.2fs  ARM-ON-STATUS SPLIT: persist %d fan-out wrappers (incl %d CURRENT_* "
                  "status subs + 0x01090201-0224 deep tree); hold %d arm wrappers (config SETs → "
                  "RSSI leaves → bare START) until CURRENT_SWEEP_STATUS accepted"
                  % (time.time() - self.t0, len(wraps), n_status, len(self.arm_blocks)))
        # AD600_ACCESS_PROBE=1: prepend access-level GETs so we log Admin/restricted BEFORE the fan-out
        # (right after association). Each is its own single-GET wrapper, lock-stepped like any get.
        if os.environ.get("AD600_ACCESS_PROBE") == "1":
            probe = [dmp_pdu(DMP_GET, a) for a in (0x01201106, 0x01201102, 0x01201103, 0x01201003)]
            wraps = [(blk, 1, "get") for blk in probe] + wraps
            print("  %6.2fs  ACCESS-PROBE prepended (GET 0x01201106/1102/1103/1003 before fan-out)"
                  % (time.time() - self.t0))
        # ── AD600_MODULE_ENABLE: the FREQCOMPAT module-open SETs (the newly-found key). Latch the
        # device state that makes the 0x01090201-0224 deep scan-module subtree INSTANTIABLE for our
        # session — our failing runs OMITTED these and the device silently dropped every 0x0109 deep
        # sub even after 23 persist passes. Prepended to the FRONT of the fan-out so they lead EVERY
        # pass, BEFORE the persisted 0x0109 deep subs. Bytes match WWB/ownership_fresh feed
        # (SET 0x0109002a=01, SET 0x0109002a=02) + the FREQCOMPAT enable SET 0x01090020=01. Sent as
        # settle wrappers (no reply expected). Flag unset → other modes are byte-for-byte unchanged.
        if os.environ.get("AD600_MODULE_ENABLE") == "1":
            mod = [bytes.fromhex(x) for x in (
                "700902020109002a01",      # SET 0x0109002a = 01  (FREQCOMPAT module-open, WWB feed)
                "700902020109002a02",      # SET 0x0109002a = 02  (FREQCOMPAT module-open, WWB feed)
                "700902020109002001")]     # SET 0x01090020 = 01  (FREQCOMPAT module enable)
            wraps = [(b, 0, "set") for b in mod] + wraps
            print("  %6.2fs  MODULE-ENABLE: prepended 3 FREQCOMPAT module-open SETs "
                  "(0x0109002a=01, 0x0109002a=02, 0x01090020=01) BEFORE the fan-out "
                  "(lead every pass; latch the 0x0109 deep-tree instantiation)"
                  % (time.time() - self.t0))
        self.lockstep = wraps
        self.ls_idx = 0
        self.ls_batch_end = 0
        self.ls_waiting = False
        if self.reply_gated:
            print("  %6.2fs  REPLY-GATED driver ACTIVE — ≤%d wrapper(s) outstanding, advance on "
                  "ACTUAL replies (fallback %.1fs/%.1fs sub/get)"
                  % (time.time() - self.t0, self.max_outstanding, self.ls_to_sub, self.ls_to_get))
        print("  %6.2fs  LOCKSTEP LOADED %d wrappers from %s"
              % (time.time() - self.t0, len(wraps), path or "BUILTIN"))

    def _drive_lockstep(self, now):
        if not self.proto_ok:
            return
        # EAGER auto-arm: the instant we own the scan (0x0107010f answered), interrupt persistence and
        # arm at the live /SCAN=N — minimises further 0x0107010f reads that would bump the id.
        if (os.environ.get("AD600_AUTO_ARM") == "1" and self.scan_owned
                and not self.armed and self.arm_blocks):
            self._fire_arm(now)
            return
        # EAGER ARM-ON-STATUS: the instant CURRENT_SWEEP_STATUS is SUB_ACCEPTed (detected mid-pass at
        # the gate-clear below), interrupt persistence and fire the arm ONCE at /SCAN=0.
        # In OWNER-CLAIM mode this eager fire is SUPPRESSED: the arm is gated on the scan-ready EVENT
        # 0x01070137=0e (owner milestone), fired by _drive_owner_claim — NOT on the CURRENT_SWEEP_STATUS
        # accept (which we get as a non-owner too, and firing then no-ops START / poisons the session).
        if (self.arm_on_status and not self.owner_claim
                and self.status_accepted["CURRENT_SWEEP_STATUS"]
                and not self.armed_status and self.arm_blocks):
            self._fire_arm_status(now)
            return
        if now < self.ls_hold_until:          # loop-gap pause (AD600_HOLD_LOOP between passes)
            return
        if self.ls_waiting:
            ready = (self.app_replies >= self.ls_target and now >= self.ls_min_time)
            if not (ready or now >= self.ls_deadline):
                return
            # TRUE REPLY-GATING: 'replies-in' (the batch's accepts/replies actually arrived) is the
            # DEFAULT clear path — it means the device DRAINED this batch, so it has queue room for
            # the next one. 'TIMEOUT' is now only the anti-deadlock FALLBACK (long ls_to_* window)
            # for a genuinely dropped reply; it must NOT be the routine advance. Advance past the
            # WHOLE batch that was outstanding (ls_batch_end), not a single wrapper.
            tag = "replies-in" if ready else "TIMEOUT(fallback)"
            print("  %6.2fs  <- batch #%d-%d gate cleared (%s)  app_replies=%d/%d  accepts=%d"
                  % (now - self.t0, self.ls_idx + 1, self.ls_batch_end, tag,
                     self.app_replies, self.ls_target, self.vec12_accepts))
            # CROSS-PASS ACCEPT TRACKING: only when the gate cleared on ACTUAL replies-in (not the
            # timeout fallback) AND the batch produced at least as many SUB_ACCEPTs (vec12) as it had
            # subscribe wrappers, attribute those accepts to the batch's subs. A batch that timed out
            # (the classic "silently dropped" status/deep-tree subs) is NOT marked — so persistence
            # keeps re-sending it until the device finally accepts it and this fires.
            if ready and self.loud_sweep:
                got = self.vec12_accepts - self.ls_batch_acc0
                nsub = sum(1 for k in range(self.ls_idx, self.ls_batch_end)
                           if self.lockstep[k][2] == "sub")
                if nsub and got >= nsub:
                    self._mark_batch_accepted(self.ls_idx, self.ls_batch_end, now)
            self.ls_waiting = False
            self.ls_idx = self.ls_batch_end
        if self.ls_idx >= len(self.lockstep):
            self.ls_loops += 1
            print("  %6.2fs  ✓ LOCKSTEP COMPLETE (pass %d) — %d wrappers, %d accepts, %d app-replies"
                  % (now - self.t0, self.ls_loops, self.ls_idx, self.vec12_accepts, self.app_replies))
            # COMBINED MODE: per-pass ACCEPTED-BRANCHES summary so the operator SEES the fan-out
            # crossing the tree live (0x0107 leaf tree, 0x0109 deep scan-module tree, CURRENT_* gate).
            if self.loud_sweep:
                self._print_branch_summary(now)
            # ARM-ON-STATUS: the instant CURRENT_SWEEP_STATUS is accepted, stop persistence and fire
            # the arm ONCE at /SCAN=0 (config SETs → RSSI leaves → bare START). START never fires
            # before this gate — it is the LAST arm wrapper and the arm only begins here.
            # OWNER-CLAIM mode suppresses this (arm is gated on the scan-ready EVENT, see above).
            if (self.arm_on_status and not self.owner_claim
                    and self.status_accepted["CURRENT_SWEEP_STATUS"]
                    and not self.armed_status and self.arm_blocks):
                self._fire_arm_status(now)
                return
            # PERSIST BUDGET CAP: don't loop forever if the device never flips the refusal. After
            # max_passes or the time budget, still attempt the arm best-effort (so a live operator
            # still gets a shot + the accept ledger) and report.
            if (self.persist_until_status and not self.status_accepted["CURRENT_SWEEP_STATUS"]
                    and (self.ls_loops >= self.max_passes or (now - self.t0) > self.persist_budget)):
                print("  %6.2fs  ⚠️  PERSIST BUDGET EXHAUSTED (pass %d / %.0fs) — CURRENT_SWEEP_STATUS "
                      "still NOT accepted; refusal never flipped this run."
                      % (now - self.t0, self.ls_loops, now - self.t0))
                if self.arm_on_status and self.arm_blocks and not self.armed_status:
                    print("  %6.2fs  → best-effort arm anyway (report only; expect no firehose)"
                          % (now - self.t0))
                    self._fire_arm_status(now)
                    return
                self.lockstep = None
                return
            # AD600_HOLD_LOOP=1: re-subscribe in a loop (fresh accept counters each pass) so we CAPTURE
            # the restricted→permissive TRANSITION when the operator triggers the device (WWB/power-cycle).
            # AUTO-ARM: the instant we OWN the scan (0x0107010f answered), stop persistence and fire the
            # RF_SCAN arm rewritten to the LIVE /SCAN=N — exactly once, no more 0x0107010f reads (each
            # read bumps the reservation id and invalidates /SCAN=N — the bug in the timed-out run).
            if os.environ.get("AD600_AUTO_ARM") == "1" and self.scan_owned and not self.armed and self.arm_blocks:
                self._fire_arm(now)
                return
            # persist across passes until owned (LOOP_UNTIL_OWN), until CURRENT_SWEEP_STATUS accepted
            # (PERSIST_UNTIL_STATUS — the combined mode), or plain HOLD_LOOP
            loop = (os.environ.get("AD600_HOLD_LOOP") == "1"
                    or (os.environ.get("AD600_LOOP_UNTIL_OWN") == "1" and not self.scan_owned)
                    or (self.persist_until_status
                        and not self.status_accepted["CURRENT_SWEEP_STATUS"]))
            if loop and self.lockstep_path and not self.armed and not self.armed_status:
                self.vec12_accepts = 0
                self.app_replies = 0
                self._load_lockstep(self.lockstep_path)   # reloads: ls_idx=0, ls_waiting=False, +access probe
                self.ls_hold_until = now + float(os.environ.get("AD600_HOLD_GAP", "3.0"))  # gap between passes
                return
            self.lockstep = None
            return
        # ── send the next batch (≤ max_outstanding wrappers) and set its reply-gate ──
        self._send_next_batch(now)

    def _send_next_batch(self, now):
        """Send up to `max_outstanding` wrappers starting at ls_idx as ONE outstanding batch, then
        arm the reply-gate on the batch's total expected replies.

        In legacy mode (reply_gated False → max_outstanding 1) this sends exactly one wrapper and
        behaves identically to the old per-wrapper send. In reply-gated mode it keeps up to
        AD600_MAX_OUTSTANDING (WWB's measured peak = 2) command wrappers in flight and lets the
        gate above clear on the ACTUAL replies, so the device drains between batches instead of
        being buried by a timed burst. No-reply wrappers (SET/vec08) are always kept solo so their
        settle floor applies cleanly and they never ride a reply-expecting batch's timeout."""
        i = self.ls_idx
        batch_expected = 0
        kinds = []
        self.ls_batch_acc0 = self.vec12_accepts   # snapshot for per-batch accept attribution
        while i < len(self.lockstep) and (i - self.ls_idx) < self.max_outstanding:
            blk, expected, kind = self.lockstep[i]
            if expected == 0 and i > self.ls_idx:
                break                              # start a fresh batch for the no-reply wrapper
            self._send_block(blk)
            kinds.append(kind)
            batch_expected += expected
            i += 1
            if expected == 0:
                break                              # a solo no-reply wrapper: settle, then advance
        self.ls_batch_end = i
        if batch_expected > 0:
            self.ls_target = self.app_replies + batch_expected
            self.ls_min_time = now
            # sub windows are the longer of the two; use it if ANY wrapper in the batch is a sub.
            self.ls_deadline = now + (self.ls_to_sub if "sub" in kinds else self.ls_to_get)
        else:
            self.ls_target = self.app_replies
            settle = float(os.environ.get("AD600_VEC08_GAP", "0.8")) if "vec08" in kinds else self.ls_settle
            self.ls_min_time = now + settle       # vec-08 holds ~800ms before START (WWB's timing)
            self.ls_deadline = now + settle
        self.ls_waiting = True

    def _mark_batch_accepted(self, lo, hi, now):
        """Attribute the SUB_ACCEPTs of the just-cleared batch [lo,hi) to their subscribe identities
        (cross-pass ledger). Sets status_accepted[...] / deep0109_accepted and prints a LOUD line the
        first time the CURRENT_SWEEP_STATUS gate (or any CURRENT_* / deep-tree branch) is crossed."""
        for k in range(lo, hi):
            blk, _expected, kind = self.lockstep[k]
            if kind != "sub":
                continue
            for kind2, ident in _sub_identities(blk):
                self.accepted_ids.add(ident)
                if kind2 == "str" and ident in self.status_accepted and not self.status_accepted[ident]:
                    self.status_accepted[ident] = True
                    star = "★★★" if ident == "CURRENT_SWEEP_STATUS" else "★"
                    print("  %6.2fs  %s STATUS SUB ACCEPTED: %s%s"
                          % (now - self.t0, star, ident,
                             "  ← GATE OPEN (arm now)" if ident == "CURRENT_SWEEP_STATUS" else ""))
                elif kind2 == "num" and 0x01090201 <= ident <= 0x01090224 \
                        and ident not in self.deep0109_accepted:
                    self.deep0109_accepted.add(ident)
                    print("  %6.2fs  ★ DEEP-TREE SUB ACCEPTED 0x%08x (0x01090201-0224: %d/36)"
                          % (now - self.t0, ident, len(self.deep0109_accepted)))

    def _print_branch_summary(self, now):
        """Per-pass 'accepted branches' summary: how far the fan-out has instantiated for our
        session — the 0x0107 leaf tree, the 0x0109 deep scan-module tree (esp 0x01090201-0224), and
        which of the three CURRENT_* gate subs are accepted yet."""
        n0107 = sum(1 for a in self.accepted_ids
                    if isinstance(a, int) and 0x01070000 <= a < 0x01080000)
        n0109 = sum(1 for a in self.accepted_ids
                    if isinstance(a, int) and 0x01090000 <= a < 0x010a0000)
        st = self.status_accepted
        print("  %6.2fs  ── ACCEPTED-BRANCHES pass=%d ── 0x0107=%d  0x0109=%d "
              "(0x01090201-0224=%d)  SWEEP_STATUS=%s  SWEEP_ID=%s  STATUS=%s"
              % (now - self.t0, self.ls_loops, n0107, n0109, len(self.deep0109_accepted),
                 "✓" if st["CURRENT_SWEEP_STATUS"] else "·",
                 "✓" if st["CURRENT_SWEEP_ID"] else "·",
                 "✓" if st["CURRENT_STATUS"] else "·"))

    def _fire_arm_status(self, now):
        """Fire WWB's RF_SCAN arm ONCE at /SCAN=0 after the CURRENT_SWEEP_STATUS gate opened. Arm =
        the held arm_blocks in FEED ORDER: the 8 RF_SCAN config SETs → the 6 &RF_SCAN_DATA:RSSI
        subscribe leaves → the bare numeric START (SET 0x01070103=00). START is the LAST wrapper, so
        it never fires before CURRENT_SWEEP_STATUS is accepted. NO /SCAN rewrite (WWB arms at SCAN=0),
        NO further 0x0107010f reads. Driven through the same reply-gated ≤max_outstanding sender."""
        arm = []
        for blk in self.arm_blocks:
            n, vec0 = self._wrapper_expect(blk)
            if vec0 == 7:                       # RSSI subscribe leaves → accept-gated
                arm.append((blk, n, "sub"))
            elif vec0 == 1:                     # (none expected, but keep the get path honest)
                arm.append((blk, n, "get"))
            else:                               # config SETs + bare START → settle (no reply)
                arm.append((blk, 0, "set"))
        self.armed_status = True
        self.armed = True                       # belt: also blocks any AUTO_ARM path if co-enabled
        self.lockstep = arm
        self.ls_idx = 0
        self.ls_batch_end = 0
        self.ls_waiting = False
        self.ls_hold_until = 0.0
        print("  %6.2fs  ✪✪ ARM-ON-STATUS firing RF_SCAN arm at /SCAN=0 (%d wrappers: config SETs → "
              "RSSI leaves → bare START 0x01070103=00, START LAST) — expect RSSI accepts then firehose"
              % (now - self.t0, len(arm)))
        self._send_next_batch(now)

    # ══════════════════════ AD600_OWNER_CLAIM — late ownership claim + scan-ready-gated arm ══════════════════════
    def _drive_owner_claim(self, now):
        """Phase controller for AD600_OWNER_CLAIM. Runs every loop AFTER the lock-step driver. Sequence
        (mirrors wwb_onboard_scan's producing order):
          fanout        → play the clean-grant fan-out ONCE (0x0107010f DEFERRED, 0x0109002a dropped)
          settle        → hold ~AD600_PRIME_SETTLE s (device finishing scan-engine init; WWB's ~2.8s gap)
          wait_owner    → having sent LATE: SUB 0x01090201 (isolated) + GET 0x0107010f (ownership claim),
                          decide OWNER (GET_REPLY) vs NOT-OWNER (GET_FAIL / silent → ABORT, no arm)
          wait_scanready→ gate the arm on the device PUSHING EVENT 0x01070137=0e (owner milestone)
          armed/aborted → fire the arm ONCE, or abort without poisoning the session."""
        if not self.proto_ok or self.oc_aborted or self.armed_status:
            return
        # PHASE fanout: wait for the clean grant fan-out to drain (one pass, not looped)
        if self.oc_phase == "fanout":
            if self.lockstep is None and self.ls_loops >= 1:
                self.oc_settle_until = now + self.prime_settle
                self.oc_phase = "settle"
                print("  %6.2fs  OWNER-CLAIM: clean-grant fan-out complete → PRIMING SETTLE %.1fs "
                      "(device finishing scan-engine init) before the LATE ownership claim (WWB t≈3.4)"
                      % (now - self.t0, self.prime_settle))
            return
        # PHASE settle: hold the priming gap, then send the LATE isolated claim
        if self.oc_phase == "settle":
            if now >= self.oc_settle_until:
                self._send_owner_claim(now)
            return
        # PHASE wait_owner: GET 0x0107010f reply or SCAN-READY EVENT is the OWNER / NOT-OWNER verdict
        if self.oc_phase == "wait_owner":
            if self.scan_owned or self.scan_ready:
                if self.scan_ready and not self.scan_owned:
                    self.scan_owned = True
                    self.scan_id = 0
                print("  %6.2fs  ★★★ OWNERSHIP CLAIMED (slot %d) — %s; arming sweep"
                      % (now - self.t0, self.scan_id or 0,
                         "EVENT 0x01070137 pushed" if self.scan_ready else "GET 0x0107010f ANSWERED"))
                self.oc_scanready_deadline = now + self.scanready_timeout
                self.oc_phase = "wait_scanready"
                # if the device already pushed scan-ready, arm on the next tick (handled below)
            elif self.scan_gfail or now >= self.oc_claim_deadline:
                why = "GFAIL" if self.scan_gfail else ("silent %.1fs timeout" % self.owner_claim_timeout)
                print("  %6.2fs  ⚠️  NOT OWNER (0x0107010f %s) — need boot-first / WWB off; "
                      "ABORTING arm to avoid poisoning" % (now - self.t0, why))
                self.oc_aborted = True
                self.oc_phase = "aborted"
                self._quit = True
                self.run_for = 0.0
            return
        # PHASE wait_scanready: arm when scan-ready event is pushed or immediately upon ownership
        if self.oc_phase == "wait_scanready":
            if self.scan_ready:
                print("  %6.2fs  ✪✪ SCAN-READY gate open — ARM firing"
                      % (now - self.t0))
                self.oc_phase = "armed"
                self._fire_arm_status(now)   # config SETs → 6 RSSI subs → bare START (LAST)
            elif now >= self.oc_scanready_deadline:
                print("  %6.2fs  ✪✪ SCAN-READY deadline reached — force ARM firing"
                      % (now - self.t0))
                self.oc_phase = "armed"
                self._fire_arm_status(now)
            return

    def _send_owner_claim(self, now):
        """LATE, isolated (mirrors WWB): re-subscribe 0x01090201 (t=2.811 in WWB, accepted only once
        the 0x0109/scan subtree has initialised) then read GET 0x0107010f (t=3.401) — the SCAN-OWNERSHIP
        claim. Sent ONCE, here, after the priming settle — never in the early fan-out."""
        sub_0201 = dmp_pdu(DMP_SUBSCRIBE, 0x01090201)
        get_010f = dmp_pdu(DMP_GET, 0x0107010f)
        print("  %6.2fs  OWNER-CLAIM: sending LATE isolated claim — SUB 0x01090201 then "
              "GET 0x0107010f (ownership claim); reply decides OWNER vs NOT-OWNER"
              % (now - self.t0))
        self._send_block(sub_0201)
        self._send_block(get_010f)
        self.oc_claim_deadline = now + self.owner_claim_timeout
        self.oc_phase = "wait_owner"

    def _fire_arm(self, now):
        """Fire WWB's RF_SCAN arm (status subs → config SETs → RSSI subs → START) rewritten to the
        live scan-id N, strict lock-step. Called once, right after ownership, with NO further reads."""
        N = self.scan_id if self.scan_id is not None else 0
        # AD600_VEC08=1: fire WWB's STANDALONE vec-0x08 RF_SCAN:CURRENT_STATUS/SCAN=N "register" subscribe
        # (a distinct DMP vector our client normally never emits) right BEFORE START — WWB's sweep-trigger.
        vec08 = rewrite_scan_idx(
            bytes.fromhex("70230807001f52465f5343414e3a43555252454e545f5354415455532f5343414e3d30"), N)
        arm = []
        for blk in self.arm_blocks:
            if b"RF_SCAN" in blk:
                blk = rewrite_scan_idx(blk, N)                 # /SCAN=0 → /SCAN=N in the string keys
                n, vec0 = self._wrapper_expect(blk)
                arm.append((blk, n, "sub" if vec0 == 7 else ("get" if vec0 == 1 else "set")))
            else:                                              # numeric START 0x01070103 = N
                if os.environ.get("AD600_VEC08") == "1":
                    arm.append((vec08, 0, "vec08"))            # standalone vec-08 register, ~before START
                arm.append((dmp_pdu(DMP_SET, 0x01070103, bytes([N & 0xff])), 0, "set"))
        self.armed = True
        self.lockstep = arm
        self.ls_idx = 0
        self.ls_batch_end = 0
        self.ls_waiting = False
        self.ls_hold_until = 0.0
        print("  %6.2fs  ✪✪ AUTO-ARM firing RF_SCAN arm at /SCAN=%d (%d wrappers) — expect RSSI accepts then firehose"
              % (now - self.t0, N, len(arm)))
        # fire the first arm batch through the same reply-gated sender (≤ max_outstanding); the
        # rest of the arm is driven by _drive_lockstep on subsequent iterations.
        self._send_next_batch(now)

    # ══════════════════════ AD600_WWB_EXACT — verbatim wrapper-stream replay ══════════════════════
    def _load_wwb_exact(self, path):
        """Load WWB's EXACT ctrl->dev wrapper stream (captures/wwb_wrapper_exact.txt). Each line is
        one SDT reliable wrapper: 't=<rel_s> nblk=.. npdu=.. vec0=.. <blockhex>|<blockhex>|...'. The
        blocks on a line SHARED one SDT wrapper on WWB's wire (here nblk=1 throughout — WWB sent one
        FAT multi-PDU DMP block per wrapper); we keep that grouping verbatim. Preserves WWB's exact
        inter-wrapper timing except idle gaps clamped to AD600_WWB_MAXGAP (collapse the ~18.8s operator
        idle without touching the 2-145ms burst or the ~1s CFL pauses)."""
        wx = []
        for raw in open(path).read().splitlines():
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            rel = 0.0
            fields = s.split()
            for f in fields:
                if f.startswith("t="):
                    try:
                        rel = float(f[2:])
                    except ValueError:
                        rel = 0.0
            blockspec = fields[-1]                       # the '|'-joined hex blocks
            try:
                blocks = [bytes.fromhex(h) for h in blockspec.split("|") if h]
            except ValueError:
                continue
            if blocks:
                wx.append((rel, blocks))
        if not wx:
            print("  [WWB-EXACT: no wrappers loaded from %s]" % path)
            return
        # cumulative clamped send-offsets (burst cadence; idle gaps collapsed)
        sched = [0.0]
        for i in range(1, len(wx)):
            gap = wx[i][0] - wx[i - 1][0]
            gap = min(max(gap, 0.0), self.wx_maxgap)
            sched.append(sched[-1] + gap)
        self.wx = wx
        self.wx_sched = sched
        self.wx_idx = 0
        self.wx_t0 = None
        self.wx_done = False
        self.wx_pass = 0
        nblk = sum(len(b) for _r, b in wx)
        npdu = sum(len(_walk_pdus(blk)) for _r, b in wx for blk in b)
        nsub = sum(1 for _r, b in wx for blk in b for (v, h, d) in _walk_pdus(blk) if v == 7)
        multi = sum(1 for _r, b in wx if len(b) > 1)
        avg = npdu / max(1, len(wx))
        print("  %6.2fs  WWB-EXACT LOADED %d wrappers (%d DMP blocks, %d PDUs, %d subscribes; "
              "avg %.2f PDUs/wrapper, %d multi-block wrappers) from %s"
              % (time.time() - self.t0, len(wx), nblk, npdu, nsub, avg, multi, path))
        print("  %6.2fs  WWB-EXACT delivery = FAT blocks (WWB's grouping, NOT flattened), BURST "
              "(NOT reply-gated), maxgap-clamp=%.2fs, one association / no re-JOIN%s"
              % (time.time() - self.t0, self.wx_maxgap,
                 (", repeat<=%d full re-bursts if no firehose" % self.wx_repeat) if self.wx_repeat else ""))

    def _send_wrapper_blocks(self, blocks):
        """Send one SDT reliable wrapper carrying `blocks` (each a plaintext DMP block, re-encrypted
        under OUR session at the continuous tx position). One block → reuse _send_block (=_send_dmp:
        exactly one 0x102 client block per reliable wrapper, WWB's grouping). Multiple blocks (not in
        the current feed) are packed into ONE wrapper to preserve WWB grouping faithfully."""
        if len(blocks) == 1:
            self._send_block(blocks[0])                 # 1 fat block = 1 reliable wrapper (verbatim)
            return
        import struct as _st, zlib as _zl
        from ad600_native import client_block as _cb, aes_ctr_at as _ctr, skip32 as _sk
        cbs = []
        for pdu in blocks:
            pos = self.tx_pos
            ct = _ctr(self.key, self.tx_nonce, pos, pdu)
            iv = self.tx_nonce + ((pos + 15) // 16).to_bytes(8, "big")  # on-wire IV ctr = ceil(pos/16), matches WWB (keystream still floor via aes_ctr_at)
            self.tx_pos += len(pdu)
            cb = b"\x01\x01" + _st.pack(">H", 16 + len(pdu)) + iv + ct
            tag = _sk(self.key[:10], _zl.crc32(cb) & 0xffffffff, True).to_bytes(4, "big")
            cbs.append(_cb(1, 0x102, 0, cb + tag))
        self._send_reliable(cbs)
        print("  %6.2fs  -> TX reliable WRAPPER (%d blocks packed)  rel-seq=0x%04x"
              % (time.time() - self.t0, len(blocks), self.rel_seq))

    def _drive_wwb_exact(self, now):
        """Time-scheduled burst: send every wrapper whose recorded (clamped) send-time has arrived.
        NOT reply-gated — the whole point. One continuous association; the base JOINs exactly once."""
        if not self.proto_ok or self.wx is None or self.wx_done:
            return
        if self.wx_t0 is None:
            self.wx_t0 = now
            self.wx_pass += 1
            print("  %6.2fs  ★ WWB-EXACT BURST START (pass %d) — %d wrappers, burst cadence, NO reply-gate"
                  % (now - self.t0, self.wx_pass, len(self.wx)))
        # fire all wrappers due by now (a burst may release several per loop iteration)
        while self.wx_idx < len(self.wx):
            if (now - self.wx_t0) < self.wx_sched[self.wx_idx]:
                break
            rel, blocks = self.wx[self.wx_idx]
            _n, _v0 = self._wrapper_expect(blocks[0])
            self._send_wrapper_blocks(blocks)
            print("  %6.2fs  WWB-EXACT wrapper %d/%d  vec0=%s npdu=%d (wwb_t=%.3f)"
                  % (now - self.t0, self.wx_idx + 1, len(self.wx), _v0, _n, rel))
            self.wx_idx += 1
        if self.wx_idx >= len(self.wx):
            self._wwb_exact_pass_end(now)

    def _wwb_exact_pass_end(self, now):
        """End of a burst pass: print the accepted-branch summary; repeat the full verbatim burst
        (fallback, AD600_WWB_REPEAT) only if no firehose yet and passes remain; else finish."""
        if not hasattr(self, "_wx_pass_end_at"):
            self._wx_pass_end_at = now                  # start the post-pass settle window
            self._print_exact_summary(now)
            return
        if (now - self._wx_pass_end_at) < self.wx_settle:
            return
        del self._wx_pass_end_at
        if self.scan_events > 0:
            print("  %6.2fs  ✓✓ WWB-EXACT: RSSI FIREHOSE IS STREAMING — verbatim replay WORKED"
                  % (now - self.t0))
            self.wx_done = True
            return
        if self.wx_pass <= self.wx_repeat:              # repeat is 'extra' passes beyond the first
            print("  %6.2fs  WWB-EXACT: no firehose after pass %d — repeating full verbatim burst "
                  "(fallback; re-reads 0x0107010f + re-fires START)"
                  % (now - self.t0, self.wx_pass))
            self.wx_idx = 0
            self.wx_t0 = None                           # re-anchor schedule for the next pass
            return
        print("  %6.2fs  WWB-EXACT: burst complete, no firehose (pass %d). See branch summary above."
              % (now - self.t0, self.wx_pass))
        self.wx_done = True

    def _track_exact_branches(self, dec):
        """Record which subscribe branches the device ACCEPTs for our session (from inbound SUB_ACCEPT
        vec-12 PDUs, header-inheritance aware) and print first-crossings for the scan tree + the RSSI
        firehose subscribe. This measures the arm on the wire instead of inferring it."""
        for vec, ht, data in _walk_pdus(dec):
            if vec != 12:                               # only SUB_ACCEPT carries a granted identity
                continue
            if ht == 0x02 and len(data) >= 4:
                a = int.from_bytes(data[:4], "big")
                if a in self.exact_accepts:
                    continue
                self.exact_accepts.add(a)
                if 0x01090201 <= a <= 0x01090224:
                    print("  %6.2fs  ★ DEEP-TREE ACCEPT 0x%08x (0x01090201-0224)"
                          % (time.time() - self.t0, a))
            elif ht == 0x07 and len(data) >= 2:
                sl = int.from_bytes(data[:2], "big"); key = data[2:2 + sl]
                for k in (b"CURRENT_SWEEP_STATUS", b"CURRENT_SWEEP_ID",
                          b"CURRENT_STATUS", b"RF_SCAN_DATA:RSSI"):
                    if k in key and k not in self.exact_accepts:
                        self.exact_accepts.add(k)
                        star = "★★★" if k == b"RF_SCAN_DATA:RSSI" else "★★"
                        print("  %6.2fs  %s STR-KEY ACCEPT %s%s"
                              % (time.time() - self.t0, star, key.decode("ascii", "replace"),
                                 "  ← RSSI FIREHOSE SUBSCRIBE GRANTED" if k == b"RF_SCAN_DATA:RSSI" else ""))

    def _print_exact_summary(self, now):
        n0107 = sum(1 for a in self.exact_accepts if isinstance(a, int) and 0x01070000 <= a < 0x01080000)
        n0109 = sum(1 for a in self.exact_accepts if isinstance(a, int) and 0x01090000 <= a < 0x010a0000)
        ndeep = sum(1 for a in self.exact_accepts if isinstance(a, int) and 0x01090201 <= a <= 0x01090224)
        strk = [a for a in self.exact_accepts if isinstance(a, bytes)]
        print("  %6.2fs  ── WWB-EXACT ACCEPTED-BRANCHES (pass %d) ── vec12-accepts=%d  0x0107=%d "
              "0x0109=%d (deep 0201-0224=%d)  str-keys=%s  RSSI-events=%d"
              % (now - self.t0, self.wx_pass, self.vec12_accepts, n0107, n0109, ndeep,
                 [s.decode("ascii", "replace") for s in strk], self.scan_events))

    def _read_new_lines(self):
        """Return complete new lines appended to the control file since last poll (never
        re-executes an old line; tolerates the file not existing yet and partial trailing writes)."""
        try:
            with open(self.cmd_path, "rb") as f:
                f.seek(self.cmd_fpos)
                data = f.read()
        except FileNotFoundError:
            return []
        except Exception as e:
            print("  [control-file read error: %r]" % e)
            return []
        if not data:
            return []
        # only consume through the last complete line; leave a partial trailing line for next poll
        nl = data.rfind(b"\n")
        if nl == -1:
            return []
        consumed = data[:nl + 1]
        self.cmd_fpos += len(consumed)
        out = []
        for raw in consumed.split(b"\n"):
            s = raw.decode("utf-8", "replace").strip()
            if s and not s.startswith("#"):
                out.append(s)
        return out

    def _send_block(self, block, queued=False):
        """Encrypt+send one raw DMP PDU block as a reliable proto-0x102 wrapper at the current tx
        position — or queue it if the association isn't up yet."""
        # ── AD600_SCANID_REWRITE: once the owned SCAN_ID N is known (>0), rewrite the '/SCAN=0' token
        # in EVERY RF_SCAN string-keyed block to the LIVE owned '/SCAN=N' at the single send choke
        # point — covers BOTH the persisted CURRENT_* status subs AND the held arm's config SETs +
        # &RF_SCAN_DATA:RSSI leaves, so all of them subscribe/configure at the live owned id (not a
        # hard-coded 0). The numeric START (0x01070103) carries no string key → stays bare =00.
        # rewrite_scan_idx is a no-op for N in (0, None), so pre-ownership sends stay verbatim /SCAN=0.
        if self.scan_id:
            if b"RF_SCAN" in block:
                block = rewrite_scan_idx(block, self.scan_id)
            elif len(block) >= 9 and block[:8].hex() == "7009020201070103":
                block = block[:8] + bytes([self.scan_id & 0xff]) + block[9:]
        if not self.proto_ok:
            self.pending.append(block)
            print("  %6.2fs  QUEUED (DMP not enabled yet) %dB: %s"
                  % (time.time() - self.t0, len(block), block[:16].hex()))
            return
        self._send_dmp(block)
        tag = "(queued) " if queued else ""
        print("  %6.2fs  -> %sTX reliable DMP  rel-seq=0x%04x  %dB: %s"
              % (time.time() - self.t0, tag, self.rel_seq, len(block), block[:24].hex()))

    def _teardown(self):
        # RELEASE the scan-slot lease BEFORE leaving, so the NEXT launch finds slot-0 FREE and can
        # claim ownership WITHOUT a power-cycle. Fire-and-forget SET 0x0107010e over slots 0..N;
        # NEVER GET 0x0107010f here (a read RE-reserves/bumps the slot — ad600_native.py:1821). Then
        # hand off to the base disassoc → LEAVING → root-leave. (The base bookend frees only the SDT
        # member; the scan-slot lease is a separate DMP lease the base teardown does not release.)
        if getattr(self, "_torn_down", False):
            return
        try:
            if self.proto_ok and self.dev_chan and os.environ.get("AD600_NORELEASE") != "1":
                nslots = int(os.environ.get("AD600_RELSLOTS", "16"))
                for _id in range(nslots):
                    self._send_block(dmp_pdu(DMP_SET, 0x0107010e, bytes([_id & 0xff])))
                print("→ RELEASE_SCAN_ID bookend sent (slots 0..%d freed) — slot-0 free for next launch"
                      % (nslots - 1))
        except Exception as e:
            print("release error: %r" % e)
        super()._teardown()

    def _exec(self, line, now):
        toks = line.split()
        cmd = toks[0].lower()

        if cmd == "raw":
            self._send_block(bytes.fromhex(toks[1]))

        elif cmd == "sub":
            self._send_block(dmp_pdu(DMP_SUBSCRIBE, int(toks[1], 16)))

        elif cmd == "get":
            self._send_block(dmp_pdu(DMP_GET, int(toks[1], 16)))

        elif cmd == "set":
            val = bytes.fromhex(toks[2]) if len(toks) > 2 else b""
            self._send_block(dmp_pdu(DMP_SET, int(toks[1], 16), val))

        elif cmd in ("lockfeed", "genfeed"):
            feed_file = line.split(None, 1)[1] if len(toks) > 1 else "BUILTIN"
            self._load_lockstep(feed_file)

        elif cmd == "wwbexact":
            self._load_wwb_exact(line.split(None, 1)[1])

        elif cmd == "file":
            path = line.split(None, 1)[1]
            gap = (float(toks[2]) / 1000.0) if len(toks) > 2 else 0.0
            try:
                raw_lines = open(path).read().splitlines()
            except Exception as e:
                print("  [file error %s: %r]" % (path, e))
                return
            n = 0
            for rl in raw_lines:
                hexs = rl.strip()
                if not hexs or hexs.startswith("#"):
                    continue
                hexs = hexs.split()[-1]                         # tolerate "delay hex" or "hex"
                try:
                    blk = bytes.fromhex(hexs)
                except ValueError:
                    continue
                self._send_block(blk)
                n += 1
                if gap > 0:
                    time.sleep(gap)
            print("  %6.2fs  -> FILE %s: sent %d DMP block(s), gap=%.0fms%s"
                  % (now - self.t0, path, n, gap * 1000,
                     "  (pipelined)" if gap == 0 else ""))

        elif cmd == "mak":
            # Force-send N unreliable mgmt-acks of the device frontier, each carrying the
            # MAK-REQUEST trailer (000100010000 = "device, ACK my reliable stream"). Tests
            # whether a MAK burst un-sticks the device's inbound consume-stall past the 3-wrapper
            # early-subscribe window. Bypasses the base's 1-in-3 cadence.
            import struct as _st
            from ad600_native import client_block, build_wrapper, mgmt_ack
            n = int(toks[1]) if len(toks) > 1 else 3
            assoc = self.dev_chan or 0
            for _ in range(n):
                tot = self.total_seq; self.total_seq = (self.total_seq + 1) & 0xffff
                blocks = [client_block(1, 1, assoc, mgmt_ack(self.dev_rel))]
                self.sock.sendto(build_wrapper(self.cid, self.our_chan, tot, self.rel_seq,
                                               self.rel_seq, blocks, False,
                                               b"\x00\x01\x00\x01\x00\x00"), self.dst)
            print("  %6.2fs  -> FORCED %d MAK-REQUEST unrel-ack(s) frontier=0x%04x"
                  % (now - self.t0, n, self.dev_rel))

        elif cmd == "assoc":
            # Manually re-fire a reciprocal ASSOC0a (assoc = device chan) — tests whether
            # re-asserting the association "commits" a subscribe batch and re-opens the
            # device's DMP ingest window for the next batch.
            import struct as _st
            from ad600_native import client_block, pdu_encode
            self._send_reliable([client_block(1, 1, self.dev_chan or 0,
                                              pdu_encode(0x0a, None, _st.pack(">I", 0x102), 1))])
            print("  %6.2fs  -> MANUAL reciprocal ASSOC0a (assoc=0x%04X)  rel-seq=0x%04x"
                  % (now - self.t0, self.dev_chan or 0, self.rel_seq))

        elif cmd == "status":
            print("  %6.2fs  STATUS  tx-rel=0x%04x  dev-rel(frontier)=0x%04x  "
                  "replies=%d  vec12-accepts=%d  vec4-scan=%d  big(>200B)=%d  "
                  "proto_ok=%s  pending=%d"
                  % (now - self.t0, self.rel_seq, self.dev_rel, self.decoded,
                     self.vec12_accepts, self.scan_events, self.big_pkts,
                     self.proto_ok, len(self.pending)))

        elif cmd == "quit":
            print("  %6.2fs  QUIT — clean disconnect + exit" % (now - self.t0))
            self._quit = True
            self.run_for = 0.0                                 # base run loop exits → _teardown()

        else:
            print("  [unknown command: %r]  (raw|file|sub|get|set|status|quit)" % line)


def main():
    argv = sys.argv[1:]
    secs = float(os.environ.get("AD600_CONSOLE_SECS", "600"))
    cmd_path, log_path = DEF_CMD, DEF_LOG
    if len(argv) >= 1:
        secs = float(argv[0])
    if len(argv) >= 2:
        cmd_path = argv[1]
    if len(argv) >= 3:
        log_path = argv[2]

    for p in (os.path.dirname(cmd_path), os.path.dirname(log_path)):
        if p and not os.path.isdir(p):
            try:
                os.makedirs(p, exist_ok=True)
            except Exception:
                pass

    console = Ad600Console(run_for=secs, cmd_path=cmd_path, log_path=log_path)
    # The app stops us with SIGINT/SIGTERM; without handlers those kill the run loop mid-flight and the
    # clean disconnect (RELEASE_SCAN_ID + LEAVE) never reaches the wire → the device keeps our stale
    # membership + scan-slot-0 lease → the next launch hits JOIN_REFUSE / NOT-OWNER until a power-cycle.
    # Flip the base loop's exit flags so it drains to a NORMAL exit → _teardown() runs cleanly.
    def _on_signal(signum, _frame):
        console._quit = True
        console.run_for = 0.0
    for _sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(_sig, _on_signal)
        except Exception:
            pass
    try:
        console.run()
    finally:
        console._teardown()   # idempotent — guarantees release + LEAVE even on an unhandled loop exception


if __name__ == "__main__":
    main()
