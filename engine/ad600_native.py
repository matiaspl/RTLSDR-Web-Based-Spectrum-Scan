#!/usr/bin/env python3
"""
AD600 native client — WWB-free spectrum reader (foundation module).

This is the engine that will replace the WWB/Frida bridge: it speaks Shure's ACN (ANSI E1.17)
SDT/DMP itself, derives every key from on-wire session values, runs SRP-6a + the 32-bit DH, and
decrypts the AD600 scan directly. See AD600_STANDALONE_SPEC.md.

This file = the validated transport + crypto foundation (Phase 1):
  - ACN Root/SDT/DMP PDU encode + decode
  - SK_util (validated byte-exact) + AES-128-CTR (validated) + CRC32/SKIP32 auth tag
  - CryptoSession: bootstrap key + encrypt/decrypt of client blocks (proven against a live capture)

SDT session-join, SRP-6a, DH, scan decode, and the HTTP bridge server bolt on next.
Stdlib only. Self-test:  python3 ad600_native.py selftest ad600_handshake.pcap
"""
import os, sys, struct, hashlib, zlib, socket

# ═══════════════════════════════ validated crypto ═══════════════════════════════

def sk_util(blob: bytes) -> bytes:
    """Byte-exact _SK_util @0x10270549c. (validated: decrypts live control channel)"""
    h = hashlib.sha256(blob).digest(); state = bytearray(h)
    v = (h[30] << 8) | h[31]; N = ((v ^ 2) % 7) + 10
    tri   = [(0,0),(1,0),(1,1),(2,0),(2,1),(2,2),(3,0),(3,1),(3,2),(3,3)]
    cross = [(0,3),(4,7),(8,11),(12,15),(2,1),(6,5),(10,9),(14,13)]
    for i in range(1, N + 1):
        P = bytearray(state[0:16]); Q = bytearray(state[16:32])
        p = [(i + t) & 3 for t in range(4)]
        for row, col in tri: P[4*row+col], P[4*p[col]+p[row]] = P[4*p[col]+p[row]], P[4*row+col]
        for row, col in tri: Q[4*row+col], Q[4*p[col]+p[row]] = Q[4*p[col]+p[row]], Q[4*row+col]
        for pi, qi in cross: P[pi], Q[qi] = Q[qi], P[pi]
        state[0:16] = P; state[16:32] = Q
        rot = bytes(state[(k + i) % 32] for k in range(32))
        state = bytearray(state[k] ^ rot[k] for k in range(32))
    return hashlib.sha256(bytes(state)).digest()

_SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
def _xt(a): return ((a<<1)^0x1b)&0xff if a&0x80 else (a<<1)
def _mul(a,b):
    r=0
    for _ in range(8):
        if b&1: r^=a
        a=_xt(a); b>>=1
    return r&0xff
def _kexp(key):
    ks=[list(key[i:i+4]) for i in range(0,16,4)]
    for i in range(4,44):
        t=list(ks[i-1])
        if i%4==0:
            t=t[1:]+t[:1]; t=[_SBOX[x] for x in t]; t[0]^=_RCON[i//4-1]
        ks.append([ks[i-4][j]^t[j] for j in range(4)])
    return ks
def aes_encrypt_block(ks, block):
    s=[[block[r+4*c] for c in range(4)] for r in range(4)]
    def add(rn):
        for c in range(4):
            w=ks[rn*4+c]
            for r in range(4): s[r][c]^=w[r]
    add(0)
    for rn in range(1,10):
        s=[[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
        s=[s[r][r:]+s[r][:r] for r in range(4)]
        ns=[[0]*4 for _ in range(4)]
        for c in range(4):
            col=[s[r][c] for r in range(4)]
            ns[0][c]=_mul(col[0],2)^_mul(col[1],3)^col[2]^col[3]
            ns[1][c]=col[0]^_mul(col[1],2)^_mul(col[2],3)^col[3]
            ns[2][c]=col[0]^col[1]^_mul(col[2],2)^_mul(col[3],3)
            ns[3][c]=_mul(col[0],3)^col[1]^col[2]^_mul(col[3],2)
        s=ns; add(rn)
    s=[[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]
    s=[s[r][r:]+s[r][:r] for r in range(4)]; add(10)
    return bytes(s[r][c] for c in range(4) for r in range(4))
def aes_ctr_at(key, nonce8, pos, data):
    """AES-128-CTR keystream from absolute byte position `pos` of a CONTINUOUS stream
       (fixed 8-byte nonce, 64-bit block counter). pos//16 = block, pos%16 = offset."""
    ks_sched=_kexp(key); blk0=pos//16; nc=pos%16; need=nc+len(data); ks=b""; bi=blk0
    while len(ks)<need:
        ks+=aes_encrypt_block(ks_sched, nonce8+((bi)&((1<<64)-1)).to_bytes(8,"big")); bi+=1
    return bytes(data[i]^ks[nc+i] for i in range(len(data)))

# ── keystream cache + position-robust decode (self-heals continuous-CTR drift) ──
_KS_CACHE={}   # (key,nonce8) -> bytearray keystream
def _ks(key, nonce8, need):
    ent=_KS_CACHE.get((key,nonce8))
    if ent is None: ent=bytearray(); _KS_CACHE[(key,nonce8)]=ent
    if len(ent)<need:
        sched=_kexp(key); bi=len(ent)//16
        while len(ent)<need:
            ent+=aes_encrypt_block(sched, nonce8+(bi&((1<<64)-1)).to_bytes(8,"big")); bi+=1
    return ent
_DMP_VECS = frozenset((1,2,3,4,5,6,7,9,10,12,13))   # GET/SET/SUB + all reply/event/accept vectors
def _valid_dmp_head(pt, exact_len=None):
    """True if `pt` begins with a well-formed DMP PDU.

    The ACN 2-byte-length PDU is [0x70|hi, lo][vector][addr-hdr][addr/name...]; so the
    vector is at pt[ds] and the address header at pt[ds+1] (ds = data-start from pdu_decode).
    The previous version read them one byte too early (pt[1]/pt[2]), which happens to hold
    for the numeric GET-reply path but REJECTS every string-addressed reply (vec=13 SUBSCRIBE
    accept, vec=4 RF_SCAN event, hdr=0x07) — that mispositioning was the RX-drift blocker.
    `exact_len` (=len(ct)) lets us reject any candidate whose declared PDU length overruns the
    decrypted block, killing false positives during the drift-recovery window search."""
    if not pt: return False
    if (pt[0] >> 4) not in (0x7, 0xf): return False          # ACN PDU flags nibble
    r = pdu_decode(pt, 0)
    if not r: return False
    f, ds, end = r
    if end < ds + 2: return False                            # need vector + addr header
    # The declared 12-bit PDU length must fit inside the ciphertext (equal for a single-PDU
    # reply, less for a batched multi-PDU block).  This length bound is the position
    # discriminator; it replaces the earlier ASCII-name heuristic, which wrongly rejected
    # vec=13 SUBSCRIBE-accepts (their hdr=0x07 body is a BINARY address handle, not the
    # echoed property string) and thereby stalled the whole string-subscribe path.
    if exact_len is not None and end > exact_len: return False
    v = pt[ds]
    if v not in _DMP_VECS: return False                      # vector
    # 4-byte-abs (0x02) or string (0x07) address header for GET/SET/SUB/reply/event. BUT the
    # subscribe accept/reject (9/10) and one-shot value (13) vectors carry a NON-address body
    # (a map handle / reason code, hdr typically 0x00) — the device answers our post-inventory
    # SETs with `70 06 09 00 00 02` (vec9, hdr=0x00), which the strict check wrongly rejected,
    # so find_ctr_pos could never lock onto those replies (RX-drift freeze). Accept them by
    # vector, bounded by the length check above. (2026-08-05 live-decode: pos 204/210/216.)
    if pt[ds+1] not in (0x02, 0x07) and v not in (9, 10, 13): return False
    return True
def find_ctr_pos(key, nonce8, ct, hint, back=64, fwd=2048):
    """Return (pos, plaintext) for `ct` in the continuous stream, searching a window
       around `hint`. Robust to drift from unaccounted device blocks/retransmits."""
    ks=_ks(key, nonce8, max(hint+fwd, hint+len(ct))+len(ct)+16)
    lo=max(0, hint-back)
    order=[hint]+[p for p in range(lo, hint+fwd) if p!=hint]
    for p in order:
        if p+len(ct)>len(ks): continue
        pt=bytes(ct[i]^ks[p+i] for i in range(len(ct)))
        if _valid_dmp_head(pt, len(ct)): return p, pt
    return None, None

def aes_ctr(key, iv16, data, nc_off=0):
    ks=_kexp(key); ctr=int.from_bytes(iv16,"big"); out=bytearray()
    stream=bytearray()
    need=nc_off+len(data)
    for b in range((need+15)//16):
        stream+=aes_encrypt_block(ks, ((ctr+b)&((1<<128)-1)).to_bytes(16,"big"))
    return bytes(data[i]^stream[nc_off+i] for i in range(len(data)))

# ── auth tag (validated): tag = SKIP32_12round(key[:10], CRC32(msg)) ──
_FTABLE = bytes([
0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46])
def _g(key10, k, w):
    g1=(w>>8)&0xff; g2=w&0xff
    g3=_FTABLE[g2 ^ key10[(4*k)  %10]]^g1
    g4=_FTABLE[g3 ^ key10[(4*k+1)%10]]^g2
    g5=_FTABLE[g4 ^ key10[(4*k+2)%10]]^g3
    g6=_FTABLE[g5 ^ key10[(4*k+3)%10]]^g4
    return ((g5<<8)|g6)&0xffff
def skip32(key10, block32, encrypt=True):
    """Shure's SKIP32 — 12 rounds (NOT standard 24). block32 big-endian: wl=hi16, wr=lo16."""
    k = 0 if encrypt else 23; step = 1 if encrypt else -1
    wl=(block32>>16)&0xffff; wr=block32&0xffff
    for _ in range(6):
        wr=(wr ^ _g(key10,k,wl) ^ k)&0xffff; k+=step
        wl=(wl ^ _g(key10,k,wr) ^ k)&0xffff; k+=step
    return ((wr<<16)|wl)&0xffffffff
def acn_auth_tag(key16: bytes, message: bytes) -> bytes:
    return skip32(key16[:10], zlib.crc32(message)&0xffffffff, True).to_bytes(4, "big")

# ═══════════════════════════════ DMP property codec ═══════════════════════════════
# Wire format (validated against live capture, 8/9 addrs matched DDL):
#   [0x70|lenhi, lenlo] [vector] [0x02 = 4-byte-abs-addr header] [4B addr BE] [value...]
# then the whole PDU is followed by the 4-byte auth tag, then encrypted as a client block.
DMP_GET, DMP_SET, DMP_SUBSCRIBE = 1, 2, 7
# ★ CORRECTED 2026-08-05 (WWB DMP dispatch RE, wwb_disasm.txt:11918000 — masks 0x208=bits3,9→GetResponse;
# 0xa=SetResponse; 0x3010=bits4,12,13→SubscriptionResponse): standard ANSI E1.17 codes.
# GET_FAIL=9, SET_FAIL=10, SUBSCRIBE_ACCEPT=12, SUBSCRIBE_REJECT=13. (Old 5,6 were wrong/unused.)
DMP_GET_REPLY, DMP_EVENT = 3, 4
DMP_GET_FAIL, DMP_SET_FAIL, DMP_SUB_ACCEPT, DMP_SUB_REJECT = 9, 10, 12, 13
DMP_ADDR_HDR = 0x02                                  # single, absolute, 4-byte address

# AD600 DMP addresses (from decrypted DDL.dat, interface-validated on the wire)
A_SRP_ACCESS_LEVEL = 0x01201003
A_SRP_EXCHANGE_A    = 0x01201008   # set  (client A, PAD_N)
A_SRP_EXCHANGE_B    = 0x01201009   # get  (device B)
A_SRP_EXCHANGE_HAMK = 0x0120100a   # get  (device proof M2)
A_SRP_EXCHANGE_M    = 0x0120100b   # set  (client proof M1)
A_SRP_EXCHANGE_SALT = 0x0120100c   # get  (device salt)
A_SRP_HASH_ID       = 0x0120100d
A_SRP_MODULUS_ID    = 0x0120100e
A_SESSION_EXCHANGE_A = 0x01200020  # set
A_SESSION_EXCHANGE_B = 0x01200021  # get
A_SESSION_GENERATE_KEY = 0x01200022 # set
A_SESSION_KEY_STATUS = 0x01200023  # get
A_SESSION_MODULUS    = 0x01200024  # get
A_SESSION_BIT_SIZE   = 0x01200025  # get

def dmp_pdu(vector, addr, value=b""):
    """One DMP PDU: vector + 4-byte-abs addr header + address + raw value."""
    body = bytes([vector, DMP_ADDR_HDR]) + struct.pack(">I", addr) + value
    total = 2 + len(body)
    if total <= 0x0FFF:
        return bytes([0x70 | (total >> 8), total & 0xff]) + body     # 2-byte len (flags 0x7)
    total = 3 + len(body)                                             # 3-byte len (flags 0xF)
    return bytes([0xF0 | (total >> 16), (total >> 8) & 0xff, total & 0xff]) + body

def dmp_batch_sub(addrs, vector=7):
    """WWB-style BATCHED subscribe: first PDU carries full header (flags 0x7: V+H+D), each
       subsequent address is a header-INHERITING continuation PDU (flags 0x1: D-only, len 6,
       4-byte addr) — exactly WWB's `7008 07 02 <a0> 1006 <a1> 1006 <a2> ...`. The hypothesis:
       a batched subscribe latches the SESSION into streaming (vec=0c) mode."""
    out = bytes([0x70,0x08,vector,DMP_ADDR_HDR]) + struct.pack(">I", addrs[0])
    for a in addrs[1:]:
        out += bytes([0x10,0x06]) + struct.pack(">I", a)   # 0x1=D-only, len 6, inherit vec+hdr
    return out

def dmp_parse(pt):
    """Parse first DMP PDU out of a decrypted plaintext (PDU [+ 4B tag]).
       Returns (vector, addr, value, tag_or_None)."""
    r = pdu_decode(pt, 0)
    if not r: return None
    f, ds, end = r
    if end - ds < 6: return None
    vector = pt[ds]; addr = int.from_bytes(pt[ds+2:ds+6], "big"); value = pt[ds+6:end]
    tag = pt[end:end+4] if len(pt) >= end+4 else None
    return vector, addr, value, tag

# ═══════════════════════════════ SRP-6a client (control-channel key) ═══════════════════════════════
# csrp-style SRP-6a, SHA-256, I="USER_LEVEL0", P="".  Group SRP_MODULUS_ID 0 = RFC5054 1024-bit, g=2.
# AD600 SRP_MODULUS_ID=1 = RFC 5054 2048-bit group, g=2 (read from WWB SRPModulus table @0x1038b8eb0)
_SRP_N_1024 = int(
 "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed"
 "8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3"
 "661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea7"
 "1d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748"
 "544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce5329"
 "9ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f5475"
 "9b65e372fcd68ef20fa7111f9e4aff73", 16)
_SRP_g = 2
_SRP_I = os.environ.get("AD600_SRP_USER","USER_LEVEL0").encode()   # SRP identity (try 'wwb' from FTP)
_SRP_P = os.environ.get("AD600_SRP_PASS","").encode()             # SRP password (try 'dSUeg=Qq' from FTP)

def _H(*parts):
    h = hashlib.sha256()
    for p in parts: h.update(p)
    return h.digest()
def _int(b):  return int.from_bytes(b, "big")
def _bytes(i, length=None):
    b = i.to_bytes((i.bit_length()+7)//8 or 1, "big")
    if length: b = b"\x00"*(length-len(b)) + b
    return b
def _pad(i):  return _bytes(i, (_SRP_N_1024.bit_length()+7)//8)   # PAD_N: left-pad to N length (128B)
def _min(b):  return b.lstrip(b"\x00") or b"\x00"                 # minimal big-endian (strip leading zeros)

class SRPClient:
    """Drives SRP-6a producing control AES key K[0:16].  Feed it salt+B; it yields A and M1."""
    def __init__(self, a_priv=None):
        self.N, self.g = _SRP_N_1024, _SRP_g
        self.Nlen = (self.N.bit_length()+7)//8
        self.a = _int(a_priv) if a_priv else _int(os.urandom(32))
        self.A = pow(self.g, self.a, self.N)
        # passphrase_vec = HashPassphrase(P) — Shure feeds SHA-256(P) as the secret (md_type 9)
        self.passphrase_vec = _H(_SRP_P)
        self.K = None; self.M1 = None; self.M2 = None
    def A_wire(self):  return _pad(self.A)          # SRP_EXCHANGE_A carries PAD_N(A)
    def compute(self, salt, B_bytes):
        B = _int(B_bytes)
        if B % self.N == 0: raise ValueError("SRP: B mod N == 0")
        u = _int(_H(_pad(self.A), _pad(B)))
        if u == 0: raise ValueError("SRP: u == 0")
        k = _int(_H(_pad(self.N), _pad(self.g)))
        x = _int(_H(_min(salt), _H(_SRP_I, b":", self.passphrase_vec)))
        S = pow((B - (k * pow(self.g, x, self.N))) % self.N, self.a + u*x, self.N)
        self.K = _H(_min(_bytes(S)))                # K = H(min(S)); control AES key = K[0:16]
        self.M1 = _H(_xor(_H(_min(_bytes(self.N))), _H(_pad(self.g))),
                     _H(_SRP_I), _min(salt), _min(_bytes(self.A)), _min(B_bytes), self.K)
        self.M2 = _H(_min(_bytes(self.A)), self.M1, self.K)
        return self.K
    def verify_hamk(self, hamk):  return self.M2 is not None and hamk[:32] == self.M2

def _xor(a, b):  return bytes(x ^ y for x, y in zip(a, b))

# ═══════════════════════════════ ACN PDU codec ═══════════════════════════════

ROOT_PREAMBLE = b"\x00\x10\x00\x00" + b"ASC-E1.17\x00\x00\x00"
VECTOR_ROOT_SDT = 1
PROTO_DMP = 0x102

def pdu_encode(vector, header, data, vec_size):
    """Build one ACN PDU (V|H|D set, 2-octet 12-bit length)."""
    body = b""
    if vector is not None: body += vector.to_bytes(vec_size, "big")
    if header is not None: body += header
    if data   is not None: body += data
    total = 2 + len(body)
    if total > 0x0FFF: raise ValueError("PDU too long for 12-bit length")
    return bytes([0x70 | (total >> 8), total & 0xff]) + body

def pdu_decode(b, i):
    if i+2 > len(b): return None
    f = b[i] >> 4
    if f & 0x8:
        ln = ((b[i]&0x0f)<<16)|(b[i+1]<<8)|b[i+2]; ds = i+3
    else:
        ln = ((b[i]&0x0f)<<8)|b[i+1]; ds = i+2
    if ln < (ds-i) or i+ln > len(b): return None
    return f, ds, i+ln    # flags, data_start, pdu_end

def root_wrap(src_cid, sdt_pdu):
    inner = VECTOR_ROOT_SDT.to_bytes(4,"big") + src_cid + sdt_pdu
    total = 2 + len(inner)
    return ROOT_PREAMBLE + bytes([0x70|(total>>8), total&0xff]) + inner

def root_parse(pkt):
    if len(pkt) < 18 or pkt[4:13] != b"ASC-E1.17": return None
    r = pdu_decode(pkt, 16)
    if not r: return None
    f, ds, end = r
    vec = int.from_bytes(pkt[ds:ds+4], "big"); cid = pkt[ds+4:ds+20]
    return cid, pkt[ds+20:end]     # src CID, SDT block

# ═══════════════════════════════ crypto session ═══════════════════════════════

class CryptoSession:
    """Bootstrap-key AES-128-CTR for the ACN reliable channel (validated against capture).
       Order per SDT role: AcceptJoin -> (recvCID,sendCID,recvChan,sendChan);
       GotConnectAccept -> (sendCID,recvCID,sendChan,recvChan). Try both if unsure."""
    def __init__(self, cid_a, cid_b, chan_a, chan_b):
        blob = cid_a + cid_b + struct.pack("<H", chan_a) + struct.pack("<H", chan_b)
        self.key = sk_util(blob)[:16]
        self.tx_nonce = os.urandom(8); self.tx_ctr = 0    # our sending counter (device does same)

    def decrypt_client_block(self, blk):
        """blk = [01 01][len=16+DMPlen][16B IV][ciphertext][4B tag].  Returns plaintext DMP.
           len delimits IV+ct (tag is appended outside it). Tag = skip32(key[:10],crc32(cb))."""
        if len(blk) < 20 or blk[0] != 0x01: return None
        ln = struct.unpack(">H", blk[2:4])[0]
        end = 4 + ln
        iv, ct = blk[4:20], blk[20:end]
        return aes_ctr(self.key, iv, ct)

    def verify_block_tag(self, blk):
        """True if the appended 4-byte tag matches skip32(key[:10], crc32(client-block-core))."""
        if len(blk) < 24: return False
        ln = struct.unpack(">H", blk[2:4])[0]; end = 4 + ln
        if len(blk) < end + 4: return False
        want = blk[end:end+4]
        calc = skip32(self.key[:10], zlib.crc32(blk[:end]) & 0xffffffff, True).to_bytes(4, "big")
        return want == calc

    def encrypt_client_block(self, dmp):
        """Wrap DMP as [01 01 00 len][16B IV][ciphertext].  (auth tag added by caller if needed)"""
        iv = self.tx_nonce + self.tx_ctr.to_bytes(8, "big")
        ct = aes_ctr(self.key, iv, dmp)
        self.tx_ctr += (len(dmp) + 15)//16
        body = iv + ct
        return b"\x01\x01" + struct.pack(">H", len(body)) + body

# ═══════════════════════════════ self-test (offline, vs capture) ═══════════════════════════════

def selftest(pcap):
    """Re-derive the bootstrap key from a capture and confirm it decrypts the control channel —
       proving this module's SK_util/AES/framing match the validated ad600_decrypt.py result."""
    import itertools
    d=open(pcap,"rb").read(); m=struct.unpack("<I",d[:4])[0]
    en="<" if m in (0xa1b2c3d4,0xa1b23c4d) else ">"; off=24; frames=[]
    while off+16<=len(d):
        _,_,incl,_=struct.unpack(en+"IIII",d[off:off+16]); off+=16
        frames.append(d[off:off+incl]); off+=incl
    cids=[]; chans=set(); blocks=[]
    for fr in frames:
        if len(fr)<42 or fr[12:14]!=b"\x08\x00" or fr[23]!=17: continue
        ihl=(fr[14]&0x0f)*4; sp,dp=struct.unpack(">HH",fr[14+ihl:14+ihl+4])
        if 57383 not in (sp,dp): continue
        pl=fr[14+ihl+8:]
        pr=root_parse(pl)
        if not pr: continue
        cid,block=pr
        if cid not in cids: cids.append(cid)
        i=0
        while i<len(block):
            r=pdu_decode(block,i)
            if not r: break
            f,ds,e=r; vec=block[ds]; rest=block[ds+1:e]
            if vec in (1,2) and len(rest)>=20:
                chans.add(struct.unpack(">H",rest[:2])[0]); cb=rest[20:]; j=0
                while j<len(cb):
                    r2=pdu_decode(cb,j)
                    if not r2: break
                    cf,cds,ce=r2; body=cb[cds:ce]; q=2 if cf&0x4 else 0
                    proto=int.from_bytes(body[q:q+4],"big") if (cf&0x2 and len(body)>=q+6) else None
                    q+=6 if cf&0x2 else 0; dmp=body[q:]
                    if proto==PROTO_DMP and len(dmp)>=20: blocks.append(dmp)
                    j=ce
            i=e
    clist=sorted(chans)
    best=None
    for c1,c2 in itertools.permutations(cids,2):
        for k1,k2 in itertools.permutations(clist,2):
            sess=CryptoSession(c1,c2,k1,k2)
            clean=sum(1 for blk in blocks if (lambda p: p and p[0]==0x70)(sess.decrypt_client_block(blk)))
            if best is None or clean>best[0]: best=(clean,sess.key.hex(),c1.hex(),c2.hex(),k1,k2)
    print("blocks=%d  best: %d clean DMP  key=%s"%(len(blocks),best[0],best[1]))
    print("order CID_a=%s CID_b=%s chan_a=0x%X chan_b=0x%X"%(best[2],best[3],best[4],best[5]))
    print("PASS — module reproduces the validated decrypt." if best[0]>=30 else "FAIL")

def discover(seconds=5):
    """Passively listen for the AD600's discovery beacon (dev -> .255:2201) to confirm it's
       alive and grab its live info. Read-only; no packets sent."""
    import time
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    try: s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
    except Exception: pass
    s.bind(("",2201)); s.settimeout(1.0)
    print("listening for AD600 discovery beacon on :2201 for %ds…"%seconds)
    seen=set(); t0=time.time()
    while time.time()-t0 < seconds:
        try: data,addr=s.recvfrom(2048)
        except socket.timeout: continue
        if addr[0] not in seen:
            seen.add(addr[0])
        txt="".join(chr(b) if 32<=b<127 else "." for b in data)
        print("  %s:%d  %dB  %s"%(addr[0],addr[1],len(data),data.hex()))
        print("        ascii: %s"%txt)
    s.close()
    print("done — %d source(s): %s"%(len(seen),", ".join(seen) or "none"))

AD600_IP = os.environ.get("AD600_IP", "192.168.5.101")
CTRL_PORT = 57383
AD600_CID = bytes.fromhex("ddac0650000011dda000000eddcccccc")   # from SDDP; auto-discovered live
SDT_VEC = {1:"REL_WRAP",2:"UNREL_WRAP",3:"CHAN_PARAMS",4:"JOIN",5:"JOIN_REFUSE",6:"JOIN_ACCEPT",
           7:"LEAVING",8:"NAK",9:"GET_SESSIONS",10:"SESSIONS",11:"ACK"}

def gen_cid():
    if os.environ.get("AD600_WWBCID"):   # impersonate WWB's fixed CID (device may grant its cached auth)
        return bytes.fromhex("71ea5337000011dda000000eddcccccc")
    return os.urandom(4) + bytes.fromhex("000011dda000000eddcccccc")

# Scan-start DMP commands (string-addressed, captured verbatim from WWB via the crypt_ctr hook).
# Full-band 470–1000 MHz, all 6 antenna curves, sweep-forever.  freq_MHz = 174 + FREQ_IDX*0.025.
SCAN_CMD_CONFIG = bytes.fromhex(
    "70280207002052465f5343414e3a5343414e5f53544152545f465245512f5343414e3d3000072bf0"
    "1025001f52465f5343414e3a5343414e5f53544f505f465245512f5343414e3d30000f4240"
    "1025001f52465f5343414e3a5343414e5f535445505f465245512f5343414e3d3000000019"
    "1029002352465f5343414e3a5343414e5f5245534f4c5554494f4e5f42572f5343414e3d3000000019"
    "1027002452465f5343414e3a5343414e5f5245504541545f524551554553542f5343414e3d30ff"
    "1023001d52465f5343414e3a43555256455f53454c4543542f5343414e3d300000007e"
    "1024002052465f5343414e3a5343414e5f53574545505f524154452f5343414e3d30003c"
    "102c002652465f5343414e3a5245414c5f54494d455f434f4d5052455353494f4e2f5343414e3d3000000024")  # REAL_TIME_COMPRESSION=0x24 (byte-exact to wwb_scan_working_realdevice.pcap @47.635; was 0x10)
SCAN_CMD_SUB_STATUS = bytes.fromhex(
    "70290707002552465f5343414e3a43555252454e545f53574545505f5354415455532f5343414e3d30"
    "1023002152465f5343414e3a43555252454e545f53574545505f49442f5343414e3d30"
    "1021001f52465f5343414e3a43555252454e545f5354415455532f5343414e3d30")
SCAN_CMD_SUB_DATA = bytes.fromhex(
    "70400707003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d312f465245515f4944583d31313834302d3333303430"
    "103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d322f465245515f4944583d31313834302d3333303430"
    "103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d332f465245515f4944583d31313834302d3333303430"
    "103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d342f465245515f4944583d31313834302d3333303430"
    "103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d352f465245515f4944583d31313834302d3333303430"
    "103e003c2652465f5343414e5f444154413a525353492f5343414e3d302f43555256455f4944583d362f465245515f4944583d31313834302d3333303430")

# Numeric scan-engine init commands (captured from WWB, sent before the string config).
SCAN_PRE = [bytes.fromhex(h) for h in (
    "700902020107010e00",             # SET 0x0107010e=0 (clean; dropped WWB's trailing GET-addr-0 PDU)
    "70080102010704f0", "70080102010704f1",
    "7008010201070240","7008010201070241","7008010201070242",
    "7008010201070243","7008010201070244","7008010201070245","7008010201070246",
    "700801020107010f",               # GET SCAN_ID
    "7008010201070210100601070200100601070201100601070202",  # GET batch
)]
# ★ WWB sends START_SCAN as a BARE SET (700902020107010300), NO trailing GET-0 (verified rhex.log 22172ms,
# len=9). We had appended 7005010000 → block became [SET START][GET null], which may stop the device firing
# the scan trigger. Match WWB: bare START. AD600_STARTTRAILER=1 restores the old trailer for A/B.
SCAN_POST = bytes.fromhex("700902020107010300" + ("7005010000" if os.environ.get("AD600_STARTTRAILER") else ""))

def rewrite_rt_compression(blob, comp):
    """Set RF_SCAN:REAL_TIME_COMPRESSION's 4-byte value in a string-addressed DMP block.

    The device measures at SCAN_STEP_FREQ (25 kHz) but peak-bins `comp` measured points into
    each delivered bin, so the DELIVERED resolution = comp * 25 kHz  (default comp=0x24=36 →
    900 kHz; comp=14 → 350 kHz).  The value is a fixed 4 bytes, so — unlike rewrite_scan_idx —
    PDU/string-address framing is UNCHANGED and this is a straight in-place swap.  Returns the
    blob untouched if `comp` is falsy or the token isn't present (so non-config blocks pass through).
    """
    if not comp:
        return blob
    # The uint32 value follows the string address "…/SCAN=0" with NO null separator (the first
    # 0x00 of 0x00000024 is the value's high byte). So match up to "SCAN=0" exactly and overwrite
    # the next 4 bytes — do NOT include a trailing \x00 in the marker (that would eat a value byte).
    marker = b"REAL_TIME_COMPRESSION/SCAN=0"
    i = blob.find(marker)
    if i < 0:
        return blob
    v = i + len(marker)
    return blob[:v] + int(comp).to_bytes(4, "big") + blob[v + 4:]


def rewrite_scan_step_rbw(blob, step_khz=None, rbw_khz=None):
    """Set RF_SCAN:SCAN_STEP_FREQ and/or SCAN_RESOLUTION_BW (uint32 kHz) in a config block.

    These are the MEASUREMENT step + filter bandwidth (default 25 kHz each). Delivered bin spacing
    = SCAN_STEP_FREQ * REAL_TIME_COMPRESSION, so to go BELOW 25 kHz you must lower the step here
    (compression's floor is 1× = 25 kHz). Whether the device honors sub-25 kHz is a hardware
    question — the freq axis is quantized to 25 kHz/idx — so this is a capability probe. Fixed
    4-byte in-place swap; framing unchanged. falsy value → that field untouched."""
    for name, val in ((b"SCAN_STEP_FREQ/SCAN=0", step_khz),
                      (b"SCAN_RESOLUTION_BW/SCAN=0", rbw_khz)):
        if not val:
            continue
        i = blob.find(name)
        if i < 0:
            continue
        v = i + len(name)
        blob = blob[:v] + int(val).to_bytes(4, "big") + blob[v + 4:]
    return blob

def rewrite_scan_range(blob, start_khz=None, stop_khz=None):
    """Set RF_SCAN:SCAN_START_FREQ / SCAN_STOP_FREQ (uint32 kHz) in a string-addressed DMP block.

    Same fixed-4-byte in-place swap as rewrite_rt_compression (value follows '…/SCAN=0' with NO
    null separator), so PDU framing is unchanged. Narrowing [start,stop] shrinks how many 600-bin
    frames tile the band → lower data rate at a given RBW (the lever for affording a fine RBW over
    a small span). start_khz/stop_khz falsy → that bound untouched. Returns blob if neither present.
    """
    for name, val in ((b"SCAN_START_FREQ/SCAN=0", start_khz),
                      (b"SCAN_STOP_FREQ/SCAN=0", stop_khz)):
        if not val:
            continue
        i = blob.find(name)
        if i < 0:
            continue
        v = i + len(name)
        blob = blob[:v] + int(val).to_bytes(4, "big") + blob[v + 4:]
    return blob


def rewrite_curve_select(blob, mask=None):
    """Set RF_SCAN:CURVE_SELECT (uint32 bitmask) in a config block.
    Bit positions 1..6 represent curves 1..6 (0x7E = all six).
    Fixed 4-byte in-place swap; framing unchanged."""
    if mask is None:
        return blob
    marker = b"CURVE_SELECT/SCAN=0"
    i = blob.find(marker)
    if i < 0:
        return blob
    v = i + len(marker)
    return blob[:v] + int(mask).to_bytes(4, "big") + blob[v + 4:]


def rewrite_repeat_request(blob, repeat=None):
    """Set RF_SCAN:SCAN_REPEAT_REQUEST (uint8: 0xFF for continuous, 0x01 for single-shot).
    Fixed 1-byte in-place swap; framing unchanged."""
    if repeat is None:
        return blob
    marker = b"SCAN_REPEAT_REQUEST/SCAN=0"
    i = blob.find(marker)
    if i < 0:
        return blob
    v = i + len(marker)
    return blob[:v] + int(repeat).to_bytes(1, "big") + blob[v + 1:]


def rewrite_scan_idx(blob, idx):
    """Rewrite every '/SCAN=0' token in a concatenated string-addressed DMP command block to
       '/SCAN=<idx>'.  SCAN_ID (0x0107010f) increments each run, so the device only honours
       config/subscribe/start on the CURRENT id.  Walks each PDU and fixes both the 12-bit PDU
       length and the 2-byte string-address-length field, so multi-digit ids stay wire-valid
       (a naive same-length replace corrupts the framing once the id reaches 2 digits)."""
    if idx in (0, None): return blob
    old = b"SCAN=0"; new = b"SCAN=" + str(idx).encode()
    dperc = len(new) - len(old)
    out = b""; i = 0
    while i < len(blob):
        r = pdu_decode(blob, i)
        if not r: out += blob[i:]; break
        f, ds, end = r                                       # f = flags nibble (V=4,H=2,D=1)
        pdu = blob[i:end]
        cnt = pdu.count(old)
        if cnt:
            delta = cnt * dperc
            # These blocks are an ACN PDU list with header inheritance: PDU0 = flags 0x7
            # (vector+header+data), continuation PDUs = flags 0x1 (data-only, inherit V/H).
            # Data (which begins with the 2-byte string-length field) starts after whatever
            # vector/header bytes THIS pdu carries.  Fix that field + the 12-bit PDU length.
            dstart = ds + (1 if f & 0x4 else 0) + (1 if f & 0x2 else 0)
            fo = dstart - i                                  # string-length field offset in `pdu`
            addrlen = int.from_bytes(pdu[fo:fo+2], "big") + delta
            body = pdu.replace(old, new)
            total = len(body)
            body = (bytes([(pdu[0] & 0xf0) | (total >> 8), total & 0xff]) + body[2:fo]
                    + int.to_bytes(addrlen, 2, "big") + body[fo+2:])
            out += body
        else:
            out += pdu
        i = end
    return out

_RF_SCAN_RX = None
def parse_rf_scan_data(dec):
    """Decrypted vec=4 EVENT -> (curve_idx, freq_idx_lo, freq_idx_hi, amps[dBm]) or None.
       Layout (matches ad600Decoder.ts): [70|len 2B][04 EVENT][07 str-hdr][2B strlen]
       [ASCII 'RF_SCAN_DATA:RSSI/SCAN=n/CURVE_IDX=1..6/FREQ_IDX=a-b;<COMP>']
       [5-byte subheader 00 00 00 <n> 02][int16-BE dBm*10 array].  COMP (bins/sample
       stride) varies (";16", ";28", ...) — do NOT hardcode it; array start = 6+strlen+5."""
    global _RF_SCAN_RX
    if _RF_SCAN_RX is None:
        import re
        _RF_SCAN_RX = re.compile(rb"&?RF_SCAN_DATA:RSSI/SCAN=\d+/CURVE_IDX=(\d+)/FREQ_IDX=(\d+)-(\d+)(?:;(\d+))?")
    if len(dec) < 7: return None
    strlen = int.from_bytes(dec[4:6], "big")         # 2-byte strlen field (dec[4:6])
    m = _RF_SCAN_RX.search(dec[6:6+strlen+2])        # match string key within string boundary
    if not m: return None
    curve = int(m.group(1)); flo = int(m.group(2)); fhi = int(m.group(3))
    p = 6 + strlen + 5                               # skip ASCII + 5-byte binary subheader
    arr = dec[p:]
    n = len(arr)//2
    amps = [struct.unpack(">h", arr[i*2:i*2+2])[0]/10.0 for i in range(n)]
    return curve, flo, fhi, amps

def build_join(src_cid, member_cid, chan, mid=1):
    # WWB advertises reliable seq-base == chan (its first reliable = chan+1); ours defaulted to
    # chan-1 (first reliable = chan). AD600_SEQBASE=chan matches WWB exactly.
    seq = (chan if os.environ.get("AD600_SEQBASE")=="chan" else (chan - 1)) & 0xffff
    params = bytes([0x00,0x05,0x00,0x00,0x02,0x00,0x32,0x00,0x14,0xff])   # from WWB template
    data = (member_cid + struct.pack(">H",mid) + struct.pack(">H",chan) + b"\x00\x00"
            + struct.pack(">I",seq) + struct.pack(">I",seq) + params)
    return root_wrap(src_cid, pdu_encode(4, None, data, 1))

def parse_reply(data):
    pr = root_parse(data)
    if not pr: return "non-ACN"
    src, sdt = pr; r = pdu_decode(sdt, 0)
    if not r: return "ACN src=%s (no SDT)"%src.hex()[:8]
    f, ds, end = r; vec = sdt[ds]
    return "ACN src=%s SDT=%s data=%s"%(src.hex()[:8], SDT_VEC.get(vec,"vec%d"%vec), sdt[ds+1:end].hex())

def build_join_accept(src_cid, leader_cid, leader_chan, relseq, recip_chan, mid=1):
    data = (leader_cid + struct.pack(">H",leader_chan) + struct.pack(">H",mid) + b"\x00\x00"
            + struct.pack(">H",relseq) + struct.pack(">H",recip_chan))
    return root_wrap(src_cid, pdu_encode(6, None, data, 1))

def _sdt_vec(sdt):
    r = pdu_decode(sdt, 0)
    if not r: return None, None
    f, ds, end = r
    return sdt[ds], sdt[ds+1:end]     # vector, data

def client_block(mid, proto, assoc, payload):
    body = struct.pack(">H",mid) + struct.pack(">I",proto) + struct.pack(">H",assoc) + payload
    total = 2 + len(body)
    return bytes([0x70|(total>>8), total&0xff]) + body

def build_wrapper(src_cid, chan, total, rel, oldest, blocks, reliable=True,
                  trailer=b"\xff\xff\xff\xff\x00\x00"):
    hdr = (struct.pack(">H",chan) + struct.pack(">I",total) + struct.pack(">I",rel)
           + struct.pack(">I",oldest) + trailer)
    return root_wrap(src_cid, pdu_encode(1 if reliable else 2, None, hdr + b"".join(blocks), 1))

def mgmt_ack(seq):   return pdu_encode(0x0e, None, struct.pack(">I", seq), 1)   # 70 07 0e 0000xxxx
def mgmt_proto():    return pdu_encode(0x09, None, struct.pack(">I", 0x102), 1) # 70 07 09 00000102

def parse_wrapper(vdata):
    """vdata = SDT wrapper payload. Returns (chan, total, rel, oldest, [client blocks])."""
    if len(vdata) < 20: return None
    chan,total,rel,oldest = struct.unpack(">HIII", vdata[:14])
    cb = vdata[20:]; blocks=[]; j=0
    while j < len(cb):
        r = pdu_decode(cb, j)
        if not r: break
        cf,cds,ce = r; body=cb[cds:ce]; q=2 if cf&0x4 else 0
        proto=int.from_bytes(body[q:q+4],"big") if (cf&0x2 and len(body)>=q+6) else None
        q+=6 if cf&0x2 else 0
        blocks.append((proto, body[q:])); j=ce
    return chan,total,rel,oldest,blocks

def join_probe():
    import time
    cid = gen_cid()
    # WWB uses a high random channel (0x8c20 etc.); a fixed low 0x0d20 may collide with device
    # internals. Pick a high random channel like WWB (env AD600_CHAN to override/pin).
    our_chan = int(os.environ.get("AD600_CHAN","0"),16) or (0x8000 | (os.urandom(1)[0]<<4) | 0x0)
    dst = (AD600_IP, CTRL_PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", int(os.environ.get("AD600_PORT","0")))); s.settimeout(float(os.environ.get("AD600_SOCKTMO","0.1")))   # AD600_PORT to pin src port (WWB uses 62288)
    print("our CID=%s  our chan=0x%04X  port=%d" % (cid.hex(), our_chan, s.getsockname()[1]))
    # ── SLP self-registration (AD600_SLP) ── WWB multicasts an ACN component advert on 8427 to
    # 239.255.254.253 announcing its CID + SDT endpoint BEFORE joining; the device builds a table of
    # known controllers from these and only fully serves recognized ones. Cold-joining without this
    # gets a 2s "who are you" stall + degraded/read-only service. Replicate WWB's exact advert.
    slp_pkt=None; slp_sock=None; last_slp=[0.0]
    if os.environ.get("AD600_SLP"):
        try:
            _t=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); _t.connect((dst[0],1)); myip=_t.getsockname()[0]; _t.close()
        except Exception: myip=os.environ.get("AD600_MYIP","192.168.5.68")
        sport=s.getsockname()[1]
        cidstr=(cid[0:4].hex()+"-"+cid[4:6].hex()+"-"+cid[6:8].hex()+"-"+cid[8:10].hex()+"-"+cid[10:16].hex()).upper()
        attrs=("(cid=%s),(acn-fctn=WWB6),(acn-uacn=WWB 6X),(acn-services=esta.dmp),"
               "(csl-esta.dmp=esta.sdt/%s:%d;esta.dmp/cd:CCDA8E0A-E139-11DF-8C7A-0015C5F3F612),"
               "(device-description=$:tftp://%s/$.ddl),"
               "(csl-esta.dmp.values=version:1_interfaceId:1_extVersion:1)")%(cidstr,myip,sport,myip)
        attrb=attrs.encode()
        after_len=b"\x00\x00"+b"\x00\x00\x00"+b"\x22\x3d"+b"\x00\x02"+b"en"+b"\x00\x00"+struct.pack(">H",len(attrb))+attrb+b"\x00"
        slp_pkt=b"\x02\x07"+(2+3+len(after_len)).to_bytes(3,"big")+after_len
        slp_sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        slp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try: slp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
        except Exception: pass
        try: slp_sock.bind(("",8427))
        except Exception as e: print("   SLP bind warn:",e)
        slp_sock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,4)
        try: slp_sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton("239.255.254.253")+socket.inet_aton(myip))
        except Exception as e: print("   SLP mcast-join warn:",e)
        for _ in range(int(os.environ.get("AD600_SLPN","3"))):
            slp_sock.sendto(slp_pkt,("239.255.254.253",8427)); time.sleep(0.12)
        last_slp[0]=time.time()
        print("→ SLP announce sent (cid=%s sdt=%s:%d, %dB) — waiting for device to register us"%(cidstr,myip,sport,len(slp_pkt)))
        time.sleep(float(os.environ.get("AD600_SLPWAIT","1.2")))
    s.sendto(build_join(cid, AD600_CID, our_chan), dst); print("→ JOIN sent")

    ad600_chan=None; accepted_us=False; sent_accept=False; joined=False
    keys=[]; decoded=0
    # SDT reliable-transport counters (mirror WWB): total++ every wrapper, rel++ only on reliable.
    _wwbbase = os.environ.get("AD600_SEQBASE")=="chan"
    total_seq=[(our_chan+1)&0xffff if _wwbbase else our_chan]
    rel_seq=[(our_chan if _wwbbase else (our_chan-1))&0xffff]; first_rel=[True]; mak_ctr=[0]
    tx_nonce=os.urandom(8); tx_bytes=[0]          # continuous TX keystream position
    rx_pos=[0]; rx_seen={}                         # continuous RX keystream position (per device rel seq)
    # SRP state
    srp=SRPClient(); boot_key=[None]; srp_salt=[None]; srp_B=[None]; srp_done=[False]
    srp_stage=["idle"]; dev_rel=[0]; proto_ok=[False]; full_sk0=[b""]; undec=[0]; scan_events=[0]
    dev_recv=set(); dev_contig=[None]   # device reliable seqs received; highest CONTIGUOUS seq to ack
    ack_freeze=[None]                   # WWB-mimic: freeze our mgmt-ack seq once DMP starts (see below)
    FREEZE=bool(os.environ.get("AD600_FREEZEACK"))
    # AD600_QUIETCTRL: live-topo ground truth (WWB scan) shows WWB keeps its CONTROL channel silent
    # mid-scan (rel static) and ACKs ONLY the DATA/firehose channel (assoc=device-data-chan). Our
    # per-0.12s control acks advance the device's Oldest and wedge its cmd pipeline after ~13 (the
    # no-sweep wall). QUIETCTRL fully suppresses control-channel acks once proto is up, matching WWB.
    QUIETCTRL=bool(os.environ.get("AD600_QUIETCTRL"))
    ACKSELF=bool(os.environ.get("AD600_ACKSELF"))   # tag mgmt-ACKs with OUR (leader) chan like WWB
    def ack_assoc(): return our_chan if ACKSELF else (ad600_chan or 0)
    def ack_seq():
        # WWB stops acking after the handshake (its ACK stays at bf73 → device `old` frozen at bf74 →
        # device streams replies fire-and-forget). Our per-wrapper ack ADVANCED the device's `old`,
        # after which the device sent only ~2 replies then went silent. FREEZE reproduces WWB: hold
        # the ack at its value when DMP began and never advance it.
        return ack_freeze[0] if (FREEZE and ack_freeze[0] is not None) else dev_rel[0]
    proto_assoc_sent=[False]            # have we sent our reciprocal ASSOC0a in response to device DECL09
    assoc_time=[None]                   # wall-clock when the FULL (bidirectional) SDT association came up
    cmd_queue=[]; last_send=[0.0]; last_ack=[0.0]   # DMP blobs to send one-at-a-time (time-paced)
    # ── AD600_HOLD (WWB-faithful reserve-and-HOLD) ──────────────────────────────────────
    # Triangulated root cause (WWB binary RE + both-direction pcap decrypt, Aug 2026):
    # the device honours the RF_SCAN:CURRENT_SWEEP_STATUS subscribe ONLY from the member that
    # OWNS the scan slot. Ownership is claimed by GET RF_SCAN:SCAN_ID (0x0107010f) — WWB's
    # InternalRequestScanId → the device stamps its get-only, device-owned CURRENT_REQUESTER_CID
    # [SCAN=N] = our SDT CID — and must be HELD (no RELEASE_SCAN_ID) through the subscribe.
    # Our defaults defeated this two ways: (1) no-read never claimed; (2) reserve-mode DID claim
    # slot N but the RELEASE bookend then freed slots 0..15 incl. N, disowning us two commands
    # before SUB_STATUS. Decrypt proof: our un-owned subscribe gets THREE vec=0x0d one-shot
    # replies (values 0x01 — data exists!) then the device declines to register the recurring
    # vec=0x04 EVENT push. Not a freeze — a subscription-registration refusal. HOLD = WWB's path.
    if os.environ.get("AD600_HOLD"):
        os.environ["AD600_NOREADID"]="0"   # DO read SCAN_ID → reserve + stamp CURRENT_REQUESTER_CID=us
        os.environ["AD600_NORELEASE"]="1"  # DO NOT release the reserved slot (both bookends off)
        os.environ.pop("AD600_SCAN0",None) # scan on the device-returned id N (rewrite_scan_idx → /SCAN=N)
        print("→ AD600_HOLD: reserve (GET SCAN_ID) and HOLD ownership through the RF_SCAN subscribe")
    scan_mode=[False]; scan_launched=[False]   # AD600_SCAN: defer string cmds until live SCAN_ID read
    import threading as _thr0
    ssm_gate=_thr0.Event()                      # set by RX when device fires EVENT 0x0109002b (module owned);
    ssm_seen=[False]                            # WWB waits for this before SET =02 + the RF_SCAN batch
    poke={"built":False,"q":[],"t":0.0}         # AD600_POKE: throw a battery of probes at a stalled session
    brute={"built":False,"q":[],"t":0.0,"big":0}  # AD600_BRUTE: subscribe RF_SCAN_DATA across SCAN=0..N
    relm={"built":False,"q":[],"t":0.0,"done":False}  # AD600_RELEASEALL: free leaked scan slots 0..N
    # ── AD600_CH2: open a SECOND SDT channel for the RSSI firehose (WWB does this) ──
    # PCAP ground-truth: WWB runs TWO concurrent channels on one session — a control channel
    # (its chan 0x4bca ↔ device 0x8151) AND a data channel it opens at scan-start (its chan 0x4bcb
    # ↔ device 0x81ea) on which the device streams 15k+ big RF_SCAN_DATA packets. Our single-channel
    # client gives the device nowhere to push → one-shot vec=13 + freeze. Fix: create a 2nd leader
    # channel (our_chan+1), let the device join it, then the device streams on its paired 2nd channel.
    CH2=bool(os.environ.get("AD600_CH2"))
    our_chan2=(our_chan+1)&0xffff
    # seq init MUST match build_join's advertised base (our_chan2-1): first wrapper total=our_chan2,
    # first reliable rel=our_chan2 — else the device sees a sequence gap and drops all ch2 traffic.
    ch2={"sent":False,"dev":None,"acc":False,"big":0,"small":0,"first_big":[None],
         "total":our_chan2,"rel":(our_chan2-1)&0xffff,"first_rel":True,"first_rel_seq":None,
         "proto_ok":False,"assoc_sent":False,"decl_sent":False,"resub":False,"idx":None,"devrel":None}
    def launch_scan(idx):
        """Build + enqueue the string-addressed scan sequence on the CURRENT scan id.
           Default order = WWB-exact (SUB_STATUS, CONFIG, SUB_DATA, START).  AD600_CONFIGFIRST
           puts CONFIG+START before the subscribes — the device halts our member after its FIRST
           string SUBSCRIBE, so front-loading the config/start gives them a chance to land before
           that halt (the subscribes are only needed to RECEIVE data, not to start the sweep)."""
        if scan_launched[0]: return
        scan_launched[0]=True
        import threading as _thr
        ftp_gate=_thr.Event()          # set on FTP-login success; gates the RF_SCAN batch (WWB enroll-before-arm)
        _cfl_close=[]                  # CFL-export close SETs; released only after FTP-login (see gate at tail)
        ch2["idx"]=idx    # remember live SCAN_ID so CH2 can re-subscribe RF_SCAN_DATA on the 2nd channel
        # ══ MODULE-OPEN PREAMBLE (defect #4, THE fix — from client_setfreeze vs wwb_scan wire diff) ══
        # DEFINITIVE FINDING: our SET 0x0109002a=01 is delivered reliably AND cumulatively ACKed by the
        # device (byte-identical to WWB's) — then SILENTLY DROPPED at the SSM (Spectrum-Scan-Module)
        # application layer, because we write to the module WITHOUT first enrolling as a subscriber of it.
        # WWB, before its enable-SET, SUBSCRIBES the entire 0x010902xx scan-module property tree and reads
        # the SRP/security *status* (GETs, NOT an SRP-6a auth — SRP was never the gate). Only an enrolled
        # subscriber's writes are honored → device fires EVENT 0x0109002b → firehose. Replay that here,
        # ahead of the enable-SET. AD600_NOMODOPEN=1 restores the old (broken) jump-straight-to-SET path.
        if os.environ.get("AD600_NOMODOPEN","0")=="0":
            _mo=[]
            # 1) OPEN THE SSM OBJECT — subscribe the full scan-module tree (WWB @ t=0.645-0.651)
            for _a in (0x01090201,0x01090202,0x01090203,0x01090204,0x01090205,0x01090206,0x01090207,
                       0x01090210,0x01090212,0x01090220,0x01090221,0x01090222,0x01090223,0x01090224):
                _mo.append(dmp_pdu(DMP_SUBSCRIBE,_a))
            # 2) READ SRP/security CONTEXT (WWB GETs these; device already reports Admin/0xff — no auth)
            for _a in (0x01201106,0x01201103,0x01201102,0x01201003):
                _mo.append(dmp_pdu(DMP_GET,_a))
            for _a in (0x01201007,0x01201103,0x01201102):
                _mo.append(dmp_pdu(DMP_SUBSCRIBE,_a))
            _mo.append(dmp_pdu(DMP_GET,0x01301019))
            # 3) RE-SUBSCRIBE 0x01090201 standalone (WWB @ t=3.480) — SUB 0x0109002b + SET follow below
            _mo.append(dmp_pdu(DMP_SUBSCRIBE,0x01090201))
            for _c in _mo: cmd_queue.append(_c)
            print("→ MODULE-OPEN: %d SSM-tree subscribes + SRP status reads enqueued BEFORE enable-SET (defect #4 fix)"%len(_mo))
        if os.environ.get("AD600_STARTB4DATA"):
            # START after SUB_STATUS+CONFIG (satisfies device's scan-request registration) but BEFORE
            # SUB_DATA (the 374B RF_SCAN_DATA subscribe that desyncs our CTR position). This puts START at
            # a correct/synced position AND after the prerequisites. SUB_DATA last (for firehose delivery).
            seq=(SCAN_CMD_SUB_STATUS, SCAN_CMD_CONFIG, SCAN_POST, SCAN_CMD_SUB_DATA)
            print("→ SCAN start (STARTB4DATA): SUB_STATUS, CONFIG, START, SUB_DATA (live SCAN idx=%d)"%idx)
        elif os.environ.get("AD600_CONFIGFIRST"):
            seq=(SCAN_CMD_CONFIG, SCAN_POST, SCAN_CMD_SUB_STATUS, SCAN_CMD_SUB_DATA)
            print("→ SCAN start (CONFIGFIRST): CONFIG, START, SUB_STATUS, SUB_DATA (live SCAN idx=%d)"%idx)
        elif os.environ.get("AD600_SUBSFIRST"):
            # (rejected) all-subs-first strands SUB_DATA (RF_SCAN_DATA) before CONFIG — the device
            # won't accept a data subscription with no sweep configured yet. Kept only for A/B.
            seq=(SCAN_CMD_SUB_STATUS, SCAN_CMD_SUB_DATA, SCAN_CMD_CONFIG, SCAN_POST)
            print("→ SCAN start (SUBS-FIRST): SUB_STATUS, SUB_DATA, CONFIG, START (live SCAN idx=%d)"%idx)
        else:
            # WWB-EXACT order. The whole batch is held (scan_launched gate) until the association is up
            # AND settled, then bursts as a unit — so CONFIG lands on a settled association and SUB_DATA
            # correctly follows CONFIG (RF_SCAN_DATA subscription needs the sweep already configured).
            seq=(SCAN_CMD_SUB_STATUS, SCAN_CMD_CONFIG, SCAN_CMD_SUB_DATA, SCAN_POST)
            print("→ SCAN start (WWB-EXACT): SUB_STATUS, CONFIG, SUB_DATA, START (live SCAN idx=%d)"%idx)
        # PREREQUISITE (from device Event Log 'New Empty Freq. List Created'): WWB creates an empty
        # Coordination Freq List BEFORE the scan config; SCAN_START_FREQ writes INTO that list. Our
        # reconnect captures already had a list, so REPLAYRAW never did this and the device halted at
        # CONFIG. SET CFL_NEW_LIST (0x01090020)=1 first → fires CFL_CREATED, then the scan config lands.
        # WWB pre-registers CURRENT_STATUS via a DISTINCT message type vec=0x08 (which our client has
        # NEVER sent — we only use GET=1/SET=2/SUB=7), as a STANDALONE PDU ~800ms BEFORE the scan config.
        # Our client instead batched CURRENT_STATUS as a vec=07 continuation inside SUB_STATUS. If vec=08
        # is a "monitor/register" subscribe the device requires to enroll us as a scan-data recipient,
        # that's the missing wire step. Send WWB's exact vec=08 CURRENT_STATUS subscribe first.
        if os.environ.get("AD600_CFLEXPORT"):
            # WWB does a CFL-EXPORT handshake at connect that our client skips ENTIRELY (these are SETs;
            # FULLINV only replays GET/SUB). SET 0x0109002a=01 opens the transient FTP server; WWB then
            # FTP-authenticates (wwb/dSUeg=Qq) and downloads /ssm_export.cfl; then SET 0x0109002a=02.
            # Even though the .cfl is empty, DOING this export (esp. the FTP auth) may enroll us as a
            # scan-data-eligible controller — the one wire step we've never performed.
            for c in ("700807020109002b",                 # SUB 0x0109002b
                      "700902020109002a017005010000",     # SET 0x0109002a=01  (open export/FTP)
                      "7009020201010201017005010000"):    # SET 0x01010201=01
                cmd_queue.append(bytes.fromhex(c))
            if os.environ.get("AD600_CFLFTP"):
                import threading, ftplib, io
                def _ftp():
                    import time as _t
                    for _ in range(int(os.environ.get("AD600_FTPRETRY","200"))):   # retry long enough to catch the window (opens after inventory drains)
                        try:
                            f=ftplib.FTP(); f.connect(AD600_IP,21,timeout=1); f.login("wwb","dSUeg=Qq")
                            buf=io.BytesIO(); f.retrbinary("RETR /ssm_export.cfl", buf.write)
                            b2=io.BytesIO();
                            try: f.retrbinary("RETR /ssm_export.dev", b2.write)
                            except Exception: pass
                            print("   → ✓ CFL FTP EXPORT: authed as wwb + downloaded cfl=%dB dev=%dB"%(len(buf.getvalue()),len(b2.getvalue())))
                            if os.environ.get("AD600_SAVEEXPORT"):
                                try:
                                    _d=os.environ.get("AD600_SAVEEXPORT")
                                    open(_d+"/ssm_export.cfl","wb").write(buf.getvalue())
                                    open(_d+"/ssm_export.dev","wb").write(b2.getvalue())
                                    print("   → saved ssm_export.cfl/.dev to %s"%_d)
                                except Exception as _se: print("   → save err: %s"%_se)
                            ftp_gate.set()   # enroll confirmed → release the gated CFL-close + RF_SCAN batch
                            if os.environ.get("AD600_CFLHOLD"):
                                # keep the authenticated FTP control session ALIVE through the scan so the
                                # device holds the "wwb" identity association for our IP during the scan.
                                for _ in range(120):
                                    try: f.voidcmd("NOOP"); _t.sleep(1.0)
                                    except Exception: break
                            f.quit(); return
                        except Exception: _t.sleep(0.15)
                    print("   → CFL FTP export: never caught the window")
                threading.Thread(target=_ftp,daemon=True).start()
            if not os.environ.get("AD600_CFLHOLD"):        # AD600_CFLHOLD: keep FTP window OPEN (don't close)
                # WWB's close = SET 0x0109002a=02 then SET 0x01010201=00 (NO vec=08 — WWB never emits
                # vector 0x08; see wwb_scan_working_realdevice.pcap @47.141/47.145). Deferred into
                # _cfl_close so it (and the RF_SCAN batch) is released ONLY after FTP-login success.
                for c in ("700902020109002a027005010000",     # SET 0x0109002a=02  (close export)
                          "7009020201010201007005010000"):    # SET 0x01010201=00
                    _cfl_close.append(bytes.fromhex(c))
            else:
                print("   → CFLHOLD: FTP export window kept OPEN through the scan (FTP-auth as wwb persists)")
            print("   → CFL-EXPORT handshake (SETs 0x0109002a/0x01010201%s) inserted"%(" + FTP" if os.environ.get("AD600_CFLFTP") else ""))
        # ★ WWB RECIPE (from full.log): WWB RELEASES scan slot 0 (SET 0x0107010e=0) at scan-start, then
        # runs the ENTIRE scan on /SCAN=0. Our client had removed the release + switched to /SCAN=<read id>,
        # so we ran on a reserved/occupied slot → sweep never produced. AD600_SCAN0 (default) matches WWB:
        # force idx=0 and prepend RELEASE_SCAN_ID=0. AD600_SCAN0=0 keeps the old read-id behaviour.
        if os.environ.get("AD600_SCAN0"):
            idx=0; ch2["idx"]=0
        # collect the main scan-start commands (vec=08 pre-sub + CFL_NEW_LIST + seq)
        sc_cmds=[]
        # A leading SUBSCRIBE (vec=08 CURRENT_STATUS) must go FIRST: it's the reliable msg that makes the
        # device DECL09 → we reciprocate ASSOC0a → the association fully opens (arming writes). If the
        # release SETs (writes) went first they'd be held by the write-gate and deadlock this bring-up.
        # ★ BYTE-PARITY: WWB NEVER sends a vector-0x08 PDU (verified against wwb_scan_working_realdevice.pcap:
        # its subscribes are all vec 0x07). The device silently ignores our malformed vec-0x08 op. Default OFF.
        if os.environ.get("AD600_VEC08","0")!="0":
            sc_cmds.append(rewrite_scan_idx(bytes.fromhex(
                "70230807001f52465f5343414e3a43555252454e545f5354415455532f5343414e3d30"), idx))
        # BOOKEND (startup): now (after the leading subscribe) release the ENTIRE slot range so a prior
        # crashed run's leaked slots are cleared and we sweep on a clean slot 0. These are writes, held by
        # the write-gate until the association opens — which the subscribe above triggers. Pairs with the
        # teardown release so the device always returns to SCAN_ID=0. We never GET 0x0107010f (would bump).
        if not os.environ.get("AD600_NORELEASE"):
            _rn = int(os.environ.get("AD600_RELSLOTS","16"))
            for _rid in range(_rn):
                sc_cmds.append(dmp_pdu(2, 0x0107010e, bytes([_rid & 0xff]))+bytes.fromhex("7005010000"))
            print("→ RELEASE bookend (startup): release slots 0..%d before scan config"%(_rn-1))
        elif os.environ.get("AD600_SCAN0"):
            sc_cmds.append(dmp_pdu(DMP_SET, 0x0107010e, b"\x00")+bytes.fromhex("7005010000"))  # RELEASE slot 0 (WWB)
        # ★ BYTE-PARITY: WWB never sends SET 0x01090020 (CFL_NEW_LIST) in the working scan stream. Default OFF.
        if os.environ.get("AD600_NEWLIST","0")!="0":
            sc_cmds.append(dmp_pdu(DMP_SET, 0x01090020, b"\x01")+bytes.fromhex("7005010000"))
        # AD600_PROBEALL: interleave MONITOR_THRESHOLD SETs with DISTINCT dBm values between each scan
        # command. The device logs each change that decrypts correctly. The FIRST value that does NOT log
        # pinpoints the command that drifts our CTR position. probe(dbm)=SET 0x01090050=<dbm*10 s16>.
        _probeall = bool(os.environ.get("AD600_PROBEALL")) or bool(os.environ.get("AD600_GETPROBE"))
        # AD600_GETPROBE: use distinct GETs (device replies vec=3 immediately IFF position synced) — read
        # from OUR log, no Event Log / persisted state needed. First GET with NO reply = the drift point;
        # a reply proves position-synced (→ functional halt, not crypto drift).
        _getp = bool(os.environ.get("AD600_GETPROBE"))
        _paddr=[0x01000012,0x01000024,0x01000025,0x01000026,0x01000028]
        def _probe(i):
            if _getp: return dmp_pdu(DMP_GET, _paddr[i])
            dbm=int(os.environ.get("AD600_PROBEBASE","-90"))-i
            return dmp_pdu(DMP_SET, 0x01090050, struct.pack(">h", dbm*10))+bytes.fromhex("7005010000")
        _pv=[0,1,2,3,4]
        if _probeall:
            sc_cmds.append(_probe(0)); print("   → %s probes interleaved (drift localizer)"%("GET" if _getp else "threshold"))
        for _ci,c in enumerate(seq):
            if c is SCAN_POST and os.environ.get("AD600_STARTID"):
                sc_cmds.append(dmp_pdu(DMP_SET, 0x01070103, bytes([idx & 0xff]))+bytes.fromhex("7005010000"))
                print("   → START_SCAN value = live SCAN_ID %d (A/B override; WWB uses 0)"%idx)
            else:
                sc_cmds.append(rewrite_scan_idx(c, idx))
            if _probeall and _ci+1 < len(_pv):
                sc_cmds.append(_probe(_pv[_ci+1]))
        # POSITION PROBE: after START, SET MONITOR_THRESHOLD (0x01090050) to a distinctive value. If the
        # device logs "monitoring threshold changed: -90dBm", our CTR position is CORRECT through the whole
        # scan flow (so START isn't being garbled by drift). If NO log entry, position drifted at/before
        # START → the device decrypted START to garbage and dropped it. AD600_POSTPROBE=1 to enable.
        if os.environ.get("AD600_POSTPROBE"):
            sc_cmds.append(dmp_pdu(DMP_SET, 0x01090050, bytes.fromhex("fc7c"))+bytes.fromhex("7005010000"))  # -900 = -90.0dBm
            print("   → POSTPROBE: SET MONITOR_THRESHOLD=-90dBm AFTER start (device should log it IFF CTR position held)")
        # DIAGNOSTIC: after START, subscribe+GET CURRENT_REQUESTER_CID so the device tells us who it
        # thinks owns the scanner. If it's NOT our CID, our START never made us the sweep owner → no vec=4.
        # ★ BYTE-PARITY: WWB does not append CURRENT_REQUESTER_CID SUB/GET after START. Default OFF (diag only).
        if os.environ.get("AD600_REQCID","0")!="0":
            sc_cmds.append(bytes.fromhex("702a0707002452465f5343414e3a43555252454e545f5245515545535445525f4349442f5343414e3d30"))  # SUB
            sc_cmds.append(bytes.fromhex("702a0107002452465f5343414e3a43555252454e545f5245515545535445525f4349442f5343414e3d30"))  # GET
            print("   → REQCID diagnostic: SUB+GET RF_SCAN:CURRENT_REQUESTER_CID (who owns the scanner?)")
        # ── FTP-ENROLL GATE (defect #3) ──────────────────────────────────────────────────────────────
        # WWB completes the CFL-export enroll (SET 0x0109002a=01 → FTP login wwb/dSUeg=Qq → RETR
        # /ssm_export.cfl + .dev → SET 0x0109002a=02) BEFORE it emits the RF_SCAN config/subscribe/START.
        # Our FTP runs on a daemon thread, so we must hold the CFL-close SETs *and* the RF_SCAN batch
        # until ftp_gate fires (login success). Otherwise the close SET can drain the FTP window shut and
        # the RF_SCAN batch races out before enroll — the original defect. Fallback timeout so a stuck
        # FTP never wedges the run. AD600_NOFTPGATE=1 restores the old ungated behaviour (A/B).
        def _arm_enqueue():
            for c in _cfl_close: cmd_queue.append(c)
            for c in sc_cmds:    cmd_queue.append(c)
        # ★ SSM-EVENT GATE (defect #4, pairs with MODULE-OPEN): once the module is open, the enable-SET
        # (=01) is honored and the device fires EVENT 0x0109002b. WWB WAITS for that event, leaves ~1.1s,
        # THEN sends the close (=02) and the RF_SCAN config/START — it never bursts them ahead of ownership.
        # This is the correct signal (not FTP-login); takes priority when MODULE-OPEN + enable-SET are live.
        # (decoupled from MODULE-OPEN 2026-08-05: WWB waits for the EVENT 0x0109002b before RF_SCAN
        # regardless of whether it pre-subscribed the tree; the gate is the EVENT, per the DMP-dispatch RE.)
        _ssm_gating = bool(os.environ.get("AD600_CFLEXPORT")) and os.environ.get("AD600_NOSSMGATE","0")=="0"
        _ftp_gating = bool(os.environ.get("AD600_CFLEXPORT")) and bool(os.environ.get("AD600_CFLFTP")) \
                      and os.environ.get("AD600_NOFTPGATE","0")=="0"
        if _ssm_gating:
            def _wait_ssm():
                to=float(os.environ.get("AD600_SSMGATE_TO","6"))
                if ssm_gate.wait(to):
                    settle=float(os.environ.get("AD600_SSMSETTLE","1.1"))
                    print("   → SSM owned (EVENT 0x0109002b) → %.1fs settle → releasing close(=02)+RF_SCAN (%d cmds)"%(settle,len(_cfl_close)+len(sc_cmds)))
                    time.sleep(settle)
                else:
                    print("   → SSM gate TIMEOUT (%.0fs, no 0x0109002b event — enable-SET may still be dropped) → releasing anyway"%to)
                _arm_enqueue()
            _thr.Thread(target=_wait_ssm,daemon=True).start()
            print("   → close(=02)+RF_SCAN GATED on SSM EVENT 0x0109002b (WWB enroll-then-configure; %d cmds pending)"%(len(_cfl_close)+len(sc_cmds)))
        elif _ftp_gating:
            def _wait_arm():
                to=float(os.environ.get("AD600_FTPGATE_TO","30"))
                if ftp_gate.wait(to):
                    print("   → FTP-enroll confirmed → releasing CFL-close + RF_SCAN batch (%d cmds)"%(len(_cfl_close)+len(sc_cmds)))
                else:
                    print("   → FTP gate TIMEOUT (%.0fs, enroll unconfirmed) → releasing RF_SCAN batch anyway"%to)
                _arm_enqueue()
            _thr.Thread(target=_wait_arm,daemon=True).start()
            print("   → RF_SCAN batch GATED on FTP-login success (enroll-before-arm; %d cmds pending)"%(len(_cfl_close)+len(sc_cmds)))
        elif os.environ.get("AD600_PACEDSCAN"):
            # WWB PACES its scan-start ~2-11ms/cmd (NOT the burst we've always used) and keeps the
            # 239.255.254.253:8427 advert PULSING (~4.05s). Fire a 239 pulse right before the scan,
            # then send the sequence directly with WWB's spacing (same thread as the loop → no race).
            for c in _cfl_close: cmd_queue.append(c)
            gap=float(os.environ.get("AD600_PACEMS","5"))/1000.0
            if slp_sock is not None:
                try: slp_sock.sendto(slp_pkt,("239.255.254.253",8427)); last_slp[0]=time.time(); print("   → 239 advert pulse (pre-scan)")
                except Exception: pass
            time.sleep(0.05)
            print("   → PACED scan-start: %d cmds @ %.0fms spacing (WWB-timing)"%(len(sc_cmds),gap*1000))
            for c in sc_cmds:
                send_dmp(c, keys[0]); time.sleep(gap)
        else:
            _arm_enqueue()
    def send_dmp(pdu, key, assoc=0):
        """ENCRYPT-THEN-MAC on a CONTINUOUS CTR stream (confirmed on-wire): the device tracks a
           byte-continuous keystream position, NOT per-message block counters — so each DMP is
           encrypted at the running position tx_bytes. client block = [01 01][len=16+DMPlen][IV]
           [ct]; IV = nonce + (pos//16); tag=skip32(key[:10], crc32(client_block)) appended."""
        pos = tx_bytes[0]
        ct = aes_ctr_at(key, tx_nonce, pos, pdu)
        iv = tx_nonce + ((pos+15)//16).to_bytes(8,"big")  # on-wire IV ctr = ceil(pos/16), matches WWB (keystream still floor via aes_ctr_at)
        tx_bytes[0] += len(pdu)
        # AD600_SDADJ: after SUB_DATA (70400707...), nudge our CTR position by N. If the device DROPS
        # SUB_DATA (never advances its position), SDADJ=-374 resyncs everything after it → confirms drift.
        if os.environ.get("AD600_SDADJ") and pdu[:4]==b"\x70\x40\x07\x07":
            tx_bytes[0] += int(os.environ.get("AD600_SDADJ"))
            print("   → SDADJ: tx_bytes %+d after SUB_DATA (resync probe)"%int(os.environ.get("AD600_SDADJ")))
        cb = b"\x01\x01" + struct.pack(">H", 16 + len(pdu)) + iv + ct
        tag = skip32(key[:10], zlib.crc32(cb)&0xffffffff, True).to_bytes(4, "big")
        send_wrapper([client_block(1,0x102,assoc, cb + tag)], True)
    def send_ch2(blocks, reliable):
        """Send an SDT wrapper on the 2nd channel (our_chan2) with ch2's own seq counters."""
        tot=ch2["total"]; ch2["total"]=(ch2["total"]+1)&0xffff
        if reliable:
            ch2["rel"]=(ch2["rel"]+1)&0xffff
            if ch2["first_rel_seq"] is None: ch2["first_rel_seq"]=ch2["rel"]
            trailer=b"\xff\xff\x00\x00\x00\x00" if ch2["first_rel"] else b"\xff\xff\xff\xff\x00\x00"
            ch2["first_rel"]=False; rel=ch2["rel"]; oldest=ch2["first_rel_seq"]
        else:
            trailer=b"\xff\xff\xff\xff\x00\x00"; rel=ch2["rel"]; oldest=rel
        s.sendto(build_wrapper(cid, our_chan2, tot, rel, oldest, blocks, reliable, trailer), dst)
    ch2_nonce=os.urandom(8); ch2_bytes=[0]; ch2_key=[None]
    def send_dmp_ch2(pdu):
        """Send a DMP command as an ENCRYPTED client-block wrapped ON the 2nd channel (ch2 key)."""
        key=ch2_key[0]; pos=ch2_bytes[0]
        ct=aes_ctr_at(key, ch2_nonce, pos, pdu)
        iv=ch2_nonce+((pos+15)//16).to_bytes(8,"big"); ch2_bytes[0]+=len(pdu)  # on-wire IV ctr = ceil(pos/16)
        cb=b"\x01\x01"+struct.pack(">H",16+len(pdu))+iv+ct
        tag=skip32(key[:10], zlib.crc32(cb)&0xffffffff, True).to_bytes(4,"big")
        send_ch2([client_block(1,0x102,0, cb+tag)], True)
    def ch2_scan_resub():
        if ch2["idx"] is not None and not ch2["resub"] and ch2_key[0]:
            ch2["resub"]=True
            send_dmp_ch2(rewrite_scan_idx(SCAN_CMD_SUB_DATA, ch2["idx"]))
            print("→ CH2: RF_SCAN_DATA subscribe sent AS DMP ON ch2 (own key) — device should deliver firehose here")
    def is_write(pdu):
        """True if this queued DMP blob's FIRST pdu is a SET (write). vector sits at offset 2 for
           flags 0x7 (2-byte len) or offset 3 for flags 0xF (3-byte len)."""
        if not pdu: return False
        off = 3 if (pdu[0] & 0xF0) == 0xF0 else 2
        return len(pdu) > off and pdu[off] == DMP_SET
    def writes_armed():
        """The write-gate: the device silently drops a SET sent on a HALF-OPEN association (our declare
           accepted, but the device's reciprocal DECL09 not yet reciprocated by us) and stalls the
           reliable stream. WWB never SETs until the association is fully up (its ~3s inventory covers
           the gap). So: no writes until we've reciprocated the device's DECL09 (proto_assoc_sent) plus
           a short settle. AD600_WRITEGATE=0 disables (to A/B test the old race)."""
        if os.environ.get("AD600_WRITEGATE") == "0": return True
        if not proto_assoc_sent[0]: return False
        return assoc_time[0] is None or (time.time()-assoc_time[0]) >= float(os.environ.get("AD600_ASSOCSETTLE","0.6"))
    def start_srp(key):
        # Write-gate = SRP access level (ours reads 0xff = unauthenticated; Admin credential exists).
        # To arm the exchange we must SELECT the level first (SET SRP_ACCESS_LEVEL=<AD600_SRP_LEVEL>),
        # else SALT/B come back as 1-byte status codes. Then SET A, and read SALT/B (GET or, with
        # AD600_SRP_SUB, SUBSCRIBE so they arrive as events). Identity/pass via AD600_SRP_USER/PASS.
        boot_key[0]=key; srp_stage[0]="sent_A"
        lvl=os.environ.get("AD600_SRP_LEVEL")
        if lvl is not None:
            cmd_queue.append(dmp_pdu(DMP_SET, A_SRP_ACCESS_LEVEL, bytes([int(lvl)&0xff])))
            print("→ SRP: SET SRP_ACCESS_LEVEL=%s (select level to authenticate)"%lvl)
        rd=DMP_SUBSCRIBE if os.environ.get("AD600_SRP_SUB") else DMP_GET
        print("→ SRP-6a: SET A(256B), %s salt+B  [I=%s pass=%s bootkey %s]"
              %("SUB" if rd==DMP_SUBSCRIBE else "GET", _SRP_I.decode(), "set" if _SRP_P else "(empty)", key.hex()[:12]))
        if os.environ.get("AD600_SRP_SUBFIRST"):
            # Subscribe to salt/B BEFORE sending A, so the device's post-A computed salt/B arrive as
            # change-notifies (vec=12/4) rather than as GET stubs read too early.
            cmd_queue.append(dmp_pdu(DMP_SUBSCRIBE, A_SRP_EXCHANGE_SALT))
            cmd_queue.append(dmp_pdu(DMP_SUBSCRIBE, A_SRP_EXCHANGE_B))
            cmd_queue.append(dmp_pdu(DMP_SET, A_SRP_EXCHANGE_A, srp.A_wire()))
        else:
            cmd_queue.append(dmp_pdu(DMP_SET, A_SRP_EXCHANGE_A, srp.A_wire()))
            cmd_queue.append(dmp_pdu(rd, A_SRP_EXCHANGE_SALT))
            cmd_queue.append(dmp_pdu(rd, A_SRP_EXCHANGE_B))
    def on_dmp(vec, addr, val):
        if addr==0x0107010f and scan_mode[0] and not scan_launched[0]:   # SCAN_ID reply
            env=os.environ.get("AD600_SCANIDX")
            idx=int(env) if env else int.from_bytes(val,"big") if val else 0
            print("← SCAN_ID=%d (val=%s)%s"%(idx, val.hex() if val else "-",
                                             " [env override]" if env else ""))
            launch_scan(idx)
        if addr==A_SRP_EXCHANGE_SALT and val: srp_salt[0]=val
        elif addr==A_SRP_EXCHANGE_B and val:  srp_B[0]=val
        elif addr==A_SRP_EXCHANGE_HAMK and val and srp.M2:
            ok=srp.verify_hamk(val)
            print("← SRP HAMK %s — control key=%s"%("OK ✓" if ok else "MISMATCH ✗", srp.K[:16].hex()))
            srp_done[0]=ok
        if srp_stage[0]=="sent_A" and srp_salt[0] and srp_B[0]:
            srp_stage[0]="sent_M"
            srp.compute(srp_salt[0], srp_B[0])
            print("→ SRP: computed K, queue SET M1, GET HAMK")
            cmd_queue.append(dmp_pdu(DMP_SET, A_SRP_EXCHANGE_M, srp.M1))
            cmd_queue.append(dmp_pdu(DMP_GET, A_SRP_EXCHANGE_HAMK))
    unacked={}; first_rel_seq=[None]          # rel_seq -> blocks awaiting ack; our FIRST reliable seq
    HOLDOLD=os.environ.get("AD600_HOLDOLD","1")!="0"   # WWB pins Oldest-Available at its first reliable
    def send_wrapper(blocks, reliable):
        tot=total_seq[0]; total_seq[0]=(total_seq[0]+1)&0xffff
        if reliable:
            rel_seq[0]=(rel_seq[0]+1)&0xffff
            if first_rel_seq[0] is None: first_rel_seq[0]=rel_seq[0]
            # ★ CORRECTED (ackcap + pcap trailer analysis): WWB's RELIABLE wrappers use ffffffff0000 (NO
            # MAK request) — the old code put the MAK here, which was WRONG and regressed streaming.
            if os.environ.get("AD600_MAK","0")!="0" and (mak_ctr[0]+1) % int(os.environ.get("AD600_MAKEVERY","6"))==0:
                mak_ctr[0]+=1
                trailer=b"\x00\x01\x00\x01\x00\x00"   # (legacy, default OFF now)
            elif first_rel[0]:
                trailer=b"\xff\xff\x00\x00\x00\x00"
            else:
                trailer=b"\xff\xff\xff\xff\x00\x00"
            first_rel[0]=False
            unacked[rel_seq[0]]=blocks
        else:
            # ★ WWB sends the MAK-REQUEST (000100010000 = "member 1/device, ACK my reliable stream") on
            # ~1-in-3 of its UNRELIABLE acks (pcap: 398/1136). This is what keeps the device acking+
            # processing our reliable commands past the SUB_STATUS freeze. AD600_ACKMAK=0 disables.
            mak_ctr[0]+=1
            if os.environ.get("AD600_ACKMAK","1")!="0" and mak_ctr[0] % int(os.environ.get("AD600_ACKMAKEVERY","3"))==0:
                trailer=b"\x00\x01\x00\x01\x00\x00"
            else:
                trailer=b"\xff\xff\xff\xff\x00\x00"
        # Oldest-Available-Wrapper. WWB PINS this at its first reliable seq forever (never releases its
        # retransmit buffer); our old code advanced it as the device acked (min(unacked)), and the device
        # then processed only ~2 of our reliable DMP commands. HOLDOLD mimics WWB (constant).
        if not reliable and os.environ.get("AD600_ACKOLDEST","1")!="0":
            # ★ ACK-capture (ackcap.log) shows WWB's UNRELIABLE acks set OLDEST == rel (no backlog claimed).
            # We were pinning oldest at first_rel_seq → the device sees us claiming a huge un-released
            # reliable window and throttles/stalls its send to us (the freeze after SUB_STATUS). Match WWB:
            # oldest = current rel on unreliable wrappers. AD600_ACKOLDEST=0 restores old behaviour.
            oldest=rel_seq[0]
        elif HOLDOLD and first_rel_seq[0] is not None:
            oldest=first_rel_seq[0]
        else:
            oldest=min(unacked) if unacked else rel_seq[0]
        pkt=build_wrapper(cid, our_chan, tot, rel_seq[0], oldest, blocks, reliable, trailer)
        s.sendto(pkt, dst)
    def on_our_ack(ackseq):                   # device acked our reliable seq up to ackseq
        for sq in [q for q in unacked if ((q-ackseq)&0xffff)==0 or ((ackseq-q)&0xffff)<0x8000]:
            unacked.pop(sq, None)             # drop everything <= ackseq
        # NOTE: fire-and-forget like WWB — no retransmit here. The device acks only
        # the FIRST reliable then just streams replies; retransmitting stale unacked
        # seqs floods the device and wedges it. Clearing happens on device liveness.
    t0=time.time()
    runfor = 40 if os.environ.get("AD600_SCAN") or os.environ.get("AD600_WWBREPLAY") or os.environ.get("AD600_REPLAYRAW") or os.environ.get("AD600_FULLINV") else 15
    # ── SESSION-RECOVERY instrumentation (AD600_RECOVER) ─────────────────────────────────
    # Ground truth: wwb_scan_working_realdevice.pcap. WWB's FIRST session (its chan 0x6996 ↔ dev
    # 0x9c94) accepts the full handshake + inventory, the device emits ONE firehose packet (t≈12.5s)
    # then WEDGES its own reliable stream — it stops advancing, ignores WWB's NAK (t≈24) AND ignores
    # WWB's rapid re-JOIN attempts on incremented channels (t≈26-34, MID 2/3/4, all unanswered).
    # WWB does NOT send a LEAVE (zero LEAVING vectors in the whole capture); it abandons the channel,
    # waits a ~19s cooldown for the device to un-wedge, then opens a COMPLETELY FRESH session (new
    # leader chan 0x6998, MID reset to 1, full JOIN+JOIN_ACCEPT+reciprocal proto-0x102 DECL09/ASSOC0a
    # BOTH directions) and re-runs the inventory+subscribe — and THAT session carries the sustained
    # scan (39-42 big pkts / 2s from t≈54 to end). The freeze is DEVICE-initiated (proven: our mock,
    # which ACKs the reliable window correctly, keeps WWB happy for 13,572 subscribes with zero re-
    # JOINs). So the fix is NOT better window management — it is to DETECT the stall and re-establish
    # a fresh session exactly like WWB. join_with_recovery() drives this outer loop; each join_probe()
    # call already mints a fresh CID + fresh random channel + fresh socket = a fresh session.
    RECOVER=bool(os.environ.get("AD600_RECOVER"))
    FH_OK=int(os.environ.get("AD600_FH_OK","20"))          # firehose pkts that mean "sustained scan = success"
    FREEZE_SECS=float(os.environ.get("AD600_FREEZE_SECS","9"))  # device died ~7s post-handshake in the capture
    fh_ok=[False]; scan_launch_t=[None]; wedged=[False]
    while time.time()-t0 < runfor:
        # ★ CH2 open — EVERY iteration (2026-08-05): was buried in the `except socket.timeout` branch and
        # gated behind the once-per-1.4s keepalive window, so with the device actively sending it never
        # fired (sent=False in every run). WWB streams the RSSI firehose on this 2nd data channel, so it
        # MUST open once the scan is launched + association settled. Independent of recv/timeout.
        if (CH2 and scan_launched[0] and not ch2["sent"] and assoc_time[0]
                and time.time()-assoc_time[0] > float(os.environ.get("AD600_CH2DELAY","2.5"))):
            s.sendto(build_join(cid, AD600_CID, our_chan2), dst); ch2["sent"]=True
            print("  %6.2fs → CH2: opened 2nd SDT channel (our_chan2=0x%04X) — awaiting device JOIN_ACCEPT"%(time.time()-t0,our_chan2))
        try: data,addr=s.recvfrom(2048)
        except socket.timeout:
            if slp_sock is not None and time.time()-last_slp[0] > float(os.environ.get("AD600_SLPINT","4.0")):
                slp_sock.sendto(slp_pkt,("239.255.254.253",8427)); last_slp[0]=time.time()   # keep our SLP registration alive like WWB
            # ★ ACK-CADENCE capture: WWB acks the device ~every 1.4s (0.7/s), cumulative frontier. We were
            # acking on every ~0.1s socket timeout (~10/s) — 14× too fast. A member flooding redundant acks
            # may get throttled. Rate-limit the keepalive to WWB's cadence. AD600_KEEPINT sets the interval.
            if joined and not (QUIETCTRL and proto_ok[0]) and time.time()-last_ack[0] > float(os.environ.get("AD600_KEEPINT","1.4")):
                send_wrapper([client_block(1,1,ack_assoc(),mgmt_ack(ack_seq()))], False)  # keepalive (WWB cadence)
                last_ack[0]=time.time()
                # AD600_RELEASEALL: SET RELEASE_SCAN_ID (0x0107010e) across the slot range to free
                # leaked/orphaned scan slots and recover an exhausted (SCAN_ID=0xff) device w/o power-cycle.
                if os.environ.get("AD600_RELEASEALL") and proto_ok[0] and assoc_time[0]:
                    if not relm["built"] and time.time()-assoc_time[0] > 1.5:
                        relm["built"]=True; relm["q"]=list(range(int(os.environ.get("AD600_RELN","64"))))
                        print("→ RELEASEALL: freeing scan slots 0..%d via SET 0x0107010e"%(len(relm["q"])-1))
                    if relm["built"] and relm["q"] and time.time()-relm["t"] > float(os.environ.get("AD600_RELGAP","0.12")):
                        _id=relm["q"].pop(0); relm["t"]=time.time()
                        try: send_dmp(dmp_pdu(2,0x0107010e,bytes([_id&0xff]))+bytes.fromhex("7005010000"), keys[0])
                        except Exception: pass
                    if relm["built"] and not relm["q"] and not relm["done"]:
                        relm["done"]=True
                        # do NOT GET SCAN_ID to check — reading it re-reserves a slot and bumps the ID.
                        print("→ RELEASEALL done — slots 0..N freed (not reading SCAN_ID back; it would re-reserve)")
                # AD600_POKE: once stalled after the scan, throw a timed battery of probes at the high
                # channel and watch what (if anything) the device coughs up. Exploratory kitchen-sink.
                if os.environ.get("AD600_POKE") and scan_launched[0] and assoc_time[0]:
                    if not poke["built"] and time.time()-assoc_time[0] > float(os.environ.get("AD600_POKEDELAY","6")):
                        poke["built"]=True; _ix=ch2["idx"] if ch2["idx"] is not None else 0
                        _vec08=bytes.fromhex("70230807001f52465f5343414e3a43555252454e545f5354415455532f5343414e3d30")
                        poke["q"]=[
                          ("SUB 0x01400303 (stream-arm)", lambda: send_dmp(dmp_pdu(7,0x01400303), keys[0])),
                          ("NAK dev_rel+1 (force resume)", lambda: send_wrapper([client_block(1,1,ack_assoc(), pdu_encode(8,None,struct.pack(">I",(dev_rel[0]+1)&0xffff),1))], False)),
                          ("re-SUB RF_SCAN_DATA", lambda: send_dmp(rewrite_scan_idx(SCAN_CMD_SUB_DATA,_ix), keys[0])),
                          ("vec08 CURRENT_STATUS", lambda: send_dmp(rewrite_scan_idx(_vec08,_ix), keys[0])),
                          ("re-CONFIG", lambda: send_dmp(rewrite_scan_idx(SCAN_CMD_CONFIG,_ix), keys[0])),
                          ("SCAN start (POST)", lambda: send_dmp(rewrite_scan_idx(SCAN_POST,_ix), keys[0])),
                          ("GET scan-status 0x0107010f", lambda: send_dmp(dmp_pdu(1,0x0107010f), keys[0])),
                          ("ACK dev_rel-1 (rewind)", lambda: send_wrapper([client_block(1,1,ack_assoc(), mgmt_ack((dev_rel[0]-1)&0xffff))], False)),
                          ("GET_SESSIONS (root vec9)", lambda: s.sendto(root_wrap(cid, pdu_encode(9,None,b"",1)), dst)),
                        ]
                        print("→ POKE: stalled at dev_rel=0x%04X — firing %d probes @ %ss gaps"%(dev_rel[0],len(poke["q"]),os.environ.get("AD600_POKEGAP","1.5")))
                    if poke["built"] and poke["q"] and time.time()-poke["t"] > float(os.environ.get("AD600_POKEGAP","1.5")):
                        _lbl,_fn=poke["q"].pop(0); poke["t"]=time.time()
                        try: _fn(); print("   POKE → %s  (pre dev_rel=0x%04X)"%(_lbl,dev_rel[0]))
                        except Exception as _e: print("   POKE %s ERR: %s"%(_lbl,_e))
                # AD600_BRUTE: sweep RF_SCAN_DATA + status subscribes across SCAN=0..N — one of these
                # slots (esp. SCAN=0, WWB's live sweep) may already be producing data the device will
                # deliver to any subscriber. Watch the global BIG-packet detector for a hit.
                if os.environ.get("AD600_BRUTE") and scan_launched[0] and assoc_time[0]:
                    if not brute["built"] and time.time()-assoc_time[0] > float(os.environ.get("AD600_BRUTEDELAY","5")):
                        brute["built"]=True; _N=int(os.environ.get("AD600_BRUTEN","8"))
                        for _n in range(_N):
                            brute["q"].append(("RF_SCAN_DATA SCAN=%d"%_n, rewrite_scan_idx(SCAN_CMD_SUB_DATA,_n)))
                            brute["q"].append(("SUB_STATUS  SCAN=%d"%_n, rewrite_scan_idx(SCAN_CMD_SUB_STATUS,_n)))
                        print("→ BRUTE: firing %d subscribes across SCAN=0..%d @ %ss gaps"%(len(brute["q"]),_N-1,os.environ.get("AD600_BRUTEGAP","0.8")))
                    if brute["built"] and brute["q"] and time.time()-brute["t"] > float(os.environ.get("AD600_BRUTEGAP","0.8")):
                        _bl,_bp=brute["q"].pop(0); brute["t"]=time.time()
                        try: send_dmp(_bp, keys[0]); print("   BRUTE → %s"%_bl)
                        except Exception as _e: print("   BRUTE %s ERR: %s"%(_bl,_e))
                # AD600_BATCH: fire a WWB-style header-inheritance BATCHED subscribe — hypothesis: a
                # batched subscribe latches the whole session into vec=0c streaming mode.
                if os.environ.get("AD600_BATCH") and scan_launched[0] and assoc_time[0] and not brute.get("batched"):
                    if time.time()-assoc_time[0] > float(os.environ.get("AD600_BATCHDELAY","4")):
                        brute["batched"]=True
                        _addrs=[0x01000012,0x01010104,0x01070444,0x01070482,0x010704c0,0x0109002b,
                                0x01090050,0x01090201,0x01090203,0x01090224,0x01201007,0x01201003,
                                0x01201106,0x01400303,0x01400360]
                        try:
                            send_dmp(dmp_batch_sub(_addrs), keys[0])
                            print("→ BATCH: fired WWB-style batched subscribe of %d props (%s) — latch test"%(len(_addrs), dmp_batch_sub(_addrs)[:18].hex()))
                        except Exception as _e: print("→ BATCH err: %s"%_e)
                # CH2: once the scan is configured + settled, open the 2nd (data) channel like WWB
                if (CH2 and scan_launched[0] and not ch2["sent"] and assoc_time[0]
                        and time.time()-assoc_time[0] > float(os.environ.get("AD600_CH2DELAY","2.5"))):
                    s.sendto(build_join(cid, AD600_CID, our_chan2), dst); ch2["sent"]=True
                    print("→ CH2: opened 2nd SDT channel (our_chan2=0x%04X) — WWB streams RSSI on the device's paired channel"%our_chan2)
                # CH2: keepalive-ACK the 2nd channel so the device keeps streaming on it
                if CH2 and ch2["acc"] and ch2["dev"] is not None:
                    dr=ch2["devrel"] if ch2["devrel"] is not None else ch2["dev"]
                    send_ch2([client_block(1,1,ch2["dev"],mgmt_ack(dr))], False)
                # single conservative retransmit only after a real stall (opt-in), never a storm
                if unacked and os.environ.get('AD600_RTX'):
                    sq=min(unacked); tot=total_seq[0]; total_seq[0]=(total_seq[0]+1)&0xffff
                    s.sendto(build_wrapper(cid, our_chan, tot, sq, our_chan, unacked[sq], True), dst)
                # advance the command queue on idle timeouts too — do NOT gate sends behind a
                # successful recv (that throttled us to ~1 cmd / recv-timeout ≈ 1.4s).
                # Deadlock guard: if we're sitting on a held write and the device hasn't DECL09'd yet,
                # a benign read (access-level GET) re-prompts its reciprocal DECL09 so the association
                # can complete. Fires at most every ~1.5s while writes are blocked pre-association.
                if (proto_ok[0] and cmd_queue and not proto_assoc_sent[0]
                        and time.time()-last_send[0] > 1.5):
                    send_dmp(dmp_pdu(DMP_SUBSCRIBE, 0x01400303), keys[0]); last_send[0]=time.time()
                    print("   → nudge SUBSCRIBE 0x01400303 (a GET won't; only a SUB triggers device DECL09)")
                if proto_ok[0] and cmd_queue and time.time()-last_send[0] > float(os.environ.get("AD600_PACE","0.0")):
                    for _ in range(int(os.environ.get("AD600_BURST","8")) if proto_assoc_sent[0] else 1):
                        if not cmd_queue: break
                        if (scan_launched[0] or is_write(cmd_queue[0])) and not writes_armed(): break   # hold scan batch / any write until assoc+settle
                        nxt=cmd_queue.pop(0); send_dmp(nxt, keys[0])
                        print("  %6.2fs → cmd (%d left) %s"%(time.time()-t0, len(cmd_queue), nxt[:14].hex()))
                        time.sleep(float(os.environ.get("AD600_BURSTGAP","0.012")))
                    last_send[0]=time.time()
            # ── AD600_RECOVER: detect the device-side stream freeze and bail for a fresh re-JOIN ──
            if RECOVER:
                if scan_launched[0] and scan_launch_t[0] is None: scan_launch_t[0]=time.time()
                if brute["big"]>=FH_OK: fh_ok[0]=True
                if (not fh_ok[0] and scan_launch_t[0] is not None
                        and time.time()-scan_launch_t[0] > FREEZE_SECS):
                    wedged[0]=True
                    print("  ★ FREEZE DETECTED @%.1fs: scan launched %.1fs ago, only %d firehose pkt(s) (<%d) — "
                          "device wedged its reliable stream (WWB saw the same). Abandoning this channel "
                          "(no LEAVE, like WWB) for a fresh re-JOIN."
                          %(time.time()-t0, time.time()-scan_launch_t[0], brute["big"], FH_OK))
                    break
            continue
        pr=root_parse(data)
        if not pr: continue
        if len(data)>200:   # global RSSI-firehose detector — ANY big inbound packet is the win signal
            brute["big"]+=1
            if brute["big"]<=5 or brute["big"]%50==0:
                print("  ★★★ %6.2fs BIG PACKET #%d len=%d — STREAM DATA! %s"%(time.time()-t0,brute["big"],len(data),data[38:52].hex()))
        src,sdt=pr
        # ── MULTI-PDU DECL09 FIX (real-device pcap byte-diff, client_scan_fail vs wwb_scan_working) ──
        # A single UDP datagram's SDT block may carry SEVERAL concatenated SDT PDUs (ACN E1.17 PDU
        # block). The device COALESCES its cumulative-ACK (UNREL_WRAP, 70..0e) and its reliable
        # DECL09 (REL_WRAP, 70..09 00000102) into ONE datagram, e.g. at t=0.115 in the failing
        # capture:  702802..70070e00008840  ||  705601..70070900000102 702e..<DMP>.
        # _sdt_vec()/the dispatch below decode ONLY the FIRST SDT PDU, so the bundled device DECL09
        # was dropped → we never sent the reciprocal ASSOC0a → the push association stayed HALF-OPEN
        # → device answered subscribes with the vec=0x0d one-shot and never opened the vec=0x04 RSSI
        # firehose. (WWB always received the DECL09 standalone, e.g. t=0.229, so it never hit this.)
        # Sweep EVERY SDT PDU in the datagram for the proto-0x102 handshake; the send is idempotent
        # (guarded by proto_assoc_sent), so re-seeing the first PDU here is harmless.
        _swoff=0
        while _swoff < len(sdt):
            _sr=pdu_decode(sdt,_swoff)
            if not _sr: break
            _sf,_sds,_send=_sr; _sv=sdt[_sds]; _svd=sdt[_sds+1:_send]; _swoff=_send
            if _sv in (1,2):
                _sw=parse_wrapper(_svd)
                if _sw:
                    for _sp,_spl in _sw[4]:
                        if _spl[:3]==b"\x70\x07\x09" and _spl[3:7]==b"\x00\x00\x01\x02" and not proto_assoc_sent[0]:
                            proto_assoc_sent[0]=True; assoc_time[0]=time.time()
                            _sa0 = 0 if os.environ.get("AD600_ASSOC0") else (ad600_chan or 0)
                            send_wrapper([client_block(1,1,_sa0,pdu_encode(0x0a,None,struct.pack(">I",0x102),1))], True)
                            print("  %6.2fs → reciprocal ASSOC0a sent (assoc=0x%04X=dev chan; multi-PDU sweep caught bundled DECL09) — FULL association up"
                                  %(time.time()-t0, _sa0))
        vec,vdata=_sdt_vec(sdt); name=SDT_VEC.get(vec,"vec%d"%vec)
        # ── CH2 routing (opt-in): handle 2nd-channel join/data WITHOUT clobbering ch1 state ──
        if CH2 and ch2["sent"]:
            if vec==6 and len(vdata)>=18 and struct.unpack(">H",vdata[16:18])[0]==our_chan2:
                ch2["dev"]=struct.unpack(">H",vdata[-2:])[0]
                print("← CH2 JOIN_ACCEPT  dev_chan2=0x%04X"%ch2["dev"]); continue
            if vec==4 and len(vdata)>=30 and struct.unpack(">H",vdata[20:22])[0]==our_chan2:
                ch2["dev"]=struct.unpack(">H",vdata[18:20])[0]
                relseq=struct.unpack(">I",vdata[26:30])[0]&0xffff; ch2["devrel"]=relseq
                s.sendto(build_join_accept(cid,AD600_CID,ch2["dev"],relseq,our_chan2),dst)
                ch2["acc"]=True; print("→ CH2 JOIN_ACCEPT sent (dev_chan2=0x%04X) — 2nd channel joined"%ch2["dev"])
                ch2_key[0]=sk_util(cid+AD600_CID+struct.pack("<H",our_chan2)+struct.pack("<H",ch2["dev"]))[:16]
                # WWB's EXACT ch2 bring-up (from pcap): (1) UNREL mgmt-ACK of the device's ch2 seq tagged
                # assoc=dev_chan2, then (2) REL DECL09 proto-0x102 with assoc=0. Device replies ASSOC0a →
                # we then send the RF_SCAN_DATA subscribe as DMP on ch2 → device floods RSSI on its ch2.
                send_ch2([client_block(1,1,ch2["dev"],mgmt_ack(relseq))], False)
                if not ch2["decl_sent"]:
                    send_ch2([client_block(1,1,0,mgmt_proto())], True); ch2["decl_sent"]=True
                    print("→ CH2: UNREL-ACK(dev seq) + REL DECL09(assoc=0) sent — WWB bring-up")
                continue
            if vec in (1,2) and ch2["dev"] is not None:
                w2=parse_wrapper(vdata)
                if w2 and w2[0]==ch2["dev"]:
                    ch2["devrel"]=w2[2]&0xffff
                    for _p,pl in w2[4]:
                        if _p==0x102 and ch2_key[0] and pl[:1]==b"\x01":   # decode device's ch2 DMP reply
                            try:
                                ln=struct.unpack(">H",pl[2:4])[0]; dmp=aes_ctr(ch2_key[0], pl[4:20], pl[20:4+ln])
                                da="".join(chr(x) if 32<=x<127 else "." for x in dmp[:56])
                                print("  CH2 IN DMP vec=0x%02x  %s"%(dmp[2] if len(dmp)>2 else 0, da))
                            except Exception as e: print("  CH2 IN DMP decode-fail:",e)
                        if pl[:3]==b"\x70\x07\x09" and pl[3:7]==b"\x00\x00\x01\x02" and not ch2["assoc_sent"]:
                            ch2["assoc_sent"]=True
                            # ★ same fix as ch1: reciprocal ASSOC0a must carry assoc=dev_chan2 (not 0),
                            # else the ch2 push channel stays half-open and RF_SCAN_DATA vec=4 events never flow.
                            _a2 = 0 if os.environ.get("AD600_ASSOC0") else (ch2["dev"] or 0)
                            send_ch2([client_block(1,1,_a2,pdu_encode(0x0a,None,struct.pack(">I",0x102),1))], True)
                            print("  → CH2: reciprocal ASSOC0a sent (assoc=0x%04X=dev_chan2)"%_a2)
                        if pl[:3]==b"\x70\x07\x0a" and pl[3:7]==b"\x00\x00\x01\x02" and not ch2["proto_ok"]:
                            ch2["proto_ok"]=True
                            print("  → CH2: device ASSOC0a — ch2 DMP association UP; sending RF_SCAN_DATA subscribe on ch2")
                            ch2_scan_resub()
                    if len(data)>200:
                        ch2["big"]+=1
                        if ch2["first_big"][0] is None:
                            ch2["first_big"][0]=time.time()-t0
                            print("  ★★ %6.2fs CH2 FIRST BIG PACKET on dev_chan2=0x%04X len=%d — STREAMING ON CHANNEL 2 ★★"%(time.time()-t0,ch2["dev"],len(data)))
                    else: ch2["small"]+=1
                    if (ch2["big"]+ch2["small"])%50==0:
                        print("  CH2 rx: %d big + %d small (dev_chan2=0x%04X)"%(ch2["big"],ch2["small"],ch2["dev"]))
                    continue
        if vec==6:                                     # JOIN_ACCEPT
            accepted_us=True; ad600_chan=struct.unpack(">H",vdata[-2:])[0]
            print("← JOIN_ACCEPT  dev chan=0x%04X"%ad600_chan)
        elif vec==4:                                   # device reciprocal JOIN -> accept
            ad600_chan=struct.unpack(">H",vdata[18:20])[0]
            # JOIN layout: member(16) mid(2) chan(2) recip(2) reserved(2) totalseq(4) relseq(4) params.
            # relseq is the 4-byte field at [26:30] (e.g. 0x0000bf73); we were reading its high half
            # [26:28]=0x0000 → our first ack was ACK(0) and our JOIN_ACCEPT advertised relseq=0, both
            # differing from WWB (which acks/echoes bf73). Read the low 16 bits.
            relseq=struct.unpack(">I",vdata[26:30])[0]&0xffff; dev_rel[0]=relseq
            if not sent_accept:
                s.sendto(build_join_accept(cid,AD600_CID,ad600_chan,relseq,our_chan),dst)
                sent_accept=True; print("→ JOIN_ACCEPT (dev chan 0x%04X)"%ad600_chan)
        elif vec in (1,2):                             # wrapper
            w=parse_wrapper(vdata)
            if w:
                _,total,rel,oldest,blocks=w
                r16=rel & 0xffff
                if vec==1:
                    # Reliable wrapper: track received seqs and ack the highest CONTIGUOUS one.
                    # Acking the latest seq ACROSS a gap (e.g. we missed 45747 but got 45748) does
                    # NOT drain the device's send-window; it wants the contiguous frontier so it can
                    # retransmit the gap. This is what keeps the device streaming past 3 replies.
                    dev_recv.add(r16)
                    if dev_contig[0] is None: dev_contig[0]=r16
                    while ((dev_contig[0]+1)&0xffff) in dev_recv: dev_contig[0]=(dev_contig[0]+1)&0xffff
                    # ★ ACK-CADENCE capture proves WWB acks the device's REL FRONTIER (the wrapper's rel),
                    # not our contiguous-received frontier. When our contiguous lags the device's rel (gap),
                    # acking behind leaves the device's send-window undrained → it freezes (the SUB_STATUS
                    # halt). Ack the frontier (r16) like WWB. AD600_ACKLATEST=0 restores contiguous acking.
                    dev_rel[0]= r16 if os.environ.get("AD600_ACKLATEST","1")!="0" else dev_contig[0]
                else:
                    if os.environ.get("AD600_ACKLATEST","1")!="0" or dev_contig[0] is None: dev_rel[0]=r16
                # Hold our own `oldest` at min(unacked) like WWB (do not jump it forward).
                bs="; ".join("p%s:%s"%(("0x%X"%p if p is not None else "-"),pl.hex()[:28]) for p,pl in blocks)
                print("  %6.2fs ← %-10s rel=0x%04X [%s]"%(time.time()-t0,name,rel,bs))
                # AD600_FASTACK: WWB acks the high (device) channel ~every few data packets (sub-10ms),
                # NOT on a ~100ms timer like our default — the device only keeps its send-window open
                # (keeps streaming) while acked. Push an immediate cumulative ACK per reliable packet.
                if os.environ.get("AD600_FASTACK") and vec==1:
                    send_wrapper([client_block(1,1,ack_assoc(),mgmt_ack(dev_rel[0]))], False)
                # process device's mgmt-acks of OUR reliable seqs (70 07 0e 0000<seq>) -> retransmit gaps
                for proto,pl in blocks:
                    if pl[:1]==b"\x70" and len(pl)>=7 and pl[2]==0x0e:
                        on_our_ack(int.from_bytes(pl[-2:],"big"))
                    # CORRECT proto-0x102 handshake (exactly as WWB, wwb_freshauth.pcap):
                    #   we DECL09 → device ASSOC0a (our declare accepted → we may start DMP)
                    #   device DECL09 → WE ASSOC0a (RELIABLE, in-sequence) ← we were skipping this,
                    #   so the device's half of the association never completed and it stopped
                    #   processing our DMP stream after 1-2 blocks.
                    # device DECL09 → WE ASSOC0a (reliable, interleaved with DMP) — the device only
                    # DECL09s AFTER it sees a reliable msg from us, so we must NOT gate on it first.
                    if pl[:3]==b"\x70\x07\x09" and pl[3:7]==b"\x00\x00\x01\x02" and not proto_assoc_sent[0]:
                        proto_assoc_sent[0]=True; assoc_time[0]=time.time()
                        # ★ FIX (pcap byte-diff): our reciprocal ASSOC0a must carry assoc=DEVICE-CHANNEL,
                        # not assoc=0. WWB tags its ASSOC0a with the device's chan (0x8151) = "I accept the
                        # association on YOUR channel"; with assoc=0 the device never registers our accept →
                        # the push channel stays half-open → subscribes are received but never processed
                        # (the freeze right after DECL09). AD600_ASSOC0 reverts to test.
                        _a0 = 0 if os.environ.get("AD600_ASSOC0") else (ad600_chan or 0)
                        send_wrapper([client_block(1,1,_a0,pdu_encode(0x0a,None,struct.pack(">I",0x102),1))], True)
                        print("  %6.2fs → reciprocal ASSOC0a sent (assoc=0x%04X=dev chan) — FULL association up; scan held %ss then fires"
                              %(time.time()-t0, _a0, os.environ.get("AD600_ASSOCSETTLE","0.6")))
                    # device ASSOC0a (accepts OUR declare) → start sending DMP commands NOW (like WWB,
                    # which sends its first DMP before the device DECL09s + before its own reciprocal assoc)
                    if pl[:3]==b"\x70\x07\x0a" and pl[3:7]==b"\x00\x00\x01\x02" and not proto_ok[0]:
                        proto_ok[0]=True
                        ack_freeze[0]=dev_rel[0]        # WWB-mimic: freeze ack here (see ack_seq)
                        print("→ device ASSOC0a — DMP enabled, queueing commands")
                        boot_key[0]=keys[0]
                        # Prime the device's reciprocal DECL09. Ground truth (WWB connect.pcap): the
                        # device declares ITS side — the half we must reciprocate to FULLY open the
                        # association that WRITES require — only AFTER it receives a SUBSCRIBE. A plain
                        # GET reply never makes it establish its push channel (our LEANSCAN GET-only run
                        # deadlocked: device answered SCAN_ID but never DECL09'd). WWB's very first
                        # command is SUBSCRIBE 0x01400303; mirror it so the association completes before
                        # any SET. AD600_PRIME=0 disables.
                        # 2026-08-05: suppress PRIME in the pure-replay mode (AD600_WWBREPLAY) — the replay
                        # file already begins with WWB's own subscribes, so our injected SUB would corrupt the
                        # verbatim stream / CTR alignment. Pure replay must inject nothing of our own.
                        if (os.environ.get("AD600_PRIME","1")!="0" and not os.environ.get("AD600_FULLINV")
                                and not os.environ.get("AD600_WWBREPLAY")):
                            cmd_queue.append(dmp_pdu(DMP_SUBSCRIBE, 0x01400303))
                            print("→ PRIME: SUBSCRIBE 0x01400303 (WWB's first cmd — triggers device DECL09)")
                        if os.environ.get("AD600_SUBPROBE"):
                            # Probe: subscribe INDIVIDUALLY to many KNOWN-GOOD device-info props (the ones
                            # the device already accepted via range-subs). If it accepts >4 → not a
                            # 4-command limit → the halt is a functional-cluster gate. If it stops at ~4
                            # → per-member command/window throttle.
                            for a in (0x01400303,0x01400360,0x01000023,0x01000024,0x01000025,0x01000026,
                                      0x01000028,0x0100002b,0x01010101,0x01010102,0x01010103,0x01000012):
                                cmd_queue.append(dmp_pdu(DMP_SUBSCRIBE, a))
                            print("→ SUBPROBE: 12 individual device-info subscribes (count accepts)")
                        if os.environ.get("AD600_FULLINV"):
                            # Replay WWB's EXACT pre-scan inventory (all subscribes + GETs, wwb_cmds.txt
                            # up to the first scan SET) to ATTACH as a real controller before configuring
                            # the scan. Hypothesis: the device silently drops control SETs until a
                            # controller has enumerated/subscribed like WWB does. The GET SCAN_ID inside
                            # the inventory (0x0107010f) triggers launch_scan → WWB-order scan batch,
                            # held by the scan_launched gate until assoc+settle. Scan cmds themselves are
                            # skipped here (launch_scan rebuilds them with the live SCAN idx).
                            scan_mode[0]=True
                            SCANADDRS={0x00255246,0x00205246,0x003c2652,0x01070103,
                                       0x0109002b,0x0109002a,0x01010201}
                            try:
                                rows=[l.strip() for l in open("/tmp/wwb_cmds.txt") if l.strip()]
                            except OSError:
                                rows=[]; print("→ FULLINV: /tmp/wwb_cmds.txt missing — skipping inventory replay (SCAN_PRE reserve path covers it)")
                            n=0
                            _noread = os.environ.get("AD600_NOREADID","1")!="0"
                            for h in rows:
                                b=bytes.fromhex(h); off=3 if (b[0]&0xF0)==0xF0 else 2
                                addr=int.from_bytes(b[off+2:off+6],"big")
                                if addr in SCANADDRS: continue        # scan/export cmds rebuilt by launch_scan
                                if _noread and addr==0x0107010f: continue   # NEVER read SCAN_ID (it re-reserves/bumps the id)
                                if os.environ.get("AD600_SKIPSCAN") and 0x01070000<=addr<0x01080000: continue  # probe: skip numeric scan-cluster
                                cmd_queue.append(b); n+=1
                            if _noread:
                                # launch is fired LATE (when the inventory queue drains, see main loop) so
                                # the session establishes first — NOT synchronously here (that would set
                                # scan_launched and the hold-gate would stall the whole inventory).
                                print("→ FULLINV: queued %d inventory cmds (SCAN_ID read stripped) → launch on slot 0 when queue drains"%n)
                            else:
                                print("→ FULLINV: queued %d WWB inventory cmds (attach like a real controller) → scan on SCAN_ID"%n)
                            # AD600_COORDINIT: WWB OPENS the coordination subsystem during CONNECT and keeps
                            # it open through the scan (full-command diff: these 5 are the ONLY things WWB does
                            # in connect that our FULLINV skips). Hypothesis: without the coordination subsystem
                            # open, the device never registers our START as a scan request. Do NOT close it (no =2).
                            if os.environ.get("AD600_COORDINIT","1")!="0":
                                for c in ("700807020109022010060109021210060109002b",  # SUB 0x01090220,0x01090212,0x0109002b
                                          "700902020109002a017005010000",               # SET 0x0109002a=01 (open coord subsystem)
                                          "7009020201010201017005010000"):              # SET 0x01010201=01
                                    cmd_queue.append(bytes.fromhex(c))
                                print("→ COORDINIT: open coordination subsystem (SUB 0x01090220/0212/002b, SET 0x0109002a=1/0x01010201=1) — kept OPEN")
                        if os.environ.get("AD600_MULTIGET"):
                            print("→ MULTIGET: SESSION recon")
                            for a in (0x01200023, 0x01200024, 0x01200025, 0x01200021, 0x01201003, 0x01201002):
                                cmd_queue.append(dmp_pdu(DMP_GET, a))
                        elif os.environ.get("AD600_STRSET"):
                            # Does a STRING-ADDRESSED SET land? (scan CONFIG is string-addressed.) SET
                            # RF_SCAN:SCAN_START_FREQ/SCAN=0 = 500000, then GET it back. If it reads 500000
                            # our string SETs land; if not, that's why our CONFIG never applies → no scan.
                            print("→ STRSET: GET SCAN_START_FREQ, SET=500000 (0007a120), GET again")
                            cmd_queue.append(bytes.fromhex("70240107002052465f5343414e3a5343414e5f53544152545f465245512f5343414e3d30"))          # GET before
                            cmd_queue.append(bytes.fromhex("70280207002052465f5343414e3a5343414e5f53544152545f465245512f5343414e3d300007a120"))  # SET=500000
                            cmd_queue.append(bytes.fromhex("70240107002052465f5343414e3a5343414e5f53544152545f465245512f5343414e3d30"))          # GET after
                        elif os.environ.get("AD600_SETTEST"):
                            sa=int(os.environ.get("AD600_SETADDR","0x010c0090"),16)
                            sv=bytes.fromhex(os.environ.get("AD600_SETVAL","00"))
                            print("→ SETTEST: GET 0x%08x, GET ACCESS_LEVEL, SET 0x%08x=%s, GET both again"%(sa,sa,sv.hex()))
                            # WWB always appends a trailing GET-addr-0 PDU (7005010000) after a SET
                            # in the SAME client block — a silent SET otherwise yields no reply and
                            # may leave the reliable stream stuck; the trailing GET forces a reply.
                            setpdu = dmp_pdu(DMP_SET, sa, sv)
                            if os.environ.get("AD600_SETTRAILER"): setpdu += bytes.fromhex("7005010000")
                            cmd_queue.append(dmp_pdu(DMP_GET, sa))          # value before
                            cmd_queue.append(dmp_pdu(DMP_GET, 0x01201003))  # access level before
                            cmd_queue.append(setpdu)                        # the write (+trailer)
                            cmd_queue.append(dmp_pdu(DMP_GET, sa))          # value after
                            cmd_queue.append(dmp_pdu(DMP_GET, 0x01201003))  # access level after
                        elif os.environ.get("AD600_REPLAYRAW"):
                            # Replay WWB's EXACT decrypted command stream (inventory + scan trigger)
                            # verbatim, re-encrypted under OUR session. Tests whether the device halts
                            # our scan subscribe (vec=13) purely because we skip WWB's startup inventory
                            # context. File = /tmp/wwb_cmds.txt (one plaintext DMP block hex per line),
                            # produced by dump_wwb_cmds.py from a fresh WWB connect capture.
                            n=0
                            for h in open("/tmp/wwb_cmds.txt"):
                                h=h.strip()
                                if h: cmd_queue.append(bytes.fromhex(h)); n+=1
                            print("→ REPLAYRAW: queued %d WWB command blocks verbatim (inventory+scan)"%n)
                        elif os.environ.get("AD600_WWBREPLAY"):
                            # ── 2026-08-05: FAITHFUL WWB REPLAY (pure) ─────────────────────────────────────
                            # Proven root cause of the scan wall: NOT crypto (single verified bootstrap key)
                            # and NOT config — WWB front-loads a large SUBSCRIBE/GET fan-out of the device +
                            # scan-engine property tree that registers it as a FULL controller before the
                            # RF_SCAN config/START SETs; our client omits it, so the device never registers us
                            # and never streams. FIX = replay WWB's EXACT plaintext command stream verbatim,
                            # re-encrypted under OUR session (our CIDs/channels/key differ — the device derives
                            # them from the on-wire session values).
                            #
                            # File = AD600_WWBREPLAY=<path> (default captures/wwb_realscan_cmds.txt): one WWB→DEV
                            # DMP block plaintext (hex) per line, in capture order (the full ~49-block sequence:
                            # ~60 SUBs, ~100 GETs, FREQCOMPAT subs, CFL enable SETs, GET SCAN_ID, RF_SCAN status
                            # subs, 8 config SETs, 6 RF_SCAN_DATA:RSSI subs, START). Each line is queued as ONE
                            # blob → the normal cmd_queue drain calls send_dmp(blob, keys[0]) = ONE reliable
                            # client block on the primary channel at a continuous CTR position. Multi-PDU lines
                            # stay a SINGLE send (never split). PRIME is suppressed above; no inventory / module-
                            # open / CFL / CH2 logic is injected here — pure replay.
                            #
                            # Ordering/pacing: the vetted drain (below, ~line 1740) sends the leading SUBs/GETs
                            # 1-per-iter until our reciprocal ASSOC0a is out (proto_assoc_sent), holds the first
                            # SET behind writes_armed() until the proto-0x102 association is FULLY up (reciprocal
                            # ASSOC0a done + settle), then streams the rest in order. We only default the pacing
                            # to WWB's ~5ms/cmd (AD600_BURSTGAP, was 12ms).
                            _rp = os.environ.get("AD600_WWBREPLAY","").strip()
                            if (not _rp) or _rp in ("1","0","yes","true","on"):
                                _rp = "/Users/nt_mbp/AD600_HANDOFF/captures/wwb_realscan_cmds.txt"
                            # SCAN_ID handling (point 3): a fresh power-cycled device is SCAN_ID=0 and WWB's file
                            # uses /SCAN=0 + START=0, so VERBATIM is correct (default). AD600_REPLAYIDX=<n>
                            # rewrites every string '/SCAN=0' token (rewrite_scan_idx) AND the numeric START
                            # value (SET 0x01070103) to slot n, for replay against a live non-zero SCAN_ID.
                            # AD600_STARTID=<n> overrides just the numeric START byte independently.
                            _ridx = os.environ.get("AD600_REPLAYIDX")
                            _idx  = int(_ridx) if _ridx else 0
                            _startb = _idx
                            if os.environ.get("AD600_STARTID"): _startb = int(os.environ.get("AD600_STARTID"))
                            os.environ.setdefault("AD600_BURSTGAP","0.005")   # WWB-timing (~5ms/cmd)
                            try:
                                _rows=[l.strip() for l in open(_rp) if l.strip() and not l.strip().startswith("#")]
                            except OSError as _e:
                                _rows=[]; print("→ WWBREPLAY: cannot open %s (%s) — nothing to replay"%(_rp,_e))
                            _n=0
                            for _h in _rows:
                                try: _b=bytes.fromhex(_h)
                                except ValueError: continue                  # skip malformed line
                                if _idx: _b=rewrite_scan_idx(_b,_idx)        # string /SCAN=0 → /SCAN=<idx>
                                if _startb and len(_b)>=9 and _b[:8].hex()=="7009020201070103":
                                    _b=_b[:8]+bytes([_startb&0xff])+_b[9:]   # numeric START SET value → live slot
                                cmd_queue.append(_b); _n+=1
                            print("→ WWBREPLAY: %d blocks from %s → VERBATIM replay (SCAN idx=%s, START=%d, ~%.0fms pacing)"
                                  %(_n,_rp,(_idx if _idx else "0/verbatim"),_startb,float(os.environ.get("AD600_BURSTGAP"))*1000))
                        elif os.environ.get("AD600_TESTGET"):
                            a=int(os.environ.get("AD600_GETADDR","0x01000023"),16)
                            print("→ TESTGET: GET 0x%08x"%a)
                            send_dmp(dmp_pdu(DMP_GET, a), keys[0])
                        elif os.environ.get("AD600_SESSION"):
                            print("→ SESSION recon: GET MODULUS/BIT_SIZE/KEY_STATUS + SCAN_ID/RANGE")
                            for a in (A_SESSION_MODULUS, A_SESSION_BIT_SIZE, A_SESSION_KEY_STATUS,
                                      0x0107010f, 0x01070490):
                                send_dmp(dmp_pdu(DMP_GET, a), keys[0])
                        elif os.environ.get("AD600_SUBONLY"):
                            if os.environ.get("AD600_SUBTHENGET"):
                                if os.environ.get("AD600_SUBNUM"):
                                    print("→ SUBNUM: subscribe NUMERIC 0x01400303 (like WWB), then 4 GETs")
                                    cmd_queue.append(dmp_pdu(7, 0x01400303))
                                else:
                                    print("→ SUBTHENGET: SUB_STATUS (string) then 4 small GETs")
                                    cmd_queue.append(SCAN_CMD_SUB_STATUS)
                                for a in (0x0107010f, 0x0120100d, 0x0120100e, 0x01201003):
                                    cmd_queue.append(dmp_pdu(DMP_GET, a))
                            else:
                                print("→ SUBONLY: subscribe to RF_SCAN_DATA + status (no SETs)")
                                cmd_queue.append(SCAN_CMD_SUB_STATUS)
                                cmd_queue.append(SCAN_CMD_SUB_DATA)
                        elif os.environ.get("AD600_SCAN"):
                            # EXACT WWB scan-start order (decoded live from wwb_scan_live.pcap):
                            #   1) SUBSCRIBE CURRENT_SWEEP_STATUS/ID/STATUS
                            #   2) SET config batch (SCAN_START_FREQ..REAL_TIME_COMPRESSION, all /SCAN=0)
                            #   3) SUBSCRIBE RF_SCAN_DATA:RSSI CURVE_IDX 1-6
                            #   4) START_SCAN (0x01070103=0)
                            # NO SCAN_PRE / no RELEASE_SCAN_ID (WWB doesn't send it; that SET poisoned us).
                            if os.environ.get("AD600_SCANMIN"):
                                print("→ SCANMIN: [claim L0?] CONFIG + START only — does it log a scan request?")
                                if os.environ.get("AD600_CLAIM"):
                                    cl=os.environ.get("AD600_CLAIM")  # e.g. "01201003=00" -> SET access level 0
                                    a,_,v=cl.partition("=")
                                    cmd_queue.append(dmp_pdu(DMP_SET,int(a,16),bytes.fromhex(v or "00")))
                                if os.environ.get("AD600_PREAUTH"):    # mirror WWB's connect preamble
                                    cmd_queue.append(dmp_pdu(7, 0x01201007))            # SUB SRP_RECONFIRM_AUTHENTICATION
                                    cmd_queue.append(dmp_pdu(DMP_SET,0x0109002a,b"\x01"))
                                    cmd_queue.append(dmp_pdu(DMP_SET,0x01010201,b"\x01"))
                                for c in (SCAN_CMD_CONFIG, SCAN_POST): cmd_queue.append(c)
                            else:
                                # Two-phase: send the numeric inits (which RESERVE a scan slot and end
                                # with GET SCAN_ID), then defer the string SUB/CONFIG/START until the
                                # SCAN_ID reply lands so /SCAN=<id> targets the CURRENT (session-specific)
                                # slot.  on_dmp() calls launch_scan(id) when 0x0107010f replies.
                                # AD600_SCANIDX still forces a fixed index (used inside on_dmp).
                                scan_mode[0]=True
                                if os.environ.get("AD600_LEANSCAN"):
                                    # The device processes only ~13 of our reliable cmds before it
                                    # stalls; the 11 inventory/antenna GETs burn that budget so CONFIG
                                    # (SCAN_START_FREQ) never lands. LEAN: send ONLY GET SCAN_ID, so
                                    # launch_scan fires and CONFIG/START arrive within the budget.
                                    print("→ LEANSCAN: GET SCAN_ID only → (deferred) scan cmds")
                                    cmd_queue.append(bytes.fromhex("700801020107010f"))   # GET SCAN_ID
                                else:
                                    # ⚠ CORRECTED (Aug 2026): "never read SCAN_ID" was the HALT CAUSE, not a
                                    # safety measure. Reading SCAN_ID (0x0107010f) RESERVES a slot AND is the
                                    # ownership claim — the device stamps CURRENT_REQUESTER_CID[N]=us, and only
                                    # then honours the RF_SCAN:CURRENT_SWEEP_STATUS subscribe from us. Skipping
                                    # it (no-read) means we NEVER own the slot → subscribe downgraded to a
                                    # one-shot vec=0d, no recurring EVENT stream. The counter "bump" the user
                                    # saw was from repeated reads WITHOUT a matching release; WWB reads once and
                                    # releases at STOP (one GET + one release ⇒ stable). Use AD600_HOLD (reads
                                    # SCAN_ID, holds ownership, no disowning bookend). AD600_NOREADID=0 = read.
                                    _noread = os.environ.get("AD600_NOREADID","1")!="0"
                                    _skid = bytes.fromhex("700801020107010f")   # GET SCAN_ID
                                    for c in SCAN_PRE[1:]:   # numeric reserve GETs (skip RELEASE SET)
                                        if _noread and c==_skid: continue        # never read SCAN_ID
                                        cmd_queue.append(c)
                                    if _noread:
                                        # launch fired LATE on queue-drain (main loop), not synchronously
                                        print("→ SCAN start (no-read): reserve GETs (no SCAN_ID read) → launch on slot 0 when queue drains")
                                    else:
                                        print("→ SCAN start: numeric inits → GET SCAN_ID → (deferred) string scan cmds")
                        elif not os.environ.get("AD600_NOSRP"):
                            start_srp(keys[0])
                # WWB does NOT ack every wrapper — per-wrapper acks advance the device's Oldest each
                # block and wedge its scan pipeline after ~13. During the handshake ack normally; once
                # DMP is flowing, rate-limit to a cumulative frontier ack (~AD600_ACKINT, default 0.12s).
                if not proto_ok[0]:
                    send_wrapper([client_block(1,1,ack_assoc(),mgmt_ack(ack_seq()))], False)  # handshake ack
                elif QUIETCTRL:
                    pass   # WWB-mimic: control channel goes silent post-handshake; only ch2/data is acked
                elif not FREEZE and time.time()-last_ack[0] > float(os.environ.get("AD600_ACKINT","0.12")):
                    send_wrapper([client_block(1,1,ack_assoc(),mgmt_ack(dev_rel[0]))], False)  # cumulative frontier
                    last_ack[0]=time.time()
                for proto,payload in blocks:
                    if proto==0x102 and keys:
                        cand = [boot_key[0]] if boot_key[0] else keys
                        ok=False
                        for k in cand:
                            # continuous-position RX: device streams one CTR keystream (fixed nonce,
                            # position = cumulative bytes). Primary = exact tracked position (proven);
                            # if that fails (drift after an unaccounted device block, e.g. post-SET),
                            # search a window to re-sync so we don't stall permanently.
                            ln=struct.unpack(">H",payload[2:4])[0]; nonce=payload[4:12]; ct=payload[20:4+ln]
                            if ct in rx_seen:
                                pos=rx_seen[ct]; dec=aes_ctr_at(k, nonce, pos, ct)
                            else:
                                pos=rx_pos[0]; dec=aes_ctr_at(k, nonce, pos, ct)
                                # exact tracked position first; on drift (post-SET/SUB, unaccounted
                                # device block) search the window with the corrected validator so
                                # string-addressed replies (vec=13/hdr=0x07) position correctly.
                                if not _valid_dmp_head(dec, len(ct)):
                                    fp,fdec=find_ctr_pos(k, nonce, ct, rx_pos[0])
                                    if fdec is not None: pos,dec=fp,fdec
                            if dec and (_valid_dmp_head(dec, len(ct)) or (ct in rx_seen and dec[0]==0x70)):
                                if ct not in rx_seen: rx_seen[ct]=pos; rx_pos[0]=max(rx_pos[0], pos+len(ct))
                                ok=True; decoded+=1
                                if not boot_key[0]: boot_key[0]=k
                                r=dmp_parse(dec)
                                if dec[2] in (DMP_GET_FAIL, DMP_SET_FAIL, DMP_SUB_REJECT):
                                    # ★ 2026-08-05: the device answers a bad GET/SET/SUB with a FAIL PDU
                                    # (vec 9/10/13), trailing 1-byte reason. These were mis-decoded as
                                    # "raw" and never ACKed → retransmit storm that LOOKED like a freeze.
                                    # Now recognized + benign (rx_pos already advanced, block ACKed).
                                    _rn=dec[-1] if dec else -1
                                    _kind={9:"GET_FAIL",10:"SET_FAIL",13:"SUB_REJECT"}[dec[2]]
                                    _addr=("0x%08x"%r[1]) if r else "null"
                                    print("   ⚠ DMP %s addr=%s reason=%d%s"%(_kind,_addr,_rn,
                                          "  ← WRITE/SUBSCRIBE REJECTED (this is a real gate)" if dec[2] in (DMP_SET_FAIL,DMP_SUB_REJECT) else " (benign — bad GET probe)"))
                                elif dec[2]==4:                      # EVENT
                                    if r and r[1]==0x0109002b and not ssm_seen[0]:
                                        ssm_seen[0]=True; ssm_gate.set()
                                        _ev=''.join(chr(c) if 32<=c<127 else '.' for c in (r[2] or b''))
                                        print("  ★ SSM EVENT 0x0109002b='%s' — MODULE OWNED (enable-SET honored!) → releasing close+RF_SCAN"%_ev[:32])
                                    rf=parse_rf_scan_data(dec)
                                    if rf:
                                        curve,flo,fhi,amps=rf
                                        f0=174+flo*0.025; f1=174+fhi*0.025
                                        mn=min(amps) if amps else 0; mx=max(amps) if amps else 0
                                        scan_events[0]+=1
                                        if scan_events[0]==1:
                                            print("\n"+"="*70+"\n  ✓✓✓  SCAN LANDED — device is streaming RF_SCAN_DATA amplitude  ✓✓✓\n"
                                                  "        (the SET took: writes are working over the native client)\n"+"="*70+"\n")
                                        print("  %6.2fs RF_SCAN_DATA curve=%d  %.1f-%.1fMHz  %d bins  %.1f..%.1f dBm"
                                              %(time.time()-t0,curve,f0,f1,len(amps),mn,mx))
                                    else:
                                        asc=''.join(chr(c) if 32<=c<127 else '' for c in dec[4:])
                                        print("   EVENT: %s"%asc[:70])
                                elif r:
                                    v,a,val,tg=r
                                    print("   DMP✓ vec=%d addr=0x%08x val(%dB)=%s"%(v,a,len(val),val.hex()[:48]))
                                    on_dmp(v,a,val)
                                else:
                                    print("   DMP✓ raw=%s"%dec.hex()[:48])
                                break
                        if not ok:
                            undec[0]+=1                              # Calc-key-encrypted (scan amplitude) block
                            if os.environ.get("AD600_RXDEBUG"):
                                k=cand[0]; ln=struct.unpack(">H",payload[2:4])[0]
                                tag=payload[4+ln:4+ln+4]
                                calc=skip32(k[:10], zlib.crc32(payload[:4+ln])&0xffffffff, True).to_bytes(4,"big")
                                # widest search for a valid DMP head under the bootstrap key
                                fp,fdec=find_ctr_pos(k, payload[4:12], payload[20:4+ln], rx_pos[0], back=512, fwd=8192)
                                print("   [RXDEBUG] undec len=%d nonce=%s tag=%s bootstrap-tag=%s(%s) "
                                      "wide-find=%s rx_pos=%d"%(ln, payload[4:12].hex(), tag.hex(), calc.hex(),
                                      "MATCH" if tag==calc else "no", ("pos%d vec=%d hdr=0x%02x"%(fp,fdec[2],fdec[3]))
                                      if fdec else "none", rx_pos[0]))
                                print("   [RXDEBUG] FULLBLK %s"%payload.hex())
                                print("   [RXDEBUG] bootkey=%s allkeys=%s"%(k.hex(),
                                      ",".join(x.hex()[:8] for x in keys)))
                                # try the block's OWN embedded 16-byte IV (per-block CTR, like the scan path)
                                for kk in (cand+keys):
                                    d2=aes_ctr(kk, payload[4:20], payload[20:4+ln])
                                    if _valid_dmp_head(d2, len(payload[20:4+ln])):
                                        print("   [RXDEBUG] PER-BLOCK-IV decodes! key=%s dec=%s"%(kk.hex()[:12],d2.hex()[:40])); break
                                # BRUTE: dump RAW decrypts for every key × mode so we can eyeball the plaintext
                                if os.environ.get("AD600_RXBRUTE"):
                                    ctb=payload[20:4+ln]; nz=payload[4:12]; blkctr=int.from_bytes(payload[12:20],"big")
                                    allk=[];
                                    for kk in (cand+keys):
                                        if kk not in allk: allk.append(kk)
                                    for ki,kk in enumerate(allk):
                                        d_pb =aes_ctr(kk, payload[4:20], ctb)                    # per-block IV, offset 0
                                        d_ctr=aes_ctr_at(kk, nz, blkctr*16, ctb)                 # continuous @ stated counter
                                        d_rx =aes_ctr_at(kk, nz, rx_pos[0], ctb)                 # continuous @ our rx_pos
                                        mark=lambda d:" <<0x70" if d and d[0]==0x70 else ""
                                        print("   [BRUTE] k%d=%s  perblk=%s%s  ctr=%s%s  rx=%s%s"%(
                                              ki,kk.hex()[:8], d_pb.hex(),mark(d_pb), d_ctr.hex(),mark(d_ctr), d_rx.hex(),mark(d_rx)))
        elif vec==8:
            # Device NAK: it detected a GAP in our reliable stream and wants a retransmit; if we
            # don't satisfy it the device LEAVEs and the session dies (root cause of the "halt after
            # ~2 commands" on longer sequences — short GET runs never NAK). Format (after leaderCID):
            # chan(2) mid(2) 0000 missedSeq(2) 0b. Retransmit every unacked reliable >= missedSeq,
            # re-using each ORIGINAL rel seq (fresh total seq), in order, so the device fills its gap.
            missed = struct.unpack(">H", vdata[22:24])[0] if len(vdata)>=24 else None
            print("← NAK missed=0x%04x %s"%(missed if missed is not None else 0, vdata.hex()[:40]))
            if missed is not None and not os.environ.get("AD600_NONAKRTX"):
                seqs=sorted(unacked, key=lambda q:(q-missed)&0xffff)
                seqs=[q for q in seqs if ((q-missed)&0xffff)<0x8000]   # missed .. newest, wrapping
                for sq in seqs:
                    tot=total_seq[0]; total_seq[0]=(total_seq[0]+1)&0xffff
                    old=first_rel_seq[0] if (HOLDOLD and first_rel_seq[0] is not None) else sq
                    s.sendto(build_wrapper(cid, our_chan, tot, sq, old, unacked[sq], True), dst)
                if seqs: print("   → retransmitted %d reliable wrapper(s) from 0x%04x"%(len(seqs), missed))
        elif vec==7:  print("← LEAVING %s"%vdata.hex()[:40])
        elif vec==5:  print("← JOIN_REFUSE %s"%vdata.hex()[:40])
        # once mutual join done, set up crypto + declare DMP protocol
        if accepted_us and sent_accept and not joined and ad600_chan:
            joined=True
            sessions=[]
            for c1,c2 in ((cid,AD600_CID),(AD600_CID,cid)):
                for k1,k2 in ((our_chan,ad600_chan),(ad600_chan,our_chan)):
                    se=CryptoSession(c1,c2,k1,k2); keys.append(se.key); sessions.append(se)
            full_sk0[0]=sk_util(cid+AD600_CID+struct.pack("<H",our_chan)+struct.pack("<H",ad600_chan))
            print("*** JOINED — us=0x%04X dev=0x%04X, %d key candidates ***"%(our_chan,ad600_chan,len(keys)))
            # mirror WWB: UNREL mgmt-ack of the device's reliable seq, THEN reliable proto declaration.
            # DMP/SRP is kicked off later, only after the device's proto-0x102 association ACK.
            # WWB waits ~80ms after JOIN before declaring (capture timing) — the device may need that
            # settle time to finish setting up our membership before it will honour the declaration.
            send_wrapper([client_block(1,1,ack_assoc(),mgmt_ack(dev_rel[0]))], False)
            time.sleep(float(os.environ.get("AD600_JOINDELAY","0")))
            send_wrapper([client_block(1,1,0,mgmt_proto())], True)   # declare proto 0x102
            print("→ mgmt-ack + proto-0x102 declaration sent (dev_rel=0x%04x)"%dev_rel[0])
        # pace: send next when prior acked (fast path) OR after PACE seconds (device acks sparsely)
        # Fire queued commands as a rapid BURST like WWB (whole inventory in ~0.5s), NOT one-per-recv:
        # dribbling at 0.25s/cmd left the device idle and it halted our member after ~13 blocks.
        if joined and proto_ok[0] and cmd_queue and time.time()-last_send[0] > float(os.environ.get("AD600_PACE","0.0")):
            # WWB: DECL -> 1 cmd -> (device DECLs) -> reciprocal ASSOC -> THEN burst the inventory.
            # Until our reciprocal ASSOC is out, send just ONE cmd/iter so the device DECLs and the
            # association completes; only after that do we blast (or the device waits on the flood).
            for _ in range(int(os.environ.get("AD600_BURST","8")) if proto_assoc_sent[0] else 1):
                if not cmd_queue: break
                if is_write(cmd_queue[0]) and not writes_armed(): break   # hold writes until FULL association
                nxt=cmd_queue.pop(0); send_dmp(nxt, keys[0])
                print("   → cmd (%d left) %s"%(len(cmd_queue), nxt[:14].hex()))
                time.sleep(float(os.environ.get("AD600_BURSTGAP","0.012")))
            last_send[0]=time.time()
        # NO-READ launch trigger: once the inventory/reserve queue has fully drained (session is up and
        # settled) and we never read SCAN_ID, launch the scan on slot 0. Replaces the old SCAN_ID-reply
        # trigger without bumping the device's slot counter. Fires once (launch_scan guards scan_launched).
        # NOTE: do NOT gate on writes_armed() here — launch_scan's own leading SUBSCRIBE is what makes
        # the device DECL09 → we reciprocate → association fully opens → the CONFIG/START writes (still
        # individually write-gated) then fire. Gating launch on writes_armed would deadlock.
        if (scan_mode[0] and not scan_launched[0] and proto_ok[0]
                and os.environ.get("AD600_NOREADID","1")!="0"
                and not cmd_queue
                and time.time()-last_send[0] > float(os.environ.get("AD600_LAUNCHSETTLE","0.4"))):
            print("→ inventory drained → launch scan on slot 0 (no SCAN_ID read)")
            launch_scan(0)
    if srp_done[0]:
        print("*** SRP COMPLETE — authenticated. control key ready for SESSION DH + scan ***")
    # Clean disconnect (mirrors WWB's quit): disassociate proto 0x102, then LEAVING, then the
    # root-layer leave — so the AD600 frees our member immediately instead of letting the session
    # linger until timeout (accumulated lingering sessions saturate its table = the degradation
    # that forced power-cycles). Sent a couple times unreliably-then-reliably for delivery.
    # On a RECOVER wedge, WWB abandons the channel SILENTLY (no LEAVE, no RELEASE storm to a wedged
    # device that would ignore/queue them anyway); replicate that so the fresh session starts clean.
    if joined and ad600_chan and not os.environ.get("AD600_NOLEAVE") and not (RECOVER and wedged[0]):
        try:
            # RELEASE_SCAN_ID (0x0107010e, DDL: "frees a scan slot") — WITHOUT this the AD600 leaks a
            # scan slot per session until SCAN_ID hits 0xff (exhausted) → device greys out → power-cycle.
            # BOOKEND (teardown): release the ENTIRE slot range 0..N (not just ours) so the device pool
            # always resets to SCAN_ID=0 after every run, regardless of what leaked. AD600_NORELEASE opts out.
            if proto_ok[0] and not os.environ.get("AD600_NORELEASE"):
                _n = int(os.environ.get("AD600_RELSLOTS","16"))
                for _id in range(_n):
                    send_dmp(dmp_pdu(2, 0x0107010e, bytes([_id & 0xff])) + bytes.fromhex("7005010000"), keys[0])
                    time.sleep(0.02)
                # NOTE: do NOT GET SCAN_ID to verify — reading 0x0107010f RESERVES a slot and bumps the
                # ID back up, defeating the release. Fire-and-forget the SETs only; never read it back.
                print("→ RELEASE_SCAN_ID bookend: freed all slots 0..%d (0x0107010e) → device reset toward SCAN_ID=0"%(_n-1))
                time.sleep(0.1)
            for _ in range(2):
                send_wrapper([client_block(1,1,0,pdu_encode(0x0c,None,struct.pack(">I",0x102),1))], True)  # disassoc 0x102
                send_wrapper([client_block(1,1,0,pdu_encode(7,None,b"",1))], True)                          # LEAVING
                time.sleep(0.05)
            # root-layer leave (vec=8): [devCID][9B params template from WWB]
            leave=root_wrap(cid, pdu_encode(8, None, AD600_CID+bytes.fromhex("b2b000010001207a06"), 1))
            s.sendto(leave, dst); s.sendto(leave, dst)
            print("→ clean disconnect sent (disassoc + LEAVING + root-leave)")
        except Exception as e:
            print("disconnect error: %s"%e)
    s.close()
    if CH2:
        print("═══ CH2 RESULT: 2nd channel sent=%s dev_chan2=%s accepted=%s | BIG=%d SMALL=%d%s ═══"
              %(ch2["sent"], ("0x%04X"%ch2["dev"]) if ch2["dev"] else None, ch2["acc"],
                ch2["big"], ch2["small"],
                (" — first big @ %.2fs ★ STREAMING WORKS"%ch2["first_big"][0]) if ch2["first_big"][0] is not None else " — no big packets"))
    print("done — decoded %d DMP blocks; %d undecryptable (Calc-key scan data); srp_done=%s"
          %(decoded, undec[0], srp_done[0]))
    # Session outcome for the outer recovery loop: OK = sustained firehose seen; WEDGED = device
    # froze its stream after the scan launched; NOSCAN = never got as far as launching the scan.
    return "OK" if fh_ok[0] else ("WEDGED" if scan_launch_t[0] is not None else "NOSCAN")

def join_with_recovery():
    """WWB-faithful recovery loop. On a device-side stream freeze, abandon the wedged channel
    (no LEAVE — exactly what WWB does; zero LEAVING vectors in wwb_scan_working_realdevice.pcap),
    wait a cooldown for the device to un-wedge (~19s gap in the capture between WWB's last failed
    re-JOIN at t≈34s and its successful fresh session at t≈54s), then call join_probe() again — a
    fresh CID + fresh random SDT channel + fresh socket = a brand-new session pair, re-running the
    full JOIN + proto-0x102 handshake + inventory + subscribe. Repeat until the firehose sustains."""
    import time
    os.environ.setdefault("AD600_RECOVER","1")
    max_att  = int(os.environ.get("AD600_MAXATT","6"))
    cooldown = float(os.environ.get("AD600_COOLDOWN","18"))   # capture: device needs ~15-20s to un-wedge
    for att in range(1, max_att+1):
        print("\n═══ SESSION ATTEMPT %d/%d — fresh CID + fresh SDT channel (WWB re-JOIN behavior) ═══" % (att, max_att))
        status = join_probe()
        if status == "OK":
            print("═══ SCAN FIREHOSE SUSTAINED on attempt %d — success ═══" % att); return
        print("═══ attempt %d ended: %s ═══" % (att, status))
        if att < max_att:
            print("   Device wedged its stream (same as WWB's 1st session). Channel abandoned with no LEAVE; "
                  "cooling down %.0fs for the device to un-wedge, then a FRESH re-JOIN on a new channel…" % cooldown)
            time.sleep(cooldown)
    print("═══ gave up after %d attempts (device never sustained the firehose) ═══" % max_att)

if __name__=="__main__":
    a = sys.argv[1] if len(sys.argv)>1 else ""
    if a=="selftest" and len(sys.argv)>=3: selftest(sys.argv[2])
    elif a=="discover": discover(int(sys.argv[2]) if len(sys.argv)>2 else 5)
    elif a=="joinrec": join_with_recovery()                    # detect-freeze + fresh re-JOIN loop (WWB-faithful)
    elif a=="join":
        # AD600_RECOVER=1 upgrades a plain `join` to the recovery loop; otherwise single-shot (unchanged).
        (join_with_recovery if os.environ.get("AD600_RECOVER") else join_probe)()
    else: print("usage: python3 ad600_native.py {selftest <pcap>|discover [secs]|join|joinrec}")
