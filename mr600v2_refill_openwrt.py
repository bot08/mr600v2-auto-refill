#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Require python3-light package
import binascii
import os
import random
import re
import socket
import struct
import sys
import time

# ============================================================================
# Configuration
# ============================================================================

ROUTER_IP = "192.168.1.1"
ROUTER_PORT = 80
USERNAME = "admin"
PASSWORD = "admin"

REFILL_NUMBER = "80808"
REFILL_TEXT = "Refill"
THRESHOLD_MB = 800

STATE_FILE = "/tmp/tplink_monitor.state"
SMS_COUNTER_FILE = "/tmp/tplink_sms_counter.state"
MAX_SMS_PER_DAY = 30
SESSION_FILE = "/tmp/tplink_session.state"
SESSION_MAX_AGE_SEC = 240
LOCK_FILE = "/tmp/tplink_monitor.lock"
LOCK_STALE_SEC = 20
NET_TIMEOUT_SEC = 8
MAX_ATTEMPTS = 2
RETRY_DELAY_SEC = 2

SYSLOG_TAG = "tplink-monitor"

ACT_GET, ACT_SET, ACT_DEL, ACT_GL, ACT_GS, ACT_CGI = 1, 2, 4, 5, 6, 8


# ============================================================================
# System log via busybox `logger`
# ============================================================================

def syslog(level: str, message: str):
    """level: 'info' | 'warning' | 'err'."""
    prio = {"info": "daemon.info", "warning": "daemon.warning", "err": "daemon.err"}.get(level, "daemon.info")
    try:
        os.spawnvp(os.P_WAIT, "logger", ["logger", "-t", SYSLOG_TAG, "-p", prio, message])
    except OSError:
        sys.stderr.write(f"[{level}] {message}\n")


# ============================================================================
# MD5 (hashlib or pure-Python fallback)
# ============================================================================

try:
    import hashlib

    def md5_hex(s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest()

except ImportError:
    _MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    _MD5_K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ]

    def _md5_bytes(msg: bytes) -> bytes:
        a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        orig_len_bits = (len(msg) * 8) & 0xffffffffffffffff
        msg = msg + b"\x80"
        while len(msg) % 64 != 56:
            msg += b"\x00"
        msg += struct.pack("<Q", orig_len_bits)

        for ofs in range(0, len(msg), 64):
            M = list(struct.unpack("<16I", msg[ofs:ofs + 64]))
            A, B, C, D = a0, b0, c0, d0
            for i in range(64):
                if i < 16:
                    F, g = (B & C) | (~B & D), i
                elif i < 32:
                    F, g = (D & B) | (~D & C), (5 * i + 1) % 16
                elif i < 48:
                    F, g = B ^ C ^ D, (3 * i + 5) % 16
                else:
                    F, g = C ^ (B | ~D), (7 * i) % 16
                F = (F + A + _MD5_K[i] + M[g]) & 0xffffffff
                A, D, C = D, C, B
                rot = _MD5_S[i]
                B = (B + ((F << rot) | (F >> (32 - rot)))) & 0xffffffff
            a0 = (a0 + A) & 0xffffffff
            b0 = (b0 + B) & 0xffffffff
            c0 = (c0 + C) & 0xffffffff
            d0 = (d0 + D) & 0xffffffff
        return struct.pack("<4I", a0, b0, c0, d0)

    def md5_hex(s: str) -> str:
        return _md5_bytes(s.encode("utf-8")).hex()


# ============================================================================
# RSA via the built-in pow()
# ============================================================================

def rsa_enc(text: str, nn_hex: str, ee_hex: str) -> str:
    n = int(nn_hex, 16)
    e = int(ee_hex, 16)
    block_size = (n.bit_length() + 7) // 8
    chunk_size = block_size - 11
    hex_len = len(nn_hex)

    out = ""
    text_bytes = text.encode("utf-8")
    for i in range(0, len(text_bytes), chunk_size):
        chunk = text_bytes[i:i + chunk_size]
        chunk = chunk + b"\x00" * (block_size - len(chunk))
        m = int.from_bytes(chunk, "big")
        c = pow(m, e, n)
        out += f"{c:0{hex_len}x}"
    return out


# ============================================================================
# AES-CBC (128-bit) pure Python
# ============================================================================

_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p & 0xff


def _key_expansion(key):
    nk = len(key) // 4
    nr = nk + 6
    nb = 4
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, nb * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w, nr


def _add_round_key(state, w, rnd):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= w[rnd * 4 + c][r]


def _sub_bytes(state, box):
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def _shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def _inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def _mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        state[3][c] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)


def _inv_mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        state[1][c] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        state[2][c] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        state[3][c] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)


def _b2s(b):
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def _s2b(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _aes_encrypt_block(block, w, nr):
    state = _b2s(block)
    _add_round_key(state, w, 0)
    for rnd in range(1, nr):
        _sub_bytes(state, _SBOX)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, w, rnd)
    _sub_bytes(state, _SBOX)
    _shift_rows(state)
    _add_round_key(state, w, nr)
    return _s2b(state)


def _aes_decrypt_block(block, w, nr):
    state = _b2s(block)
    _add_round_key(state, w, nr)
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, _INV_SBOX)
        _add_round_key(state, w, rnd)
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes(state, _INV_SBOX)
    _add_round_key(state, w, 0)
    return _s2b(state)


def _pkcs7_pad(data: bytes, block=16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 0 < n <= 16:
        return data[:-n]
    return data


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    w, nr = _key_expansion(key)
    out = b""
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = bytes(a ^ b for a, b in zip(plaintext[i:i + 16], prev))
        enc = _aes_encrypt_block(block, w, nr)
        out += enc
        prev = enc
    return out


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    w, nr = _key_expansion(key)
    out = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = _aes_decrypt_block(block, w, nr)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return out


# ============================================================================
# TP-Link frame utilities
# ============================================================================

def to_kv(data) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, (list, tuple)):
        return ("\r\n".join(data) + "\r\n") if data else ""
    if isinstance(data, dict):
        out = ""
        for key, val in data.items():
            if val is not None:
                if isinstance(val, str):
                    val = val.replace("\n", "\x12").replace("\r", "\x12")
                out += f"{key}={val}\r\n"
            else:
                out += f"{key}\r\n"
        return out
    return ""


def make_data_frame(reqs: list) -> str:
    sections = []
    for req in reqs:
        stack = req.get("stack") or "0,0,0,0,0,0"
        pstack = "0,0,0,0,0,0"
        attrs = to_kv(req.get("attrs"))
        nb_attrs = attrs.count("\r\n")
        sections.append({
            "method": req["method"], "controller": req["controller"],
            "stack": stack, "pstack": pstack, "attrs": attrs, "nb_attrs": nb_attrs,
        })
    header = "&".join(str(s["method"]) for s in sections)
    data_str = ""
    for i, s in enumerate(sections):
        data_str += f"[{s['controller']}#{s['stack']}#{s['pstack']}]{i},{s['nb_attrs']}\r\n{s['attrs']}"
    return header + "\r\n" + data_str


def from_data_frame(frame: str) -> dict:
    lines = frame.strip().splitlines()
    obj_header_re = re.compile(r"^\[\d,\d,\d,\d,\d,\d\]\d")
    attr_re = re.compile(r"^([a-zA-Z0-9]+)=(.*)$")
    error_re = re.compile(r"^\[error\](\d+)$")

    data, current, error_code = [], None, 0
    for line in lines:
        line = line.strip("\r")
        if obj_header_re.match(line):
            if current is not None:
                data.append(current)
            current = {}
            continue
        m = error_re.match(line)
        if m:
            error_code = int(m.group(1))
            if current is not None:
                data.append(current)
                current = None
            continue
        m = attr_re.match(line)
        if m and current is not None:
            current[m.group(1)] = m.group(2)
    if current is not None:
        data.append(current)
    return {"error": error_code, "data": data}


# ============================================================================
# HTTP client using raw sockets with session Cookie support
# ============================================================================

class HttpError(Exception):
    pass


def _dechunk(body: bytes) -> bytes:
    out = b""
    while body:
        line_end = body.find(b"\r\n")
        if line_end == -1:
            break
        size_line = body[:line_end].split(b";")[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        if size == 0:
            break
        chunk_start = line_end + 2
        out += body[chunk_start:chunk_start + size]
        body = body[chunk_start + size + 2:]
    return out


class HttpClient:
    def __init__(self, host: str, port: int = 80, timeout: float = NET_TIMEOUT_SEC):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.cookies = {}

    def _update_cookies(self, set_cookies: list):
        for raw in set_cookies:
            part = raw.split(";", 1)[0].strip()
            if "=" in part:
                k, v = part.split("=", 1)
                self.cookies[k.strip()] = v.strip()

    def _cookie_header(self) -> str:
        if not self.cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def request(self, method: str, path: str, body=b"", extra_headers=None):
        extra_headers = extra_headers or {}
        if isinstance(body, str):
            body = body.encode("utf-8")

        headers = {
            "Host": self.host,
            "Connection": "close",
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Referer": f"http://{self.host}/",
            "Content-Length": str(len(body)),
        }
        cookie_str = self._cookie_header()
        if cookie_str:
            headers["Cookie"] = cookie_str
        headers.update(extra_headers)

        req_lines = [f"{method} {path} HTTP/1.1"]
        for k, v in headers.items():
            req_lines.append(f"{k}: {v}")
        req_lines.append("")
        req_lines.append("")
        req_bytes = "\r\n".join(req_lines).encode("utf-8") + body

        # Connect directly without getaddrinfo (avoids the idna codec)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
            sock.sendall(req_bytes)

            buf = b""
            header_end = -1
            while header_end == -1:
                chunk = sock.recv(4096)
                if not chunk:
                    raise HttpError("Connection closed before headers received")
                buf += chunk
                header_end = buf.find(b"\r\n\r\n")

            header_data = buf[:header_end]
            body_data = buf[header_end + 4:]

            header_lines = header_data.decode("iso-8859-1").split("\r\n")
            status_line = header_lines[0]
            status_parts = status_line.split(" ", 2)
            status_code = int(status_parts[1]) if len(status_parts) > 1 else 0

            resp_headers = {}
            set_cookies = []
            for line in header_lines[1:]:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k_clean = k.strip().lower()
                v_clean = v.strip()
                if k_clean == "set-cookie":
                    set_cookies.append(v_clean)
                else:
                    resp_headers[k_clean] = v_clean

            self._update_cookies(set_cookies)

            if "content-length" in resp_headers:
                need = int(resp_headers["content-length"])
                while len(body_data) < need:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    body_data += chunk
                body_data = body_data[:need]
            elif resp_headers.get("transfer-encoding", "").lower() == "chunked":
                while b"0\r\n\r\n" not in body_data and b"\r\n0\r\n" not in body_data[-8:]:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    body_data += chunk
                body_data = _dechunk(body_data)
            else:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    body_data += chunk

            return status_code, resp_headers, body_data
        finally:
            sock.close()


# ============================================================================
# TP-Link client
# ============================================================================

class TPLinkClient:
    def __init__(self, host=ROUTER_IP, port=ROUTER_PORT, username=USERNAME, password=PASSWORD):
        self.http = HttpClient(host, port)
        self.username = username
        self.password = password

        micros = int(time.time() * 1000000)
        self.key_str = str(micros + random.randint(0, 999))[:16]
        self.iv_str = str(micros + random.randint(0, 999))[:16]
        self.key_b = self.key_str.encode("utf-8")
        self.iv_b = self.iv_str.encode("utf-8")

        self.hash = md5_hex(f"{self.username}{self.password}")
        self.nn = ""
        self.ee = ""
        self.seq = 0
        self.token = ""

    def _aes_enc(self, pt: str) -> str:
        padded = _pkcs7_pad(pt.encode("utf-8"), 16)
        enc = aes_cbc_encrypt(padded, self.key_b, self.iv_b)
        return binascii.b2a_base64(enc).decode("utf-8").strip()

    def _aes_dec(self, b64: str) -> str:
        clean = b64.strip()
        if clean.startswith("<") or clean.startswith("{"):
            return f"[Non-AES: {clean[:150]}]"
        try:
            raw = aes_cbc_decrypt(binascii.a2b_base64(clean), self.key_b, self.iv_b)
            return _pkcs7_unpad(raw).decode("utf-8", errors="ignore")
        except Exception as e:
            return f"[Decryption Error: {e}]"

    def _get_parm(self) -> bool:
        status, _, body = self.http.request("POST", "/cgi/getParm", body="")
        text = body.decode("utf-8", errors="ignore")
        ee = re.search(r'var ee="([^"]+)";', text)
        nn = re.search(r'var nn="([^"]+)";', text)
        sq = re.search(r'var seq="?(\d+)"?;', text)
        if ee and nn and sq:
            self.ee, self.nn, self.seq = ee.group(1), nn.group(1), int(sq.group(1))
            return True
        return False

    def login(self) -> bool:
        if not self._get_parm():
            return False

        login_data = f"{self.username}\n{self.password}"
        enc_login = self._aes_enc(login_data)

        sign_plain = f"key={self.key_str}&iv={self.iv_str}&h={self.hash}&s={self.seq + len(enc_login)}"
        sign_login = rsa_enc(sign_plain, self.nn, self.ee)

        # Escape only = and +; do not escape slashes /
        enc_url = enc_login.replace("=", "%3D").replace("+", "%2B")
        path = f"/cgi/login?data={enc_url}&sign={sign_login}&Action=1&LoginStatus=0"

        status, headers, body = self.http.request("POST", path, body="")
        text = body.decode("utf-8", errors="ignore")
        if "$.ret=0" not in text:
            return False

        for p in ["/", "/index.htm", "/main.htm"]:
            try:
                _, _, main_body = self.http.request("GET", p)
                main_text = main_body.decode("utf-8", errors="ignore")
                m = re.search(r'var\s+token\s*=\s*"([a-f0-9]+)"', main_text, re.IGNORECASE)
                if m:
                    self.token = m.group(1)
                    break
            except Exception:
                pass

        return bool(self.token)

    def execute(self, reqs: list) -> dict:
        if not self.token:
            if not self.login():
                raise RuntimeError("Login failed")

        frame = make_data_frame(reqs)
        enc_data = self._aes_enc(frame)
        sign_plain = f"h={self.hash}&s={self.seq + len(enc_data)}"
        sign_gdpr = rsa_enc(sign_plain, self.nn, self.ee)

        body = f"sign={sign_gdpr}\r\ndata={enc_data}\r\n"
        status, headers, resp_body = self.http.request(
            "POST", "/cgi_gdpr", body=body,
            extra_headers={"Content-Type": "text/plain", "TokenID": self.token},
        )
        if status != 200:
            raise RuntimeError(f"HTTP {status}: {resp_body[:200].decode('utf-8', errors='ignore')}")

        decrypted = self._aes_dec(resp_body.decode("utf-8", errors="ignore"))
        parsed = from_data_frame(decrypted)
        return parsed

    def get_total_used_mb(self) -> float:
        # Request both blocks as in the working code
        reqs = [
            {"method": ACT_GL, "controller": "WAN_LTE_INTF_CFG", "attrs": []},
            {"method": ACT_GL, "controller": "WAN_COMMON_INTF_CFG", "attrs": ["WANAccessType"]},
        ]
        result = self.execute(reqs)
        slots = []
        for obj in result.get("data", []):
            if "dailyFlow" not in obj:
                continue
            try:
                daily_flow = float(obj.get("dailyFlow", 0))
                total_stat = float(obj.get("totalStatistics", 0))
            except ValueError:
                daily_flow = 0.0
                total_stat = 0.0
            slots.append({
                "daily_flow": daily_flow,
                "total_mb": round(total_stat / 1024 / 1024, 2),
            })
        if not slots:
            raise RuntimeError("No SIM statistics found in WAN_LTE_INTF_CFG response")

        active = max(slots, key=lambda s: s["daily_flow"])
        return active["total_mb"]

    def send_sms(self, number: str, message: str) -> bool:
        reqs = [{
            "method": ACT_SET,
            "controller": "LTE_SMS_SENDNEWMSG",
            "attrs": {"index": 1, "to": number, "textContent": message},
        }]
        result = self.execute(reqs)
        return result.get("error") == 0

    def restore_session(self, session_data):
        # Restore a previously saved session to skip login
        self.token = session_data.get("token", "")
        self.key_str = session_data.get("key_str", "")
        self.iv_str = session_data.get("iv_str", "")
        self.key_b = self.key_str.encode("utf-8")
        self.iv_b = self.iv_str.encode("utf-8")
        self.nn = session_data.get("nn", "")
        self.ee = session_data.get("ee", "")
        self.seq = int(session_data.get("seq", "0"))
        self.hash = session_data.get("hash", "")
        self.http.cookies = session_data.get("cookies", {})


# ============================================================================
# State management (/tmp) and locking
# ============================================================================

def read_state():
    try:
        with open(STATE_FILE, "r") as f:
            content = f.read()
        m = re.search(r"baseline_mb=([0-9.]+)", content)
        if m:
            return float(m.group(1))
    except FileNotFoundError:
        pass
    return None


def write_state(baseline_mb: float):
    tmp_path = STATE_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(f"baseline_mb={baseline_mb:.2f}\n")
        f.write(f"updated={time.strftime('%Y-%m-%dT%H:%M:%S')}\n")
    os.replace(tmp_path, STATE_FILE)


def read_sms_counter():
    # Read daily SMS counter. Returns (date_str, count)
    try:
        with open(SMS_COUNTER_FILE, "r") as f:
            content = f.read()
        m_date = re.search(r"date=(\d{4}-\d{2}-\d{2})", content)
        m_count = re.search(r"count=(\d+)", content)
        if m_date and m_count:
            return m_date.group(1), int(m_count.group(1))
    except FileNotFoundError:
        pass
    return None, 0


def write_sms_counter(date_str: str, count: int):
    # Write daily SMS counter atomically
    tmp_path = SMS_COUNTER_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(f"date={date_str}\n")
        f.write(f"count={count}\n")
    os.replace(tmp_path, SMS_COUNTER_FILE)


def check_sms_limit() -> bool:
    # Check if daily SMS limit is reached. Returns True if SMS can be sent.
    today = time.strftime("%Y-%m-%d")
    saved_date, count = read_sms_counter()
    if saved_date != today:
        # New day — reset counter
        write_sms_counter(today, 0)
        return True
    if count >= MAX_SMS_PER_DAY:
        return False
    return True


def increment_sms_counter():
    # Increment SMS counter for today.
    today = time.strftime("%Y-%m-%d")
    saved_date, count = read_sms_counter()
    if saved_date != today:
        write_sms_counter(today, 1)
    else:
        write_sms_counter(today, count + 1)


def save_session(client):
    # Save session state to file for reuse between runs
    tmp_path = SESSION_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(f"token={client.token}\n")
        f.write(f"key_str={client.key_str}\n")
        f.write(f"iv_str={client.iv_str}\n")
        f.write(f"nn={client.nn}\n")
        f.write(f"ee={client.ee}\n")
        f.write(f"seq={client.seq}\n")
        f.write(f"hash={client.hash}\n")
        for k, v in client.http.cookies.items():
            f.write(f"cookie_{k}={v}\n")
    os.replace(tmp_path, SESSION_FILE)


def load_session():
    # Load session if file exists and is younger than SESSION_MAX_AGE_SEC
    try:
        age = time.time() - os.path.getmtime(SESSION_FILE)
        if age > SESSION_MAX_AGE_SEC:
            return None
        with open(SESSION_FILE, "r") as f:
            content = f.read()
        data = {}
        cookies = {}
        for line in content.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k.startswith("cookie_"):
                    cookies[k[7:]] = v
                else:
                    data[k] = v
        data["cookies"] = cookies
        if data.get("token"):
            return data
    except (FileNotFoundError, OSError):
        pass
    return None


def delete_session():
    try:
        os.remove(SESSION_FILE)
    except OSError:
        pass


def acquire_lock() -> bool:
    try:
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True
    except FileExistsError:
        try:
            age = time.time() - os.path.getmtime(LOCK_FILE)
        except OSError:
            return False
        if age > LOCK_STALE_SEC:
            try:
                os.remove(LOCK_FILE)
            except OSError:
                pass
            return acquire_lock_once_more()
        return False


def acquire_lock_once_more() -> bool:
    try:
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True
    except FileExistsError:
        return False


def release_lock():
    try:
        os.remove(LOCK_FILE)
    except OSError:
        pass


def with_retries(fn, what: str):
    last_err = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return fn(), None
        except Exception as e:
            last_err = e
            if attempt < MAX_ATTEMPTS:
                time.sleep(RETRY_DELAY_SEC)
    return None, f"{what} failed after {MAX_ATTEMPTS} attempts: {last_err}"


# ============================================================================
# Main entry point
# ============================================================================

def main():
    if not acquire_lock():
        return

    try:
        # Check DAILY SMS limit before doing anything
        if not check_sms_limit():
            _, count = read_sms_counter()
            syslog("warning", f"Daily SMS limit reached ({count}/{MAX_SMS_PER_DAY}). Skipping this run.")
            return

        # Try to reuse a cached session
        session = load_session()

        client = TPLinkClient()

        if session:
            client.restore_session(session)

        current_mb, err = with_retries(client.get_total_used_mb, "get usage")
        if err:
            syslog("err", err)
            if session:
                delete_session()
            return

        # Save session after successful API call (login may have happened)
        if not session:
            save_session(client)

        baseline_mb = read_state()

        if baseline_mb is None:
            ok, err = with_retries(lambda: client.send_sms(REFILL_NUMBER, REFILL_TEXT), "send initial SMS")
            if err:
                syslog("err", err)
                delete_session()
                return
            if not ok:
                syslog("err", "First run: router rejected Refill SMS (error != 0). Not counted, baseline not set, will retry next run.")
                return
            increment_sms_counter()
            write_state(current_mb)
            syslog("info", f"First run: initial Refill SMS sent. Total used={current_mb:.2f} MB, baseline set.")
            return

        if current_mb < baseline_mb:
            syslog("info", f"Counter reset detected: {baseline_mb:.2f} MB -> {current_mb:.2f} MB. Baseline updated, no SMS sent.")
            write_state(current_mb)
            return

        used_since_refill = current_mb - baseline_mb

        if used_since_refill >= THRESHOLD_MB:
            ok, err = with_retries(lambda: client.send_sms(REFILL_NUMBER, REFILL_TEXT), "send Refill SMS")
            if err:
                syslog("err", f"{err}. Used {used_since_refill:.2f} MB (threshold {THRESHOLD_MB} MB), baseline NOT reset, will retry next run.")
                delete_session()
                return
            if not ok:
                syslog("err", f"Router rejected Refill SMS (error != 0). Used {used_since_refill:.2f} MB (threshold {THRESHOLD_MB} MB), not counted, baseline NOT reset, will retry next run.")
                return
            increment_sms_counter()
            write_state(current_mb)
            _, count = read_sms_counter()
            syslog("info", f"Threshold reached ({used_since_refill:.2f} MB >= {THRESHOLD_MB} MB). Refill SMS sent, baseline reset to {current_mb:.2f} MB. SMS today: {count}/{MAX_SMS_PER_DAY}.")
        else:
            syslog("info", f"Total used={current_mb:.2f} MB, used since last Refill={used_since_refill:.2f} MB (threshold {THRESHOLD_MB} MB). No action.")
    except Exception as e:
        syslog("err", f"Unexpected error: {e}")
    finally:
        release_lock()


if __name__ == "__main__":
    main()