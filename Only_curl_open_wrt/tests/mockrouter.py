"""Fake MR600 v2 web UI: real RSA-512 keypair, real AES session, TP-Link frames."""
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.chdir(_ROOT)
_sys.path.insert(0, _os.path.join(_ROOT, "Only_curl_open_wrt", "tests"))

import base64, binascii, hashlib, importlib.util, json, os, random, re, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

spec = importlib.util.spec_from_file_location("ref", "mr600v2_refill_openwrt.py")
ref = importlib.util.module_from_spec(spec); spec.loader.exec_module(ref)

def _prime(bits, rnd):
    while True:
        c = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if all(pow(a, c - 1, c) == 1 for a in (2, 3, 5, 7, 11, 13, 17, 19, 23)):
            return c

rnd = random.Random(20260905)
P, Q = _prime(256, rnd), _prime(256, rnd)
N = P * Q
E = 0x10001
D = pow(E, -1, (P - 1) * (Q - 1))
NN_HEX = "%0128x" % N
EE_HEX = "010001"
SEQ = 566778899
TOKEN = "a1b2c3d4e5f6"
COOKIE = "JSESSIONID=deadbeefcafe"

# scenario knobs, set from the test driver
SCENARIO = {"total_bytes": 1073741824, "sms_error": 0, "slots": True}

def rsa_decrypt_hex(hexstr):
    out = b""
    blk = 128
    for i in range(0, len(hexstr), blk):
        c = int(hexstr[i:i + blk], 16)
        m = pow(c, D, N)
        # real firmware strips each block's zero padding independently
        out += m.to_bytes(64, "big").rstrip(b"\x00")
    return out

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    session = {}

    def log_message(self, *a):
        pass

    def _send(self, body, extra=None, code=200):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, why):
        H.session["error"] = why
        self._send("FAIL: " + why, code=500)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.htm", "/main.htm"):
            if COOKIE not in (self.headers.get("Cookie") or ""):
                return self._fail("missing cookie on " + path)
            if path != "/":
                return self._send("no token here")
            return self._send('<html><script>var token = "%s";</script></html>' % TOKEN)
        self._send("not found", code=404)

    def do_POST(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""

        if path == "/cgi/getParm":
            return self._send('var ee="%s";\nvar nn="%s";\nvar seq="%d";\n' % (EE_HEX, NN_HEX, SEQ))

        if path == "/cgi/login":
            data_b64 = qs["data"][0]
            sign_hex = qs["sign"][0]
            plain = rsa_decrypt_hex(sign_hex).decode()
            m = re.match(r"key=(\d+)&iv=(\d+)&h=([0-9a-f]+)&s=(\d+)$", plain)
            if not m:
                return self._fail("bad sign payload: %r" % plain)
            key, iv, h, s = m.group(1), m.group(2), m.group(3), int(m.group(4))
            if h != hashlib.md5(b"adminadmin").hexdigest():
                return self._fail("bad password hash %s" % h)
            if s != SEQ + len(data_b64):
                return self._fail("bad seq %d, want %d" % (s, SEQ + len(data_b64)))
            creds = ref._pkcs7_unpad(ref.aes_cbc_decrypt(
                base64.b64decode(data_b64), key.encode(), iv.encode())).decode()
            if creds != "admin\nadmin":
                return self._fail("bad creds %r" % creds)
            H.session["key"], H.session["iv"] = key.encode(), iv.encode()
            return self._send('var ret = "$.ret=0";',
                              {"Set-Cookie": COOKIE + "; Path=/; HttpOnly"})

        if path == "/cgi_gdpr":
            if COOKIE not in (self.headers.get("Cookie") or ""):
                return self._fail("missing cookie on /cgi_gdpr")
            if self.headers.get("TokenID") != TOKEN:
                return self._fail("bad TokenID %r" % self.headers.get("TokenID"))
            if (self.headers.get("Content-Type") or "") != "text/plain":
                return self._fail("bad Content-Type %r" % self.headers.get("Content-Type"))
            body = raw.decode()
            sm = re.match(r"sign=([0-9a-f]+)\r\ndata=(.*)\r\n$", body, re.S)
            if not sm:
                return self._fail("bad gdpr body %r" % body[:120])
            sign_hex, data_b64 = sm.group(1), sm.group(2)
            plain = rsa_decrypt_hex(sign_hex).decode()
            m = re.match(r"h=([0-9a-f]+)&s=(\d+)$", plain)
            if not m:
                return self._fail("bad gdpr sign %r" % plain)
            if int(m.group(2)) != SEQ + len(data_b64):
                return self._fail("bad gdpr seq")
            key, iv = H.session["key"], H.session["iv"]
            frame = ref._pkcs7_unpad(ref.aes_cbc_decrypt(base64.b64decode(data_b64), key, iv)).decode()
            H.session.setdefault("frames", []).append(frame)
            resp = self.build_response(frame)
            enc = base64.b64encode(ref.aes_cbc_encrypt(
                ref._pkcs7_pad(resp.encode(), 16), key, iv)).decode()
            return self._send(enc)

        self._send("not found", code=404)

    def build_response(self, frame):
        if "WAN_LTE_INTF_CFG" in frame:
            want = ("5&5\r\n[WAN_LTE_INTF_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
                    "[WAN_COMMON_INTF_CFG#0,0,0,0,0,0#0,0,0,0,0,0]1,1\r\nWANAccessType\r\n")
            if frame != want:
                H.session["error"] = "usage frame mismatch: %r" % frame
            if not SCENARIO["slots"]:
                return "[1,0,0,0,0,0]0\r\nWANAccessType=1\r\n[error]0\r\n"
            return ("[1,0,0,0,0,0]0\r\ndailyFlow=3\r\ntotalStatistics=12345\r\n"
                    "[1,0,0,0,0,0]1\r\ndailyFlow=99\r\ntotalStatistics=%d\r\n"
                    "[1,0,0,0,0,0]2\r\nWANAccessType=1\r\n[error]0\r\n" % SCENARIO["total_bytes"])
        if "LTE_SMS_SENDNEWMSG" in frame:
            want = ("2\r\n[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\n"
                    "index=1\r\nto=80808\r\ntextContent=Refill\r\n")
            if frame != want:
                H.session["error"] = "sms frame mismatch: %r" % frame
            H.session["sms_sent"] = H.session.get("sms_sent", 0) + 1
            return "[error]%d\r\n" % SCENARIO["sms_error"]
        return "[error]0\r\n"

def serve(port):
    srv = HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

if __name__ == "__main__":
    import time
    port = int(sys.argv[1])
    serve(port)
    print("mock on", port, flush=True)
    while True:
        time.sleep(1)
