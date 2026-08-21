#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tplink_lib.py - convenient library for TP-Link Archer MR600.

Usage in your own scripts:

    from tplink_lib import get_usage, send_sms, list_sms, read_sms, delete_sms

    print(get_usage())
    send_sms("+77777777777", "ALARM")
    for sms in list_sms():
        print(sms["from"], sms["content"])

The client logs in automatically on the first call and reuses the
session for all subsequent calls within the process.
"""

import re
import time
import random
import hashlib
import binascii
import requests
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ROUTER_IP = "192.168.1.1"
USERNAME  = "admin"
PASSWORD  = "admin"

ACT_GET = 1
ACT_SET = 2
ACT_DEL = 4
ACT_GL  = 5
ACT_GS  = 6
ACT_CGI = 8


def md5s(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def rsa_enc(text: str, nn_hex: str, ee_hex: str) -> str:
    n = int(nn_hex, 16)
    e = int(ee_hex, 16)
    block_size = (n.bit_length() + 7) // 8
    chunk_size = block_size - 11
    hex_len = len(nn_hex)

    out = ""
    text_bytes = text.encode('utf-8')
    for i in range(0, len(text_bytes), chunk_size):
        chunk = text_bytes[i:i + chunk_size]
        chunk = chunk + b'\x00' * (block_size - len(chunk))
        m = int.from_bytes(chunk, 'big')
        c = pow(m, e, n)
        out += f"{c:0{hex_len}x}"
    return out


# ---------------- Protocol frame encode/decode ----------------

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
                    val = val.replace('\n', '\x12').replace('\r', '\x12')
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
            "method": req["method"],
            "controller": req["controller"],
            "stack": stack,
            "pstack": pstack,
            "attrs": attrs,
            "nb_attrs": nb_attrs,
        })

    header = "&".join(str(s["method"]) for s in sections)
    data_str = ""
    for i, s in enumerate(sections):
        data_str += f"[{s['controller']}#{s['stack']}#{s['pstack']}]{i},{s['nb_attrs']}\r\n{s['attrs']}"

    return header + "\r\n" + data_str


def from_data_frame(frame: str) -> dict:
    lines = frame.strip().splitlines()
    obj_header_re = re.compile(r'^\[\d,\d,\d,\d,\d,\d\]\d')
    attr_re = re.compile(r'^([a-zA-Z0-9]+)=(.*)$')
    error_re = re.compile(r'^\[error\](\d+)$')

    data = []
    current = None
    error_code = 0

    for line in lines:
        line = line.strip('\r')
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

    return {"error": error_code, "data": data}


def prettify(resp: dict) -> dict:
    int_attrs = {"index", "sendResult"}
    bool_attrs = {"unread"}
    for obj in resp["data"]:
        for key in list(obj.keys()):
            if key in int_attrs:
                try:
                    obj[key] = int(obj[key])
                except ValueError:
                    pass
            elif key in bool_attrs:
                try:
                    obj[key] = int(obj[key]) > 0
                except ValueError:
                    pass
            elif key == "content":
                obj[key] = obj[key].replace("\x12", "\n")
    return resp


# ---------------- Client ----------------

class TPLinkClient:
    def __init__(self, host=ROUTER_IP, username=USERNAME, password=PASSWORD):
        self.base = f"http://{host}"
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": f"{self.base}/",
        })

        micros = time.time_ns() // 1000
        self.key_str = str(micros + random.randint(0, 999))[:16]
        self.iv_str = str(micros + random.randint(0, 999))[:16]
        self.key_b = self.key_str.encode('utf-8')
        self.iv_b = self.iv_str.encode('utf-8')

        self.hash = md5s(f"{self.username}{self.password}")
        self.nn = ""
        self.ee = ""
        self.seq = 0
        self.token = ""

    def aes_enc(self, pt: str) -> str:
        c = AES.new(self.key_b, AES.MODE_CBC, self.iv_b)
        padded = pad(pt.encode('utf-8'), 16, style='pkcs7')
        return binascii.b2a_base64(c.encrypt(padded)).decode('utf-8').strip()

    def aes_dec(self, b64: str) -> str:
        clean = b64.strip()
        if clean.startswith("<") or clean.startswith("{"):
            return f"[Non-AES: {clean[:150]}]"
        try:
            c = AES.new(self.key_b, AES.MODE_CBC, self.iv_b)
            raw = c.decrypt(binascii.a2b_base64(clean))
            try:
                return unpad(raw, 16, style='pkcs7').decode('utf-8', errors='ignore')
            except Exception:
                return raw.rstrip(b'\x00').decode('utf-8', errors='ignore')
        except Exception as e:
            return f"[Decryption Error: {e}]"

    def get_parm(self) -> bool:
        r = self.session.post(f"{self.base}/cgi/getParm", data="", timeout=5)
        ee = re.search(r'var ee="([^"]+)";', r.text)
        nn = re.search(r'var nn="([^"]+)";', r.text)
        sq = re.search(r'var seq="?(\d+)"?;', r.text)
        if ee and nn and sq:
            self.ee = ee.group(1)
            self.nn = nn.group(1)
            self.seq = int(sq.group(1))
            return True
        return False

    def login(self) -> bool:
        if not self.get_parm():
            return False

        login_data = f"{self.username}\n{self.password}"
        enc_login = self.aes_enc(login_data)

        sign_plain = f"key={self.key_str}&iv={self.iv_str}&h={self.hash}&s={self.seq + len(enc_login)}"
        sign_login = rsa_enc(sign_plain, self.nn, self.ee)

        enc_url = enc_login.replace('=', '%3D').replace('+', '%2B')
        login_url = f"{self.base}/cgi/login?data={enc_url}&sign={sign_login}&Action=1&LoginStatus=0"

        r = self.session.post(login_url, data="", timeout=5)
        if "$.ret=0" not in r.text:
            return False

        for u in [f"{self.base}/", f"{self.base}/index.htm", f"{self.base}/main.htm"]:
            try:
                r_main = self.session.get(u, timeout=5)
                m = re.search(r'var\s+token\s*=\s*"([a-f0-9]+)"', r_main.text, re.IGNORECASE)
                if m:
                    self.token = m.group(1)
                    break
            except Exception:
                pass

        return bool(self.token)

    def execute(self, reqs: list) -> dict:
        if not self.token:
            if not self.login():
                raise RuntimeError("Failed to log in to the router")

        frame = make_data_frame(reqs)
        enc_data = self.aes_enc(frame)
        sign_plain = f"h={self.hash}&s={self.seq + len(enc_data)}"
        sign_gdpr = rsa_enc(sign_plain, self.nn, self.ee)

        body = f"sign={sign_gdpr}\r\ndata={enc_data}\r\n"
        headers = {"Content-Type": "text/plain", "TokenID": self.token}

        r = self.session.post(f"{self.base}/cgi_gdpr", data=body.encode('utf-8'),
                               headers=headers, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")

        decrypted = self.aes_dec(r.text)
        parsed = from_data_frame(decrypted)
        return prettify(parsed)

    # ---------- Traffic / usage ----------

    def raw_usage(self) -> dict:
        """Raw data for all SIM slots from WAN_LTE_INTF_CFG."""
        reqs = [
            {"method": ACT_GL, "controller": "WAN_LTE_INTF_CFG", "attrs": []},
            {"method": ACT_GL, "controller": "WAN_COMMON_INTF_CFG", "attrs": ["WANAccessType"]},
        ]
        return self.execute(reqs)

    def get_usage(self) -> dict:
        """
        Returns a convenient summary of data usage.
        MR600 has 2 SIM slots; the function returns data for both
        and separately marks the "active" one (where dailyFlow > 0).
        """
        raw = self.raw_usage()
        slots = []
        for obj in raw["data"]:
            if "dailyFlow" not in obj:
                continue  # This is not a usage record (for example, a WANAccessType block)
            try:
                daily_flow = float(obj.get("dailyFlow", 0))
                total_stat = float(obj.get("totalStatistics", 0))
            except ValueError:
                daily_flow = 0.0
                total_stat = 0.0

            current_date = obj.get("currentDate", "0")
            try:
                current_date_int = int(float(current_date))
                current_date_str = (datetime.fromtimestamp(current_date_int).isoformat()
                                     if current_date_int > 0 else None)
            except (ValueError, OSError):
                current_date_str = None

            slots.append({
                "daily_flow_bytes": daily_flow,
                "daily_flow_mb": round(daily_flow / 1024 / 1024, 2),
                "total_statistics_bytes": total_stat,
                "total_statistics_mb": round(total_stat / 1024 / 1024, 2),
                "data_limit": obj.get("dataLimit"),
                "enable_data_limit": obj.get("enableDataLimit") == "1",
                "warning_percent": obj.get("warningPercent"),
                "current_date": current_date_str,
                "raw": obj,
            })

        active = max(slots, key=lambda s: s["daily_flow_bytes"], default=None)

        return {"slots": slots, "active": active}

    # ---------- SMS ----------

    def sms_list(self, folder: str = "inbox") -> list:
        if folder == "inbox":
            box_ctrl, msg_ctrl = "LTE_SMS_RECVMSGBOX", "LTE_SMS_RECVMSGENTRY"
            attrs = ["index", "from", "content", "receivedTime", "unread"]
        elif folder == "sent":
            box_ctrl, msg_ctrl = "LTE_SMS_SENDMSGBOX", "LTE_SMS_SENDMSGENTRY"
            attrs = ["index", "to", "content", "sendTime"]
        else:
            raise ValueError("folder must be 'inbox' or 'sent'")

        reqs = [
            {"method": ACT_SET, "controller": box_ctrl, "attrs": {"PageNumber": 1}},
            {"method": ACT_GL, "controller": msg_ctrl, "attrs": attrs},
        ]
        result = self.execute(reqs)
        return result["data"]

    def sms_read(self, folder: str, index: int) -> dict:
        if folder == "inbox":
            ctrl = "LTE_SMS_RECVMSGENTRY"
            attrs = ["index", "from", "content", "receivedTime", "unread"]
        elif folder == "sent":
            ctrl = "LTE_SMS_SENDMSGENTRY"
            attrs = ["index", "to", "content", "sendTime"]
        else:
            raise ValueError("folder must be 'inbox' or 'sent'")

        reqs = [{
            "method": ACT_GET,
            "controller": ctrl,
            "stack": f"{index},0,0,0,0,0",
            "attrs": attrs,
        }]
        result = self.execute(reqs)
        return result["data"][0] if result["data"] else {}

    def sms_delete(self, folder: str, index: int) -> bool:
        ctrl = "LTE_SMS_RECVMSGENTRY" if folder == "inbox" else "LTE_SMS_SENDMSGENTRY"
        reqs = [{
            "method": ACT_DEL,
            "controller": ctrl,
            "stack": f"{index},0,0,0,0,0",
        }]
        result = self.execute(reqs)
        return result["error"] == 0

    def sms_send(self, number: str, message: str) -> bool:
        reqs = [{
            "method": ACT_SET,
            "controller": "LTE_SMS_SENDNEWMSG",
            "attrs": {"index": 1, "to": number, "textContent": message},
        }]
        result = self.execute(reqs)
        return result["error"] == 0


# ---------------- Module-level convenience functions ----------------
# One shared client per process; login occurs only once.

_client: "TPLinkClient | None" = None


def _get_client() -> TPLinkClient:
    global _client
    if _client is None:
        _client = TPLinkClient()
        if not _client.login():
            _client = None
            raise RuntimeError("Failed to log in to the router")
    return _client


def get_usage() -> dict:
    """Return dict {'slots': [...], 'active': {...}} with SIM usage data."""
    return _get_client().get_usage()


def list_sms(folder: str = "inbox") -> list:
    """List SMS messages in 'inbox' or 'sent'."""
    return _get_client().sms_list(folder)


def read_sms(folder: str, index: int) -> dict:
    """Read one SMS by its list position."""
    return _get_client().sms_read(folder, index)


def delete_sms(folder: str, index: int) -> bool:
    """Delete an SMS by its position. Returns True on success."""
    return _get_client().sms_delete(folder, index)


def send_sms(number: str, message: str) -> bool:
    """Send an SMS. Returns True on success."""
    return _get_client().sms_send(number, message)


# ---------------- Usage example ----------------

if __name__ == "__main__":
    usage = get_usage()
    print("Active SIM:", usage["active"])

    usage = get_usage()
    print(usage["active"])

    print("\nRecent SMS:")
    for sms in list_sms("inbox")[:5]:
        print(f"  [{sms['index']}] {sms['from']}: {sms['content'][:60]}")

    # send_sms("80808", "Refill")
    # delete_sms("inbox", 1)