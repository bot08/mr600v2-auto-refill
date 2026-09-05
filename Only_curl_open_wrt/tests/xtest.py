import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.chdir(_ROOT)
_sys.path.insert(0, _os.path.join(_ROOT, "Only_curl_open_wrt", "tests"))
import importlib.util, os, subprocess, sys, random, binascii
spec = importlib.util.spec_from_file_location("ref", "mr600v2_refill_openwrt.py")
ref = importlib.util.module_from_spec(spec); spec.loader.exec_module(ref)

AWK = "Only_curl_open_wrt/tplink_crypto.awk"
def run(mode, env, awk=None):
    e = dict(os.environ); e.update(env)
    cmd = (awk or os.environ.get("XTEST_AWK", "awk")).split()
    r = subprocess.run(cmd + ["-f", AWK, "-v", "mode=" + mode],
                       stdin=subprocess.DEVNULL, capture_output=True, env=e)
    if r.returncode != 0:
        raise SystemExit("awk failed: " + r.stderr.decode())
    if r.stderr:
        print("stderr:", r.stderr.decode()[:300])
    return r.stdout.decode("utf-8", "replace")

def py_aes_enc(pt, key, iv):
    return binascii.b2a_base64(ref.aes_cbc_encrypt(ref._pkcs7_pad(pt.encode(), 16),
                               key.encode(), iv.encode())).decode().strip()

fails = 0
key, iv = "1756987654321000", "1756987654321999"

# --- AES encrypt: login blob, usage frame, sms frame, odd lengths
usage_frame = ref.make_data_frame([
    {"method": ref.ACT_GL, "controller": "WAN_LTE_INTF_CFG", "attrs": []},
    {"method": ref.ACT_GL, "controller": "WAN_COMMON_INTF_CFG", "attrs": ["WANAccessType"]}])
sms_frame = ref.make_data_frame([{"method": ref.ACT_SET, "controller": "LTE_SMS_SENDNEWMSG",
    "attrs": {"index": 1, "to": "80808", "textContent": "Refill"}}])

cases = [
    ("enc_login", {"TL_USER": "admin", "TL_PASS": "admin"}, "admin\nadmin"),
    ("enc_login", {"TL_USER": "admin", "TL_PASS": "P@ss w0rd!#&=+/"}, "admin\nP@ss w0rd!#&=+/"),
    ("enc_usage", {}, usage_frame),
    ("enc_sms",   {"SMS_TO": "80808", "SMS_TEXT": "Refill"}, sms_frame),
]
for mode, env, expect_pt in cases:
    env = dict(env); env.update(AESKEY=key, AESIV=iv)
    got = run(mode, env)
    want = py_aes_enc(expect_pt, key, iv)
    ok = got == want
    fails += not ok
    print(("PASS " if ok else "FAIL ") + mode, "" if ok else "\n  got %s\n want %s" % (got, want))

for n in list(range(0, 40)) + [255, 256, 1000]:
    pt = "".join(chr(random.randint(32, 126)) for _ in range(n))
    got = run("enc_text", {"AESKEY": key, "AESIV": iv, "PT": pt})
    want = py_aes_enc(pt, key, iv)
    if got != want:
        fails += 1; print("FAIL enc_text len=%d" % n)
print("PASS enc_text length sweep" if not fails else "")

# --- AES decrypt round trip
for n in [0, 1, 15, 16, 17, 200, 3000]:
    pt = "".join(random.choice("abcXYZ019 =\r\n[]#,") for _ in range(n))
    ct = py_aes_enc(pt, key, iv)
    got = run("dec", {"AESKEY": key, "AESIV": iv, "CT": ct})
    if got != pt:
        fails += 1; print("FAIL dec len=%d" % n, repr(got[:80]), repr(pt[:80]))
print("PASS dec round trip" if not fails else "")

# --- RSA against the reference implementation
random.seed(7)
nns = []
# real-shaped 512-bit RSA moduli (product of two 256-bit primes), plus the
# odd/short forms TP-Link firmwares have been seen to hand out
def _prime(bits):
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if all(pow(a, c - 1, c) == 1 for a in (2, 3, 5, 7, 11, 13, 17)):
            return c
for _ in range(3):
    nns.append("%0128x" % (_prime(256) * _prime(256)))
nns.append("%096x" % (_prime(192) * _prime(192)))   # 384-bit modulus
for nnh in nns:
    for eeh in ["010001", "03", "10001"]:
        for text in ["h=5f4dcc3b5aa765d61d8327deb882cf99&s=1234",
                     "key=1756987654321000&iv=1756987654321999&h=5f4dcc3b5aa765d61d8327deb882cf99&s=999999",
                     "x"]:
            got = run("rsa", {"RSA_TEXT": text, "RSA_N": nnh, "RSA_E": eeh})
            want = ref.rsa_enc(text, nnh, eeh)
            if got != want:
                fails += 1
                print("FAIL rsa e=%s len=%d\n  got %s\n want %s" % (eeh, len(text), got[:80], want[:80]))
print("PASS rsa" if not fails else "")

# --- from_data_frame parity is tested separately in the shell layer
print("\nTOTAL FAILURES:", fails)
sys.exit(1 if fails else 0)
