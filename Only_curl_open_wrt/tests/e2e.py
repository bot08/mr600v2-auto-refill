"""Run the python original and the shell port against the same mock router and
diff their syslog output, state files and SMS counters."""
import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.chdir(_ROOT)
_sys.path.insert(0, _os.path.join(_ROOT, "Only_curl_open_wrt", "tests"))

import importlib.util, io, os, re, shutil, subprocess, sys, tempfile, contextlib
import mockrouter
from mockrouter import H, SCENARIO

# --- hard network guard: this harness must NEVER reach a real router ---------
import socket as _socket
_real_connect = _socket.socket.connect
def _guarded_connect(self, addr):
    if not (isinstance(addr, tuple) and addr[0] in ("127.0.0.1", "localhost")):
        raise RuntimeError("BLOCKED outbound connection to %r" % (addr,))
    return _real_connect(self, addr)
_socket.socket.connect = _guarded_connect

PORT = 8731
mockrouter.serve(PORT)

spec = importlib.util.spec_from_file_location("ref", "mr600v2_refill_openwrt.py")
ref = importlib.util.module_from_spec(spec); spec.loader.exec_module(ref)

WORK = tempfile.mkdtemp(prefix="tpl")
def paths(tag):
    return (os.path.join(WORK, tag + ".state"),
            os.path.join(WORK, tag + ".sms"),
            os.path.join(WORK, tag + ".lock"))

def reset_session():
    H.session.clear()

def run_python(tag, state=None, sms=None):
    st, sc, lk = paths(tag)
    for f in (st, sc, lk):
        if os.path.exists(f): os.remove(f)
    if state is not None: open(st, "w").write(state)
    if sms is not None: open(sc, "w").write(sms)
    # NB: TPLinkClient's defaults were bound at import time, so rebinding
    # ref.ROUTER_IP is not enough - the constructor must be pinned explicitly.
    ref.ROUTER_IP, ref.ROUTER_PORT = "127.0.0.1", PORT
    _orig_cls = ref.TPLinkClient
    class _Pinned(_orig_cls):
        def __init__(self):
            _orig_cls.__init__(self, host="127.0.0.1", port=PORT,
                               username=ref.USERNAME, password=ref.PASSWORD)
    ref.TPLinkClient = _Pinned
    ref.STATE_FILE, ref.SMS_COUNTER_FILE, ref.LOCK_FILE = st, sc, lk
    logs = []
    orig = ref.syslog
    ref.syslog = lambda lvl, msg: logs.append("%s: %s" % (lvl, msg))
    try:
        ref.main()
    finally:
        ref.syslog = orig
        ref.TPLinkClient = _orig_cls
    return logs, _read(st), _read(sc)

def run_shell(tag, state=None, sms=None):
    st, sc, lk = paths(tag + "_sh")
    for f in (st, sc, lk):
        if os.path.exists(f): os.remove(f)
    if state is not None: open(st, "w").write(state)
    if sms is not None: open(sc, "w").write(sms)
    env = dict(os.environ)
    env.update(TPL_ROUTER_IP="127.0.0.1", TPL_ROUTER_PORT=str(PORT),
               TPL_STATE_FILE=st, TPL_SMS_COUNTER_FILE=sc, TPL_LOCK_FILE=lk,
               TPL_CRYPTO_AWK=os.path.abspath("Only_curl_open_wrt/tplink_crypto.awk"),
               TPL_AWK=os.environ.get("XTEST_AWK", "awk"),
               PATH=os.environ["PATH"])
    r = subprocess.run(["sh", "Only_curl_open_wrt/tplink_router_monitor.sh"],
                       capture_output=True, env=env, stdin=subprocess.DEVNULL)
    logs = []
    for line in r.stderr.decode().splitlines():
        m = re.match(r"\[(\w+)\] (.*)$", line)
        if m: logs.append("%s: %s" % (m.group(1), m.group(2)))
        else: logs.append("RAW: " + line)
    if r.stdout.strip():
        logs.append("STDOUT: " + r.stdout.decode().strip())
    return logs, _read(st), _read(sc)

def _read(p):
    if not os.path.exists(p): return None
    return re.sub(r"updated=.*", "updated=<ts>", open(p).read())

SCENARIOS = [
    ("first run, no state",        dict(total_bytes=1073741824), None, None),
    ("below threshold",            dict(total_bytes=1073741824), "baseline_mb=900.00\nupdated=x\n", None),
    ("threshold reached",          dict(total_bytes=1073741824), "baseline_mb=100.00\nupdated=x\n", None),
    ("exactly at threshold",       dict(total_bytes=1024*1024*900), "baseline_mb=100.00\nupdated=x\n", None),
    ("counter reset detected",     dict(total_bytes=1024*1024*50), "baseline_mb=900.00\nupdated=x\n", None),
    ("router rejects sms",         dict(total_bytes=1073741824, sms_error=4), "baseline_mb=100.00\nupdated=x\n", None),
    ("router rejects first sms",   dict(total_bytes=1073741824, sms_error=4), None, None),
    ("no sim slots",               dict(slots=False), "baseline_mb=100.00\nupdated=x\n", None),
    ("daily limit reached",        dict(total_bytes=1073741824), "baseline_mb=100.00\nupdated=x\n", None),
    ("fractional usage",           dict(total_bytes=1234567891), "baseline_mb=123.45\nupdated=x\n", None),
]

import datetime
today = datetime.date.today().strftime("%Y-%m-%d")
fails = 0
for name, knobs, state, sms in SCENARIOS:
    SCENARIO.update(total_bytes=1073741824, sms_error=0, slots=True)
    SCENARIO.update(knobs)
    if name == "daily limit reached":
        sms = "date=%s\ncount=30\n" % today
    else:
        sms = "date=%s\ncount=3\n" % today

    reset_session(); pl, pst, psc = run_python("py", state, sms)
    perr = H.session.get("error")
    reset_session(); sl, sst, ssc = run_shell("sh", state, sms)
    serr = H.session.get("error")

    ok = (pl == sl) and (pst == sst) and (psc == ssc) and not perr and not serr
    fails += not ok
    print(("PASS  " if ok else "FAIL  ") + name)
    if not ok:
        print("   py log:", pl, "\n   sh log:", sl)
        print("   py state:", repr(pst), " sh state:", repr(sst))
        print("   py sms:", repr(psc), " sh sms:", repr(ssc))
        if perr: print("   mock error (python run):", perr)
        if serr: print("   mock error (shell run):", serr)
    else:
        print("      ", sl[0] if sl else "(silent)")

shutil.rmtree(WORK, ignore_errors=True)
print("\nTOTAL FAILURES:", fails)
sys.exit(1 if fails else 0)
