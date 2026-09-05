import os as _os, sys as _sys
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_os.chdir(_ROOT)
_sys.path.insert(0, _os.path.join(_ROOT, "Only_curl_open_wrt", "tests"))
import os, subprocess, sys, tempfile, time, threading, re
import mockrouter
PORT = 8732
mockrouter.serve(PORT)
W = tempfile.mkdtemp(prefix="tpllock")
st, sc, lk = (os.path.join(W, n) for n in ("state", "sms", "lock"))
open(sc, "w").write("date=2000-01-01\ncount=0\n")
open(st, "w").write("baseline_mb=100.00\nupdated=x\n")

def run():
    env = dict(os.environ)
    env.update(TPL_ROUTER_IP="127.0.0.1", TPL_ROUTER_PORT=str(PORT),
               TPL_STATE_FILE=st, TPL_SMS_COUNTER_FILE=sc, TPL_LOCK_FILE=lk,
               TPL_CRYPTO_AWK=os.path.abspath("Only_curl_open_wrt/tplink_crypto.awk"))
    return subprocess.run(["sh", "Only_curl_open_wrt/tplink_router_monitor.sh"],
                          capture_output=True, env=env, stdin=subprocess.DEVNULL)

fails = 0
# 1) a fresh lock held by someone else must make the run a silent no-op
open(lk, "w").write("99999")
r = run()
ok = r.stderr.strip() == b"" and not os.path.exists(st + ".tmp")
print(("PASS " if ok else "FAIL ") + "fresh lock -> silent skip", r.stderr[:200])
fails += not ok
ok = os.path.exists(lk)
print(("PASS " if ok else "FAIL ") + "someone else's lock left intact")
fails += not ok

# 2) a stale lock (> LOCK_STALE_SEC) must be broken and the run must proceed
old = time.time() - 60
os.utime(lk, (old, old))
r = run()
out = r.stderr.decode()
ok = "Refill SMS sent" in out or "No action" in out
print(("PASS " if ok else "FAIL ") + "stale lock -> broken and run proceeds", out.strip()[:120])
fails += not ok
ok = not os.path.exists(lk)
print(("PASS " if ok else "FAIL ") + "lock released on exit")
fails += not ok

# 3) two concurrent runs: exactly one does the work
os.remove(st) if os.path.exists(st) else None
open(st, "w").write("baseline_mb=100.00\nupdated=x\n")
res = {}
def worker(i):
    res[i] = run().stderr.decode()
ts = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
for t in ts: t.start()
for t in ts: t.join()
active = [v for v in res.values() if v.strip()]
ok = len(active) == 1
print(("PASS " if ok else "FAIL ") + "concurrent runs -> exactly one acts",
      [v.strip()[:70] for v in res.values()])
fails += not ok

# 4) no leftover scratch files in /tmp namespace
leftovers = [f for f in os.listdir(W) if f.endswith(".tmp") or "cookies" in f]
ok = not leftovers
print(("PASS " if ok else "FAIL ") + "no leftover temp files", leftovers)
fails += not ok

print("\nTOTAL FAILURES:", fails)
sys.exit(1 if fails else 0)
