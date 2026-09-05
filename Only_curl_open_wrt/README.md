# MR600 v2 auto-refill — busybox + curl port

A drop-in replacement for `mr600v2_refill_openwrt.py` for routers where
`python3-light` cannot be installed. It uses nothing but what OpenWrt already
ships — busybox (`ash`, `awk`, `md5sum`, `logger`, `date`, `sed`, `grep`) — plus
`curl`.

## Files

| File | Role |
|---|---|
| `tplink_crypto.awk` | AES-128-CBC, PKCS#7, base64 and RSA `m^e mod n`, in pure POSIX awk |
| `tplink_router_monitor.sh` | The monitor itself: HTTP via curl, frame parsing, state, locking, syslog |
| `console_init.sh` | Generated installer — paste into the router console |
| `make_console_init.sh` | Regenerates `console_init.sh` from the two sources |
| `tests/` | Parity tests against the python original (run on a PC, not the router) |

## Install

Paste `console_init.sh` into the router shell. It writes the two files plus the
`tplink_auto_refill.sh` wrapper to `/root`, runs a crypto selftest against this
device's own awk, and only then installs the one-minute cron entry. If the
selftest fails nothing is scheduled.

After editing `tplink_crypto.awk` or `tplink_router_monitor.sh`, run
`sh make_console_init.sh` so the installer matches the sources.

## What replaces what

| Python original | Here |
|---|---|
| `hashlib.md5` / pure-python MD5 | `md5sum` |
| pure-python AES-128-CBC | `tplink_crypto.awk` |
| `pow(m, e, n)` on ints | Montgomery modexp on 16-bit limbs in awk |
| raw sockets, manual `Set-Cookie` and chunked decoding | `curl`, with the same "replay every cookie by name" policy |
| `make_data_frame` / `from_data_frame` | frames built inside awk, responses parsed by awk |
| `/tmp` state, daily SMS cap, `O_EXCL` lock, retries, `logger` | the same, in `ash` |

State file formats (`/tmp/tplink_monitor.state`,
`/tmp/tplink_sms_counter.state`), the daily cap, the lock semantics and every
syslog message are byte-identical to the python version, so the two can be
swapped in either direction without resetting the baseline.

## Configuration

Edit the block at the top of `tplink_router_monitor.sh`. Every setting can also
be overridden from the environment using a `TPL_` prefix
(`TPL_ROUTER_IP`, `TPL_USERNAME`, `TPL_THRESHOLD_MB`, ...). The prefix is not
cosmetic: bare `USERNAME` and `PASSWORD` are frequently already set in a login
shell and would otherwise silently replace the router credentials.

## Tests

Run from the repository root, on a PC with python3 and awk:

```sh
python Only_curl_open_wrt/tests/xtest.py     # awk crypto vs the python crypto
python Only_curl_open_wrt/tests/e2e.py       # both implementations vs a mock router
python Only_curl_open_wrt/tests/locktest.py  # lock: stale, contended, released
```

`xtest.py` compares AES output, decryption round trips and RSA output against
the functions in `mr600v2_refill_openwrt.py` across several moduli, exponents
and message lengths. `e2e.py` stands up a fake MR600 web UI with a real RSA-512
keypair — it decrypts the `sign` parameter with the private key and the payload
with the session AES key, so the wire format is checked, not just the maths —
then runs the python original and the shell port through ten scenarios and
diffs their syslog output, state files and SMS counters.

`e2e.py` installs a socket guard that refuses any connection other than
`127.0.0.1`. Keep it: `TPLinkClient.__init__` binds `ROUTER_IP` as a default
argument at import time, so rebinding the module global is *not* enough to
redirect the python original away from the real router.

To check the port against a stricter awk than your system default:

```sh
printf '#!/bin/sh\nexec gawk --posix "$@"\n' > /tmp/posixawk; chmod +x /tmp/posixawk
TPL_AWK=/tmp/posixawk XTEST_AWK=/tmp/posixawk python Only_curl_open_wrt/tests/e2e.py
```

## Performance

The RSA work is the slow part: two signatures per run, each two 512-bit
exponentiations. On a desktop awk this is ~0.2 s; on an MT7621 with busybox awk
expect a few seconds, which still fits comfortably inside the one-minute cron
slot and the 30-second stagger used by the wrapper. `R^2 mod n` and `n0inv` are
computed once per modulus rather than per block — recomputing them would
roughly double the cost.

## Known differences

* Timeouts: the python client sets a 5 s timeout per socket operation; curl gets
  `--connect-timeout 5` and `--max-time 15`. A stalled transfer therefore fails
  slightly differently, never later.
* The text after `... failed after 2 attempts:` differs. The python version
  interpolates a python exception; this one reports the HTTP status or the
  parse failure. The level, prefix and the resulting behaviour are the same.
* `float()` on a malformed `dailyFlow`/`totalStatistics` zeroes both fields in
  python; awk zeroes only the malformed one. No firmware has been seen to send
  either.
