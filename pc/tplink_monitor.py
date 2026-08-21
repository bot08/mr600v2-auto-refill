#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tplink_monitor.py - MR600 traffic monitor.

Logic:
  1. Always sends an SMS "Refill" when the script starts (required first run).
  2. Then checks Total Used (totalStatistics) for the active SIM every 30 seconds;
      this is the same cumulative counter shown by the router admin panel.
  3. When usage since the last Refill reaches >= 800 MB, sends
      another SMS "Refill" and resets the baseline.
  4. If the counter "drops" (for example, after a billing-cycle reset),
      updates the baseline without sending an SMS.

Run:
    python tplink_monitor.py
Stop: Ctrl+C
"""

import time
import sys
from datetime import datetime

import tplink_lib
from tplink_lib import get_usage, send_sms

REFILL_NUMBER = "80808"
REFILL_TEXT = "Refill"
THRESHOLD_MB = 800
CHECK_INTERVAL_SEC = 30

MAX_RETRIES_PER_CHECK = 3


def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def force_relogin():
    """Clear the cached client; the next tplink_lib call will log in again."""
    tplink_lib._client = None


def get_total_used_mb() -> float:
    """Total Used (totalStatistics), the cumulative counter shown by the router admin panel.
    Unlike dailyFlow, it is not reset daily."""
    usage = get_usage()
    active = usage.get("active")
    if not active:
        raise RuntimeError("Could not determine the active SIM (no 'active' data)")
    return active["total_statistics_mb"]


def try_send_refill() -> bool:
    """Send Refill with retries and re-login after session failures."""
    for attempt in range(1, MAX_RETRIES_PER_CHECK + 1):
        try:
            ok = send_sms(REFILL_NUMBER, REFILL_TEXT)
            if ok:
                return True
            log(f"send_sms returned error != 0 (attempt {attempt})")
        except Exception as e:
            log(f"Error sending SMS (attempt {attempt}): {e}")
            force_relogin()
        time.sleep(3)
    return False


def try_get_total_used_mb():
    """Return total_statistics_mb, or None if all attempts fail."""
    for attempt in range(1, MAX_RETRIES_PER_CHECK + 1):
        try:
            return get_total_used_mb()
        except Exception as e:
            log(f"Error getting usage (attempt {attempt}): {e}")
            force_relogin()
            time.sleep(3)
    return None


def monitor():
    log("=== MR600 traffic monitor started ===")
    log(f"Threshold: {THRESHOLD_MB} MB, check interval: {CHECK_INTERVAL_SEC} sec")

    # --- Required first Refill ---
    log("Sending required first Refill...")
    if try_send_refill():
        log("First Refill sent")
    else:
        log("Could not send the first Refill after several attempts. Stopping.")
        sys.exit(1)

    baseline_mb = try_get_total_used_mb()
    if baseline_mb is None:
        log("Could not get the initial Total Used value. Stopping.")
        sys.exit(1)
    log(f"Baseline (Total Used): {baseline_mb:.2f} MB")

    while True:
        time.sleep(CHECK_INTERVAL_SEC)

        current_mb = try_get_total_used_mb()
        if current_mb is None:
            log("Skipping this check because of connection errors.")
            continue

        # The counter dropped, likely because of a new billing cycle or router reboot.
        if current_mb < baseline_mb:
            log(f"Counter reset detected: {baseline_mb:.2f} -> {current_mb:.2f} MB. Updating baseline.")
            baseline_mb = current_mb
            continue

        used = current_mb - baseline_mb
        log(f"Total Used={current_mb:.2f} MB, since last Refill: {used:.2f} MB")

        if used >= THRESHOLD_MB:
            log(f"Usage reached {used:.2f} MB (threshold {THRESHOLD_MB} MB), sending Refill...")
            if try_send_refill():
                log("Refill sent, resetting baseline")
                baseline_mb = current_mb
            else:
                log("Could not send Refill. Will retry on the next iteration "
                    "(baseline was not reset to avoid missing the threshold).")


if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        log("Stopped by user (Ctrl+C).")