#!/bin/sh
# TP-Link MR600 v2 auto-refill monitor - busybox + curl only, no python.
# Behaviourally identical to mr600v2_refill_openwrt.py, including the state
# file formats, the syslog wording and the daily SMS cap.

# ============================================================================
# Configuration. Every setting may be overridden from the environment with a
# TPL_ prefix (TPL_ROUTER_IP, TPL_USERNAME, ...). The prefix matters: bare
# USERNAME/PASSWORD are commonly already set in a login shell and would
# silently replace the router credentials.
# ============================================================================

ROUTER_IP="${TPL_ROUTER_IP:-192.168.1.1}"
ROUTER_PORT="${TPL_ROUTER_PORT:-80}"
USERNAME="${TPL_USERNAME:-admin}"
PASSWORD="${TPL_PASSWORD:-admin}"

REFILL_NUMBER="${TPL_REFILL_NUMBER:-80808}"
REFILL_TEXT="${TPL_REFILL_TEXT:-Refill}"
THRESHOLD_MB="${TPL_THRESHOLD_MB:-800}"

STATE_FILE="${TPL_STATE_FILE:-/tmp/tplink_monitor.state}"
SMS_COUNTER_FILE="${TPL_SMS_COUNTER_FILE:-/tmp/tplink_sms_counter.state}"
MAX_SMS_PER_DAY="${TPL_MAX_SMS_PER_DAY:-30}"
LOCK_FILE="${TPL_LOCK_FILE:-/tmp/tplink_monitor.lock}"
LOCK_STALE_SEC=15
NET_TIMEOUT_SEC=5
MAX_ATTEMPTS=2
RETRY_DELAY_SEC=2

SYSLOG_TAG="tplink-monitor"

CRYPTO_AWK="${TPL_CRYPTO_AWK:-/root/tplink_crypto.awk}"
AWK="${TPL_AWK:-awk}"

USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

TMPDIR_RUN="/tmp/tplink_monitor.$$"
HDR_FILE="$TMPDIR_RUN.hdr"
BODY_FILE="$TMPDIR_RUN.body"
PLAIN_FILE="$TMPDIR_RUN.plain"
POST_FILE="$TMPDIR_RUN.post"
COOKIE_FILE="$TMPDIR_RUN.cookies"

# ============================================================================
# System log via busybox `logger`
# ============================================================================

syslog() {
    _lvl="$1"; _msg="$2"
    case "$_lvl" in
        info) _prio="daemon.info" ;;
        warning) _prio="daemon.warning" ;;
        err) _prio="daemon.err" ;;
        *) _prio="daemon.info" ;;
    esac
    logger -t "$SYSLOG_TAG" -p "$_prio" "$_msg" 2>/dev/null || \
        printf '[%s] %s\n' "$_lvl" "$_msg" >&2
}

cleanup_run_files() {
    rm -f "$HDR_FILE" "$BODY_FILE" "$PLAIN_FILE" "$POST_FILE" "$COOKIE_FILE"
}

# ============================================================================
# HTTP with the same cookie semantics as the python client: every cookie is
# kept by name and replayed on every request, regardless of path or domain.
# ============================================================================

cookie_header() {
    [ -s "$COOKIE_FILE" ] || return 0
    "$AWK" '{ if (NR > 1) printf "; "; printf "%s=%s", $1, substr($0, index($0, " " ) + 1) }' "$COOKIE_FILE"
}

absorb_cookies() {
    [ -s "$HDR_FILE" ] || return 0
    "$AWK" -v jar="$COOKIE_FILE" '
        BEGIN {
            n = 0
            while ((getline line < jar) > 0) {
                k = line; sub(/ .*/, "", k)
                v = substr(line, index(line, " ") + 1)
                if (!(k in seen)) { seen[k] = 1; order[++n] = k }
                val[k] = v
            }
            close(jar)
        }
        {
            line = $0
            sub(/\r$/, "", line)
            if (tolower(substr(line, 1, 11)) != "set-cookie:") next
            c = substr(line, 12)
            sub(/;.*/, "", c)
            sub(/^[ \t]+/, "", c); sub(/[ \t]+$/, "", c)
            p = index(c, "=")
            if (p == 0) next
            k = substr(c, 1, p - 1); v = substr(c, p + 1)
            sub(/^[ \t]+/, "", k); sub(/[ \t]+$/, "", k)
            sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
            if (!(k in seen)) { seen[k] = 1; order[++n] = k }
            val[k] = v
        }
        END {
            out = ""
            for (i = 1; i <= n; i++) out = out order[i] " " val[order[i]] "\n"
            printf "%s", out > jar
            close(jar)
        }
    ' "$HDR_FILE"
}

# http_get PATH ; http_post PATH [BODYFILE] [CONTENT_TYPE] [TOKENID]
# Body lands in $BODY_FILE, headers in $HDR_FILE. Returns curl's exit status.
http_request() {
    _method="$1"; _path="$2"; _bodyfile="$3"; _ctype="$4"; _token="$5"
    _cookie="$(cookie_header)"

    set -- -s -S -o "$BODY_FILE" -D "$HDR_FILE" \
        --connect-timeout "$NET_TIMEOUT_SEC" --max-time "$((NET_TIMEOUT_SEC * 3))" \
        -w '%{http_code}' \
        -A "$USER_AGENT" \
        -H "Accept: */*" \
        -H "Connection: close" \
        -H "Referer: http://$ROUTER_IP/"

    if [ -n "$_cookie" ]; then
        set -- "$@" -H "Cookie: $_cookie"
    fi
    if [ -n "$_token" ]; then
        set -- "$@" -H "TokenID: $_token"
    fi
    if [ -n "$_ctype" ]; then
        set -- "$@" -H "Content-Type: $_ctype"
    else
        set -- "$@" -H "Content-Type:"
    fi

    if [ "$_method" = "POST" ]; then
        if [ -n "$_bodyfile" ]; then
            set -- "$@" -X POST --data-binary "@$_bodyfile"
        else
            set -- "$@" -X POST --data-binary ""
        fi
    fi

    HTTP_STATUS="$(curl "$@" "http://$ROUTER_IP:$ROUTER_PORT$_path" 2>/dev/null)"
    _rc=$?
    absorb_cookies
    [ "$_rc" -eq 0 ] || return 1
    return 0
}

# ============================================================================
# TP-Link session
# ============================================================================

session_init() {
    HASH="$(printf '%s' "$USERNAME$PASSWORD" | md5sum | cut -d' ' -f1)"
    [ -n "$HASH" ] || return 1
    # str(int(time*1e6) + rand(0,999))[:16], same shape as the python client
    _now="$(date +%s)"
    _kv="$("$AWK" -v s="$_now" -v p="$$" 'BEGIN {
        srand(s + p)
        printf "%.0f %.0f", s * 1000000 + int(rand() * 1000), s * 1000000 + int(rand() * 1000)
    }')"
    KEY_STR="$(printf '%s' "${_kv% *}" | cut -c1-16)"
    IV_STR="$(printf '%s' "${_kv#* }" | cut -c1-16)"
    NN=""; EE=""; SEQ=0; TOKEN=""
    : > "$COOKIE_FILE"
}

get_parm() {
    http_request POST "/cgi/getParm" || return 1
    EE="$(sed -n 's/.*var ee="\([^"]*\)".*/\1/p' "$BODY_FILE" | head -1)"
    NN="$(sed -n 's/.*var nn="\([^"]*\)".*/\1/p' "$BODY_FILE" | head -1)"
    SEQ="$(sed -n 's/.*var seq="\{0,1\}\([0-9][0-9]*\)"\{0,1\};.*/\1/p' "$BODY_FILE" | head -1)"
    [ -n "$EE" ] && [ -n "$NN" ] && [ -n "$SEQ" ] || return 1
    return 0
}

rsa_sign() {
    RSA_TEXT="$1" RSA_N="$NN" RSA_E="$EE" "$AWK" -v mode=rsa -f "$CRYPTO_AWK" </dev/null
}

do_login() {
    get_parm || return 1

    _enc="$(AESKEY="$KEY_STR" AESIV="$IV_STR" TL_USER="$USERNAME" TL_PASS="$PASSWORD" \
            "$AWK" -v mode=enc_login -f "$CRYPTO_AWK" </dev/null)"
    [ -n "$_enc" ] || return 1

    _sign="$(rsa_sign "key=$KEY_STR&iv=$IV_STR&h=$HASH&s=$((SEQ + ${#_enc}))")"
    [ -n "$_sign" ] || return 1

    # escape only = and +, leave / alone (matches the python client exactly)
    _encurl="$(printf '%s' "$_enc" | sed -e 's/=/%3D/g' -e 's/+/%2B/g')"

    http_request POST "/cgi/login?data=$_encurl&sign=$_sign&Action=1&LoginStatus=0" || return 1
    grep -qF '$.ret=0' "$BODY_FILE" || return 1

    TOKEN=""
    for _p in "/" "/index.htm" "/main.htm"; do
        if http_request GET "$_p"; then
            TOKEN="$(sed -n \
                's/.*[Vv][Aa][Rr][ \t][ \t]*[Tt][Oo][Kk][Ee][Nn][ \t]*=[ \t]*"\([a-fA-F0-9][a-fA-F0-9]*\)".*/\1/p' \
                "$BODY_FILE" | head -1)"
            [ -n "$TOKEN" ] && break
        fi
    done
    [ -n "$TOKEN" ] || return 1
    return 0
}

# execute ENC_MODE [env assignments already exported by caller]
# Encrypts the frame produced by ENC_MODE, posts it to /cgi_gdpr and leaves the
# decrypted response in $PLAIN_FILE. Returns 1 on any transport-level failure,
# which is what the python code surfaces as an exception.
tp_execute() {
    _mode="$1"

    if [ -z "$TOKEN" ]; then
        do_login || return 1
    fi

    _enc="$(AESKEY="$KEY_STR" AESIV="$IV_STR" SMS_TO="$SMS_TO" SMS_TEXT="$SMS_TEXT" \
            "$AWK" -v mode="$_mode" -f "$CRYPTO_AWK" </dev/null)"
    [ -n "$_enc" ] || return 1

    _sign="$(rsa_sign "h=$HASH&s=$((SEQ + ${#_enc}))")"
    [ -n "$_sign" ] || return 1

    printf 'sign=%s\r\ndata=%s\r\n' "$_sign" "$_enc" > "$POST_FILE"

    http_request POST "/cgi_gdpr" "$POST_FILE" "text/plain" "$TOKEN" || return 1
    [ "$HTTP_STATUS" = "200" ] || return 1

    AESKEY="$KEY_STR" AESIV="$IV_STR" CT="$(cat "$BODY_FILE")" \
        "$AWK" -v mode=dec -f "$CRYPTO_AWK" </dev/null > "$PLAIN_FILE" || return 1
    return 0
}

# Parses the decrypted frame the way from_data_frame() does and prints
# "<error> <total_mb>"; total_mb is empty when no SIM slot was reported.
parse_usage() {
    "$AWK" '
        {
            line = $0
            sub(/\r$/, "", line)
            if (line ~ /^\[[0-9],[0-9],[0-9],[0-9],[0-9],[0-9]\][0-9]/) {
                nobj++; open = 1; has[nobj] = 0; next
            }
            if (line ~ /^\[error\][0-9]+$/) { err = substr(line, 8) + 0; open = 0; next }
            if (!open) next
            if (line ~ /^[a-zA-Z0-9]+=/) {
                p = index(line, "=")
                k = substr(line, 1, p - 1); v = substr(line, p + 1)
                if (k == "dailyFlow") { df[nobj] = v + 0; has[nobj] = 1 }
                else if (k == "totalStatistics") { ts[nobj] = v + 0 }
            }
        }
        END {
            best = -1
            for (i = 1; i <= nobj; i++) {
                if (!has[i]) continue
                if (best < 0 || df[i] > df[best]) best = i
            }
            if (best < 0) printf "%d \n", err
            else printf "%d %.2f\n", err, ts[best] / 1024 / 1024
        }
    ' "$PLAIN_FILE"
}

parse_error() {
    "$AWK" '
        { line = $0; sub(/\r$/, "", line)
          if (line ~ /^\[error\][0-9]+$/) { err = substr(line, 8) + 0 } }
        END { printf "%d\n", err }
    ' "$PLAIN_FILE"
}

# ============================================================================
# State management (/tmp) and locking
# ============================================================================

read_state() {
    [ -f "$STATE_FILE" ] || return 1
    _b="$(sed -n 's/.*baseline_mb=\([0-9][0-9.]*\).*/\1/p' "$STATE_FILE" | head -1)"
    [ -n "$_b" ] || return 1
    printf '%s' "$_b"
}

write_state() {
    "$AWK" -v b="$1" -v d="$(date +%Y-%m-%dT%H:%M:%S)" 'BEGIN {
        print "baseline_mb=" sprintf("%.2f", b)
        print "updated=" d
    }' > "$STATE_FILE.tmp"
    mv "$STATE_FILE.tmp" "$STATE_FILE"
}

# prints "<date> <count>"; date is empty when the file is missing or malformed
read_sms_counter() {
    _d=""; _c=0
    if [ -f "$SMS_COUNTER_FILE" ]; then
        _d="$(sed -n 's/.*date=\([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\).*/\1/p' "$SMS_COUNTER_FILE" | head -1)"
        _c="$(sed -n 's/.*count=\([0-9][0-9]*\).*/\1/p' "$SMS_COUNTER_FILE" | head -1)"
        if [ -z "$_d" ] || [ -z "$_c" ]; then _d=""; _c=0; fi
    fi
    printf '%s %s' "$_d" "$_c"
}

write_sms_counter() {
    printf 'date=%s\ncount=%s\n' "$1" "$2" > "$SMS_COUNTER_FILE.tmp"
    mv "$SMS_COUNTER_FILE.tmp" "$SMS_COUNTER_FILE"
}

# returns 0 when an SMS may still be sent today
check_sms_limit() {
    _today="$(date +%Y-%m-%d)"
    set -- $(read_sms_counter)
    _saved="$1"; _count="${2:-0}"
    if [ "$_saved" != "$_today" ]; then
        write_sms_counter "$_today" 0
        return 0
    fi
    [ "$_count" -ge "$MAX_SMS_PER_DAY" ] && return 1
    return 0
}

increment_sms_counter() {
    _today="$(date +%Y-%m-%d)"
    set -- $(read_sms_counter)
    _saved="$1"; _count="${2:-0}"
    if [ "$_saved" != "$_today" ]; then
        write_sms_counter "$_today" 1
    else
        write_sms_counter "$_today" "$((_count + 1))"
    fi
}

sms_count_today() {
    set -- $(read_sms_counter)
    printf '%s' "${2:-0}"
}

file_age_sec() {
    _mt="$(date -r "$1" +%s 2>/dev/null)" || _mt=""
    [ -n "$_mt" ] || _mt="$(stat -c %Y "$1" 2>/dev/null)"
    if [ -n "$_mt" ]; then
        printf '%s' "$(( $(date +%s) - _mt ))"
        return 0
    fi
    # Neither `date -r` nor `stat` in this busybox: fall back to find's minute
    # granularity, so a crashed run can still never deadlock us forever.
    if find "$1" -mmin +1 2>/dev/null | grep -q . ; then
        printf '%s' "61"
        return 0
    fi
    printf '%s' "0"
    return 0
}

lock_create() {
    (set -C; printf '%s' "$$" > "$LOCK_FILE") 2>/dev/null
}

acquire_lock() {
    lock_create && return 0
    _age="$(file_age_sec "$LOCK_FILE")" || return 1
    if [ "$_age" -gt "$LOCK_STALE_SEC" ]; then
        rm -f "$LOCK_FILE" 2>/dev/null
        lock_create && return 0
    fi
    return 1
}

release_lock() {
    rm -f "$LOCK_FILE" 2>/dev/null
}

# fcmp A OP B  -> exit status 0 when true (float aware)
fcmp() {
    "$AWK" -v a="$1" -v b="$3" -v op="$2" 'BEGIN {
        if (op == "lt") r = (a < b)
        else if (op == "ge") r = (a >= b)
        else r = 0
        exit r ? 0 : 1
    }'
}

fsub() { "$AWK" -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", a - b }'; }
ffmt() { "$AWK" -v a="$1" 'BEGIN { printf "%.2f", a }'; }

# ============================================================================
# Retry wrappers (MAX_ATTEMPTS tries, RETRY_DELAY_SEC apart)
# ============================================================================

try_get_usage() {
    _attempt=1
    while [ "$_attempt" -le "$MAX_ATTEMPTS" ]; do
        LAST_ERR=""
        if tp_execute enc_usage; then
            set -- $(parse_usage)
            _err="$1"; _mb="$2"
            if [ -n "$_mb" ]; then
                USAGE_MB="$_mb"
                return 0
            fi
            LAST_ERR="No SIM statistics found in WAN_LTE_INTF_CFG response"
        else
            LAST_ERR="router request failed (HTTP status ${HTTP_STATUS:-none})"
            TOKEN=""
        fi
        _attempt=$((_attempt + 1))
        [ "$_attempt" -le "$MAX_ATTEMPTS" ] && sleep "$RETRY_DELAY_SEC"
    done
    return 1
}

# sets SMS_ERRCODE; returns 1 only on transport failure (python's exception path)
try_send_sms() {
    SMS_TO="$REFILL_NUMBER"
    SMS_TEXT="$REFILL_TEXT"
    _attempt=1
    while [ "$_attempt" -le "$MAX_ATTEMPTS" ]; do
        LAST_ERR=""
        if tp_execute enc_sms; then
            SMS_ERRCODE="$(parse_error)"
            return 0
        fi
        LAST_ERR="router request failed (HTTP status ${HTTP_STATUS:-none})"
        TOKEN=""
        _attempt=$((_attempt + 1))
        [ "$_attempt" -le "$MAX_ATTEMPTS" ] && sleep "$RETRY_DELAY_SEC"
    done
    return 1
}

# ============================================================================
# Main entry point
# ============================================================================

main() {
    acquire_lock || exit 0
    trap 'release_lock; cleanup_run_files' EXIT INT TERM

    if ! check_sms_limit; then
        syslog warning "Daily SMS limit reached ($(sms_count_today)/$MAX_SMS_PER_DAY). Skipping this run."
        return 0
    fi

    session_init || { syslog err "Unexpected error: cannot initialise session (md5sum/awk missing?)"; return 0; }

    if ! try_get_usage; then
        syslog err "get usage failed after $MAX_ATTEMPTS attempts: $LAST_ERR"
        return 0
    fi
    current_mb="$USAGE_MB"

    if ! baseline_mb="$(read_state)"; then
        if ! try_send_sms; then
            syslog err "send initial SMS failed after $MAX_ATTEMPTS attempts: $LAST_ERR"
            return 0
        fi
        if [ "$SMS_ERRCODE" != "0" ]; then
            syslog err "First run: router rejected Refill SMS (error != 0). Not counted, baseline not set, will retry next run."
            return 0
        fi
        increment_sms_counter
        write_state "$current_mb"
        syslog info "First run: initial Refill SMS sent. Total used=$(ffmt "$current_mb") MB, baseline set."
        return 0
    fi

    if fcmp "$current_mb" lt "$baseline_mb"; then
        syslog info "Counter reset detected: $(ffmt "$baseline_mb") MB -> $(ffmt "$current_mb") MB. Baseline updated, no SMS sent."
        write_state "$current_mb"
        return 0
    fi

    used_since_refill="$(fsub "$current_mb" "$baseline_mb")"

    if fcmp "$used_since_refill" ge "$THRESHOLD_MB"; then
        if ! try_send_sms; then
            syslog err "send Refill SMS failed after $MAX_ATTEMPTS attempts: $LAST_ERR. Used $used_since_refill MB (threshold $THRESHOLD_MB MB), baseline NOT reset, will retry next run."
            return 0
        fi
        if [ "$SMS_ERRCODE" != "0" ]; then
            syslog err "Router rejected Refill SMS (error != 0). Used $used_since_refill MB (threshold $THRESHOLD_MB MB), not counted, baseline NOT reset, will retry next run."
            return 0
        fi
        increment_sms_counter
        write_state "$current_mb"
        syslog info "Threshold reached ($used_since_refill MB >= $THRESHOLD_MB MB). Refill SMS sent, baseline reset to $(ffmt "$current_mb") MB. SMS today: $(sms_count_today)/$MAX_SMS_PER_DAY."
    else
        syslog info "Total used=$(ffmt "$current_mb") MB, used since last Refill=$used_since_refill MB (threshold $THRESHOLD_MB MB). No action."
    fi
    return 0
}

main "$@"
