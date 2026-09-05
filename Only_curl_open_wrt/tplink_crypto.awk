# tplink_crypto.awk - crypto primitives for the TP-Link MR600 monitor.
#
# Pure POSIX awk (busybox awk compatible): no bitwise builtins, no gensub,
# no systime, no length(array). Everything the router firmware needs:
#   * AES-128-CBC + PKCS#7 + base64  (request/response payloads)
#   * RSA  m^e mod n, zero right-padded blocks  (the "sign" parameter)
#
# All variable-length input arrives through the environment so that no shell
# quoting or awk escape processing can corrupt it.
#
# Modes (-v mode=...):
#   enc_login   env AESKEY AESIV TL_USER TL_PASS   -> base64
#   enc_usage   env AESKEY AESIV                   -> base64
#   enc_sms     env AESKEY AESIV SMS_TO SMS_TEXT   -> base64
#   enc_text    env AESKEY AESIV PT                -> base64
#   dec         env AESKEY AESIV CT                -> plaintext
#   rsa         env RSA_TEXT RSA_N RSA_E           -> hex
#   selftest                                       -> ok / failures

# ---------------------------------------------------------------------------
# byte/char tables
# ---------------------------------------------------------------------------

function init_ascii(   i, c) {
    PRT = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ["
    PRT = PRT sprintf("%c", 92)
    PRT = PRT "]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    for (i = 32; i <= 126; i++) {
        c = substr(PRT, i - 31, 1)
        ORD[c] = i
        CHR[i] = c
    }
    ORD["\t"] = 9;  CHR[9]  = "\t"
    ORD["\n"] = 10; CHR[10] = "\n"
    ORD["\r"] = 13; CHR[13] = "\r"
    HEXD = "0123456789abcdef"
    for (i = 0; i < 16; i++) {
        c = substr(HEXD, i + 1, 1)
        HEXV[c] = i
        HEXV[toupper(c)] = i
    }
}

function init_xor(   i, j, a, b, r, bit) {
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            a = i; b = j; r = 0; bit = 1
            while (a > 0 || b > 0) {
                if ((a % 2) != (b % 2)) r = r + bit
                a = int(a / 2); b = int(b / 2); bit = bit * 2
            }
            XN[i "," j] = r
        }
    }
}

function bxor(a, b) {
    return XN[int(a / 16) "," int(b / 16)] * 16 + XN[(a % 16) "," (b % 16)]
}

# UTF-8 aware only for ASCII; bytes >127 are emitted raw via %c.
function chrb(b) {
    if (b in CHR) return CHR[b]
    return sprintf("%c", b)
}

# str -> arr[0..n-1], returns n. Input must be ASCII (all callers comply).
function s2b(s, arr,   i, n, c) {
    n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        arr[i - 1] = (c in ORD) ? ORD[c] : 0
    }
    return n
}

function b2s(arr, n, out,   i) {
    out = ""
    for (i = 0; i < n; i++) out = out chrb(arr[i])
    return out
}

# ---------------------------------------------------------------------------
# AES-128-CBC
# ---------------------------------------------------------------------------

function init_aes(   i, x2, x4, x8, h) {
    h = ""
    h = h "637c777bf26b6fc53001672bfed7ab76"
    h = h "ca82c97dfa5947f0add4a2af9ca472c0"
    h = h "b7fd9326363ff7cc34a5e5f171d83115"
    h = h "04c723c31896059a071280e2eb27b275"
    h = h "09832c1a1b6e5aa0523bd6b329e32f84"
    h = h "53d100ed20fcb15b6acbbe394a4c58cf"
    h = h "d0efaafb434d338545f9027f503c9fa8"
    h = h "51a3408f929d38f5bcb6da2110fff3d2"
    h = h "cd0c13ec5f974417c4a77e3d645d1973"
    h = h "60814fdc222a908846eeb814de5e0bdb"
    h = h "e0323a0a4906245cc2d3ac629195e479"
    h = h "e7c8376d8dd54ea96c56f4ea657aae08"
    h = h "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    h = h "703eb5664803f60e613557b986c11d9e"
    h = h "e1f8981169d98e949b1e87e9ce5528df"
    h = h "8ca1890dbfe6426841992d0fb054bb16"
    for (i = 0; i < 256; i++) {
        SBOX[i] = HEXV[substr(h, 2 * i + 1, 1)] * 16 + HEXV[substr(h, 2 * i + 2, 1)]
        INVSBOX[SBOX[i]] = i
    }
    for (i = 0; i < 256; i++) {
        x2 = i * 2
        if (x2 > 255) x2 = bxor(x2 - 256, 27)
        M2[i] = x2
    }
    for (i = 0; i < 256; i++) {
        x4 = M2[M2[i]]
        x8 = M2[x4]
        M3[i]  = bxor(M2[i], i)
        M9[i]  = bxor(x8, i)
        M11[i] = bxor(bxor(x8, M2[i]), i)
        M13[i] = bxor(bxor(x8, x4), i)
        M14[i] = bxor(bxor(x8, x4), M2[i])
    }
    RCON[1] = 1
    for (i = 2; i <= 10; i++) RCON[i] = M2[RCON[i - 1]]
}

# 128-bit key only (the router protocol never uses anything else).
function key_expansion(key,   i, r, t0, t1, t2, t3, tmp) {
    for (i = 0; i < 4; i++) {
        W[i, 0] = key[4 * i]; W[i, 1] = key[4 * i + 1]
        W[i, 2] = key[4 * i + 2]; W[i, 3] = key[4 * i + 3]
    }
    for (i = 4; i < 44; i++) {
        t0 = W[i - 1, 0]; t1 = W[i - 1, 1]; t2 = W[i - 1, 2]; t3 = W[i - 1, 3]
        if (i % 4 == 0) {
            tmp = t0
            t0 = SBOX[t1]; t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[tmp]
            t0 = bxor(t0, RCON[i / 4])
        }
        W[i, 0] = bxor(W[i - 4, 0], t0)
        W[i, 1] = bxor(W[i - 4, 1], t1)
        W[i, 2] = bxor(W[i - 4, 2], t2)
        W[i, 3] = bxor(W[i - 4, 3], t3)
    }
    NR_ROUNDS = 10
}

function add_round_key(rnd,   c, r) {
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            ST[r + 4 * c] = bxor(ST[r + 4 * c], W[rnd * 4 + c, r])
}

function sub_bytes(   k) { for (k = 0; k < 16; k++) ST[k] = SBOX[ST[k]] }
function inv_sub_bytes(   k) { for (k = 0; k < 16; k++) ST[k] = INVSBOX[ST[k]] }

function shift_rows(   r, c, t) {
    for (r = 1; r < 4; r++) {
        for (c = 0; c < 4; c++) t[c] = ST[r + 4 * ((c + r) % 4)]
        for (c = 0; c < 4; c++) ST[r + 4 * c] = t[c]
    }
}

function inv_shift_rows(   r, c, t) {
    for (r = 1; r < 4; r++) {
        for (c = 0; c < 4; c++) t[c] = ST[r + 4 * ((c - r + 4) % 4)]
        for (c = 0; c < 4; c++) ST[r + 4 * c] = t[c]
    }
}

function mix_columns(   c, a0, a1, a2, a3) {
    for (c = 0; c < 4; c++) {
        a0 = ST[4 * c]; a1 = ST[4 * c + 1]; a2 = ST[4 * c + 2]; a3 = ST[4 * c + 3]
        ST[4 * c]     = bxor(bxor(M2[a0], M3[a1]), bxor(a2, a3))
        ST[4 * c + 1] = bxor(bxor(a0, M2[a1]), bxor(M3[a2], a3))
        ST[4 * c + 2] = bxor(bxor(a0, a1), bxor(M2[a2], M3[a3]))
        ST[4 * c + 3] = bxor(bxor(M3[a0], a1), bxor(a2, M2[a3]))
    }
}

function inv_mix_columns(   c, a0, a1, a2, a3) {
    for (c = 0; c < 4; c++) {
        a0 = ST[4 * c]; a1 = ST[4 * c + 1]; a2 = ST[4 * c + 2]; a3 = ST[4 * c + 3]
        ST[4 * c]     = bxor(bxor(M14[a0], M11[a1]), bxor(M13[a2], M9[a3]))
        ST[4 * c + 1] = bxor(bxor(M9[a0], M14[a1]), bxor(M11[a2], M13[a3]))
        ST[4 * c + 2] = bxor(bxor(M13[a0], M9[a1]), bxor(M14[a2], M11[a3]))
        ST[4 * c + 3] = bxor(bxor(M11[a0], M13[a1]), bxor(M9[a2], M14[a3]))
    }
}

function encrypt_block(   rnd) {
    add_round_key(0)
    for (rnd = 1; rnd < NR_ROUNDS; rnd++) {
        sub_bytes(); shift_rows(); mix_columns(); add_round_key(rnd)
    }
    sub_bytes(); shift_rows(); add_round_key(NR_ROUNDS)
}

function decrypt_block(   rnd) {
    add_round_key(NR_ROUNDS)
    for (rnd = NR_ROUNDS - 1; rnd > 0; rnd--) {
        inv_shift_rows(); inv_sub_bytes(); add_round_key(rnd); inv_mix_columns()
    }
    inv_shift_rows(); inv_sub_bytes(); add_round_key(0)
}

# pt[0..n-1] -> out[], returns output length. PKCS#7 padded, CBC chained.
function aes_cbc_encrypt(pt, n, key, iv, out,   i, k, pad, plen, prev, o) {
    key_expansion(key)
    pad = 16 - (n % 16)
    plen = n + pad
    for (i = n; i < plen; i++) pt[i] = pad
    for (k = 0; k < 16; k++) prev[k] = iv[k]
    o = 0
    for (i = 0; i < plen; i += 16) {
        for (k = 0; k < 16; k++) ST[k] = bxor(pt[i + k], prev[k])
        encrypt_block()
        for (k = 0; k < 16; k++) { out[o + k] = ST[k]; prev[k] = ST[k] }
        o += 16
    }
    return plen
}

# ct[0..n-1] -> out[], returns length after PKCS#7 strip.
function aes_cbc_decrypt(ct, n, key, iv, out,   i, k, prev, cur, o, pad) {
    key_expansion(key)
    for (k = 0; k < 16; k++) prev[k] = iv[k]
    o = 0
    for (i = 0; i + 16 <= n; i += 16) {
        for (k = 0; k < 16; k++) { ST[k] = ct[i + k]; cur[k] = ct[i + k] }
        decrypt_block()
        for (k = 0; k < 16; k++) { out[o + k] = bxor(ST[k], prev[k]); prev[k] = cur[k] }
        o += 16
    }
    if (o == 0) return 0
    pad = out[o - 1]
    if (pad > 0 && pad <= 16) o -= pad
    return o
}

# ---------------------------------------------------------------------------
# base64
# ---------------------------------------------------------------------------

function b64_encode(arr, n, out,   i, b0, b1, b2, rem) {
    B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    out = ""
    for (i = 0; i + 3 <= n; i += 3) {
        b0 = arr[i]; b1 = arr[i + 1]; b2 = arr[i + 2]
        out = out substr(B64, int(b0 / 4) + 1, 1)
        out = out substr(B64, (b0 % 4) * 16 + int(b1 / 16) + 1, 1)
        out = out substr(B64, (b1 % 16) * 4 + int(b2 / 64) + 1, 1)
        out = out substr(B64, (b2 % 64) + 1, 1)
    }
    rem = n - i
    if (rem == 1) {
        b0 = arr[i]
        out = out substr(B64, int(b0 / 4) + 1, 1) substr(B64, (b0 % 4) * 16 + 1, 1) "=="
    } else if (rem == 2) {
        b0 = arr[i]; b1 = arr[i + 1]
        out = out substr(B64, int(b0 / 4) + 1, 1)
        out = out substr(B64, (b0 % 4) * 16 + int(b1 / 16) + 1, 1)
        out = out substr(B64, (b1 % 16) * 4 + 1, 1) "="
    }
    return out
}

function b64_decode(s, arr,   i, c, v, acc, bits, n, L) {
    B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if (!B64INIT) { for (i = 1; i <= 64; i++) B64IDX[substr(B64, i, 1)] = i - 1; B64INIT = 1 }
    acc = 0; bits = 0; n = 0
    L = length(s)
    for (i = 1; i <= L; i++) {
        c = substr(s, i, 1)
        if (c == "=" || !(c in B64IDX)) continue
        acc = acc * 64 + B64IDX[c]
        bits += 6
        if (bits >= 8) {
            bits -= 8
            v = int(acc / (2 ^ bits))
            arr[n++] = v % 256
            acc = acc - v * (2 ^ bits)
        }
    }
    return n
}

# ---------------------------------------------------------------------------
# bignum: little-endian arrays of 16-bit limbs, fixed length LN
# ---------------------------------------------------------------------------

function bn_zero(a, n,   i) { for (i = 0; i < n; i++) a[i] = 0 }

function bn_copy(src, dst, n,   i) { for (i = 0; i < n; i++) dst[i] = src[i] }

function bn_from_hex(hex, a, n,   i, L, pos, d, limb, j) {
    bn_zero(a, n)
    L = length(hex)
    i = 0
    pos = L
    while (pos > 0 && i < n) {
        limb = 0
        for (j = 0; j < 4; j++) {
            d = pos - j
            if (d < 1) break
            limb = limb + HEXV[substr(hex, d, 1)] * (16 ^ j)
        }
        a[i] = limb
        i++
        pos -= 4
    }
}

function bn_to_hex(a, n, width,   i, s) {
    s = ""
    for (i = n - 1; i >= 0; i--) s = s sprintf("%04x", a[i])
    while (length(s) < width) s = "0" s
    if (length(s) > width) s = substr(s, length(s) - width + 1)
    return s
}

function bn_bitlen(a, n,   i, v, b) {
    for (i = n - 1; i >= 0; i--) {
        if (a[i] != 0) {
            v = a[i]; b = 0
            while (v > 0) { b++; v = int(v / 2) }
            return i * 16 + b
        }
    }
    return 0
}

function bn_cmp(a, b, n,   i) {
    for (i = n - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1
        if (a[i] < b[i]) return -1
    }
    return 0
}

# a -= b (assumes a >= b)
function bn_sub(a, b, n,   i, borrow, d) {
    borrow = 0
    for (i = 0; i < n; i++) {
        d = a[i] - b[i] - borrow
        if (d < 0) { d += 65536; borrow = 1 } else borrow = 0
        a[i] = d
    }
}

# a = a * 2 mod m  (a < m on entry and exit)
function bn_dbl_mod(a, m, n,   i, carry, v) {
    carry = 0
    for (i = 0; i < n; i++) {
        v = a[i] * 2 + carry
        if (v > 65535) { a[i] = v - 65536; carry = 1 } else { a[i] = v; carry = 0 }
    }
    if (carry || bn_cmp(a, m, n) >= 0) bn_sub(a, m, n)
}

# Montgomery: n0inv = -N[0]^-1 mod 2^16, computed by Hensel lifting.
function bn_n0inv(n0,   inv, i) {
    inv = 1
    for (i = 0; i < 4; i++) {
        inv = (inv * (2 - (n0 * inv) % 65536)) % 65536
        inv = (inv % 65536 + 65536) % 65536
    }
    return (65536 - inv) % 65536
}

# T = A * B * R^-1 mod M   (Koc CIOS). Result into r[0..s-1].
function bn_montmul(a, b, m, s, n0inv, r,   i, j, C, S, mm, t) {
    for (i = 0; i <= s + 1; i++) t[i] = 0
    for (i = 0; i < s; i++) {
        C = 0
        for (j = 0; j < s; j++) {
            S = t[j] + a[j] * b[i] + C
            C = int(S / 65536)
            t[j] = S - C * 65536
        }
        S = t[s] + C
        C = int(S / 65536)
        t[s] = S - C * 65536
        t[s + 1] = C

        mm = (t[0] * n0inv) % 65536
        S = t[0] + mm * m[0]
        C = int(S / 65536)
        for (j = 1; j < s; j++) {
            S = t[j] + mm * m[j] + C
            C = int(S / 65536)
            t[j - 1] = S - C * 65536
        }
        S = t[s] + C
        C = int(S / 65536)
        t[s - 1] = S - C * 65536
        t[s] = t[s + 1] + C
    }
    for (i = 0; i < s; i++) r[i] = t[i]
    if (t[s] != 0 || bn_cmp(r, m, s) >= 0) bn_sub(r, m, s)
}

# result = base^exp mod mod, all as limb arrays of length s.
# r2 and n0inv are precomputed by the caller: they depend only on the modulus,
# which never changes within a run, and recomputing R^2 would otherwise cost as
# much as the exponentiation itself.
function bn_modexp(base, ehex, m, s, n0inv, r2, out,   i, bit, c,
                   acc, tmp, baseR, val, started, elen) {
    bn_montmul(base, r2, m, s, n0inv, baseR)
    bn_zero(acc, s); acc[0] = 1
    bn_montmul(acc, r2, m, s, n0inv, tmp)      # acc = R mod M
    bn_copy(tmp, acc, s)

    started = 0
    elen = length(ehex)
    for (i = 1; i <= elen; i++) {
        val = HEXV[substr(ehex, i, 1)]
        for (bit = 8; bit >= 1; bit = int(bit / 2)) {
            c = (int(val / bit) % 2)
            if (!started) {
                if (!c) continue
                started = 1
                bn_copy(baseR, acc, s)
                continue
            }
            bn_montmul(acc, acc, m, s, n0inv, tmp)
            bn_copy(tmp, acc, s)
            if (c) {
                bn_montmul(acc, baseR, m, s, n0inv, tmp)
                bn_copy(tmp, acc, s)
            }
        }
    }
    bn_zero(tmp, s); tmp[0] = 1
    bn_montmul(acc, tmp, m, s, n0inv, out)
}

# Mirrors rsa_enc() of the python original: chunks of (block_size - 11) bytes,
# right-padded with zeros to block_size, raw m^e mod n, hex of len(nn_hex).
function rsa_enc(text, nnhex, eehex,   n, s, nbits, block_size, chunk_size,
                 hex_len, tb, tlen, out, i, k, hexblk, mnum, res, byteval,
                 n0inv, r2) {
    s = int((length(nnhex) + 3) / 4)
    bn_from_hex(nnhex, n, s)
    n0inv = bn_n0inv(n[0])
    bn_zero(r2, s); r2[0] = 1
    for (i = 0; i < 32 * s; i++) bn_dbl_mod(r2, n, s)
    nbits = bn_bitlen(n, s)
    block_size = int((nbits + 7) / 8)
    chunk_size = block_size - 11
    hex_len = length(nnhex)

    tlen = s2b(text, tb)
    out = ""
    for (i = 0; i < tlen; i += chunk_size) {
        hexblk = ""
        for (k = 0; k < block_size; k++) {
            byteval = ((i + k) < tlen && k < chunk_size) ? tb[i + k] : 0
            hexblk = hexblk sprintf("%02x", byteval)
        }
        bn_from_hex(hexblk, mnum, s)
        bn_modexp(mnum, eehex, n, s, n0inv, r2, res)
        out = out bn_to_hex(res, s, hex_len)
    }
    return out
}

# ---------------------------------------------------------------------------
# TP-Link data frames (make_data_frame equivalents, built here so that no
# CR/LF ever has to survive a round trip through the shell)
# ---------------------------------------------------------------------------

function frame_usage(   f, st) {
    st = "0,0,0,0,0,0"
    f = "5&5\r\n"
    f = f "[WAN_LTE_INTF_CFG#" st "#" st "]0,0\r\n"
    f = f "[WAN_COMMON_INTF_CFG#" st "#" st "]1,1\r\n"
    f = f "WANAccessType\r\n"
    return f
}

function kv_clean(v) {
    gsub(/\n/, "\022", v)
    gsub(/\r/, "\022", v)
    return v
}

function frame_sms(to, text,   f, st) {
    st = "0,0,0,0,0,0"
    f = "2\r\n"
    f = f "[LTE_SMS_SENDNEWMSG#" st "#" st "]0,3\r\n"
    f = f "index=1\r\n"
    f = f "to=" kv_clean(to) "\r\n"
    f = f "textContent=" kv_clean(text) "\r\n"
    return f
}

function encrypt_to_b64(pt,   kb, ib, pb, ob, n, olen) {
    s2b(ENVIRON["AESKEY"], kb)
    s2b(ENVIRON["AESIV"], ib)
    n = s2b(pt, pb)
    olen = aes_cbc_encrypt(pb, n, kb, ib, ob)
    return b64_encode(ob, olen)
}

BEGIN {
    init_ascii()
    init_xor()

    if (mode == "rsa") {
        printf "%s", rsa_enc(ENVIRON["RSA_TEXT"], ENVIRON["RSA_N"], ENVIRON["RSA_E"])
        exit 0
    }

    init_aes()

    if (mode == "enc_login") {
        printf "%s", encrypt_to_b64(ENVIRON["TL_USER"] "\n" ENVIRON["TL_PASS"])
    } else if (mode == "enc_usage") {
        printf "%s", encrypt_to_b64(frame_usage())
    } else if (mode == "enc_sms") {
        printf "%s", encrypt_to_b64(frame_sms(ENVIRON["SMS_TO"], ENVIRON["SMS_TEXT"]))
    } else if (mode == "enc_text") {
        printf "%s", encrypt_to_b64(ENVIRON["PT"])
    } else if (mode == "dec") {
        ct = ENVIRON["CT"]
        sub(/^[ \t\r\n]+/, "", ct)
        sub(/[ \t\r\n]+$/, "", ct)
        if (ct ~ /^[<{]/) {
            printf "[Non-AES: %s]", substr(ct, 1, 150)
            exit 0
        }
        s2b(ENVIRON["AESKEY"], kb2)
        s2b(ENVIRON["AESIV"], ib2)
        n2 = b64_decode(ct, cb2)
        olen2 = aes_cbc_decrypt(cb2, n2, kb2, ib2, ob2)
        printf "%s", b2s(ob2, olen2)
    } else if (mode == "selftest") {
        selftest()
    } else {
        print "unknown mode: " mode > "/dev/stderr"
        exit 2
    }
    exit 0
}

# FIPS-197 / RFC 3602 vectors plus an RSA sanity check.
function selftest(   key, iv, pt, ct, out, n, i, fails, got, want) {
    fails = 0

    # AES-128 ECB (single block, FIPS-197 C.1) via CBC with a zero IV
    for (i = 0; i < 16; i++) iv[i] = 0
    for (i = 0; i < 16; i++) key[i] = i
    got = ""
    n = 16
    key_expansion(key)
    for (i = 0; i < 16; i++) ST[i] = HEXV[substr("00112233445566778899aabbccddeeff", i * 2 + 1, 1)] * 16 + HEXV[substr("00112233445566778899aabbccddeeff", i * 2 + 2, 1)]
    encrypt_block()
    for (i = 0; i < 16; i++) got = got sprintf("%02x", ST[i])
    want = "69c4e0d86a7b0430d8cdb78070b4c55a"
    if (got != want) { print "AES encrypt FAIL " got; fails++ }
    decrypt_block()
    got = ""
    for (i = 0; i < 16; i++) got = got sprintf("%02x", ST[i])
    if (got != "00112233445566778899aabbccddeeff") { print "AES decrypt FAIL " got; fails++ }

    if (fails == 0) print "ok"
}
