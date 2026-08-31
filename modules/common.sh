#!/usr/bin/env bash
# =============================================================================
# common.sh — shared helpers: logging, config loading, curl wrapper, hashing
# Sourced by cachehunter.sh and every module. Not meant to be run directly.
# =============================================================================

# Guard against double-sourcing
if [[ -n "${__CACHEHUNTER_COMMON_LOADED:-}" ]]; then
    return 0 2>/dev/null || exit 0
fi
__CACHEHUNTER_COMMON_LOADED=1

# --- Colors (disabled if not a TTY) -----------------------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_INFO=$'\033[36m'; C_OK=$'\033[32m'
    C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_FIND=$'\033[35m'
else
    C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_FIND=""
fi

_ts() { date '+%Y-%m-%d %H:%M:%S'; }

log_info()   { printf '%s[INFO]%s  %s\n'    "$C_INFO" "$C_RESET" "$*" | tee -a "${LOG_FILE:-/dev/null}"; }
log_ok()     { printf '%s[OK]%s    %s\n'    "$C_OK"   "$C_RESET" "$*" | tee -a "${LOG_FILE:-/dev/null}"; }
log_warn()   { printf '%s[WARN]%s  %s\n'    "$C_WARN" "$C_RESET" "$*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_error()  { printf '%s[ERROR]%s %s\n'    "$C_ERR"  "$C_RESET" "$*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_finding(){ printf '%s[FINDING]%s %s\n'  "$C_FIND" "$C_RESET" "$*" | tee -a "${LOG_FILE:-/dev/null}"; }

# --- Dependency checking -----------------------------------------------------
# check_bin NAME DISPLAY_LABEL [OPTIONAL=0|1]
# Sets CACHEHUNTER_MISSING_REQUIRED=1 if a required tool is absent.
check_bin() {
    local bin="$1" label="$2" optional="${3:-0}"
    if command -v "$bin" >/dev/null 2>&1; then
        printf '[+] %-16s OK\n' "$label"
        return 0
    else
        if [[ "$optional" == "1" ]]; then
            printf '[!] %-16s not found — optional, related step will be skipped\n' "$label"
        else
            printf '[!] %-16s MISSING (required)\n' "$label"
            CACHEHUNTER_MISSING_REQUIRED=1
        fi
        return 1
    fi
}

# --- Hashing / small utils ---------------------------------------------------
sha256_of_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

sha256_of_string() {
    printf '%s' "$1" | { command -v sha256sum >/dev/null 2>&1 && sha256sum || shasum -a 256; } | awk '{print $1}'
}

random_token() {
    # short, harmless, URL-safe random token
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 6
    else
        head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-12
    fi
}

# csv_escape FIELD — wraps in quotes and escapes embedded quotes
csv_escape() {
    local s="$1"
    s="${s//\"/\"\"}"
    printf '"%s"' "$s"
}

ensure_dirs() {
    for d in "$@"; do mkdir -p "$d"; done
}

# --- curl wrapper -------------------------------------------------------------
# ch_curl METHOD URL [extra curl args...]
# Writes response body to stdout is avoided; instead returns via files for
# safety with binary bodies. Prints a single TSV metadata line to stdout:
# status\ttime_total\tsize_download\theaders_file\tbody_file
ch_curl() {
    local method="$1" url="$2"; shift 2
    local hdr_file body_file
    hdr_file="$(mktemp)"; body_file="$(mktemp)"
    local status time_total size_download

    # shellcheck disable=SC2086
    status=$(curl -s -o "$body_file" -D "$hdr_file" \
        -X "$method" \
        -A "${USER_AGENT:-CacheHunter/1.0}" \
        --max-time "${TIMEOUT:-10}" \
        --retry "${RETRIES:-2}" \
        -w '%{http_code}|%{time_total}|%{size_download}' \
        "$@" "$url" 2>>"${LOG_FILE:-/dev/null}") || true

    IFS='|' read -r http_code time_total size_download <<< "$status"
    printf '%s\t%s\t%s\t%s\t%s\n' "${http_code:-000}" "${time_total:-0}" "${size_download:-0}" "$hdr_file" "$body_file"
}

# get_header HEADERS_FILE NAME — case-insensitive header lookup
get_header() {
    local file="$1" name="$2"
    grep -i -m1 -E "^${name}:" "$file" 2>/dev/null | sed -E "s/^[^:]+:[[:space:]]*//I" | tr -d '\r'
}

sleep_delay() {
    local d="${REQUEST_DELAY:-0.5}"
    [[ "$d" != "0" ]] && sleep "$d" 2>/dev/null || true
}
