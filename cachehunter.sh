#!/usr/bin/env bash
# =============================================================================
# CacheHunter — Web Cache Security Automation Framework
# For AUTHORIZED bug-bounty programs, penetration tests, and labs only.
#
# Investigates: web-cache misconfiguration, cache-key inconsistencies, and
# potential web-cache poisoning. Never auto-labels a HIT/MISS transition as
# "vulnerable" — everything downstream of this script is evidence for a
# human to confirm manually.
# =============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR"

# --- Load modules -------------------------------------------------------
# shellcheck source=modules/common.sh
source "$SCRIPT_DIR/modules/common.sh"
# shellcheck source=modules/discovery.sh
source "$SCRIPT_DIR/modules/discovery.sh"
# shellcheck source=modules/cache-analysis.sh
source "$SCRIPT_DIR/modules/cache-analysis.sh"
# shellcheck source=modules/nuclei.sh
source "$SCRIPT_DIR/modules/nuclei.sh"
# shellcheck source=modules/wcvs.sh
source "$SCRIPT_DIR/modules/wcvs.sh"
# shellcheck source=modules/paramminer.sh
source "$SCRIPT_DIR/modules/paramminer.sh"
# shellcheck source=modules/reporting.sh
source "$SCRIPT_DIR/modules/reporting.sh"

# --- Load config ---------------------------------------------------------
CONFIG_FILE="$SCRIPT_DIR/config/config.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=config/config.conf
    source "$CONFIG_FILE"
fi

# --- Defaults / CLI state -------------------------------------------------
SINGLE_URL=""
TARGET_FILE=""
USER_TEMPLATES=()
OUTPUT_DIR="${OUTPUT_DIR:-output}"
LOG_DIR="${LOG_DIR:-logs}"
RESUME=0
PASSIVE_ONLY=0

usage() {
    cat <<'EOF'
Usage:

  ./cachehunter.sh -u <url>
  ./cachehunter.sh -l <file>
  ./cachehunter.sh -u <url> -t <nuclei-template>
  ./cachehunter.sh -l <file> -t <nuclei-template>
  ./cachehunter.sh -u <url> -t tmpl1.yaml -t tmpl2.yaml -t tmpl3.yaml
  ./cachehunter.sh -u <url> -t tmpl1.yaml,tmpl2.yaml,tmpl3.yaml

Options:
  -u <url>      Single target (e.g. https://target.example.com)
  -l <file>     Target/subdomain list, one per line
  -t <file>     User-provided Nuclei template (.yaml), run exactly as-is.
                Repeat -t for multiple templates, or pass a comma-separated
                list in one -t. All given templates run in the same Nuclei
                invocation.
  -o <dir>      Output directory (default: output)
  -c <n>        Concurrency (default: from config.conf)
  -d <seconds>  Delay between requests (default: from config.conf)
  --skip-katana
  --skip-gau
  --skip-wayback
  --skip-nuclei
  --skip-wcvs
  --skip-paramminer
  --passive-only     Discovery + baseline only; skip active differential/poisoning probes
  --resume           Reuse existing intermediate output instead of restarting
  --help             Show this help text

Notes:
  * -u and -l are mutually exclusive.
  * This tool is for AUTHORIZED testing only (bug bounty in-scope targets,
    pentests, CTFs, labs). See README.md before running against anything.
EOF
}

# --- Argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u) SINGLE_URL="$2"; shift 2 ;;
        -l) TARGET_FILE="$2"; shift 2 ;;
        -t)
            # Support comma-separated list in one -t AND repeated -t flags
            IFS=',' read -r -a _split_templates <<< "$2"
            USER_TEMPLATES+=("${_split_templates[@]}")
            shift 2
            ;;
        -o) OUTPUT_DIR="$2"; shift 2 ;;
        -c) CONCURRENCY="$2"; shift 2 ;;
        -d) REQUEST_DELAY="$2"; shift 2 ;;
        --skip-katana) USE_KATANA=false; shift ;;
        --skip-gau) USE_GAU=false; shift ;;
        --skip-wayback) USE_WAYBACK=false; shift ;;
        --skip-nuclei) USE_NUCLEI=false; shift ;;
        --skip-wcvs) USE_WCVS=false; shift ;;
        --skip-paramminer) USE_PARAMMINER=false; shift ;;
        --passive-only) PASSIVE_ONLY=1; shift ;;
        --resume) RESUME=1; shift ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -n "$SINGLE_URL" && -n "$TARGET_FILE" ]]; then
    echo "Error: -u and -l are mutually exclusive." >&2; exit 1
fi
if [[ -z "$SINGLE_URL" && -z "$TARGET_FILE" ]]; then
    usage; exit 1
fi
for _tmpl in "${USER_TEMPLATES[@]:-}"; do
    [[ -z "$_tmpl" ]] && continue
    if [[ ! -f "$_tmpl" ]]; then
        echo "Error: Nuclei template not found: $_tmpl" >&2; exit 1
    fi
done

# --- Directories / logging -------------------------------------------------
ensure_dirs "$OUTPUT_DIR"/{raw,urls,cache,nuclei,wcvs,reports} "$LOG_DIR" input

RUN_ID="$(date '+%Y%m%d-%H%M%S')"
LOG_FILE="$LOG_DIR/cachehunter-${RUN_ID}.log"
: > "$LOG_FILE"

INPUT_TARGETS="input/.targets-${RUN_ID}.txt"
if [[ -n "$SINGLE_URL" ]]; then
    echo "$SINGLE_URL" > "$INPUT_TARGETS"
else
    if [[ ! -f "$TARGET_FILE" ]]; then
        log_error "Target file not found: $TARGET_FILE"; exit 1
    fi
    cp "$TARGET_FILE" "$INPUT_TARGETS"
fi

# --- Trap handling -----------------------------------------------------
CACHEHUNTER_MISSING_REQUIRED=0
cleanup() {
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        log_error "CacheHunter exited with code $rc — see $LOG_FILE"
    fi
    rm -f "$INPUT_TARGETS" 2>/dev/null || true
}
trap cleanup EXIT
trap 'log_warn "Interrupted (Ctrl+C) — partial results preserved in $OUTPUT_DIR"; exit 130' INT TERM

# --- Dependency check --------------------------------------------------
log_info "Checking dependencies..."
check_bin curl "curl" || true
check_bin katana "Katana" 1 || true
check_bin gau "gau" 1 || true
check_bin waybackurls "waybackurls" 1 || true
check_bin "${NUCLEI_BIN:-nuclei}" "nuclei" 1 || true
check_bin "${WCVS_BIN:-wcvs}" "WCVS" 1 || true
echo "[!] Param Miner ... Burp extension — manual/integration step required (see README.md)"

if [[ "${CACHEHUNTER_MISSING_REQUIRED:-0}" -eq 1 ]]; then
    log_error "A required dependency (curl) is missing. Aborting."
    exit 1
fi

# =============================================================================
# PIPELINE
# =============================================================================
LIVE_TARGETS="$OUTPUT_DIR/raw/live-targets.txt"
KATANA_OUT="$OUTPUT_DIR/raw/katana-urls.txt"
GAU_OUT="$OUTPUT_DIR/raw/gau-urls.txt"
WAYBACK_OUT="$OUTPUT_DIR/raw/wayback-urls.txt"
ALL_URLS="$OUTPUT_DIR/urls/all-urls.txt"
PARAM_URLS="$OUTPUT_DIR/urls/parameterized.txt"
HV_URLS="$OUTPUT_DIR/urls/high-value.txt"
CACHE_CANDIDATES="$OUTPUT_DIR/urls/cache-candidates.txt"

BASELINE_JSONL="$OUTPUT_DIR/cache/baseline.jsonl"
DIFF_JSONL="$OUTPUT_DIR/cache/diff.jsonl"
KEYDIFF_JSONL="$OUTPUT_DIR/cache/keydiff.jsonl"
POISON_JSONL="$OUTPUT_DIR/cache/poisoning.jsonl"

NUCLEI_OUT="$OUTPUT_DIR/nuclei/results.txt"
WCVS_DIR="$OUTPUT_DIR/wcvs"
PARAMMINER_TARGETS="$OUTPUT_DIR/cache/paramminer-targets.txt"

CORRELATED_JSONL="$OUTPUT_DIR/reports/correlated.jsonl"

log_info "=== CacheHunter run $RUN_ID starting ==="

# --- 1. Normalize + live validation -----------------------------------------
if [[ $RESUME -eq 1 && -s "$LIVE_TARGETS" ]]; then
    log_info "Resume: reusing existing live targets ($LIVE_TARGETS)"
else
    log_info "Loading targets..."
    log_ok "$(wc -l < "$INPUT_TARGETS" | tr -d ' ') target(s) loaded"
    normalize_targets "$INPUT_TARGETS" "$LIVE_TARGETS"
fi

if [[ ! -s "$LIVE_TARGETS" ]]; then
    log_error "No live targets confirmed. Aborting."
    exit 1
fi

# --- 2. URL discovery ---------------------------------------------------
if [[ $RESUME -eq 1 && -s "$ALL_URLS" ]]; then
    log_info "Resume: reusing deduplicated URL set ($ALL_URLS)"
else
    run_katana "$LIVE_TARGETS" "$KATANA_OUT"
    run_gau "$LIVE_TARGETS" "$GAU_OUT"
    run_wayback "$LIVE_TARGETS" "$WAYBACK_OUT"
    log_info "Deduplicating..."
    deduplicate_urls "$KATANA_OUT" "$GAU_OUT" "$WAYBACK_OUT" "$ALL_URLS"
fi

filter_candidates "$ALL_URLS" "$PARAM_URLS" "$HV_URLS"
sort -u "$PARAM_URLS" "$HV_URLS" > "$CACHE_CANDIDATES" 2>/dev/null || cp "$ALL_URLS" "$CACHE_CANDIDATES"
[[ ! -s "$CACHE_CANDIDATES" ]] && cp "$ALL_URLS" "$CACHE_CANDIDATES"

# --- 3. Cache baseline ---------------------------------------------------
log_info "Cache analysis..."
if [[ $RESUME -eq 1 && -s "$BASELINE_JSONL" ]]; then
    log_info "Resume: reusing cache baseline"
else
    collect_cache_metadata "$CACHE_CANDIDATES" "$BASELINE_JSONL"
fi

if [[ $PASSIVE_ONLY -eq 1 ]]; then
    log_info "--passive-only set: skipping active differential/poisoning probes"
    : > "$DIFF_JSONL"; : > "$KEYDIFF_JSONL"; : > "$POISON_JSONL"
else
    if [[ $RESUME -eq 1 && -s "$DIFF_JSONL" ]]; then
        log_info "Resume: reusing MISS/HIT differential results"
    else
        run_cache_differential "$CACHE_CANDIDATES" "$DIFF_JSONL"
    fi
    if [[ $RESUME -eq 1 && -s "$KEYDIFF_JSONL" ]]; then
        log_info "Resume: reusing cache-key differential results"
    else
        run_cache_key_differential "$CACHE_CANDIDATES" "$KEYDIFF_JSONL"
    fi
    if [[ $RESUME -eq 1 && -s "$POISON_JSONL" ]]; then
        log_info "Resume: reusing poisoning probe results"
    else
        run_poisoning_probe "$CACHE_CANDIDATES" "$POISON_JSONL" "${MARKER_PREFIX:-CACHEHUNTER}"
    fi
fi

# --- 4. Nuclei / WCVS -----------------------------------------------------
if [[ $RESUME -eq 1 && -s "$NUCLEI_OUT" ]]; then
    log_info "Resume: reusing Nuclei results"
else
    _user_templates_joined="$(IFS=','; echo "${USER_TEMPLATES[*]:-}")"
    run_nuclei "$CACHE_CANDIDATES" "$_user_templates_joined" "$NUCLEI_OUT"
fi

if [[ $RESUME -eq 1 && -f "$WCVS_DIR/wcvs-stdout.txt" ]]; then
    log_info "Resume: reusing WCVS results"
else
    run_wcvs "$CACHE_CANDIDATES" "$WCVS_DIR"
fi

# --- 5. Param Miner target prep --------------------------------------------
prepare_paramminer_targets "$DIFF_JSONL" "$WCVS_DIR/wcvs-stdout.txt" "$NUCLEI_OUT" "$PARAMMINER_TARGETS"

# --- 6. Correlation + reporting ---------------------------------------------
correlate_results "$DIFF_JSONL" "$KEYDIFF_JSONL" "$POISON_JSONL" "$WCVS_DIR/wcvs-stdout.txt" "$NUCLEI_OUT" "$CORRELATED_JSONL"
generate_report "$CORRELATED_JSONL" "$OUTPUT_DIR/reports" "$RUN_ID"

log_info "=== CacheHunter run $RUN_ID complete ==="
log_ok "Reports available in $OUTPUT_DIR/reports/"
