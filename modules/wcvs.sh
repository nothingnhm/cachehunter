#!/usr/bin/env bash
# =============================================================================
# wcvs.sh — Web Cache Vulnerability Scanner integration against the
# prioritized candidate set only (never the raw firehose of URLs).
# =============================================================================

# run_wcvs CANDIDATES_FILE OUT_DIR
run_wcvs() {
    local candidates="$1" out_dir="$2"
    ensure_dirs "$out_dir"

    if [[ "${USE_WCVS:-true}" != "true" ]]; then
        log_info "WCVS skipped (--skip-wcvs)"; return 0
    fi
    if ! command -v "${WCVS_BIN:-wcvs}" >/dev/null 2>&1; then
        log_warn "WCVS binary '${WCVS_BIN:-wcvs}' not found — skipping WCVS stage"
        return 0
    fi
    if [[ ! -s "$candidates" ]]; then
        log_warn "No candidate URLs for WCVS, skipping"
        return 0
    fi

    local stdout_file="$out_dir/wcvs-stdout.txt"
    local stderr_file="$out_dir/wcvs-stderr.txt"
    log_info "Running WCVS against $(wc -l < "$candidates" | tr -d ' ') candidate URL(s)..."

    # WCVS invocation kept conservative: it reads targets from stdin/-l style
    # flag depending on version. We use a generic -l list pattern and cap
    # concurrency; adjust to your installed WCVS version's actual flags if
    # they differ.
    if timeout "$((TIMEOUT * 30))" "${WCVS_BIN:-wcvs}" -l "$candidates" \
            -c "${CONCURRENCY:-5}" \
            > "$stdout_file" 2> "$stderr_file"; then
        log_ok "WCVS completed successfully"
    else
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            log_warn "WCVS timed out — partial results (if any) preserved in $stdout_file"
        else
            log_warn "WCVS exited with code $rc — see $stderr_file for details"
        fi
    fi
}
