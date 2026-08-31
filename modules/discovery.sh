#!/usr/bin/env bash
# =============================================================================
# discovery.sh — target normalization + URL discovery (katana/gau/wayback)
# =============================================================================

# normalize_targets INPUT_FILE OUTPUT_FILE
# Accepts bare domains or full URLs, strips comments/blank lines/dupes,
# and probes http/https to find the live scheme rather than assuming HTTPS.
normalize_targets() {
    local in_file="$1" out_file="$2"
    local raw_file="$OUTPUT_DIR/raw/targets-raw.txt"
    ensure_dirs "$(dirname "$out_file")" "$(dirname "$raw_file")"

    # Strip comments, blank lines, trailing slashes/whitespace, dedupe
    grep -vE '^\s*(#|$)' "$in_file" \
        | sed -E 's#[[:space:]]+$##; s#/+$##' \
        | sed -E 's#^https?://##I' \
        | tr -d '\r' \
        | awk 'NF' \
        | sort -u > "$raw_file"

    log_info "Normalized $(wc -l < "$raw_file" | tr -d ' ') unique host(s), probing scheme..."
    : > "$out_file"

    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        sleep_delay
        local chosen=""
        # Prefer HTTPS, fall back to HTTP. Don't assume.
        local res
        res=$(ch_curl GET "https://${host}" -k -L --max-redirs 3 2>/dev/null) || true
        local code; code=$(cut -f1 <<< "$res")
        if [[ "$code" =~ ^[2-3][0-9]{2}$ || "$code" =~ ^40[13]$ ]]; then
            chosen="https://${host}"
        else
            res=$(ch_curl GET "http://${host}" -L --max-redirs 3 2>/dev/null) || true
            code=$(cut -f1 <<< "$res")
            if [[ "$code" =~ ^[2-3][0-9]{2}$ || "$code" =~ ^40[13]$ ]]; then
                chosen="http://${host}"
            fi
        fi
        # cleanup temp files from ch_curl
        local hf bf; hf=$(cut -f4 <<< "$res"); bf=$(cut -f5 <<< "$res")
        [[ -f "$hf" ]] && rm -f "$hf"; [[ -f "$bf" ]] && rm -f "$bf"

        if [[ -n "$chosen" ]]; then
            echo "$chosen" >> "$out_file"
        else
            log_warn "Host unreachable on both schemes, skipping: $host"
        fi
    done < "$raw_file"

    sort -u -o "$out_file" "$out_file"
    log_ok "$(wc -l < "$out_file" | tr -d ' ') live target(s) confirmed"
}

# run_katana LIVE_TARGETS_FILE OUT_FILE
run_katana() {
    local targets="$1" out="$2"
    if [[ "${USE_KATANA:-true}" != "true" ]]; then
        log_info "Katana skipped (--skip-katana)"; : > "$out"; return 0
    fi
    if ! command -v katana >/dev/null 2>&1; then
        log_warn "katana not installed, skipping"; : > "$out"; return 0
    fi
    log_info "Running Katana..."
    katana -list "$targets" -silent -jc -kf all \
        -c "${CONCURRENCY:-5}" -timeout "${TIMEOUT:-10}" \
        -H "User-Agent: ${USER_AGENT}" \
        2>>"$LOG_FILE" | sort -u > "$out" || true
    log_ok "$(wc -l < "$out" | tr -d ' ') URLs discovered (Katana)"
}

# run_gau LIVE_TARGETS_FILE OUT_FILE
run_gau() {
    local targets="$1" out="$2"
    if [[ "${USE_GAU:-true}" != "true" ]]; then
        log_info "gau skipped (--skip-gau)"; : > "$out"; return 0
    fi
    if ! command -v gau >/dev/null 2>&1; then
        log_warn "gau not installed, skipping"; : > "$out"; return 0
    fi
    log_info "Running gau..."
    : > "$out"
    while IFS= read -r url; do
        local host="${url#*://}"
        gau --threads "${CONCURRENCY:-5}" "$host" 2>>"$LOG_FILE" >> "$out" || true
        sleep_delay
    done < "$targets"
    sort -u -o "$out" "$out"
    log_ok "$(wc -l < "$out" | tr -d ' ') historical URLs discovered (gau)"
}

# run_wayback LIVE_TARGETS_FILE OUT_FILE
run_wayback() {
    local targets="$1" out="$2"
    if [[ "${USE_WAYBACK:-true}" != "true" ]]; then
        log_info "Wayback skipped (--skip-wayback)"; : > "$out"; return 0
    fi
    if command -v waybackurls >/dev/null 2>&1; then
        log_info "Running waybackurls..."
        : > "$out"
        while IFS= read -r url; do
            local host="${url#*://}"
            waybackurls "$host" 2>>"$LOG_FILE" >> "$out" || true
            sleep_delay
        done < "$targets"
    else
        log_warn "waybackurls not installed, falling back to web.archive.org CDX API"
        : > "$out"
        while IFS= read -r url; do
            local host="${url#*://}"
            local res; res=$(ch_curl GET "http://web.archive.org/cdx/search/cdx?url=${host}/*&output=text&fl=original&collapse=urlkey")
            local bf; bf=$(cut -f5 <<< "$res")
            [[ -f "$bf" ]] && cat "$bf" >> "$out" && rm -f "$bf"
            local hf; hf=$(cut -f4 <<< "$res"); [[ -f "$hf" ]] && rm -f "$hf"
            sleep_delay
        done < "$targets"
    fi
    sort -u -o "$out" "$out"
    log_ok "$(wc -l < "$out" | tr -d ' ') archive URLs discovered (Wayback)"
}

# deduplicate_urls FILE1 FILE2 FILE3 ... -- OUT_FILE
deduplicate_urls() {
    local out="${*: -1}"
    local files=("${@:1:$#-1}")
    cat "${files[@]}" 2>/dev/null | grep -E '^https?://' | sort -u > "$out" || true
    log_ok "$(wc -l < "$out" | tr -d ' ') unique URLs after deduplication"
}

# filter_candidates ALL_URLS_FILE PARAM_OUT HIGHVALUE_OUT
# Prioritization only — never a vulnerability claim.
filter_candidates() {
    local all="$1" param_out="$2" hv_out="$3"

    grep -E '[?&][A-Za-z0-9_%-]+=' "$all" 2>/dev/null | sort -u > "$param_out" || : > "$param_out"

    local keywords='api|user|account|profile|admin|search|callback|redirect|download|file|image|page|product|cart|login|dashboard|graphql'
    grep -Ei "/($keywords)([/?]|$)" "$all" 2>/dev/null | sort -u > "$hv_out" || : > "$hv_out"

    log_ok "$(wc -l < "$param_out" | tr -d ' ') parameterized URLs, $(wc -l < "$hv_out" | tr -d ' ') high-value-path URLs"
}
