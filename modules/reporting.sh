#!/usr/bin/env bash
# =============================================================================
# reporting.sh — correlation engine + final report generation
# Never assigns CRITICAL. Priority order: poisoning > key-inconsistency >
# interesting cache config > normal cacheable. Deduplicates equivalent
# findings before writing output.
# =============================================================================

# correlate_results DIFF_JSONL KEYDIFF_JSONL POISON_JSONL WCVS_STDOUT NUCLEI_JSONL OUT_JSONL
correlate_results() {
    local diff="$1" keydiff="$2" poison="$3" wcvs_out="$4" nuclei_jsonl="$5" out="$6"
    ensure_dirs "$(dirname "$out")"
    local tmp; tmp=$(mktemp)
    : > "$tmp"

    _emit() {
        # $1 url  $2 finding_type  $3 severity  $4 evidence  $5 detected_by
        printf '{"url":%s,"finding_type":%s,"severity":"%s","evidence":%s,"detected_by":%s}\n' \
            "$(_json_str "$1")" "$(_json_str "$2")" "$3" "$(_json_str "$4")" "$(_json_str "$5")" >> "$tmp"
    }

    if [[ -s "$poison" ]]; then
        while IFS= read -r line; do
            echo "$line" | grep -q '"label":"POTENTIAL_CACHE_POISONING"' || continue
            local url; url=$(echo "$line" | grep -oE '"url":"[^"]*"' | head -1 | sed -E 's/"url":"([^"]*)"/\1/')
            _emit "$url" "Potential cache poisoning" "HIGH" "$line" "CacheHunter poisoning probe"
        done < "$poison"
    fi

    if [[ -s "$keydiff" ]]; then
        while IFS= read -r line; do
            echo "$line" | grep -q '"label":"POSSIBLE_CACHE_KEY_INCONSISTENCY"' || continue
            local url; url=$(echo "$line" | grep -oE '"base_url":"[^"]*"' | head -1 | sed -E 's/"base_url":"([^"]*)"/\1/')
            _emit "$url" "Possible cache-key inconsistency" "MEDIUM" "$line" "CacheHunter differential analyzer"
        done < "$keydiff"
    fi

    if [[ -s "$diff" ]]; then
        while IFS= read -r line; do
            local url label
            url=$(echo "$line" | grep -oE '"url":"[^"]*"' | head -1 | sed -E 's/"url":"([^"]*)"/\1/')
            label=$(echo "$line" | grep -oE '"label":"[^"]*"' | head -1 | sed -E 's/"label":"([^"]*)"/\1/')
            case "$label" in
                CACHE_BEHAVIOR_INTERESTING)
                    _emit "$url" "Interesting cache configuration" "LOW" "$line" "CacheHunter MISS/HIT analyzer" ;;
                CACHEABLE_ENDPOINT)
                    _emit "$url" "Normal cacheable endpoint" "INFO" "$line" "CacheHunter MISS/HIT analyzer" ;;
            esac
        done < "$diff"
    fi

    if [[ -s "$nuclei_jsonl" ]]; then
        while IFS= read -r line; do
            local url; url=$(echo "$line" | grep -oE '"host":"[^"]*"|"matched-at":"[^"]*"' | head -1 | sed -E 's/"[^"]+":"([^"]*)"/\1/')
            [[ -z "$url" ]] && continue
            _emit "$url" "Nuclei template match" "MEDIUM" "$line" "Nuclei"
        done < "$nuclei_jsonl"
    fi

    # Deduplicate equivalent findings (same url + finding_type)
    awk -F'"finding_type":' '{
        split($2,a,","); key=$0
        u=$1; ft=a[1]
        dedupe_key = u ft
        if (!(dedupe_key in seen)) { seen[dedupe_key]=1; print }
    }' "$tmp" > "$out"
    rm -f "$tmp"

    local total; total=$(wc -l < "$out" | tr -d ' ')
    log_ok "Correlation engine produced $total deduplicated finding(s)"
}

# generate_report CORRELATED_JSONL OUT_DIR TARGET_LABEL
generate_report() {
    local correlated="$1" out_dir="$2" target_label="${3:-scan}"
    ensure_dirs "$out_dir"
    local txt="$out_dir/report.txt" json="$out_dir/report.json" csv="$out_dir/report.csv"

    # JSON: wrap lines into an array
    {
        echo "["
        local first=1
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ $first -eq 0 ]] && echo ","
            printf '%s' "$line"
            first=0
        done < "$correlated"
        echo ""
        echo "]"
    } > "$json"

    # CSV
    echo 'severity,finding_type,url,detected_by' > "$csv"
    if [[ -s "$correlated" ]]; then
        while IFS= read -r line; do
            local sev ft url det
            sev=$(echo "$line" | grep -oE '"severity":"[^"]*"' | sed -E 's/"severity":"([^"]*)"/\1/')
            ft=$(echo "$line" | grep -oE '"finding_type":"[^"]*"' | sed -E 's/"finding_type":"([^"]*)"/\1/')
            url=$(echo "$line" | grep -oE '"url":"[^"]*"' | head -1 | sed -E 's/"url":"([^"]*)"/\1/')
            det=$(echo "$line" | grep -oE '"detected_by":"[^"]*"' | sed -E 's/"detected_by":"([^"]*)"/\1/')
            printf '%s,%s,%s,%s\n' "$(csv_escape "$sev")" "$(csv_escape "$ft")" "$(csv_escape "$url")" "$(csv_escape "$det")" >> "$csv"
        done < "$correlated"
    fi

    # TXT — human-readable, sorted by priority
    {
        echo "======================================================================"
        echo " CacheHunter Report — $target_label"
        echo " Generated: $(_ts)"
        echo "======================================================================"
        echo
        for sev_type in "Potential cache poisoning" "Possible cache-key inconsistency" "Interesting cache configuration" "Normal cacheable endpoint" "Nuclei template match"; do
            local matches
            matches=$(grep -F "\"finding_type\":\"$sev_type\"" "$correlated" 2>/dev/null || true)
            [[ -z "$matches" ]] && continue
            echo "---- $sev_type ----"
            echo
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                local sev url det
                sev=$(echo "$line" | grep -oE '"severity":"[^"]*"' | sed -E 's/"severity":"([^"]*)"/\1/')
                url=$(echo "$line" | grep -oE '"url":"[^"]*"' | head -1 | sed -E 's/"url":"([^"]*)"/\1/')
                det=$(echo "$line" | grep -oE '"detected_by":"[^"]*"' | sed -E 's/"detected_by":"([^"]*)"/\1/')
                echo "Finding:      $sev_type"
                echo "Severity:     $sev"
                echo "URL:          $url"
                echo "Detected by:  $det"
                echo "Status:       Needs manual validation"
                echo "Recommended:  Reproduce in Burp Repeater with Param Miner active;"
                echo "              confirm cache-object identity before reporting."
                echo
            done <<< "$matches"
        done
        echo "======================================================================"
        echo " End of report. All MEDIUM/HIGH findings require manual confirmation"
        echo " before being submitted to a bug-bounty program."
        echo "======================================================================"
    } > "$txt"

    log_ok "Reports written: $txt, $json, $csv"
}
