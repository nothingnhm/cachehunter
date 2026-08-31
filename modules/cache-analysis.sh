#!/usr/bin/env bash
# =============================================================================
# cache-analysis.sh — baseline collection, MISS/HIT behavior, cache-key
# differential testing, and conservative cache-poisoning probing.
#
# IMPORTANT: nothing in this file emits a "vulnerability" verdict. It only
# emits observations (CACHEABLE_ENDPOINT, CACHE_BEHAVIOR_INTERESTING,
# POSSIBLE_CACHE_KEY_INCONSISTENCY, POTENTIAL_CACHE_POISONING) that the
# correlation engine and human reviewer must validate further.
# =============================================================================

CACHE_HEADER_NAMES=(Cache-Control Age ETag Vary Expires Pragma X-Cache CF-Cache-Status Via Server Content-Type Content-Length)

# collect_cache_metadata URL_LIST OUT_JSONL
# One JSONL line per URL with baseline HTTP metadata + body hash.
collect_cache_metadata() {
    local urls="$1" out="$2"
    ensure_dirs "$(dirname "$out")"
    : > "$out"
    local n=0
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        n=$((n+1))
        local res; res=$(ch_curl GET "$url" -L --max-redirs 3)
        local code time size hf bf
        IFS=$'\t' read -r code time size hf bf <<< "$res"
        local body_hash="none"
        [[ -f "$bf" ]] && body_hash=$(sha256_of_file "$bf")

        local json
        json=$(printf '{"url":%s,"status":"%s","time_total":"%s","size":"%s"' \
            "$(_json_str "$url")" "$code" "$time" "$size")
        for h in "${CACHE_HEADER_NAMES[@]}"; do
            local key; key=$(echo "$h" | tr 'A-Z-' 'a-z_')
            local val; val=$( [[ -f "$hf" ]] && get_header "$hf" "$h" || echo "" )
            json+=$(printf ',"%s":%s' "$key" "$(_json_str "$val")")
        done
        json+=$(printf ',"body_hash":"%s"}' "$body_hash")
        echo "$json" >> "$out"

        [[ -f "$hf" ]] && rm -f "$hf"; [[ -f "$bf" ]] && rm -f "$bf"
        sleep_delay
    done < "$urls"
    log_ok "Collected cache baseline metadata for $n URL(s)"
}

_json_str() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    printf '"%s"' "$s"
}

# run_cache_differential URL_LIST OUT_JSONL
# Two sequential requests per URL; classifies MISS/HIT-style transitions.
# Never labels the result "vulnerable" — only descriptive tags.
run_cache_differential() {
    local urls="$1" out="$2"
    ensure_dirs "$(dirname "$out")"
    : > "$out"
    local n=0 interesting=0
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        n=$((n+1))

        local r1; r1=$(ch_curl GET "$url" -L --max-redirs 3)
        local c1 t1 s1 h1 b1; IFS=$'\t' read -r c1 t1 s1 h1 b1 <<< "$r1"
        local xc1 cf1 hash1
        xc1=$( [[ -f "$h1" ]] && get_header "$h1" "X-Cache" || echo "" )
        cf1=$( [[ -f "$h1" ]] && get_header "$h1" "CF-Cache-Status" || echo "" )
        hash1=$( [[ -f "$b1" ]] && sha256_of_file "$b1" || echo "none" )

        sleep_delay
        local r2; r2=$(ch_curl GET "$url" -L --max-redirs 3)
        local c2 t2 s2 h2 b2; IFS=$'\t' read -r c2 t2 s2 h2 b2 <<< "$r2"
        local xc2 cf2 hash2
        xc2=$( [[ -f "$h2" ]] && get_header "$h2" "X-Cache" || echo "" )
        cf2=$( [[ -f "$h2" ]] && get_header "$h2" "CF-Cache-Status" || echo "" )
        hash2=$( [[ -f "$b2" ]] && sha256_of_file "$b2" || echo "none" )

        local label="NO_CACHE_INDICATORS"
        local combined="${xc1}|${cf1} -> ${xc2}|${cf2}"
        if echo "$combined" | grep -Eiq 'miss.*->.*hit'; then
            label="CACHEABLE_ENDPOINT"
        elif echo "$combined" | grep -Eiq 'bypass.*->.*hit'; then
            label="CACHEABLE_ENDPOINT"
        elif [[ -n "$xc1$cf1$xc2$cf2" ]]; then
            label="CACHE_BEHAVIOR_INTERESTING"
        fi

        if [[ "$label" != "NO_CACHE_INDICATORS" ]]; then
            interesting=$((interesting+1))
            log_finding "$label — $url ($combined)"
        fi

        printf '{"url":%s,"label":"%s","req1":{"status":"%s","x_cache":%s,"cf_cache_status":%s,"body_hash":"%s"},"req2":{"status":"%s","x_cache":%s,"cf_cache_status":%s,"body_hash":"%s"}}\n' \
            "$(_json_str "$url")" "$label" \
            "$c1" "$(_json_str "$xc1")" "$(_json_str "$cf1")" "$hash1" \
            "$c2" "$(_json_str "$xc2")" "$(_json_str "$cf2")" "$hash2" >> "$out"

        for f in "$h1" "$b1" "$h2" "$b2"; do [[ -f "$f" ]] && rm -f "$f"; done
        sleep_delay
    done < "$urls"
    log_ok "Cache differential pass complete: $interesting/$n endpoint(s) showed cache indicators"
}

# run_cache_key_differential URL_LIST OUT_JSONL
# Sends two distinct query-string variations of the same URL and compares
# response identity vs. inferred cache-object identity.
run_cache_key_differential() {
    local urls="$1" out="$2"
    ensure_dirs "$(dirname "$out")"
    : > "$out"
    local flagged=0 n=0
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        n=$((n+1))
        local base="$url" sep="?"
        [[ "$url" == *\?* ]] && { base="${url%%\?*}"; sep="&"; }

        local urlA="${base}${sep}chtest=AAA"
        local urlB="${base}${sep}chtest=BBB"

        local ra; ra=$(ch_curl GET "$urlA" -L --max-redirs 3)
        local ca ta sa ha ba; IFS=$'\t' read -r ca ta sa ha ba <<< "$ra"
        local hashA xcA; hashA=$( [[ -f "$ba" ]] && sha256_of_file "$ba" || echo none )
        xcA=$( [[ -f "$ha" ]] && get_header "$ha" "X-Cache" || echo "" )

        sleep_delay
        local rb; rb=$(ch_curl GET "$urlB" -L --max-redirs 3)
        local cb tb sb hb bb; IFS=$'\t' read -r cb tb sb hb bb <<< "$rb"
        local hashB xcB; hashB=$( [[ -f "$bb" ]] && sha256_of_file "$bb" || echo none )
        xcB=$( [[ -f "$hb" ]] && get_header "$hb" "X-Cache" || echo "" )

        local label="SAME_RESPONSE_DIFFERENT_INPUT_EXPECTED"
        # If bodies differ (expected — different param values) but the cache
        # layer reports HIT on the second, distinct-input request, that is
        # suspicious: a different request may be resolving to the same
        # cached object. This is evidence only, not confirmation.
        if [[ "$hashA" != "$hashB" ]] && echo "$xcB" | grep -qi 'hit'; then
            label="POSSIBLE_CACHE_KEY_INCONSISTENCY"
            flagged=$((flagged+1))
            log_finding "POSSIBLE_CACHE_KEY_INCONSISTENCY — $base (distinct bodies, second request served as HIT)"
        elif [[ "$hashA" == "$hashB" ]]; then
            label="SAME_CACHE_OBJECT_LIKELY"
        fi

        printf '{"base_url":%s,"label":"%s","reqA":{"url":%s,"status":"%s","x_cache":%s,"body_hash":"%s"},"reqB":{"url":%s,"status":"%s","x_cache":%s,"body_hash":"%s"}}\n' \
            "$(_json_str "$base")" "$label" \
            "$(_json_str "$urlA")" "$ca" "$(_json_str "$xcA")" "$hashA" \
            "$(_json_str "$urlB")" "$cb" "$(_json_str "$xcB")" "$hashB" >> "$out"

        for f in "$ha" "$ba" "$hb" "$bb"; do [[ -f "$f" ]] && rm -f "$f"; done
        sleep_delay
    done < "$urls"
    log_ok "Cache-key differential pass complete: $flagged/$n possible inconsistency flag(s)"
}

# run_poisoning_probe URL_LIST OUT_JSONL MARKER_PREFIX
# Sends a harmless unique marker in a header commonly implicated in cache
# poisoning (X-Forwarded-Host), then re-requests the same URL cleanly to see
# whether the marker leaked into the cached representation.
run_poisoning_probe() {
    local urls="$1" out="$2" prefix="${3:-CACHEHUNTER}"
    ensure_dirs "$(dirname "$out")"
    : > "$out"
    local flagged=0 n=0
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        n=$((n+1))
        local token; token="${prefix}_$(random_token)"
        local marker_host="${token}.cache-probe.invalid"

        # Step 1: controlled request carrying the marker in a header known to
        # sometimes influence cache keys / unkeyed inputs.
        local r1; r1=$(ch_curl GET "$url" -L --max-redirs 3 \
            -H "X-Forwarded-Host: ${marker_host}" \
            -H "X-Forwarded-Scheme: https")
        local c1 t1 s1 h1 b1; IFS=$'\t' read -r c1 t1 s1 h1 b1 <<< "$r1"
        local marker_reflected="no"
        [[ -f "$b1" ]] && grep -q "$token" "$b1" 2>/dev/null && marker_reflected="yes"
        local xc1; xc1=$( [[ -f "$h1" ]] && get_header "$h1" "X-Cache" || echo "" )
        [[ -f "$h1" ]] && grep -q "$token" "$h1" 2>/dev/null && marker_reflected="yes_in_headers"

        sleep_delay
        # Step 2: clean follow-up request, no marker, no special headers.
        local r2; r2=$(ch_curl GET "$url" -L --max-redirs 3)
        local c2 t2 s2 h2 b2; IFS=$'\t' read -r c2 t2 s2 h2 b2 <<< "$r2"
        local marker_in_clean="no"
        [[ -f "$b2" ]] && grep -q "$token" "$b2" 2>/dev/null && marker_in_clean="yes"
        [[ -f "$h2" ]] && grep -q "$token" "$h2" 2>/dev/null && marker_in_clean="yes_in_headers"
        local xc2; xc2=$( [[ -f "$h2" ]] && get_header "$h2" "X-Cache" || echo "" )

        local label="NO_POISONING_INDICATORS"
        if [[ "$marker_reflected" != "no" && "$marker_in_clean" != "no" ]]; then
            # Marker appeared in the controlled response AND survived into an
            # unrelated clean request. Still requires manual confirmation
            # that this is actually served from a shared cache (not e.g.
            # session state), so we call it POTENTIAL, not confirmed.
            label="POTENTIAL_CACHE_POISONING"
            flagged=$((flagged+1))
            log_finding "POTENTIAL_CACHE_POISONING — $url (marker survived into clean request; MANUAL VERIFICATION REQUIRED)"
        elif [[ "$marker_reflected" != "no" ]]; then
            label="MARKER_REFLECTED_NOT_CACHED"
        fi

        printf '{"url":%s,"label":"%s","token":"%s","controlled":{"status":"%s","x_cache":%s,"marker_reflected":"%s"},"clean_followup":{"status":"%s","x_cache":%s,"marker_present":"%s"}}\n' \
            "$(_json_str "$url")" "$label" "$token" \
            "$c1" "$(_json_str "$xc1")" "$marker_reflected" \
            "$c2" "$(_json_str "$xc2")" "$marker_in_clean" >> "$out"

        for f in "$h1" "$b1" "$h2" "$b2"; do [[ -f "$f" ]] && rm -f "$f"; done
        sleep_delay
    done < "$urls"
    log_ok "Poisoning probe complete: $flagged/$n POTENTIAL_CACHE_POISONING flag(s) — all require manual confirmation"
}
