#!/usr/bin/env bash
# =============================================================================
# nuclei.sh — runs a user-supplied template exactly as provided, and
# optionally the local nuclei-templates/ directory if no template is given.
# Never rewrites or replaces the user's template file.
# =============================================================================

# run_nuclei TARGETS_FILE USER_TEMPLATES(optional, comma-separated) OUT_FILE
run_nuclei() {
    local targets="$1" user_templates_csv="$2" out="$3"
    ensure_dirs "$(dirname "$out")"

    if [[ "${USE_NUCLEI:-true}" != "true" ]]; then
        log_info "Nuclei skipped (--skip-nuclei)"; : > "$out"; return 0
    fi
    if ! command -v "${NUCLEI_BIN:-nuclei}" >/dev/null 2>&1; then
        log_warn "nuclei not installed, skipping"; : > "$out"; return 0
    fi
    if [[ ! -s "$targets" ]]; then
        log_warn "No targets available for Nuclei, skipping"; : > "$out"; return 0
    fi

    if [[ -n "$user_templates_csv" ]]; then
        local -a templates=()
        IFS=',' read -r -a templates <<< "$user_templates_csv"

        local -a template_flags=()
        for tmpl in "${templates[@]}"; do
            [[ -z "$tmpl" ]] && continue
            if [[ ! -f "$tmpl" ]]; then
                log_error "Nuclei template not found: $tmpl"
                return 1
            fi
            template_flags+=(-t "$tmpl")
        done

        if [[ "${#template_flags[@]}" -eq 0 ]]; then
            log_warn "No valid user templates resolved, skipping Nuclei"
            : > "$out"
            return 0
        fi

        log_info "Running Nuclei with ${#templates[@]} user-supplied template(s): ${templates[*]}"
        "${NUCLEI_BIN:-nuclei}" -l "$targets" "${template_flags[@]}" \
            -c "${CONCURRENCY:-5}" -timeout "${TIMEOUT:-10}" \
            -H "User-Agent: ${USER_AGENT}" \
            -silent -jsonl -o "$out" 2>>"$LOG_FILE" || true
    elif [[ -d "${DEFAULT_NUCLEI_TEMPLATES:-nuclei-templates}" ]] && \
         [[ -n "$(ls -A "${DEFAULT_NUCLEI_TEMPLATES:-nuclei-templates}" 2>/dev/null)" ]]; then
        log_info "No -t supplied; running local nuclei-templates/ (not guaranteed to cover cache poisoning)"
        "${NUCLEI_BIN:-nuclei}" -l "$targets" -t "${DEFAULT_NUCLEI_TEMPLATES}" \
            -c "${CONCURRENCY:-5}" -timeout "${TIMEOUT:-10}" \
            -H "User-Agent: ${USER_AGENT}" \
            -silent -jsonl -o "$out" 2>>"$LOG_FILE" || true
    else
        log_info "No user template and no local templates found — skipping Nuclei stage"
        : > "$out"
        return 0
    fi

    local count=0
    [[ -f "$out" ]] && count=$(wc -l < "$out" | tr -d ' ')
    log_ok "Nuclei finished: $count result(s)"
}
