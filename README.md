# CacheHunter

A modular Bash framework for investigating **web-cache misconfiguration**,
**cache-key inconsistencies**, and **potential web-cache poisoning** —
built for **authorized** bug-bounty programs, penetration tests, and labs.

> ⚠️ **Authorization required.** Only run this against targets you are
> explicitly authorized to test, CacheHunter avoids
> destructive payloads, credential attacks, and DoS-style traffic by
> design, but authorization is still on you.

---

## 1. Architecture

```
cachehunter.sh (orchestrator)
  │
  ├── modules/common.sh          shared logging, curl wrapper, hashing, dep checks
  ├── modules/discovery.sh       target normalization, live-check, Katana/gau/Wayback, dedupe, filtering
  ├── modules/cache-analysis.sh  baseline collection, MISS/HIT behavior, cache-key differential, poisoning probe
  ├── modules/nuclei.sh          runs a user-supplied (or local) Nuclei template as-is
  ├── modules/wcvs.sh            Web Cache Vulnerability Scanner integration
  ├── modules/paramminer.sh      ranks targets for manual Param Miner (Burp) analysis
  └── modules/reporting.sh       correlation engine + report.txt / report.json / report.csv
```

Every module is a self-contained set of functions sourced by
`cachehunter.sh`; none of them execute on their own. This keeps the
pipeline auditable and lets you re-run a single stage manually (e.g.
`source modules/cache-analysis.sh` in a shell for ad-hoc testing).

### Pipeline

```
INPUT (-u / -l)
   → normalize_targets (scheme probing, dedupe)
   → live HTTP validation
   → Katana + gau + Wayback (parallelizable, independent)
   → deduplicate_urls
   → filter_candidates (parameterized / high-value paths — prioritization only)
   → collect_cache_metadata (baseline headers + body hash)
   → run_cache_differential (MISS→HIT style labeling)
   → run_cache_key_differential (distinct-input / same-object check)
   → run_poisoning_probe (harmless marker survival test)
   → run_nuclei (user template, executed exactly as provided)
   → run_wcvs (against the filtered candidate set only)
   → prepare_paramminer_targets (ranked list for manual Burp import)
   → correlate_results (priority: poisoning > key-inconsistency > interesting > normal)
   → generate_report (report.txt / report.json / report.csv)
```

---

## 2. Installation

Target platform: **Kali Linux / Bash 5+**.

```bash
git clone <this-repo> cachehunter
cd cachehunter
chmod +x cachehunter.sh

# Core dependency (required)
sudo apt install curl

# Recommended (each is optional — CacheHunter degrades gracefully if absent)
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# WCVS: install per https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
```

Param Miner has **no CLI** — see section 6.

---

## 3. Usage

```bash
./cachehunter.sh -u https://target.example.com
./cachehunter.sh -l subdomains.txt
./cachehunter.sh -u https://target.example.com -t ./custom-cache-template.yaml
./cachehunter.sh -l subdomains.txt -t ./custom-cache-template.yaml -c 3 -d 1 --resume
```

```
Options:
  -u <url>      Single target
  -l <file>     Target/subdomain list, one per line
  -t <file>     User-provided Nuclei template, executed exactly as-is
  -o <dir>      Output directory (default: output)
  -c <n>        Concurrency
  -d <seconds>  Delay between requests
  --skip-katana / --skip-gau / --skip-wayback / --skip-nuclei / --skip-wcvs / --skip-paramminer
  --passive-only   Discovery + baseline only, no active differential/poisoning probes
  --resume         Reuse existing intermediate output instead of restarting
  --help
```

### Example output directory after a run

```
output/
├── raw/
│   ├── live-targets.txt
│   ├── katana-urls.txt
│   ├── gau-urls.txt
│   └── wayback-urls.txt
├── urls/
│   ├── all-urls.txt
│   ├── parameterized.txt
│   ├── high-value.txt
│   └── cache-candidates.txt
├── cache/
│   ├── baseline.jsonl
│   ├── diff.jsonl
│   ├── keydiff.jsonl
│   ├── poisoning.jsonl
│   └── paramminer-targets.txt
├── nuclei/
│   └── results.txt
├── wcvs/
│   ├── wcvs-stdout.txt
│   └── wcvs-stderr.txt
└── reports/
    ├── correlated.jsonl
    ├── report.txt
    ├── report.json
    └── report.csv
```

---

## 4. Detection methodology

CacheHunter never claims a vulnerability outright. It produces layered
**evidence** for a human to confirm:

| Stage | What it measures | Output label |
|---|---|---|
| MISS/HIT differential | Two sequential requests, compares `X-Cache`/`CF-Cache-Status` transitions | `CACHEABLE_ENDPOINT`, `CACHE_BEHAVIOR_INTERESTING` |
| Cache-key differential | Two requests with distinct query values; checks whether a *different* request is served as a cache `HIT` (same cache object despite different input) | `POSSIBLE_CACHE_KEY_INCONSISTENCY`, `SAME_CACHE_OBJECT_LIKELY` |
| Poisoning probe | Sends a harmless unique marker (via `X-Forwarded-Host`), then re-requests cleanly to see if the marker survived into an unrelated response | `POTENTIAL_CACHE_POISONING`, `MARKER_REFLECTED_NOT_CACHED` |

The key distinction the framework enforces at every stage:

```
same response            (expected — nothing interesting)
        ≠
same cache object         (different requests resolving to one cached
                            representation — needs confirmation)
        ≠
confirmed poisoning        (attacker-controlled content demonstrably
                            served to a subsequent, unrelated clean
                            request — requires manual proof)
```

CacheHunter's automated output stops at "potential" / "possible" for the
second and third rows. Confirming true positives requires manual
verification (see section 7).

---

## 5. False positives — why they happen

- **CDNs cache almost everything by default.** A `MISS → HIT` transition
  on its own is normal, expected behavior for static or semi-static
  content — not a finding. CacheHunter labels this `CACHEABLE_ENDPOINT`,
  not a vulnerability.
- **Load balancers / A-B testing** can make two requests with different
  query strings return different-looking `X-Cache` values for reasons
  unrelated to cache-key design (e.g. routing to different backend pools).
- **Session-bound personalization** can make a marker "reappear" in a
  later request because of cookies/session state, not because it was
  cached and served to a different user. `run_poisoning_probe` uses a
  clean, cookie-free follow-up request specifically to reduce this, but
  it cannot fully eliminate session-adjacent false positives — always
  re-test from a separate network/identity in Burp.
- **Reverse proxies rewriting headers** can produce misleading
  `X-Cache`/`CF-Cache-Status` values that don't reflect the actual origin
  cache behavior.

Every finding in `report.txt`/`.json`/`.csv` carries an `evidence` field
with the raw request/response comparison so you can audit exactly why it
was flagged.

---

## 6. Param Miner workflow (manual, Burp Suite)

Param Miner is a **Burp Suite extension** (BApp Store), not a CLI tool —
CacheHunter does not fabricate a command-line invocation for it.

1. Run CacheHunter normally. It writes a ranked target list to
   `output/cache/paramminer-targets.txt`, scored by cache-header
   presence, parameter count, and WCVS/Nuclei hits.
2. In Burp, add these hosts/URLs to your **Target → Scope**.
3. Install **Param Miner** from the BApp Store if not already installed.
4. Send each ranked target to **Repeater** or use Param Miner's
   right-click context menu: *"Guess GET parameters"*,
   *"Guess headers"*, *"Guess cookie names"* — and specifically its
   **cache-poisoning-aware header guessing** (it ships with a curated
   list of cache-key-relevant headers like `X-Forwarded-Host`,
   `X-Forwarded-Scheme`, `X-Original-URL`, etc.).
5. For anything Param Miner flags, manually replicate the
   controlled-request → clean-follow-up-request pattern CacheHunter used
   in `run_poisoning_probe`, but with Param Miner's discovered
   unkeyed input, to build a reproducible PoC.

If your environment has a genuine headless/CLI wrapper around Param
Miner, point `PARAMMINER_CLI` in `config/config.conf` at it and
`modules/paramminer.sh` will invoke it automatically — this is opt-in,
never assumed.

---

## 7. Manual validation checklist (before reporting anything)

- [ ] Reproduce the finding from a **different IP/network** if possible —
      rules out session/IP-based personalization.
- [ ] Reproduce with **cookies stripped** to rule out session-bound state.
- [ ] For key-inconsistency findings: confirm in Burp that two
      *semantically different* requests really do share one cached
      response (compare full headers + body, not just a hash).
- [ ] For poisoning findings: demonstrate the *unrelated clean request*
      genuinely receives attacker-influenced content — not just that the
      marker appears somewhere incidentally.
- [ ] Check the target program's scope/rules — cache poisoning PoCs can
      affect other users; follow the program's disclosure process, not
      ad-hoc testing against live user traffic beyond what's needed to
      demonstrate impact.

---

## 8. Safety notes

- No destructive payloads, credential attacks, or DoS behavior are
  included.
- All poisoning probes use a random, harmless marker
  (`CACHEHUNTER_<random-hex>`) — nothing that alters application state.
- Concurrency and request delay default to conservative values
  (`config/config.conf`) — raise them deliberately, not by default.
- `--resume` and cached intermediate files mean you don't need to
  re-hammer a target to pick up where a scan left off.
