# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-file Flask web app (`app.py`, ~2300 lines) that helps a firewall engineer minimize and clean up rule sets. It runs locally, auto-opens a browser tab, and serves a self-contained dark-themed UI. Everything — analysis engine, Check Point script generator, policy scanner, and all HTML/CSS/JS templates — lives in `app.py`. There are no external assets, no database, and no JS build step.

## Commands

```bash
pip install flask                 # only runtime dependency
python app.py                     # runs at http://127.0.0.1:5000 and opens a browser tab
```

Build the standalone Windows .exe (output: `dist\FirewallRuleAnalyzer.exe`, fully self-contained):

```cmd
pip install flask pyinstaller
pyinstaller firewall_analyzer.spec
```

There are no tests, linter config, or CI. `firewall_analyzer.spec` lists Flask/Werkzeug/Jinja submodules as `hiddenimports` — if you add a new third-party import, add it there or the frozen .exe will fail at runtime.

## Architecture

The file is organized into labeled sections (search for the `─────` banner comments). Three independent engines feed a thin Flask routing layer at the bottom. Each engine is pure functions over parsed CSV rows — no shared mutable state — which makes them easy to reason about in isolation.

**1. Rule Analysis Engine** (`parse_csv` → `filter_rows` → `analyze` → `rules_to_csv`)
Takes a traffic-hit CSV (columns: `src, dst, transport, action, service, count`) and emits least-permissive replacement rules. `analyze()` runs in passes: collect services per (src, dst); summarize source IPs into subnets via `summarize_ips`; merge services per (src, dst); compress consecutive ports into ranges via `compress_services`; then group rules sharing the same destination+service. Key thresholds live as defaults in `summarize_ips` (a /24 collapses when ≥50% present **or** ≥10 distinct IPs) and `compress_services` (`object_group_threshold=6` flags a rule as needing an object group). `filter_rows` drops any flow with `count < 2`.

`analyze(rows, subnet_map, mode)` takes an **output-detail mode** (`SUMMARIZE_MODE` / `SPECIFIC_MODE`, the constants at the top of the engine; `summarize` is the default and the pre-existing behavior). `SPECIFIC_MODE` turns off all three consolidation steps — no named-subnet or /24 summarization of either side, no port-range compression (`compress_services(..., compress_ranges=False)` lists every port), and no grouping by destination+service, so the output is one rule per exact source→destination pair. Only deduplication of identical flows remains. The rule dicts have the same shape in both modes, so `rules_to_csv`, `generate_checkpoint_script`, and `match_rules_to_policy` are mode-agnostic. The UI exposes the choice as a radio pair in the analyzer's Input card and every analyzer POST endpoint reads it via `_analysis_mode()` (unknown/absent values fall back to `summarize`).

**2. Check Point Script Generator** (`generate_checkpoint_script`)
Turns analyzed rules into a `mgmt_cli` bash script that creates host/network/service/service-group objects. It deliberately does **not** emit access rules (the header says so). De-duplication is via `created` sets passed through `cp_add_*` helpers.

**3. Policy Scanner Engine** (`parse_policy_csv` → `audit_policy` / `recommend_split`)
Reads a SecureTrack-style policy export. Important format quirks: the **first 3 lines are metadata and skipped**; line 4 is the header. Columns are located by header name with a **fixed-position fallback** (`_col_index`), because the export has stable column letters — Source = col R (index 17), Destination = col U (index 20); the other audited fallbacks (`Device Name`=3, `Disabled`=14, `Service`=22, `Action`=26, `Comment`=31, `Logged`=32, `Last Hit`=41, `Shadowing Status`=43) are constants next to `audit_policy`. `audit_policy` runs eight severity-rated checks per rule — Critical: `Any` src/dst/service on ALLOW rules only; High: overly permissive **enabled** ALLOW rules (network object /16 or wider, broad service such as `ALL_*` or a >1000-port range, or >50 objects in one field — `MANY_OBJECTS`; disabled rules are skipped since an inactive rule grants no access and is already flagged as disabled); Medium: bi-directional rules (Source == Destination, with Any==Any excluded) and missing logging (`Logged` column not true; disabled rules are skipped); Low: missing comment, unused (Last Hit empty or >180 days old; disabled rules are skipped), disabled, and shadowed (`Shadowing Status` contains "shadowed" but isn't `NOT_SHADOWED`; disabled rules skipped). Scoring starts at 1000 and **every individual finding deducts** its severity's points (Critical 6 / High 4 / Medium 2 / Low 1), floored at 0; the thresholds live as module constants (`UNUSED_AFTER_DAYS`, `BROAD_PREFIX_LEN`, etc.). It also returns the distinct `Device Name` and `Policy Name` values for the dashboard. The UI's score bands are: >950 green, >800 yellow, 600–800 orange, <600 red (`bandFor` in `SCANNER_HTML`), drawn as an SVG speedometer gauge (`initGauge`/`gaugeArc`). `audit_to_csv` exports one category or all findings. `recommend_split` proposes least-permissive uni-directional replacements for selected bi-directional rules by clustering objects that share a /16 or a common leading name token (`_cluster_objects`, `_objects_related`).

**4. Rule-vs-Policy Coverage Match** (`match_rules_to_policy` → `coverage_to_csv`)
Cross-references the analyzer's generated rules against an *existing* policy export (same SecureTrack format as engine 3) so the engineer can see, per generated rule, whether they need a brand-new rule or can just amend an existing one. Only **enabled ALLOW** policy rules can permit traffic (deny/disabled are skipped). Path (Source→Destination) matching is IP-aware: it pulls the network embedded in a policy object name via `_object_network` (e.g. `HCA-10.0.0.0m8` → `10.0.0.0/8`) and tests subnet containment (`_net_covered`), treating `Any` as covering everything. Service objects are **named** (e.g. `Allscripts_Citrix_ICA`) and can't be resolved to ports without a service-object dictionary, so service coverage is **best-effort** (`_policy_service_state`): `Any`/`ALL_*` and a literal port-number hit count as `ok`, otherwise `unknown` ("verify/add"). Each generated rule gets a status — **covered** (path + service confirmed, no change), **amend** (path allowed but service unconfirmed and/or some source objects missing → add to the named existing rule), or **new** (no ALLOW rule covers the path). The whole feature is **optional**: it only runs when a policy file is supplied alongside the traffic CSV.

**Subnet name map:** Several engines accept a `subnet_map`, built at request time by `load_staged_subnet_map()` from every CSV staged next to `app.py` whose filename starts with `all_networks` (each file has a `CIDR,NAME` header; up to ~25 files). Entries are sorted most-specific-first so the best (longest-prefix) match wins. Named subnets take priority over automatic /24 aggregation, and names flow through to display labels and Check Point object names. This map is no longer uploaded through the UI — it is read from disk on each request (`_load_subnet_map`).

**Routing layer** (bottom of file): `/` serves a toolbox landing page, `/analyzer` and `/scanner` serve the two tool pages. POST endpoints (`/analyze` — accepts an optional second `policy` file field; when present it also runs `match_rules_to_policy` and returns `coverage` + `summary` (backward compatible without it); it and the three other analyzer endpoints also accept an optional `mode` form field (`summarize`/`specific`) — `/download`, `/download_checkpoint`, `/coverage_download` (the coverage CSV; needs both `file` and `policy`), `/scan`, `/recommend`, `/recommend_download`, `/scan_download` — takes an optional `category` form field to export a single audit category — and `/report_executive` / `/report_engineer`, which download self-contained light-themed HTML reports built by `generate_executive_report` / `generate_engineer_report` — both share `_REPORT_CSS` via `_report_head(title, extra_css)`, and the engineer plan additionally gets `_LANDSCAPE_CSS` (`@page { size: landscape }` plus a wider page) because its per-category tables are 7 columns wide) re-parse the uploaded file on every call — there is no server-side session or caching, so each download endpoint repeats the full parse+analyze pipeline. Most endpoints wrap their body in a broad `try/except` that returns `{"error": str(e)}`.

## Conventions

- **The UI is embedded.** `ANALYZER_HTML`, `SCANNER_HTML`, `HOME_HTML`, and `SHARED_CSS` are raw-string Python constants rendered with `render_template_string`. Editing the frontend means editing these strings in `app.py`. The shared dark theme (CSS custom properties for `--bg`, `--accent`, etc.) is duplicated between `ANALYZER_HTML` and `SHARED_CSS` — keep them in sync if you change theme tokens.
- Service strings use the `proto-port` format (`tcp-443`, `udp-53`) and port ranges as `proto-start-end` (`tcp-80-82`). `build_service_string`, `compress_services`, and `cp_add_service` all assume this shape.
- All CSV reads decode as `utf-8-sig` to tolerate BOM-prefixed exports.
- `sample_traffic.csv` and `sample_policy.csv` are the canonical test inputs for the two engines.
