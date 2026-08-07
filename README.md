# Firewall Rule Analyzer

A local web toolbox for firewall engineers. It runs on your machine, opens a
browser tab automatically, and provides two tools from a single landing page:

- **Rule Analyzer** — analyzes firewall hit logs (CSV) to generate
  least-permissive replacement rules, and can emit a Check Point `mgmt_cli`
  object-creation script.
- **Policy Scanner** — audits a SecureTrack-style policy export against eight
  severity-rated checks, scores the policy out of 1000 on a speedometer
  dashboard, recommends uni-directional splits for bi-directional rules, and
  exports findings as CSVs or polished HTML reports.

---

## Files

| File | Purpose |
|------|---------|
| `app.py` | Flask application — the entire tool (engines + embedded UI) |
| `firewall_analyzer.spec` | PyInstaller build spec |
| `sample_traffic.csv` | Example input for the Rule Analyzer |
| `sample_policy.csv` | Example input for the Policy Scanner |
| `all_networks*.csv` (optional) | Subnet name map files staged next to `app.py` |
| `README.md` | This file |

---

## Running Without Building (Python)

If Python 3.8+ is installed:

```bash
pip install flask
python app.py
```

A browser tab will open automatically at http://127.0.0.1:5000

---

## Building the .exe (Windows)

### Prerequisites

1. Install Python 3.8+ from https://python.org
   ✅ Check "Add Python to PATH" during install

2. Open Command Prompt and install dependencies:

```cmd
pip install flask pyinstaller
```

### Build

```cmd
cd path\to\firewall_analyzer
pyinstaller firewall_analyzer.spec
```

The `.exe` will be created at:

```
dist\FirewallRuleAnalyzer.exe
```

### Distribute

You only need to ship `dist\FirewallRuleAnalyzer.exe` — it is fully self-contained.
No Python installation is required on the target machine.

---

# Tool 1: Rule Analyzer

Takes a traffic-hit CSV and emits the least-permissive rule set that covers the
observed traffic.

## CSV Input Format

| Column | Description |
|--------|-------------|
| `src` | Source IP address |
| `dst` | Destination IP address |
| `transport` | TCP or UDP |
| `action` | allowed (informational, ignored) |
| `service` | Port number |
| `count` | Number of hits for this flow |

## Output Detail

Pick how much the generated rules are consolidated before you hit **Analyze**.
The choice applies to the on-screen table and to both downloads.

- **Consolidated** (default) — summarizes sources into named or /24 subnets,
  compresses ports into ranges, and merges rules that share a destination and
  service. Fewest rules.
- **Specific** — exact source and destination addresses, every port listed on
  its own, and one rule per source→destination pair. Most rules, but nothing
  is widened beyond the traffic that was actually observed.

## Rule Design Logic

- **Minimum hits:** Flows with `count < 2` are excluded (noise filtering)
- **Subnet summarization** *(Consolidated only)*: If ≥50% of IPs in a /24
  subnet appear (or ≥10 distinct IPs), the rule uses the subnet
  (e.g., `10.0.68.0/24`) instead of individual IPs
- **Port compression** *(Consolidated only)*: Consecutive ports collapse into
  ranges (`tcp-80-82`). In either mode, rules needing 6+ service objects are
  flagged for an object group
- **Least permissive:** Rules are scoped to exact destination IPs and specific
  ports/protocols
- **Output format:** `Source, Destination, Service`
  (e.g., `10.0.68.0/24, 10.27.221.240, tcp-2443`)

## Outputs

- **Rules CSV** — the generated replacement rules
- **Check Point script** — a `mgmt_cli` bash script that creates the
  host/network/service/service-group objects for the rules (it deliberately
  does **not** create the access rules themselves)

---

# Tool 2: Policy Scanner

Reads a SecureTrack-style policy export CSV (the first 3 lines are report
metadata and are skipped; line 4 is the header) and audits every rule.

## Audit Checks and Scoring

The policy starts at **1000 points** and every individual finding deducts its
severity's points (a rule can be flagged by several checks at once; the score
floors at 0).

| Check | Severity | Deduction |
|-------|----------|-----------|
| `Any` as source, destination, or service (ALLOW rules only) | Critical | −6 |
| Overly permissive **enabled** ALLOW rule (network /16 or wider, broad service such as `ALL_*` or a >1000-port range, or >50 objects in one field) | High | −4 |
| Bi-directional (Source == Destination) | Medium | −2 |
| Missing logging (`Logged` column not true) | Medium | −2 |
| Missing comment | Low | −1 |
| Unused (never hit, or last hit > 180 days ago) | Low | −1 |
| Disabled | Low | −1 |
| Shadowed (`Shadowing Status` is shadowed) | Low | −1 |

### Exemptions

Two kinds of rule only *look* permissive and are not penalized:

**1. The catch-all cleanup rule** — Source `Any`, Destination `Any`, Service
`Any`, and a deny action (`deny`/`drop`/`reject`/`block`). Every policy is
expected to end with one, so it is skipped before any check runs, never appears
in a finding list, and costs no points. A rule that is `Any`/`Any`/`Any` but
**allows** traffic is still Critical, and a rule with a blank/unrecognized
Action is never treated as a cleanup rule.

**2. Any-source DHCP/BOOTP rules** — a DHCP client broadcasts before it holds an
address, so `Any` as the *source* of a DHCP/BOOTP rule is unavoidable rather
than a defect. When the Source contains `Any` and **any** Service object names
DHCP or BOOTP (`DHCP`, `dhcp-relay`, `bootps`, `bootpc`, …), the **source side**
of the Critical `Any` and High overly-permissive checks is waived. Everything
else about the rule is still audited — an `Any` **destination**, a broad
destination or service, and every hygiene check (comment, logging, unused,
shadowed, disabled) all still apply. Unlike the cleanup rule, the row is still
counted as audited and can still appear in findings. Because both waived checks
apply to ALLOW rules only, a deny DHCP rule has nothing waived and is not
reported as a waiver.

The scanner reports how many rules it actually scored, plus the cleanup-exempt
and DHCP-waiver counts, on the score line and in both HTML reports.

## Score Dashboard

- **Speedometer gauge** with the score, needle, and color-banded track:
  above **950** green (Excellent), above **800** yellow (Good),
  **600–800** orange (At Risk), below **600** red (Critical)
- **Device name(s)** from the export, shown in bold and colored by the
  overall score band
- **Category cards** — click a category to view its flagged rules, each with
  an explanation of exactly why it was flagged

## Exports

- **Per-category CSV** or **all-findings CSV** worklists
- **Executive Report** — a self-contained, print-ready HTML summary for
  leadership: score, findings at a glance, plain-language risk narrative, and
  recommended next steps
- **Engineer Cleanup Plan** — a self-contained HTML runbook: prioritized
  remediation phases with step-by-step guidance and the affected rules per
  phase. Its rule tables are wide, so it is set to print **landscape**

## Bi-Directional Split Recommendations

Select flagged bi-directional rules and click **Recommendations** to generate
least-permissive uni-directional replacements (objects are clustered by shared
/16 or common name prefix), then download them as CSV.

---

## Subnet Name Map (optional)

Stage one or more `all_networks*.csv` files (header: `CIDR,NAME`) next to
`app.py` (or the `.exe`). The Rule Analyzer uses the names for display labels
and Check Point object names; the longest-prefix match wins, and named subnets
take priority over automatic /24 aggregation. The files are read from disk on
each request — no upload needed. The map is only applied in **Consolidated**
output mode; **Specific** mode deliberately keeps the raw addresses.
