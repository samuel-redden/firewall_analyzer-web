# Firewall Rule Analyzer

Analyzes firewall hit logs (CSV) to generate least-permissive replacement rules,
automatically collapsing IPs into subnets where >50% of the /24 is present.

---

## Files

| File | Purpose |
|------|---------|
| `app.py` | Flask application — the entire tool |
| `firewall_analyzer.spec` | PyInstaller build spec |
| `sample_traffic.csv` | Example input for testing |
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

## CSV Input Format

| Column | Description |
|--------|-------------|
| `src` | Source IP address |
| `dst` | Destination IP address |
| `transport` | TCP or UDP |
| `action` | allowed (informational, ignored) |
| `service` | Port number |
| `count` | Number of hits for this flow |

---

## Rule Design Logic

- **Minimum hits:** Flows with `count < 2` are excluded (noise filtering)
- **Subnet summarization:** If >50% of IPs in a /24 subnet appear in src or dst, the rule uses the subnet (e.g., `10.0.68.0/24`) instead of individual IPs
- **Least permissive:** Rules are scoped to exact destination IPs and specific ports/protocols
- **Output format:** `Source, Destination, Service` (e.g., `10.0.68.0/24, 10.27.221.240, tcp-2443`)

---

## Output CSV Example

```
Source,Destination,Service
10.0.68.0/24,10.27.221.240,tcp-2443
192.168.10.5,10.27.221.100,tcp-443
192.168.10.8,10.27.221.100,tcp-443
192.168.20.1,10.27.221.100,tcp-443
172.16.5.10,10.27.221.100,udp-53
172.16.5.20,10.27.221.100,udp-53
10.1.1.5,10.50.0.20,tcp-8080
10.1.1.6,10.50.0.20,tcp-8080
```
