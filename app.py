import os
import io
import csv
import glob
import json
import re
import threading
import webbrowser
import ipaddress
from collections import defaultdict
from flask import Flask, request, jsonify, send_file, render_template_string

app = Flask(__name__)

# ─────────────────────────────────────────────
#  FIREWALL RULE ANALYSIS ENGINE
# ─────────────────────────────────────────────

def parse_csv(file_stream):
    """Parse the uploaded CSV, return list of dicts."""
    content = file_stream.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    rows = []
    for row in reader:
        # Normalize column names (strip whitespace)
        clean = {k.strip().lower(): v.strip() for k, v in row.items()}
        rows.append(clean)
    return rows


def filter_rows(rows):
    """Remove rows with count < 2."""
    filtered = []
    for r in rows:
        try:
            count = int(r.get("count", 0))
        except ValueError:
            count = 0
        if count >= 2:
            filtered.append(r)
    return filtered


# Subnet name maps are staged alongside this script as one or more CSV files
# whose names start with "all_networks" (e.g. all_networks_10_0_0_0.csv).
# Each file has a "CIDR,NAME" header row.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
SUBNET_FILE_PREFIX = "all_networks"


class SubnetMap:
    """
    Holds the staged subnet name map. Behaves like the old list of
    (ip_network, name) tuples — it is iterable (most-specific first), supports
    len() and truthiness — so existing call sites keep working. On top of that
    it provides match(), a longest-prefix lookup that is ~O(distinct prefix
    lengths) instead of a linear scan over every network.

    The lookup groups networks into per-(version, prefix-length) dicts keyed by
    the network address as an int. To match an IP we walk the distinct prefix
    lengths from longest to shortest, mask the IP to each length, and do a dict
    lookup — the first hit is the most-specific match.
    """

    def __init__(self, entries):
        # entries: list of (ip_network, name), already sorted most-specific first.
        self.entries = entries
        # version -> list of prefix lengths present, longest first
        self._plens = {4: [], 6: []}
        # version -> prefix_len -> {network_int: (net, name)}
        self._buckets = {4: {}, 6: {}}
        # version -> prefix_len -> mask int
        self._masks = {4: {}, 6: {}}
        bits = {4: 32, 6: 128}
        for net, name in entries:
            v = net.version
            plen = net.prefixlen
            bucket = self._buckets[v].get(plen)
            if bucket is None:
                bucket = self._buckets[v][plen] = {}
                self._masks[v][plen] = ((1 << plen) - 1) << (bits[v] - plen)
            # First entry wins for an exact-duplicate CIDR, matching the old
            # linear scan which returned the first match in sorted order.
            bucket.setdefault(int(net.network_address), (net, name))
        for v in (4, 6):
            self._plens[v] = sorted(self._buckets[v].keys(), reverse=True)

    def match(self, ip_obj):
        """Return (network, name) for the most-specific named subnet containing ip_obj, or None."""
        v = ip_obj.version
        ip_int = int(ip_obj)
        buckets = self._buckets[v]
        masks = self._masks[v]
        for plen in self._plens[v]:
            hit = buckets[plen].get(ip_int & masks[plen])
            if hit is not None:
                return hit
        return None

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    def __bool__(self):
        return bool(self.entries)


def clean_subnet_name(name):
    """Collapse runs of 2+ hyphens to a single '-' (e.g. 'NCZ---Maria-Parham'
    -> 'NCZ-Maria-Parham'). The all_networks exports use '---' as a separator;
    we normalize it for both the web GUI display and the file exports."""
    return re.sub(r"-{2,}", "-", name)


def load_staged_subnet_map():
    """
    Build the subnet name map from every CSV staged in the app directory whose
    filename starts with "all_networks". Each file is a CSV with CIDR and NAME
    columns, e.g.:
        CIDR,NAME
        10.14.216.0/24,TNF-Hillside-VLAN-2
    Returns a SubnetMap of (ip_network, name_str) entries sorted most-specific
    first so the best (longest-prefix) match wins.
    """
    subnets = []
    pattern = os.path.join(APP_DIR, SUBNET_FILE_PREFIX + "*.csv")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, encoding="utf-8-sig", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    clean = {k.strip().lower(): (v or "").strip()
                             for k, v in row.items() if k}
                    cidr = clean.get("cidr", "")
                    name = clean.get("name", "")
                    # A row needs both a CIDR and a name; a nameless entry would
                    # otherwise produce an empty-named Check Point object later.
                    if not cidr or not name:
                        continue
                    name = clean_subnet_name(name)
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        continue
                    subnets.append((net, name))
        except OSError:
            continue
    # Most-specific prefix first so best-match wins
    subnets.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return SubnetMap(subnets)


def match_named_subnet(ip_obj, subnet_map):
    """Return (network, name) for the most-specific named subnet containing ip_obj, or None."""
    matcher = getattr(subnet_map, "match", None)
    if matcher is not None:
        return matcher(ip_obj)
    # Fallback for a plain list of (net, name) tuples.
    for net, name in subnet_map:
        if ip_obj in net:
            return net, name
    return None


def normalize_ip(ip_str):
    """Return an ipaddress object or None."""
    try:
        return ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None


def subnet_key(ip_obj, prefix_len=24):
    """Return the /24 (or given prefix) network containing the IP."""
    net = ipaddress.ip_network(f"{ip_obj}/{prefix_len}", strict=False)
    return net


def summarize_ips(ip_list, threshold=0.50, min_count=10, subnet_map=None):
    """
    Given a list of IP strings, collapse to named subnets (from subnet_map)
    or /24 subnets where more than `threshold` fraction of addresses are present,
    OR where at least `min_count` distinct IPs of the /24 are present.
    Named subnets take priority over /24 aggregation.
    Returns a list of strings (individual IPs or CIDR subnets).
    """
    subnet_map = subnet_map or []

    parsed = []
    for ip_str in ip_list:
        obj = normalize_ip(ip_str)
        if obj:
            parsed.append(obj)

    if not parsed:
        return list(set(ip_list))

    result = []
    unmatched = []

    # First pass: match against named subnets
    for ip in parsed:
        match = match_named_subnet(ip, subnet_map)
        if match:
            net, _ = match
            result.append(str(net))
        else:
            unmatched.append(ip)

    # Second pass: apply /24 threshold to IPs not covered by a named subnet
    subnet_members = defaultdict(set)
    for ip in unmatched:
        net = subnet_key(ip)
        subnet_members[net].add(ip)

    for net, members in subnet_members.items():
        total_hosts = max(net.num_addresses - 2, 1)
        ratio = len(members) / total_hosts
        if ratio >= threshold or len(members) >= min_count:
            result.append(str(net))
        else:
            for ip in members:
                result.append(str(ip))

    return sorted(set(result))


def build_service_string(transport, port):
    """Format service as tcp-PORT or udp-PORT."""
    proto = transport.strip().lower()
    return f"{proto}-{port.strip()}"


def compress_services(svc_set, object_group_threshold=6):
    """
    Given a set of service strings like {'tcp-80', 'tcp-81', 'tcp-82', 'udp-53'},
    return a tuple (service_str, needs_object_group).

    Rules:
      - Group by protocol.
      - Within each protocol, collapse consecutive port numbers into ranges
        e.g. tcp-80, tcp-81, tcp-82 -> tcp-80-82
      - Count resulting entries (individual ports + ranges each count as 1).
      - If total entries across all protocols > object_group_threshold,
        set needs_object_group = True.
      - service_str is the comma-joined list of compressed entries.
    """
    proto_ports = defaultdict(list)
    for svc in svc_set:
        parts = svc.split("-", 1)
        if len(parts) != 2:
            continue
        proto = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            continue
        proto_ports[proto].append(port)

    compressed_entries = []

    for proto in sorted(proto_ports.keys()):
        ports = sorted(set(proto_ports[proto]))
        ranges = []
        start = ports[0]
        end   = ports[0]
        for p in ports[1:]:
            if p == end + 1:
                end = p
            else:
                ranges.append((start, end))
                start = end = p
        ranges.append((start, end))

        for (s, e) in ranges:
            if s == e:
                compressed_entries.append(f"{proto}-{s}")
            else:
                compressed_entries.append(f"{proto}-{s}-{e}")

    needs_object_group = len(compressed_entries) > object_group_threshold

    return ", ".join(compressed_entries), needs_object_group


def analyze(rows, subnet_map=None):
    """
    Core analysis:
      1. Collect all (transport, port) pairs per (src_set, dst).
      2. Summarize src IPs into named subnets (subnet_map) or /24 subnets where >50% present.
      3. Merge all services for the same (summarized_src, dst) into one rule.
    Returns list of rule dicts: {source, destination, service}
    """
    subnet_map = subnet_map or []

    # Pass 1 — collect src IPs and services per dst
    # key = dst  →  {src: set of (transport, port)}
    dst_src_services = defaultdict(lambda: defaultdict(set))

    def resolve_addr(addr_str):
        """Collapse addr to its named subnet CIDR if it matches, otherwise return as-is."""
        obj = normalize_ip(addr_str)
        if obj and subnet_map:
            match = match_named_subnet(obj, subnet_map)
            if match:
                return str(match[0])
        return addr_str

    for r in rows:
        src       = r.get("src", "").strip()
        dst       = r.get("dst", "").strip()
        transport = r.get("transport", "tcp").strip().lower()
        service   = r.get("service", "").strip()

        if not src or not dst or not service:
            continue

        dst_src_services[resolve_addr(dst)][src].add((transport, service))

    # Pass 2 — for each dst, summarize src IPs, then merge services
    # key = (summarized_src, dst)  →  set of service strings
    merged = defaultdict(set)

    for dst, src_map in dst_src_services.items():
        all_srcs = list(src_map.keys())
        summarized = summarize_ips(all_srcs, subnet_map=subnet_map)

        # Build a reverse map: original_ip → summarized_entry
        ip_to_summary = {}
        for orig in all_srcs:
            obj = normalize_ip(orig)
            if obj:
                # Named subnet takes priority
                if subnet_map:
                    match = match_named_subnet(obj, subnet_map)
                    if match:
                        ip_to_summary[orig] = str(match[0])
                        continue
                # Fall back to /24 collapse check
                net_str = str(subnet_key(obj))
                ip_to_summary[orig] = net_str if net_str in summarized else orig
            else:
                ip_to_summary[orig] = orig

        # Accumulate services under the summarized source key
        for orig_src, svcs in src_map.items():
            summary_src = ip_to_summary.get(orig_src, orig_src)
            for transport, port in svcs:
                svc_str = build_service_string(transport, port)
                merged[(summary_src, dst)].add(svc_str)

    # Build a quick CIDR→name lookup for display formatting
    cidr_to_name = {str(net): name for net, name in subnet_map}

    def display_addr(addr):
        name = cidr_to_name.get(addr)
        return "{}-{}".format(name, addr) if name else addr

    # Pass 3 — build per-(src, dst) rules with compressed services
    raw_rules = []
    for (src, dst), svcs in merged.items():
        service_str, needs_og = compress_services(svcs)
        raw_rules.append({
            "source":              src,
            "destination":         dst,
            "source_display":      display_addr(src),
            "destination_display": display_addr(dst),
            "service":             service_str,
            "object_group":        needs_og
        })

    # Pass 4 — group rules that share the same destination + service into one rule
    dst_svc_map = defaultdict(list)
    for rule in raw_rules:
        dst_svc_map[(rule["destination"], rule["service"])].append(rule)

    rules = []
    for (dst, svc), group in dst_svc_map.items():
        group.sort(key=lambda r: r["source"])
        sources         = [r["source"]         for r in group]
        sources_display = [r["source_display"]  for r in group]
        rules.append({
            "source":              ", ".join(sources_display),
            "sources":             sources,
            "destination":         dst,
            "destination_display": group[0]["destination_display"],
            "service":             svc,
            "object_group":        any(r["object_group"] for r in group)
        })

    rules.sort(key=lambda r: (r["destination"], r["source"]))
    return rules


def rules_to_csv(rules):
    """Convert list of rule dicts to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Source", "Destination", "Service", "Notes"])
    for r in rules:
        note = "RECOMMEND OBJECT GROUP - too many service entries" if r.get("object_group") else ""
        writer.writerow([r.get("source_display", r["source"]), r.get("destination_display", r["destination"]), r["service"], note])
    return output.getvalue()




# ─────────────────────────────────────────────
#  CHECKPOINT MGMT CLI SCRIPT GENERATOR
# ─────────────────────────────────────────────

def safe_name(value):
    return (value.replace("/", "_").replace(".", "_")
                 .replace("-", "_").replace(",", "").replace(" ", ""))


def cp_add_host_or_network(addr, created, name_map=None):
    lines = []
    if name_map and addr in name_map:
        name = safe_name(name_map[addr])
    else:
        name = "obj_" + safe_name(addr)
    if name in created:
        return lines, name
    created.add(name)
    try:
        net = ipaddress.ip_network(addr, strict=False)
        if net.prefixlen == 32:
            lines.append(
                'mc add host name "{}" ip-address "{}" --format json'.format(name, str(net.network_address))
            )
        else:
            lines.append(
                'mc add network name "{}" subnet "{}" subnet-mask "{}" --format json'.format(
                    name, str(net.network_address), str(net.netmask))
            )
    except ValueError:
        lines.append('mc add host name "{}" ip-address "{}" --format json'.format(name, addr))
    return lines, name


def cp_add_service(svc_token, created):
    lines = []
    parts = svc_token.strip().split("-")
    if len(parts) < 2:
        return lines, svc_token
    proto = parts[0].lower()
    cp_type = "tcp" if proto == "tcp" else "udp"
    if len(parts) == 2:
        port = parts[1]
        name = "svc_{}_{}".format(proto, port)
        if name not in created:
            created.add(name)
            lines.append('mc add service-{} name "{}" port "{}" --format json'.format(cp_type, name, port))
    elif len(parts) == 3:
        p_start, p_end = parts[1], parts[2]
        name = "svc_{}_{}_{}".format(proto, p_start, p_end)
        if name not in created:
            created.add(name)
            lines.append('mc add service-{} name "{}" port "{}-{}" --format json'.format(
                cp_type, name, p_start, p_end))
    else:
        name = "svc_" + safe_name(svc_token)
    return lines, name


def generate_checkpoint_script(rules, subnet_map=None):
    created_objs = set()
    created_svcs = set()

    # Build friendly name lookup: {cidr_str: name}
    name_map = {}
    if subnet_map:
        for net, name in subnet_map:
            name_map[str(net)] = name

    header = [
        "#!/bin/bash",
        "# ============================================================",
        "# Check Point mgmt_cli Automation Script",
        "# Generated by Firewall Rule Analyzer",
        "# NOTE: Access rules are NOT included — add rules manually.",
        "# ============================================================",
        "",
        "# --- UPDATE THESE BEFORE RUNNING ---",
        'MGMT_HOST="192.168.1.1"   # Management server IP or hostname',
        'MGMT_USER="admin"',
        'MGMT_PASS="YourPasswordHere"',
        "",
        "# --- Login and capture session ID ---",
        'SID=$(mgmt_cli login user "$MGMT_USER" password "$MGMT_PASS" \\',
        '      management "$MGMT_HOST" --format json \\',
        "      | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"sid\"])')",
        "",
        'echo "Logged in. Session: $SID"',
        "",
        "# Wrapper — every call uses our session ID",
        'function mc() { mgmt_cli --session-id "$SID" "$@"; }',
        "",
    ]

    addr_sec = [
        "# ============================================================",
        "# SECTION 1 — Network Objects (Hosts & Networks)",
        "# ============================================================",
        "",
    ]
    svc_sec = [
        "# ============================================================",
        "# SECTION 2 — Service Objects (TCP/UDP ports and ranges)",
        "# ============================================================",
        "",
    ]
    grp_sec = [
        "# ============================================================",
        "# SECTION 3 — Service Groups",
        "# ============================================================",
        "",
    ]

    for rule_num, rule in enumerate(rules, start=1):
        sources = rule.get("sources") or [rule["source"]]
        dst   = rule["destination"]
        svc   = rule["service"]
        is_og = rule.get("object_group", False)

        # Address objects — one per source, plus destination
        for src in sources:
            src_out, _ = cp_add_host_or_network(src, created_objs, name_map)
            addr_sec += src_out
        _, dst_name = cp_add_host_or_network(dst, created_objs, name_map)

        # Service objects
        tokens = [t.strip() for t in svc.split(",") if t.strip()]
        svc_names = []
        for tok in tokens:
            tok_out, tok_name = cp_add_service(tok, created_svcs)
            svc_sec += tok_out
            svc_names.append(tok_name)

        src_disp = rule.get("source", sources[0])
        dst_disp = rule.get("destination_display", dst)

        # Service group (whenever >1 service token)
        if len(svc_names) > 1:
            grp_name = "svcgrp_{:03d}_to_{}".format(rule_num, dst_name)
            if len(grp_name) > 55:
                grp_name = "svcgrp_rule_{:03d}".format(rule_num)
            member_args = " ".join(
                'members.{} "{}"'.format(i + 1, n) for i, n in enumerate(svc_names)
            )
            og_note = "  # <<< OBJECT GROUP RECOMMENDED" if is_og else ""
            grp_sec.append("# Rule {}: {} -> {}".format(rule_num, src_disp, dst_disp))
            grp_sec.append(
                'mc add service-group name "{}" {} --format json{}'.format(grp_name, member_args, og_note)
            )
            grp_sec.append("")

    footer = [
        "# ============================================================",
        "# SECTION 4 — Publish & Logout",
        "# ============================================================",
        "",
        'echo "Publishing changes..."',
        "mc publish --format json",
        "",
        "mc logout --format json",
        'echo "Done. All objects created and published."',
        "",
    ]

    all_lines = (
        header
        + addr_sec + [""]
        + svc_sec  + [""]
        + grp_sec  + [""]
        + footer
    )
    return "\n".join(all_lines)

# ─────────────────────────────────────────────
#  POLICY SCANNER ENGINE
# ─────────────────────────────────────────────

# Spreadsheet column letters (1-based) → 0-based index.
#   Source      = column R = index 17
#   Destination = column U = index 20
SRC_COL_INDEX = 17
DST_COL_INDEX = 20

# Columns surfaced in the bi-directional report, by header name with a
# fixed-position fallback for this firewall export format.
_REPORT_FIELDS = [
    ("Seq No.",     0),
    ("Rule Name",   13),
    ("Policy Name", 5),
    ("Source",      SRC_COL_INDEX),
    ("Destination", DST_COL_INDEX),
    ("Service",     22),
    ("Action",      26),
]


def parse_policy_csv(file_stream):
    """
    Parse a SecureTrack-style policy export.

    The first 3 lines are report metadata and are ignored. Line 4 is the
    header row; everything after is rule data. Returns (header, data_rows)
    where each row is a list of cell strings.
    """
    content = file_stream.read().decode("utf-8-sig")
    # csv.reader handles quoted fields containing commas/newlines correctly.
    all_rows = list(csv.reader(io.StringIO(content)))
    # Drop the first 3 metadata lines.
    body = all_rows[3:]
    if not body:
        return [], []
    header = body[0]
    data = [r for r in body[1:] if any(cell.strip() for cell in r)]
    return header, data


def _col_index(header, name, default_idx):
    """Find a column by (case-insensitive) header name, else fall back to a fixed index."""
    target = name.strip().lower()
    for i, h in enumerate(header):
        if h.strip().lower() == target:
            return i
    return default_idx


def _cell(row, idx):
    return row[idx].strip() if idx < len(row) else ""


def scan_bidirectional(header, data):
    """
    Objective 1 — flag rules whose Source (col R) equals their Destination
    (col U). Comparison is trimmed and case-insensitive. Returns a list of
    report dicts, one per flagged rule.
    """
    src_idx = _col_index(header, "Source", SRC_COL_INDEX)
    dst_idx = _col_index(header, "Destination", DST_COL_INDEX)

    # Resolve report field indices once.
    fields = [(label, _col_index(header, label, default)) for label, default in _REPORT_FIELDS]

    flagged = []
    for row in data:
        src = _cell(row, src_idx)
        dst = _cell(row, dst_idx)
        if src and dst and src.lower() == dst.lower():
            flagged.append({label: _cell(row, idx) for label, idx in fields})
    return flagged


def bidirectional_to_csv(flagged):
    """Convert flagged rules to a CSV report string."""
    output = io.StringIO()
    columns = [label for label, _ in _REPORT_FIELDS]
    writer = csv.writer(output)
    writer.writerow(columns)
    for r in flagged:
        writer.writerow([r.get(c, "") for c in columns])
    return output.getvalue()


# ─────────────────────────────────────────────
#  UNI-DIRECTIONAL SPLIT RECOMMENDATIONS
# ─────────────────────────────────────────────
#
# Given a bi-directional rule, propose the set of least-permissive
# uni-directional rules that together replace it. To keep the rule count as
# low as possible while staying specific, the objects on each side are
# clustered by (a) shared IP /16 — "same /16 or smaller" — and (b) common
# leading name token. Each (source-cluster → destination-cluster) pair, in
# both directions, becomes one proposed rule.

# Pulls an IPv4 (with an optional mask written as 'm24' or '/24') out of an
# object name such as 'HCA-10.0.0.0m8', or a bare '10.45.2.0/24'.
_IP_IN_NAME_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[m/](\d{1,2}))?")


def _split_objects(cell):
    """
    Split a Source/Destination cell into individual objects. A single rule
    may list several objects in one cell separated by newlines, semicolons,
    or commas (commas only survive to here when the cell was CSV-quoted).
    """
    if not cell:
        return []
    return [p.strip() for p in re.split(r"[;,\n]+", cell) if p.strip()]


def _object_network(obj):
    """Return the ipaddress network embedded in an object name, or None."""
    m = _IP_IN_NAME_RE.search(obj)
    if not m:
        return None
    ip, mask = m.group(1), m.group(2)
    try:
        return ipaddress.ip_network(f"{ip}/{mask}" if mask else f"{ip}/32", strict=False)
    except ValueError:
        return None


def _name_prefix(obj):
    """Leading name token (text before the first '-', '_', or digit), lower-cased."""
    return re.split(r"[-_]|\d", obj.strip(), maxsplit=1)[0].lower()


def _slash16(net):
    """The /16 containing a network's address — the grouping key for IP scheme."""
    return ipaddress.ip_network(f"{net.network_address}/16", strict=False)


def _objects_related(a, b):
    """
    Two objects can share a uni-directional rule when they sit in the same
    /16 (or a tighter subnet) OR share a common leading name token.
    """
    na, nb = _object_network(a), _object_network(b)
    if na is not None and nb is not None and _slash16(na) == _slash16(nb):
        return True
    pa, pb = _name_prefix(a), _name_prefix(b)
    return bool(pa) and pa == pb


def _cluster_objects(objs):
    """
    Greedily group related objects so each cluster becomes one rule side.
    Returns a list of (members, basis) tuples; 'basis' explains the grouping.
    """
    clusters = []
    for o in objs:
        for c in clusters:
            if any(_objects_related(o, m) for m in c):
                c.append(o)
                break
        else:
            clusters.append([o])

    result = []
    for members in clusters:
        nets = [n for n in (_object_network(m) for m in members) if n is not None]
        if len(members) == 1:
            basis = "single object"
        elif len(nets) == len(members) and len({_slash16(n) for n in nets}) == 1:
            basis = f"same /16: {_slash16(nets[0])}"
        else:
            basis = f"name: {_name_prefix(members[0])}*"
        result.append((members, basis))
    return result


# Columns surfaced in the recommendation report.
_RECOMMEND_FIELDS = ["From Rule", "Direction", "Source", "Destination",
                     "Service", "Action", "Grouping Basis"]


def recommend_split(rule):
    """
    Propose least-permissive uni-directional rules that together replace one
    bi-directional rule. Returns a list of report dicts keyed by
    _RECOMMEND_FIELDS.
    """
    src_clusters = _cluster_objects(_split_objects(rule.get("Source", "")))
    dst_clusters = _cluster_objects(_split_objects(rule.get("Destination", "")))
    service = rule.get("Service", "") or "ANY"
    action = rule.get("Action", "") or "ALLOW"
    origin = rule.get("Rule Name") or rule.get("Seq No.") or "(unnamed)"

    proposed = []
    seen = set()
    for label, a_clusters, b_clusters in (
        ("forward", src_clusters, dst_clusters),
        ("reverse", dst_clusters, src_clusters),
    ):
        for a_members, a_basis in a_clusters:
            for b_members, b_basis in b_clusters:
                src = "; ".join(a_members)
                dst = "; ".join(b_members)
                # Drop degenerate self-rules (e.g. when Source == Destination).
                if src.lower() == dst.lower():
                    continue
                key = (src.lower(), dst.lower(), service.lower())
                if key in seen:
                    continue
                seen.add(key)
                basis = a_basis if a_basis == b_basis else f"src {a_basis} / dst {b_basis}"
                proposed.append({
                    "From Rule": origin,
                    "Direction": "A -> B" if label == "forward" else "B -> A",
                    "Source": src,
                    "Destination": dst,
                    "Service": service,
                    "Action": action,
                    "Grouping Basis": basis,
                })
    return proposed


def recommend_for_rules(rules):
    """Flatten split recommendations across several selected rules."""
    out = []
    for r in rules:
        out.extend(recommend_split(r))
    return out


def recommendations_to_csv(proposed):
    """Convert proposed uni-directional rules to a CSV report string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_RECOMMEND_FIELDS)
    for r in proposed:
        writer.writerow([r.get(c, "") for c in _RECOMMEND_FIELDS])
    return output.getvalue()


# ─────────────────────────────────────────────
#  HTML TEMPLATE
# ─────────────────────────────────────────────

ANALYZER_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Firewall Rule Analyzer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #0a0e14;
    --panel:     #0f1520;
    --border:    #1e2d42;
    --accent:    #00d4ff;
    --accent2:   #ff6b35;
    --text:      #c8d8e8;
    --muted:     #4a6080;
    --success:   #00ff9d;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Syne', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Animated grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  /* Glow orbs */
  body::after {
    content: '';
    position: fixed;
    width: 600px; height: 600px;
    top: -200px; left: -200px;
    background: radial-gradient(circle, rgba(0,212,255,0.07) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
  }

  .orb2 {
    position: fixed;
    width: 400px; height: 400px;
    bottom: -100px; right: -100px;
    background: radial-gradient(circle, rgba(255,107,53,0.06) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
  }

  .container {
    position: relative;
    z-index: 1;
    max-width: 1100px;
    margin: 0 auto;
    padding: 40px 24px;
  }

  /* ── Header ── */
  header {
    display: flex;
    align-items: center;
    gap: 20px;
    margin-bottom: 48px;
  }

  .logo-mark {
    width: 52px; height: 52px;
    border: 2px solid var(--accent);
    display: grid;
    place-items: center;
    position: relative;
    flex-shrink: 0;
  }
  .logo-mark::before {
    content: '';
    position: absolute;
    inset: 4px;
    border: 1px solid rgba(0,212,255,0.3);
  }
  .logo-mark svg { color: var(--accent); }

  .header-text h1 {
    font-size: 1.8rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    background: linear-gradient(90deg, #fff 0%, var(--accent) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .header-text p {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-top: 2px;
  }

  /* ── Cards ── */
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 32px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    opacity: 0.5;
  }

  .card-label {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .card-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  /* ── Drop zone ── */
  #dropzone {
    border: 1px dashed var(--border);
    padding: 52px 32px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s;
    position: relative;
  }
  #dropzone:hover, #dropzone.drag-over {
    border-color: var(--accent);
    background: rgba(0,212,255,0.04);
  }
  #dropzone input[type=file] {
    position: absolute;
    inset: 0;
    opacity: 0;
    cursor: pointer;
    width: 100%;
    height: 100%;
  }
  .drop-icon {
    font-size: 2.5rem;
    margin-bottom: 12px;
    filter: grayscale(0.3);
  }
  .drop-title {
    font-size: 1rem;
    font-weight: 700;
    color: #fff;
    margin-bottom: 6px;
  }
  .drop-sub {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
  }
  #file-name {
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--success);
    margin-top: 16px;
    min-height: 1.2em;
  }

  /* ── Button ── */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 14px 32px;
    font-family: var(--mono);
    font-size: 0.82rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    border: none;
    cursor: pointer;
    transition: all 0.2s;
    position: relative;
    overflow: hidden;
  }
  .btn-primary {
    background: var(--accent);
    color: var(--bg);
    font-weight: 700;
  }
  .btn-primary:hover:not(:disabled) {
    background: #fff;
    box-shadow: 0 0 30px rgba(0,212,255,0.4);
  }
  .btn-primary:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
  .btn-secondary {
    background: transparent;
    color: var(--success);
    border: 1px solid var(--success);
  }
  .btn-secondary:hover {
    background: rgba(0,255,157,0.08);
    box-shadow: 0 0 20px rgba(0,255,157,0.2);
  }
  .btn-checkpoint {
    background: transparent;
    color: #f0a500;
    border: 1px solid #f0a500;
  }
  .btn-checkpoint:hover {
    background: rgba(240,165,0,0.08);
    box-shadow: 0 0 20px rgba(240,165,0,0.25);
  }

  .actions { display: flex; gap: 12px; margin-top: 24px; flex-wrap: wrap; }

  /* ── Status bar ── */
  #status-bar {
    display: none;
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 12px 16px;
    border: 1px solid var(--border);
    margin-top: 16px;
    align-items: center;
    gap: 10px;
    color: var(--muted);
  }
  #status-bar.active { display: flex; }
  #status-bar.error  { border-color: var(--accent2); color: var(--accent2); }
  #status-bar.ok     { border-color: var(--success); color: var(--success); }

  .spinner {
    width: 14px; height: 14px;
    border: 2px solid rgba(0,212,255,0.2);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Stats row ── */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }
  .stat {
    background: rgba(0,212,255,0.04);
    border: 1px solid var(--border);
    padding: 16px;
    text-align: center;
  }
  .stat-value {
    font-family: var(--mono);
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--accent);
    display: block;
  }
  .stat-label {
    font-family: var(--mono);
    font-size: 0.62rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    margin-top: 4px;
    display: block;
  }

  /* ── Rules table ── */
  .table-wrap {
    overflow-x: auto;
    max-height: 480px;
    overflow-y: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--mono);
    font-size: 0.8rem;
  }
  thead th {
    background: rgba(0,212,255,0.10);
    color: var(--accent);
    text-align: left;
    padding: 12px 16px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-size: 0.65rem;
    position: sticky; top: 0;
    border-bottom: 2px solid var(--accent);
    z-index: 1;
  }

  /* Zebra striping for row separation */
  tbody tr:nth-child(odd)  { background: rgba(255,255,255,0.02); }
  tbody tr:nth-child(even) { background: rgba(0,0,0,0.15); }

  tbody tr {
    border-bottom: 1px solid rgba(0,212,255,0.08);
    transition: background 0.15s;
  }
  tbody tr:hover {
    background: rgba(0,212,255,0.08) !important;
    outline: 1px solid rgba(0,212,255,0.2);
    outline-offset: -1px;
  }

  tbody td {
    padding: 13px 16px;
    color: var(--text);
    vertical-align: middle;
    border-right: 1px solid rgba(0,212,255,0.05);
    line-height: 1.5;
  }
  tbody td:last-child { border-right: none; }

  /* Column colour coding */
  tbody td:nth-child(1) { color: #e8f4ff; font-weight: 600; }
  tbody td:nth-child(2) { color: #b8d4f0; }
  tbody td:nth-child(3) { color: #7ec8a0; font-family: var(--mono); font-size: 0.78rem; }
  tbody td:nth-child(4) { }

  /* Row number gutter */
  tbody td:nth-child(1)::before {
    content: attr(data-row);
    display: inline-block;
    width: 22px;
    font-size: 0.6rem;
    color: var(--muted);
    margin-right: 8px;
    text-align: right;
    opacity: 0.5;
    font-family: var(--mono);
  }

  .tag {
    display: inline-block;
    padding: 2px 8px;
    font-size: 0.65rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .tag-subnet {
    background: rgba(0,212,255,0.12);
    color: var(--accent);
    border: 1px solid rgba(0,212,255,0.3);
  }
  .tag-og {
    background: rgba(255,107,53,0.12);
    color: var(--accent2);
    border: 1px solid rgba(255,107,53,0.4);
    font-size: 0.62rem;
    padding: 3px 8px;
    letter-spacing: 0.06em;
  }
  tbody tr.og-row td:nth-child(1) {
    border-left: 3px solid var(--accent2);
    padding-left: 13px;
  }

  #results { display: none; }
  #results.visible { display: block; }
</style>
</head>
<body>
<div class="orb2"></div>
<div class="container">

  <!-- Header -->
  <header>
    <div class="logo-mark">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <div class="header-text">
      <h1>Firewall Rule Analyzer</h1>
      <p>// rule minimization &amp; summarization engine</p>
    </div>
    <a href="/" style="margin-left:auto;font-family:var(--mono);font-size:0.72rem;letter-spacing:0.12em;text-transform:uppercase;color:var(--muted);text-decoration:none;border:1px solid var(--border);padding:8px 14px;transition:all .2s;" onmouseover="this.style.color='var(--accent)';this.style.borderColor='var(--accent)'" onmouseout="this.style.color='var(--muted)';this.style.borderColor='var(--border)'">&larr; Toolbox</a>
  </header>

  <!-- Upload card -->
  <div class="card">
    <div class="card-label">01 &mdash; Input</div>

    <div id="dropzone">
      <input type="file" id="file-input" accept=".csv">
      <div class="drop-icon">📂</div>
      <div class="drop-title">Drop your CSV file here</div>
      <div class="drop-sub">or click to browse &nbsp;·&nbsp; columns: src, dst, transport, action, service, count</div>
    </div>
    <div id="file-name"></div>

    <div class="actions">
      <button class="btn btn-primary" id="analyze-btn" disabled>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
        Analyze &amp; Build Rules
      </button>
    </div>

    <div id="status-bar">
      <div class="spinner" id="spinner"></div>
      <span id="status-msg">Processing…</span>
    </div>
  </div>

  <!-- Results card -->
  <div id="results" class="card">
    <div class="card-label">02 &mdash; Generated Rules</div>

    <div class="stats-row" id="stats-row"></div>

    <div class="table-wrap">
      <table id="rules-table">
        <thead>
          <tr>
            <th>Source</th>
            <th>Destination</th>
            <th>Service</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody id="rules-tbody"></tbody>
      </table>
    </div>

    <div class="actions">
      <button class="btn btn-secondary" id="download-btn">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
          <polyline points="7 10 12 15 17 10"/>
          <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        Download CSV
      </button>
      <button class="btn btn-checkpoint" id="download-cp-btn">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <rect x="2" y="3" width="20" height="14" rx="2"/>
          <polyline points="8 21 12 17 16 21"/>
          <line x1="12" y1="17" x2="12" y2="3"/>
        </svg>
        Download Check Point Script (.sh)
      </button>
    </div>
  </div>

</div>

<script>
  const fileInput     = document.getElementById('file-input');
  const dropzone      = document.getElementById('dropzone');
  const fileNameEl    = document.getElementById('file-name');
  const analyzeBtn    = document.getElementById('analyze-btn');
  const statusBar     = document.getElementById('status-bar');
  const statusMsg     = document.getElementById('status-msg');
  const spinner       = document.getElementById('spinner');
  const resultsEl     = document.getElementById('results');
  const statsRow      = document.getElementById('stats-row');
  const rulesBody     = document.getElementById('rules-tbody');
  const downloadBtn   = document.getElementById('download-btn');
  const downloadCpBtn = document.getElementById('download-cp-btn');

  let lastRules = [];

  // ── CSV Drag & Drop ──
  dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag-over'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
  dropzone.addEventListener('drop', e => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) { fileInput.files = e.dataTransfer.files; updateFile(); }
  });
  fileInput.addEventListener('change', updateFile);

  function updateFile() {
    if (fileInput.files.length) {
      fileNameEl.textContent = '✓ ' + fileInput.files[0].name;
      analyzeBtn.disabled = false;
    }
  }

  function buildFormData() {
    const fd = new FormData();
    fd.append('file', fileInput.files[0]);
    return fd;
  }

  // ── Analyze ──
  analyzeBtn.addEventListener('click', async () => {
    if (!fileInput.files.length) return;

    setStatus('active', 'Uploading and analyzing traffic data…');
    analyzeBtn.disabled = true;
    resultsEl.classList.remove('visible');

    try {
      const res = await fetch('/analyze', { method: 'POST', body: buildFormData() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Server error');

      lastRules = data.rules;
      renderResults(data);
      setStatus('ok', `Done — ${data.rules.length} rule(s) generated from ${data.total_rows} traffic rows.`);
    } catch (err) {
      setStatus('error', 'Error: ' + err.message);
    } finally {
      analyzeBtn.disabled = false;
    }
  });

  function setStatus(type, msg) {
    statusBar.className = 'active ' + type;
    statusMsg.textContent = msg;
    spinner.style.display = type === 'active' ? 'block' : 'none';
  }

  function renderResults(data) {
    const subnets = data.rules.filter(r => r.source.includes('/')).length;
    const ogCount = data.rules.filter(r => r.object_group).length;
    statsRow.innerHTML = `
      <div class="stat"><span class="stat-value">${data.total_rows}</span><span class="stat-label">Input Rows</span></div>
      <div class="stat"><span class="stat-value">${data.filtered_rows}</span><span class="stat-label">After Filter</span></div>
      <div class="stat"><span class="stat-value">${data.rules.length}</span><span class="stat-label">Rules Generated</span></div>
      <div class="stat"><span class="stat-value">${subnets}</span><span class="stat-label">Subnets Collapsed</span></div>
      ${ogCount > 0 ? `<div class="stat"><span class="stat-value" style="color:var(--accent2)">${ogCount}</span><span class="stat-label">Object Groups Rec.</span></div>` : ''}
    `;

    rulesBody.innerHTML = '';
    data.rules.forEach((r, idx) => {
      const rowNum = String(idx + 1).padStart(2, '0');
      const isSubnet = r.source.includes('/');
      const srcLabel = r.source_display || r.source;
      const dstLabel = r.destination_display || r.destination;
      const tr = document.createElement('tr');
      if (r.object_group) tr.classList.add('og-row');
      tr.innerHTML = `
        <td data-row="${rowNum}">${srcLabel}${isSubnet ? ' <span class="tag tag-subnet">subnet</span>' : ''}</td>
        <td>${dstLabel}</td>
        <td>${r.service}</td>
        <td>${r.object_group ? '<span class="tag tag-og">&#9888; use object-group</span>' : ''}</td>
      `;
      rulesBody.appendChild(tr);
    });

    resultsEl.classList.add('visible');
    resultsEl.scrollIntoView({ behavior: 'smooth' });
  }

  // ── Download helpers ──
  async function triggerDownload(endpoint, filename) {
    if (!fileInput.files.length) return;
    const res = await fetch(endpoint, { method: 'POST', body: buildFormData() });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  downloadBtn.addEventListener('click', () => triggerDownload('/download', 'firewall_rules.csv'));
  downloadCpBtn.addEventListener('click', () => triggerDownload('/download_checkpoint', 'checkpoint_build.sh'));
</script>
</body>
</html>
"""


# Shared theme tokens + base styling used by the home and scanner pages.
SHARED_CSS = r"""
  :root {
    --bg:        #0a0e14;
    --panel:     #0f1520;
    --border:    #1e2d42;
    --accent:    #00d4ff;
    --accent2:   #ff6b35;
    --text:      #c8d8e8;
    --muted:     #4a6080;
    --success:   #00ff9d;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Syne', sans-serif;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }
  body::after {
    content: '';
    position: fixed;
    width: 600px; height: 600px;
    top: -200px; left: -200px;
    background: radial-gradient(circle, rgba(0,212,255,0.07) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
  }
  .orb2 {
    position: fixed;
    width: 400px; height: 400px;
    bottom: -100px; right: -100px;
    background: radial-gradient(circle, rgba(255,107,53,0.06) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
  }
  .container {
    position: relative;
    z-index: 1;
    max-width: 1100px;
    margin: 0 auto;
    padding: 40px 24px;
  }
  header {
    display: flex;
    align-items: center;
    gap: 20px;
    margin-bottom: 48px;
  }
  .logo-mark {
    width: 52px; height: 52px;
    border: 2px solid var(--accent);
    display: grid;
    place-items: center;
    position: relative;
    flex-shrink: 0;
  }
  .logo-mark::before {
    content: '';
    position: absolute;
    inset: 4px;
    border: 1px solid rgba(0,212,255,0.3);
  }
  .logo-mark svg { color: var(--accent); }
  .header-text h1 {
    font-size: 1.8rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    background: linear-gradient(90deg, #fff 0%, var(--accent) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .header-text p {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-top: 2px;
  }
  .back-link {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 0.72rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    text-decoration: none;
    border: 1px solid var(--border);
    padding: 8px 14px;
    transition: all .2s;
  }
  .back-link:hover { color: var(--accent); border-color: var(--accent); }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 32px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    opacity: 0.5;
  }
  .card-label {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .card-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 14px 32px;
    font-family: var(--mono);
    font-size: 0.82rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    border: none;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn-primary { background: var(--accent); color: var(--bg); font-weight: 700; }
  .btn-primary:hover:not(:disabled) { background: #fff; box-shadow: 0 0 30px rgba(0,212,255,0.4); }
  .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-secondary { background: transparent; color: var(--success); border: 1px solid var(--success); }
  .btn-secondary:hover { background: rgba(0,255,157,0.08); box-shadow: 0 0 20px rgba(0,255,157,0.2); }
  .actions { display: flex; gap: 12px; margin-top: 24px; flex-wrap: wrap; }
"""


# ─────────────────────────────────────────────
#  HOME — SECURITY TOOLBOX LANDING
# ─────────────────────────────────────────────

HOME_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Toolbox</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
""" + SHARED_CSS + r"""
  .tools {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 24px;
  }
  .tool {
    display: block;
    text-decoration: none;
    color: inherit;
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 32px;
    position: relative;
    overflow: hidden;
    transition: all 0.2s;
  }
  .tool::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    opacity: 0.5;
  }
  .tool:hover {
    border-color: var(--accent);
    transform: translateY(-3px);
    box-shadow: 0 12px 40px rgba(0,212,255,0.12);
  }
  .tool-icon {
    width: 48px; height: 48px;
    border: 1px solid var(--accent);
    display: grid; place-items: center;
    color: var(--accent);
    margin-bottom: 20px;
  }
  .tool h2 {
    font-size: 1.25rem;
    font-weight: 800;
    color: #fff;
    margin-bottom: 8px;
    letter-spacing: -0.01em;
  }
  .tool p {
    font-size: 0.9rem;
    color: var(--text);
    line-height: 1.5;
    margin-bottom: 20px;
  }
  .tool-go {
    font-family: var(--mono);
    font-size: 0.72rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--accent);
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .tool:hover .tool-go { gap: 14px; }
  .intro {
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--muted);
    letter-spacing: 0.06em;
    margin-bottom: 32px;
  }
</style>
</head>
<body>
<div class="orb2"></div>
<div class="container">

  <header>
    <div class="logo-mark">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <div class="header-text">
      <h1>Security Toolbox</h1>
      <p>// network security utilities</p>
    </div>
  </header>

  <div class="intro">// select a tool to get started</div>

  <div class="tools">

    <a class="tool" href="/analyzer">
      <div class="tool-icon">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
      </div>
      <h2>Firewall Rule Analyzer</h2>
      <p>Turn firewall hit logs into least-permissive replacement rules &mdash; collapses IPs into subnets and generates Check Point build scripts.</p>
      <span class="tool-go">Open analyzer &rarr;</span>
    </a>

    <a class="tool" href="/scanner">
      <div class="tool-icon">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
      </div>
      <h2>Policy Scanner</h2>
      <p>Review a policy export for issues. Flags bi-directional rules, then recommends how to break selected rules into least-permissive uni-directional rules.</p>
      <span class="tool-go">Open scanner &rarr;</span>
    </a>

  </div>

</div>
</body>
</html>
"""


# ─────────────────────────────────────────────
#  POLICY SCANNER PAGE
# ─────────────────────────────────────────────

SCANNER_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Policy Scanner</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
""" + SHARED_CSS + r"""
  #dropzone {
    border: 1px dashed var(--border);
    padding: 52px 32px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s;
    position: relative;
  }
  #dropzone:hover, #dropzone.drag-over {
    border-color: var(--accent);
    background: rgba(0,212,255,0.04);
  }
  #dropzone input[type=file] {
    position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%;
  }
  .drop-icon { font-size: 2.5rem; margin-bottom: 12px; filter: grayscale(0.3); }
  .drop-title { font-size: 1rem; font-weight: 700; color: #fff; margin-bottom: 6px; }
  .drop-sub { font-family: var(--mono); font-size: 0.72rem; color: var(--muted); }
  #file-name { font-family: var(--mono); font-size: 0.78rem; color: var(--success); margin-top: 16px; min-height: 1.2em; }

  #status-bar {
    display: none;
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 12px 16px;
    border: 1px solid var(--border);
    margin-top: 16px;
    align-items: center;
    gap: 10px;
    color: var(--muted);
  }
  #status-bar.active { display: flex; }
  #status-bar.error  { border-color: var(--accent2); color: var(--accent2); }
  #status-bar.ok     { border-color: var(--success); color: var(--success); }
  .spinner {
    width: 14px; height: 14px;
    border: 2px solid rgba(0,212,255,0.2);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .stats-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }
  .stat { background: rgba(0,212,255,0.04); border: 1px solid var(--border); padding: 16px; text-align: center; }
  .stat-value { font-family: var(--mono); font-size: 1.8rem; font-weight: 700; color: var(--accent); display: block; }
  .stat-value.warn { color: var(--accent2); }
  .stat-label { font-family: var(--mono); font-size: 0.62rem; letter-spacing: 0.15em; text-transform: uppercase; color: var(--muted); margin-top: 4px; display: block; }

  .table-wrap { overflow-x: auto; max-height: 480px; overflow-y: auto; }
  table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 0.8rem; }
  thead th {
    background: rgba(0,212,255,0.10);
    color: var(--accent);
    text-align: left;
    padding: 12px 16px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-size: 0.65rem;
    position: sticky; top: 0;
    border-bottom: 2px solid var(--accent);
    z-index: 1;
  }
  tbody tr:nth-child(odd)  { background: rgba(255,255,255,0.02); }
  tbody tr:nth-child(even) { background: rgba(0,0,0,0.15); }
  tbody tr { border-bottom: 1px solid rgba(0,212,255,0.08); transition: background 0.15s; }
  tbody tr:hover { background: rgba(0,212,255,0.08) !important; outline: 1px solid rgba(0,212,255,0.2); outline-offset: -1px; }
  tbody td { padding: 13px 16px; color: var(--text); vertical-align: middle; border-right: 1px solid rgba(0,212,255,0.05); line-height: 1.5; }
  tbody td:last-child { border-right: none; }

  .empty {
    text-align: center;
    padding: 40px;
    font-family: var(--mono);
    font-size: 0.85rem;
    color: var(--success);
  }

  #results { display: none; }
  #results.visible { display: block; }

  /* Row selection */
  td.check-cell, th.check-cell { width: 38px; text-align: center; padding-left: 10px; padding-right: 10px; }
  input[type=checkbox] { width: 15px; height: 15px; accent-color: var(--accent); cursor: pointer; vertical-align: middle; }
  .actions-row { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 4px; }
  #select-info { font-family: var(--mono); font-size: 0.72rem; color: var(--muted); margin: 14px 0 4px; }

  /* Recommendation modal */
  .modal-overlay {
    display: none;
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.72);
    backdrop-filter: blur(2px);
    z-index: 50;
    align-items: flex-start;
    justify-content: center;
    padding: 48px 20px;
    overflow-y: auto;
  }
  .modal-overlay.open { display: flex; }
  .modal {
    background: var(--panel);
    border: 1px solid var(--accent);
    box-shadow: 0 0 50px rgba(0,212,255,0.18);
    max-width: 1040px; width: 100%;
    padding: 28px 28px 24px;
    position: relative;
  }
  .modal h3 { font-family: var(--sans); color: #fff; font-size: 1.25rem; margin-bottom: 6px; }
  .modal .modal-sub { font-family: var(--mono); font-size: 0.72rem; color: var(--muted); margin-bottom: 20px; }
  .modal-close {
    position: absolute; top: 16px; right: 16px;
    background: none; border: 1px solid var(--border); color: var(--muted);
    width: 30px; height: 30px; cursor: pointer; font-family: var(--mono); font-size: 0.9rem;
    transition: all 0.15s;
  }
  .modal-close:hover { color: var(--accent2); border-color: var(--accent2); }
</style>
</head>
<body>
<div class="orb2"></div>
<div class="container">

  <header>
    <div class="logo-mark">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/>
        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
    </div>
    <div class="header-text">
      <h1>Policy Scanner</h1>
      <p>// bi-directional detection &middot; uni-directional split recommendations</p>
    </div>
    <a class="back-link" href="/">&larr; Toolbox</a>
  </header>

  <div class="card">
    <div class="card-label">01 &mdash; Input</div>
    <div id="dropzone">
      <input type="file" id="file-input" accept=".csv">
      <div class="drop-icon">📂</div>
      <div class="drop-title">Drop your policy CSV here</div>
      <div class="drop-sub">or click to browse &nbsp;·&nbsp; first 3 lines are ignored &nbsp;·&nbsp; flags rules where Source = Destination</div>
    </div>
    <div id="file-name"></div>

    <div class="actions">
      <button class="btn btn-primary" id="scan-btn" disabled>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        Scan Policy
      </button>
    </div>

    <div id="status-bar">
      <div class="spinner" id="spinner"></div>
      <span id="status-msg">Processing…</span>
    </div>
  </div>

  <div id="results" class="card">
    <div class="card-label">02 &mdash; Bi-Directional Rules</div>
    <div class="stats-row" id="stats-row"></div>
    <div id="select-info" style="display:none;"></div>
    <div id="report-area"></div>
    <div class="actions actions-row" id="download-actions" style="display:none;">
      <button class="btn btn-primary" id="recommend-btn" disabled>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M9 18h6M10 22h4"/>
          <path d="M12 2a7 7 0 00-4 12.7c.6.5 1 1.3 1 2.1V17h6v-.2c0-.8.4-1.6 1-2.1A7 7 0 0012 2z"/>
        </svg>
        Recommendations
      </button>
      <button class="btn btn-secondary" id="download-btn">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
          <polyline points="7 10 12 15 17 10"/>
          <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        Download Report CSV
      </button>
    </div>
  </div>

</div>

<!-- Recommendation modal -->
<div class="modal-overlay" id="rec-modal">
  <div class="modal">
    <button class="modal-close" id="rec-close" title="Close">&times;</button>
    <h3>Proposed Uni-Directional Rules</h3>
    <div class="modal-sub" id="rec-sub"></div>
    <div id="rec-area"></div>
    <div class="actions" id="rec-actions" style="display:none;">
      <button class="btn btn-secondary" id="rec-download-btn">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
          <polyline points="7 10 12 15 17 10"/>
          <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        Download Proposed Rules CSV
      </button>
    </div>
  </div>
</div>

<script>
  const fileInput = document.getElementById('file-input');
  const dropzone  = document.getElementById('dropzone');
  const fileNameEl = document.getElementById('file-name');
  const scanBtn   = document.getElementById('scan-btn');
  const statusBar = document.getElementById('status-bar');
  const statusMsg = document.getElementById('status-msg');
  const spinner   = document.getElementById('spinner');
  const resultsEl = document.getElementById('results');
  const statsRow  = document.getElementById('stats-row');
  const reportArea = document.getElementById('report-area');
  const downloadActions = document.getElementById('download-actions');
  const downloadBtn = document.getElementById('download-btn');
  const recommendBtn = document.getElementById('recommend-btn');
  const selectInfo = document.getElementById('select-info');
  const recModal = document.getElementById('rec-modal');
  const recClose = document.getElementById('rec-close');
  const recSub = document.getElementById('rec-sub');
  const recArea = document.getElementById('rec-area');
  const recActions = document.getElementById('rec-actions');
  const recDownloadBtn = document.getElementById('rec-download-btn');

  let currentFlagged = [];      // flagged rules from the latest scan
  let lastRecommendRules = [];  // rules sent to the most recent recommendation

  dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag-over'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
  dropzone.addEventListener('drop', e => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) { fileInput.files = e.dataTransfer.files; updateFile(); }
  });
  fileInput.addEventListener('change', updateFile);

  function updateFile() {
    if (fileInput.files.length) {
      fileNameEl.textContent = '✓ ' + fileInput.files[0].name;
      scanBtn.disabled = false;
    }
  }

  function setStatus(type, msg) {
    statusBar.className = 'active ' + type;
    statusMsg.textContent = msg;
    spinner.style.display = type === 'active' ? 'block' : 'none';
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  scanBtn.addEventListener('click', async () => {
    if (!fileInput.files.length) return;
    setStatus('active', 'Uploading and scanning policy…');
    scanBtn.disabled = true;
    resultsEl.classList.remove('visible');

    try {
      const fd = new FormData();
      fd.append('file', fileInput.files[0]);
      const res = await fetch('/scan', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Server error');
      renderResults(data);
      setStatus('ok', `Done — ${data.flagged.length} bi-directional rule(s) found in ${data.total_rules} rule(s).`);
    } catch (err) {
      setStatus('error', 'Error: ' + err.message);
    } finally {
      scanBtn.disabled = false;
    }
  });

  function renderResults(data) {
    const count = data.flagged.length;
    currentFlagged = data.flagged;
    statsRow.innerHTML = `
      <div class="stat"><span class="stat-value">${data.total_rules}</span><span class="stat-label">Rules Scanned</span></div>
      <div class="stat"><span class="stat-value ${count ? 'warn' : ''}">${count}</span><span class="stat-label">Bi-Directional</span></div>
    `;

    if (!count) {
      reportArea.innerHTML = '<div class="empty">✓ No bi-directional rules found — no rule has an identical source and destination.</div>';
      downloadActions.style.display = 'none';
      selectInfo.style.display = 'none';
    } else {
      const cols = data.columns;
      let html = '<div class="table-wrap"><table><thead><tr>';
      html += '<th class="check-cell"><input type="checkbox" id="select-all" title="Select all"></th>';
      cols.forEach(c => { html += `<th>${escapeHtml(c)}</th>`; });
      html += '</tr></thead><tbody>';
      data.flagged.forEach((r, i) => {
        html += '<tr>';
        html += `<td class="check-cell"><input type="checkbox" class="row-check" data-idx="${i}"></td>`;
        cols.forEach(c => { html += `<td>${escapeHtml(r[c])}</td>`; });
        html += '</tr>';
      });
      html += '</tbody></table></div>';
      reportArea.innerHTML = html;
      downloadActions.style.display = 'flex';
      selectInfo.style.display = 'block';
      updateSelection();
    }

    resultsEl.classList.add('visible');
    resultsEl.scrollIntoView({ behavior: 'smooth' });
  }

  function getSelectedRules() {
    return Array.from(reportArea.querySelectorAll('.row-check:checked'))
      .map(b => currentFlagged[Number(b.dataset.idx)]);
  }

  function updateSelection() {
    const n = getSelectedRules().length;
    recommendBtn.disabled = n === 0;
    selectInfo.textContent = n
      ? `${n} rule${n === 1 ? '' : 's'} selected — click Recommendations to propose a uni-directional split.`
      : 'Select one or more rules below, then click Recommendations.';
  }

  // Delegate checkbox changes (table is re-rendered on each scan).
  reportArea.addEventListener('change', e => {
    if (e.target.id === 'select-all') {
      reportArea.querySelectorAll('.row-check').forEach(b => { b.checked = e.target.checked; });
    } else if (e.target.classList.contains('row-check')) {
      const all = reportArea.querySelector('#select-all');
      if (all) all.checked = reportArea.querySelectorAll('.row-check').length
        === reportArea.querySelectorAll('.row-check:checked').length;
    }
    updateSelection();
  });

  downloadBtn.addEventListener('click', async () => {
    if (!fileInput.files.length) return;
    const fd = new FormData();
    fd.append('file', fileInput.files[0]);
    const res = await fetch('/scan_download', { method: 'POST', body: fd });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'bidirectional_rules.csv';
    a.click();
    URL.revokeObjectURL(url);
  });

  // ── Recommendations ───────────────────────────────────────────
  function closeModal() { recModal.classList.remove('open'); }
  recClose.addEventListener('click', closeModal);
  recModal.addEventListener('click', e => { if (e.target === recModal) closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

  recommendBtn.addEventListener('click', async () => {
    const rules = getSelectedRules();
    if (!rules.length) return;
    lastRecommendRules = rules;
    recArea.innerHTML = '<div class="empty" style="color:var(--muted);">Building recommendations…</div>';
    recActions.style.display = 'none';
    recModal.classList.add('open');
    try {
      const res = await fetch('/recommend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Server error');
      renderRecommendations(rules.length, data);
    } catch (err) {
      recArea.innerHTML = `<div class="empty" style="color:var(--accent2);">Error: ${escapeHtml(err.message)}</div>`;
    }
  });

  function renderRecommendations(selectedCount, data) {
    const proposed = data.proposed || [];
    recSub.textContent = `${selectedCount} bi-directional rule(s) → ${proposed.length} proposed uni-directional rule(s), `
      + 'grouped by IP /16 and object-name similarity.';
    if (!proposed.length) {
      recArea.innerHTML = '<div class="empty">No distinct uni-directional rules could be derived from the selection.</div>';
      recActions.style.display = 'none';
      return;
    }
    const cols = data.columns;
    let html = '<div class="table-wrap"><table><thead><tr>';
    cols.forEach(c => { html += `<th>${escapeHtml(c)}</th>`; });
    html += '</tr></thead><tbody>';
    proposed.forEach(r => {
      html += '<tr>';
      cols.forEach(c => { html += `<td>${escapeHtml(r[c])}</td>`; });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    recArea.innerHTML = html;
    recActions.style.display = 'flex';
  }

  recDownloadBtn.addEventListener('click', async () => {
    if (!lastRecommendRules.length) return;
    const res = await fetch('/recommend_download', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rules: lastRecommendRules })
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'proposed_unidirectional_rules.csv';
    a.click();
    URL.revokeObjectURL(url);
  });
</script>
</body>
</html>
"""


# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HOME_HTML)


@app.route("/analyzer")
def analyzer_page():
    return render_template_string(ANALYZER_HTML)


@app.route("/scanner")
def scanner_page():
    return render_template_string(SCANNER_HTML)


_subnet_cache_lock = threading.Lock()
_subnet_cache = {"sig": None, "map": None}


def _staged_subnet_signature():
    """A cheap fingerprint of the staged all_networks*.csv files (path, mtime, size).
    Changes whenever a file is added, removed, or edited, so the cache stays fresh."""
    pattern = os.path.join(APP_DIR, SUBNET_FILE_PREFIX + "*.csv")
    sig = []
    for path in sorted(glob.glob(pattern)):
        try:
            st = os.stat(path)
            sig.append((path, st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    return tuple(sig)


def _load_subnet_map():
    """Load the subnet name map from the all_networks*.csv files staged in the app dir.

    Parsing ~140k rows on every request is the bulk of the per-request cost, so the
    built SubnetMap is cached in memory and only rebuilt when the staged files change.
    """
    sig = _staged_subnet_signature()
    with _subnet_cache_lock:
        if _subnet_cache["sig"] == sig and _subnet_cache["map"] is not None:
            return _subnet_cache["map"]
        subnet_map = load_staged_subnet_map()
        _subnet_cache["sig"] = sig
        _subnet_cache["map"] = subnet_map
        return subnet_map


@app.route("/analyze", methods=["POST"])
def analyze_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    try:
        subnet_map = _load_subnet_map()
        rows = parse_csv(f)
        total_rows = len(rows)
        filtered = filter_rows(rows)
        rules = analyze(filtered, subnet_map=subnet_map)
        return jsonify({
            "rules": rules,
            "total_rows": total_rows,
            "filtered_rows": len(filtered),
            "subnet_entries": len(subnet_map)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download", methods=["POST"])
def download_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    try:
        subnet_map = _load_subnet_map()
        rows = parse_csv(f)
        filtered = filter_rows(rows)
        rules = analyze(filtered, subnet_map=subnet_map)
        csv_data = rules_to_csv(rules)
        buf = io.BytesIO(csv_data.encode("utf-8"))
        buf.seek(0)
        return send_file(
            buf,
            mimetype="text/csv",
            as_attachment=True,
            download_name="firewall_rules.csv"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download_checkpoint", methods=["POST"])
def download_checkpoint_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    try:
        subnet_map = _load_subnet_map()
        rows = parse_csv(f)
        filtered = filter_rows(rows)
        rules = analyze(filtered, subnet_map=subnet_map)
        script = generate_checkpoint_script(rules, subnet_map=subnet_map)
        buf = io.BytesIO(script.encode("utf-8"))
        buf.seek(0)
        return send_file(
            buf,
            mimetype="text/plain",
            as_attachment=True,
            download_name="checkpoint_build.sh"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/scan", methods=["POST"])
def scan_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    try:
        header, data = parse_policy_csv(f)
        flagged = scan_bidirectional(header, data)
        return jsonify({
            "flagged": flagged,
            "columns": [label for label, _ in _REPORT_FIELDS],
            "total_rules": len(data),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/recommend", methods=["POST"])
def recommend_route():
    payload = request.get_json(silent=True) or {}
    rules = payload.get("rules", [])
    if not rules:
        return jsonify({"error": "No rules selected"}), 400
    try:
        proposed = recommend_for_rules(rules)
        return jsonify({"proposed": proposed, "columns": _RECOMMEND_FIELDS})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/recommend_download", methods=["POST"])
def recommend_download_route():
    payload = request.get_json(silent=True) or {}
    rules = payload.get("rules", [])
    if not rules:
        return jsonify({"error": "No rules selected"}), 400
    try:
        proposed = recommend_for_rules(rules)
        csv_data = recommendations_to_csv(proposed)
        buf = io.BytesIO(csv_data.encode("utf-8"))
        buf.seek(0)
        return send_file(
            buf,
            mimetype="text/csv",
            as_attachment=True,
            download_name="proposed_unidirectional_rules.csv"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/scan_download", methods=["POST"])
def scan_download_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    try:
        header, data = parse_policy_csv(f)
        flagged = scan_bidirectional(header, data)
        csv_data = bidirectional_to_csv(flagged)
        buf = io.BytesIO(csv_data.encode("utf-8"))
        buf.seek(0)
        return send_file(
            buf,
            mimetype="text/csv",
            as_attachment=True,
            download_name="bidirectional_rules.csv"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def open_browser():
    import time
    time.sleep(1.2)
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False)
