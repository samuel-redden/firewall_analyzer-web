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
from datetime import datetime
from html import escape
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

# Columns surfaced in the audit reports, by header name with a
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
#  POLICY AUDIT ENGINE
# ─────────────────────────────────────────────
#
# Audits every rule in the export against eight checks, each with a severity.
# The policy starts at 1000 points and every individual finding deducts its
# severity's points (a rule can be flagged by several checks at once); the
# score floors at 0.
#
#   Critical (-6)  'Any' as source, destination, or service — ALLOW rules only
#   High     (-4)  Overly permissive ALLOW rule: broad network objects
#                  (/16 or wider), broad service objects (ALL_*, huge port
#                  ranges), or very long object lists
#   Medium   (-2)  Bi-directional: Source == Destination
#   Medium   (-2)  Missing logging: Logged column is not true
#   Low      (-1)  Missing comment
#   Low      (-1)  Unused: never hit, or last hit > 180 days ago
#   Low      (-1)  Disabled
#   Low      (-1)  Shadowed: Shadowing Status is shadowed (NOT_SHADOWED is fine)

STARTING_SCORE = 1000
UNUSED_AFTER_DAYS = 180
BROAD_PREFIX_LEN = 16      # a network object of /16 or wider is "broad"
MANY_OBJECTS = 10          # more than this many objects in one field is "broad"
BROAD_PORT_SPAN = 1000     # a service range covering more ports than this is "broad"

SEVERITY_POINTS = {"Critical": 6, "High": 4, "Medium": 2, "Low": 1}

# Fixed-position fallbacks for the audited columns (header name still wins).
DEVICE_COL_INDEX = 3
DISABLED_COL_INDEX = 14
SERVICE_COL_INDEX = 22
ACTION_COL_INDEX = 26
COMMENT_COL_INDEX = 31
LOGGED_COL_INDEX = 32
LAST_HIT_COL_INDEX = 41
SHADOWING_COL_INDEX = 43

AUDIT_CATEGORIES = [
    {"key": "any",           "label": "Any Src/Dst/Service", "severity": "Critical"},
    {"key": "permissive",    "label": "Overly Permissive",   "severity": "High"},
    {"key": "bidirectional", "label": "Bi-Directional",      "severity": "Medium"},
    {"key": "no_logging",    "label": "Missing Logging",     "severity": "Medium"},
    {"key": "no_comment",    "label": "Missing Comment",     "severity": "Low"},
    {"key": "unused",        "label": "Unused Rules",        "severity": "Low"},
    {"key": "disabled",      "label": "Disabled Rules",      "severity": "Low"},
    {"key": "shadowed",      "label": "Shadowed Rules",      "severity": "Low"},
]

AUDIT_REPORT_COLUMNS = [label for label, _ in _REPORT_FIELDS] + ["Finding"]

_DATE_FORMATS = ("%m/%d/%Y", "%m/%d/%y", "%Y-%m-%d", "%d-%b-%Y", "%d/%m/%Y")
_PORT_RANGE_RE = re.compile(r"(\d{1,5})\s*-\s*(\d{1,5})")
# 'all' as its own token, where '_'/'-' count as separators: matches ALL_TCP
# and 'All Services' but not 'Allscripts'.
_ALL_SERVICE_RE = re.compile(r"(?<![a-z0-9])all(?![a-z0-9])", re.IGNORECASE)


def _is_allow(action):
    return action.strip().lower() in ("allow", "accept", "permit")


def _field_has_any(cell):
    """True when a Source/Destination/Service cell contains an 'Any' object."""
    return any(o.lower() in ("any", "*") for o in _split_objects(cell))


def _broad_service_reason(svc_obj):
    """Why a single service object is overly broad, or None if it isn't."""
    if _ALL_SERVICE_RE.search(svc_obj):
        return f"broad service '{svc_obj}'"
    m = _PORT_RANGE_RE.search(svc_obj)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        if 0 <= lo <= hi <= 65535 and hi - lo + 1 > BROAD_PORT_SPAN:
            return f"service '{svc_obj}' spans {hi - lo + 1} ports"
    return None


def _parse_last_hit(value):
    """Parse a Last Hit cell into a datetime, or None if blank/unrecognized."""
    token = value.strip().split()[0] if value.strip() else ""
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(token, fmt)
        except ValueError:
            continue
    return None


def audit_policy(header, data, today=None):
    """
    Run all six checks over the parsed policy export. Returns a dict with the
    score, the per-category findings, and the report columns.
    """
    today = today or datetime.now()
    src_idx = _col_index(header, "Source", SRC_COL_INDEX)
    dst_idx = _col_index(header, "Destination", DST_COL_INDEX)
    svc_idx = _col_index(header, "Service", SERVICE_COL_INDEX)
    action_idx = _col_index(header, "Action", ACTION_COL_INDEX)
    disabled_idx = _col_index(header, "Disabled", DISABLED_COL_INDEX)
    comment_idx = _col_index(header, "Comment", COMMENT_COL_INDEX)
    logged_idx = _col_index(header, "Logged", LOGGED_COL_INDEX)
    last_hit_idx = _col_index(header, "Last Hit", LAST_HIT_COL_INDEX)
    shadow_idx = _col_index(header, "Shadowing Status", SHADOWING_COL_INDEX)
    device_idx = _col_index(header, "Device Name", DEVICE_COL_INDEX)
    fields = [(label, _col_index(header, label, default)) for label, default in _REPORT_FIELDS]

    findings = {c["key"]: [] for c in AUDIT_CATEGORIES}
    devices = []
    rules_with_findings = 0

    def flag(key, row, detail):
        report = {label: _cell(row, idx) for label, idx in fields}
        report["Finding"] = detail
        findings[key].append(report)

    for row in data:
        flags_before = sum(len(v) for v in findings.values())
        src = _cell(row, src_idx)
        dst = _cell(row, dst_idx)
        svc = _cell(row, svc_idx)
        disabled = _cell(row, disabled_idx).lower() in ("true", "yes", "1", "disabled")
        allow = _is_allow(_cell(row, action_idx))

        device = _cell(row, device_idx)
        if device and device not in devices:
            devices.append(device)

        # Critical — 'Any' as source, destination, or service on an ALLOW rule.
        # (An Any-Any-Any drop/cleanup rule is normal practice, so deny rules
        # are exempt.)
        if allow:
            any_fields = [name for name, cell in
                          (("Source", src), ("Destination", dst), ("Service", svc))
                          if _field_has_any(cell)]
            if any_fields:
                flag("any", row, "Any in " + " + ".join(any_fields))

        # High — overly permissive ALLOW rule.
        if allow:
            reasons = []
            for side, cell in (("Source", src), ("Destination", dst)):
                objs = _split_objects(cell)
                for o in objs:
                    net = _object_network(o)
                    if net is not None and net.prefixlen <= BROAD_PREFIX_LEN:
                        reasons.append(f"{side} has broad network {net} ({o})")
                if len(objs) > MANY_OBJECTS:
                    reasons.append(f"{side} lists {len(objs)} objects")
            svc_objs = _split_objects(svc)
            for o in svc_objs:
                reason = _broad_service_reason(o)
                if reason:
                    reasons.append(reason)
            if len(svc_objs) > MANY_OBJECTS:
                reasons.append(f"Service lists {len(svc_objs)} objects")
            if reasons:
                flag("permissive", row, "; ".join(reasons))

        # Medium — bi-directional: Source == Destination (trimmed, case-insensitive).
        # Any==Any is excluded: that's the 'Any' problem, not a bi-directional one.
        if src and dst and src.lower() == dst.lower() and not _field_has_any(src):
            flag("bidirectional", row, "Source and Destination are identical")

        # Medium — missing logging. Disabled rules are skipped: an inactive
        # rule isn't logging anything by definition and is already flagged below.
        if not disabled:
            logged = _cell(row, logged_idx).lower()
            if logged not in ("true", "yes", "1", "log", "enabled"):
                flag("no_logging", row,
                     f"Logging is '{_cell(row, logged_idx)}'" if logged else "Logging not set")

        # Low — missing comment.
        if not _cell(row, comment_idx):
            flag("no_comment", row, "No comment")

        # Low — unused. Disabled rules are skipped: they can't accrue hits
        # and are already flagged below.
        if not disabled:
            last_hit_raw = _cell(row, last_hit_idx)
            if not last_hit_raw:
                flag("unused", row, "Never hit")
            else:
                hit = _parse_last_hit(last_hit_raw)
                if hit is not None:
                    age = (today - hit).days
                    if age > UNUSED_AFTER_DAYS:
                        flag("unused", row, f"Last hit {last_hit_raw} ({age} days ago)")

        # Low — disabled.
        if disabled:
            flag("disabled", row, "Rule is disabled")

        # Low — shadowed: an earlier rule already matches this traffic.
        # Disabled rules are skipped; shadowing only matters for active rules.
        if not disabled:
            shadow_raw = _cell(row, shadow_idx)
            shadow = shadow_raw.lower()
            if "shadowed" in shadow and not shadow.startswith("not"):
                flag("shadowed", row, f"Shadowing status: {shadow_raw}")

        if sum(len(v) for v in findings.values()) > flags_before:
            rules_with_findings += 1

    categories = []
    deductions = 0
    for cat in AUDIT_CATEGORIES:
        rules = findings[cat["key"]]
        points = SEVERITY_POINTS[cat["severity"]]
        deductions += points * len(rules)
        categories.append({**cat, "points": points, "count": len(rules), "rules": rules})

    return {
        "total_rules": len(data),
        "score": max(0, STARTING_SCORE - deductions),
        "starting_score": STARTING_SCORE,
        "deductions": deductions,
        "devices": devices,
        "rules_with_findings": rules_with_findings,
        "columns": AUDIT_REPORT_COLUMNS,
        "categories": categories,
    }


def audit_to_csv(result, category_key=None):
    """
    Export findings as CSV — one category when category_key is given,
    otherwise every finding with its category and severity.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Category", "Severity"] + result["columns"])
    for cat in result["categories"]:
        if category_key and cat["key"] != category_key:
            continue
        for r in cat["rules"]:
            writer.writerow([cat["label"], cat["severity"]]
                            + [r.get(c, "") for c in result["columns"]])
    return output.getvalue()


# ─────────────────────────────────────────────
#  AUDIT REPORTS (EXECUTIVE / ENGINEER)
# ─────────────────────────────────────────────
#
# Both reports are generated as fully self-contained HTML documents on a light,
# print-friendly theme, so they can be opened anywhere, printed, or saved to
# PDF from the browser — no extra dependencies.

# Light-theme palette used in the downloadable reports (the app UI's neon
# colors don't read well on white).
_REPORT_SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High":     "#d35400",
    "Medium":   "#b07d00",
    "Low":      "#2471a3",
}


def _report_band(score):
    """(label, color) for the score on the light report theme — same
    thresholds as the UI's bandFor()."""
    if score > 950:
        return "Excellent", "#1e8e5a"
    if score > 800:
        return "Good", "#b07d00"
    if score >= 600:
        return "At Risk", "#d35400"
    return "Critical", "#c0392b"


# Plain-business-language explanation of each category, for the executive
# report. Keyed by category key; {n} is the finding count.
_EXEC_NARRATIVES = {
    "any": "{n} rule(s) allow traffic from any source, to any destination, or on "
           "any service. These grant the broadest possible access and are the most "
           "likely path for an attacker or malware to move through the network.",
    "permissive": "{n} rule(s) grant access far more broadly than necessary — entire "
                  "networks or very large service ranges — which increases the impact "
                  "of any single compromised system.",
    "bidirectional": "{n} rule(s) allow traffic in both directions between the same "
                     "systems, which usually grants more access than the business "
                     "need requires.",
    "no_logging": "{n} rule(s) do not record traffic logs, creating blind spots for "
                  "security monitoring, incident response, and audits.",
    "no_comment": "{n} rule(s) have no documentation, making it difficult to know why "
                  "the access exists or whether it is still required.",
    "unused": f"{{n}} rule(s) have not matched any traffic in over {UNUSED_AFTER_DAYS} "
              "days, suggesting the access is no longer needed and can likely be removed.",
    "disabled": "{n} rule(s) are disabled but still present in the policy, adding "
                "clutter and the risk of accidental re-enablement.",
    "shadowed": "{n} rule(s) are shadowed — earlier rules always match first, so these "
                "are dead weight that complicates the policy.",
}

# Step-by-step remediation guidance per category, for the engineer report.
_ENGINEER_STEPS = {
    "any": [
        "Export this category to CSV and treat it as your highest-priority worklist.",
        "For each rule, gather the traffic it actually carries (hit logs or a traffic query).",
        "Feed a traffic-hit CSV into the Rule Analyzer tool to generate least-permissive replacement rules.",
        "Stage the replacement rules above the Any rule, monitor for a change window, then remove the Any rule.",
    ],
    "permissive": [
        "Identify what actually needs the access: narrow broad networks (/16 or wider) to the specific subnets or hosts in use.",
        "Replace ALL_* or wide port-range services with the specific protocol/ports observed in traffic.",
        "Where many objects are listed in one rule, split by application or use object groups with meaningful names.",
        "Validate with traffic data before and after each change.",
    ],
    "bidirectional": [
        "In the Policy Scanner, select the flagged rules and click Recommendations to generate uni-directional splits.",
        "Confirm with the application owner which direction(s) are genuinely initiated.",
        "Implement the needed direction(s), monitor, then remove the bi-directional rule.",
    ],
    "no_logging": [
        "Enable logging on each flagged rule — this is a low-risk change.",
        "Confirm logs are forwarded to your SIEM / log collector.",
        "Adopt a standard: every new rule ships with logging enabled.",
    ],
    "no_comment": [
        "Add a comment with the change ticket, requester/owner, and purpose for each rule.",
        "Where the purpose is unknown, treat the rule as a candidate for the unused-rule review below.",
        "Enforce a comment standard for all future changes.",
    ],
    "unused": [
        f"Confirm the rule has had no hits for at least {UNUSED_AFTER_DAYS} days (extend the window for yearly batch jobs / DR paths).",
        "Disable the rule first rather than deleting it.",
        "After a full change cycle with no impact, delete it.",
    ],
    "disabled": [
        "Confirm no pending change or seasonal process still needs the rule.",
        "Delete disabled rules that have no documented reason to remain.",
    ],
    "shadowed": [
        "Identify the earlier rule(s) that shadow each flagged rule.",
        "If the shadowing rule is correct, delete the shadowed rule; if not, fix the ordering.",
        "Re-run the export afterwards to confirm the shadowing is resolved.",
    ],
}

# Columns shown in the engineer report's per-category tables, and the row cap
# per table (the CSV export carries the full list).
_ENGINEER_TABLE_COLUMNS = ["Seq No.", "Rule Name", "Source", "Destination",
                           "Service", "Action", "Finding"]
_ENGINEER_TABLE_MAX_ROWS = 40

_REPORT_CSS = """
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #1f2d3d; background: #f4f6f8; line-height: 1.55; }
  .page { max-width: 860px; margin: 0 auto; padding: 48px 56px; background: #fff; }
  header { border-bottom: 3px solid #1f2d3d; padding-bottom: 18px; margin-bottom: 28px; }
  h1 { font-size: 1.7rem; letter-spacing: -0.01em; }
  .meta { color: #5a6b7e; font-size: 0.85rem; margin-top: 6px; }
  h2 { font-size: 1.05rem; text-transform: uppercase; letter-spacing: 0.08em;
       border-bottom: 1px solid #d8dee5; padding-bottom: 6px; margin: 30px 0 14px; }
  p, li { font-size: 0.92rem; }
  ul, ol { padding-left: 22px; }
  li { margin-bottom: 6px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.82rem; margin: 10px 0; }
  th { background: #1f2d3d; color: #fff; text-align: left; padding: 8px 10px; font-weight: 600; }
  td { padding: 7px 10px; border-bottom: 1px solid #e3e8ee; vertical-align: top; }
  tr:nth-child(even) td { background: #f7f9fb; }
  .sev { display: inline-block; padding: 1px 9px; border-radius: 3px; color: #fff;
         font-size: 0.72rem; font-weight: 600; letter-spacing: 0.04em; }
  .score-hero { display: flex; align-items: center; gap: 28px; background: #f7f9fb;
                border: 1px solid #e3e8ee; border-radius: 6px; padding: 22px 28px; }
  .score-hero .num { font-size: 3.4rem; font-weight: 700; line-height: 1; }
  .score-hero .of { color: #5a6b7e; font-size: 1rem; }
  .score-hero .band { display: inline-block; margin-top: 6px; padding: 3px 12px;
                      border-radius: 3px; color: #fff; font-size: 0.78rem;
                      font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; }
  .score-hero .desc { font-size: 0.88rem; color: #3c4d61; }
  .device { font-weight: 700; }
  .phase { margin-bottom: 26px; }
  .phase h3 { font-size: 0.95rem; margin-bottom: 6px; }
  .phase .why { color: #5a6b7e; font-size: 0.85rem; font-style: italic; margin-bottom: 8px; }
  .more { color: #5a6b7e; font-size: 0.8rem; font-style: italic; }
  footer { margin-top: 36px; padding-top: 14px; border-top: 1px solid #d8dee5;
           color: #8294a7; font-size: 0.75rem; }
  @media print {
    body { background: #fff; }
    .page { padding: 0; max-width: none; }
    .phase, .score-hero { break-inside: avoid; }
  }
"""


def _report_head(title):
    return ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<title>{escape(title)}</title><style>{_REPORT_CSS}</style></head><body>"
            "<div class=\"page\">")


def _report_meta_line(result):
    devices = ", ".join(result["devices"]) or "unknown device"
    date = datetime.now().strftime("%B %d, %Y")
    return (f"Device(s): <span class=\"device\">{escape(devices)}</span> &middot; "
            f"Generated {date} &middot; {result['total_rules']} rule(s) reviewed")


def _report_footer():
    return ("<footer>Generated by Firewall Rule Analyzer &mdash; Policy Scanner. "
            "Score bands: above 950 Excellent &middot; above 800 Good &middot; "
            "600&ndash;800 At Risk &middot; below 600 Critical.</footer>"
            "</div></body></html>")


def _sev_chip(severity):
    color = _REPORT_SEVERITY_COLORS[severity]
    return f"<span class=\"sev\" style=\"background:{color}\">{severity}</span>"


def _findings_table(result):
    out = ["<table><tr><th>Severity</th><th>Category</th><th>Findings</th>"
           "<th>Points Deducted</th></tr>"]
    for cat in result["categories"]:
        deducted = cat["count"] * cat["points"]
        out.append(f"<tr><td>{_sev_chip(cat['severity'])}</td>"
                   f"<td>{escape(cat['label'])}</td>"
                   f"<td>{cat['count']}</td><td>&minus;{deducted}</td></tr>")
    out.append(f"<tr><td></td><td><b>Total</b></td>"
               f"<td><b>{sum(c['count'] for c in result['categories'])}</b></td>"
               f"<td><b>&minus;{result['deductions']}</b></td></tr></table>")
    return "".join(out)


def _score_hero(result, extra_desc=""):
    band, color = _report_band(result["score"])
    pct = (100.0 * result["rules_with_findings"] / result["total_rules"]) if result["total_rules"] else 0.0
    desc = (f"{result['rules_with_findings']} of {result['total_rules']} rule(s) "
            f"({pct:.0f}%) have at least one finding; the policy lost "
            f"{result['deductions']} of {result['starting_score']} points.")
    return (f"<div class=\"score-hero\"><div><span class=\"num\" style=\"color:{color}\">"
            f"{result['score']}</span><span class=\"of\"> / {result['starting_score']}</span><br>"
            f"<span class=\"band\" style=\"background:{color}\">{band}</span></div>"
            f"<div class=\"desc\">{desc} {extra_desc}</div></div>")


def generate_executive_report(result):
    """A leadership-facing HTML summary: score, findings table, plain-language
    risk narrative, and recommended next steps."""
    parts = [_report_head("Firewall Policy Security Report")]
    parts.append("<header><h1>Firewall Policy Security Report</h1>"
                 f"<div class=\"meta\">{_report_meta_line(result)}</div></header>")
    parts.append("<h2>Security Score</h2>")
    parts.append(_score_hero(
        result, "The score starts at 1000 and each finding deducts points by severity "
                "(Critical &minus;6, High &minus;4, Medium &minus;2, Low &minus;1)."))

    parts.append("<h2>Findings at a Glance</h2>")
    parts.append(_findings_table(result))

    parts.append("<h2>What This Means</h2>")
    flagged = [c for c in result["categories"] if c["count"]]
    if flagged:
        parts.append("<ul>")
        for cat in flagged:
            text = _EXEC_NARRATIVES[cat["key"]].format(n=cat["count"])
            parts.append(f"<li><b>{escape(cat['label'])}</b> ({cat['severity']}): {text}</li>")
        parts.append("</ul>")
    else:
        parts.append("<p>No issues were found. The policy meets all eight audit checks.</p>")

    parts.append("<h2>Recommended Next Steps</h2><ol>"
                 "<li>Remediate Critical and High findings first — replace any-access and "
                 "overly broad rules with least-privilege rules based on observed traffic.</li>"
                 "<li>Schedule a hygiene cleanup: enable logging, document rules, and remove "
                 "unused, disabled, and shadowed rules.</li>"
                 "<li>Adopt standards so new rules ship with logging, documentation, and "
                 "least-privilege scope by default.</li>"
                 "<li>Re-run this audit after each remediation cycle and track the score "
                 "as the policy-health KPI.</li></ol>")
    parts.append(_report_footer())
    return "".join(parts)


def generate_engineer_report(result):
    """An engineer-facing HTML runbook: prioritized phases, step-by-step
    remediation guidance, and the flagged rules for each category."""
    parts = [_report_head("Firewall Policy Cleanup Plan")]
    parts.append("<header><h1>Firewall Policy Cleanup Plan</h1>"
                 f"<div class=\"meta\">{_report_meta_line(result)}</div></header>")
    parts.append("<h2>Current State</h2>")
    parts.append(_score_hero(result))

    parts.append("<h2>Before You Start</h2><ul>"
                 "<li>Take a full backup/export of the current policy.</li>"
                 "<li>Work through the phases in order — highest severity first.</li>"
                 "<li>Make changes in small batches under change control, and monitor "
                 "after each batch.</li>"
                 "<li>Export each category to CSV from the Policy Scanner for the full "
                 "worklists; tables below are capped at "
                 f"{_ENGINEER_TABLE_MAX_ROWS} rows.</li></ul>")

    phase_num = 0
    for cat in result["categories"]:
        if not cat["count"]:
            continue
        phase_num += 1
        parts.append(f"<div class=\"phase\"><h3>Phase {phase_num}: {escape(cat['label'])} "
                     f"&mdash; {_sev_chip(cat['severity'])} "
                     f"({cat['count']} rule(s), &minus;{cat['count'] * cat['points']} points)</h3>")
        parts.append(f"<div class=\"why\">{escape(_EXEC_NARRATIVES[cat['key']].format(n=cat['count']))}</div>")
        parts.append("<ol>")
        for step in _ENGINEER_STEPS[cat["key"]]:
            parts.append(f"<li>{escape(step)}</li>")
        parts.append("</ol>")

        parts.append("<table><tr>" +
                     "".join(f"<th>{escape(c)}</th>" for c in _ENGINEER_TABLE_COLUMNS) +
                     "</tr>")
        for r in cat["rules"][:_ENGINEER_TABLE_MAX_ROWS]:
            parts.append("<tr>" + "".join(
                f"<td>{escape(r.get(c, ''))}</td>" for c in _ENGINEER_TABLE_COLUMNS) + "</tr>")
        parts.append("</table>")
        remaining = cat["count"] - _ENGINEER_TABLE_MAX_ROWS
        if remaining > 0:
            parts.append(f"<p class=\"more\">&hellip; and {remaining} more — export the "
                         "category CSV for the full list.</p>")
        parts.append("</div>")

    if phase_num == 0:
        parts.append("<h2>Remediation Phases</h2>"
                     "<p>No findings — there is nothing to clean up. Re-run the audit "
                     "after the next policy change.</p>")

    parts.append("<h2>After Each Phase</h2><ul>"
                 "<li>Re-export the policy and re-run the Policy Scanner to confirm the "
                 "findings are resolved and the score improved.</li>"
                 "<li>Record the changes and updated score for the next review.</li></ul>")
    parts.append(_report_footer())
    return "".join(parts)


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
      <p>Audit a policy export against eight severity-rated checks (Any, overly permissive, bi-directional, missing logging, missing comment, unused, disabled, shadowed), score it out of 1000, and export findings to CSV.</p>
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

  /* Score dashboard */
  .score-wrap { display: flex; align-items: center; justify-content: center; gap: 48px; flex-wrap: wrap; margin-bottom: 28px; }
  .score-main { text-align: center; }
  #gauge { display: block; width: 260px; max-width: 100%; margin: 0 auto; overflow: visible; }
  #gauge text { font-family: var(--mono); font-size: 8px; fill: var(--muted); letter-spacing: 0.05em; }
  #gauge-fill { transition: stroke 0.4s; }
  #gauge-needle {
    transform-box: view-box;
    transform-origin: 110px 112px;
    transition: transform 0.9s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .score-readout { margin-top: 6px; }
  .score-value { font-family: var(--mono); font-size: 2.6rem; font-weight: 700; line-height: 1; }
  .score-denom { font-family: var(--mono); font-size: 0.85rem; color: var(--muted); }
  .score-band {
    display: inline-block;
    font-family: var(--mono); font-size: 0.7rem;
    letter-spacing: 0.2em; text-transform: uppercase;
    padding: 4px 14px; border: 1px solid currentColor; margin-top: 10px;
  }
  .score-side { flex: 0 1 auto; min-width: 260px; }
  .score-device {
    font-family: var(--mono); font-size: 0.7rem;
    letter-spacing: 0.15em; text-transform: uppercase;
    color: var(--muted); margin-bottom: 16px;
  }
  .score-device b { font-family: var(--sans); font-size: 1.15rem; font-weight: 800; letter-spacing: 0.04em; }
  .score-math { font-family: var(--mono); font-size: 0.78rem; color: var(--text); margin-top: 12px; }
  .score-legend { font-family: var(--mono); font-size: 0.65rem; letter-spacing: 0.08em; color: var(--muted); margin-top: 6px; }
  .score-actions { display: flex; flex-direction: column; gap: 12px; }
  .btn-sm { padding: 11px 18px; font-size: 0.72rem; justify-content: flex-start; }

  /* Severity palette */
  .sev-critical { --sev: #ff4757; }
  .sev-high     { --sev: #ff6b35; }
  .sev-medium   { --sev: #ffd166; }
  .sev-low      { --sev: #00d4ff; }

  /* Category cards */
  .cat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
  .cat-card {
    border: 1px solid var(--border);
    background: rgba(255,255,255,0.02);
    padding: 14px 10px;
    text-align: center;
    cursor: pointer;
    transition: all 0.15s;
  }
  .cat-card:hover { border-color: var(--sev); }
  .cat-card.active { border-color: var(--sev); background: rgba(255,255,255,0.05); box-shadow: 0 0 14px rgba(0,0,0,0.4); }
  .cat-count { font-family: var(--mono); font-size: 1.7rem; font-weight: 700; color: var(--sev); display: block; }
  .cat-card.clean .cat-count { color: var(--success); }
  .cat-label { font-family: var(--mono); font-size: 0.62rem; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text); margin-top: 4px; display: block; }
  .cat-sev { font-family: var(--mono); font-size: 0.6rem; color: var(--muted); margin-top: 4px; display: block; }

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
      <p>// eight-point policy audit &middot; security score &middot; split recommendations</p>
    </div>
    <a class="back-link" href="/">&larr; Toolbox</a>
  </header>

  <div class="card">
    <div class="card-label">01 &mdash; Input</div>
    <div id="dropzone">
      <input type="file" id="file-input" accept=".csv">
      <div class="drop-icon">📂</div>
      <div class="drop-title">Drop your policy CSV here</div>
      <div class="drop-sub">or click to browse &nbsp;·&nbsp; first 3 lines are ignored &nbsp;·&nbsp; checks: Any &middot; permissive &middot; bi-directional &middot; no logging &middot; no comment &middot; unused &middot; disabled &middot; shadowed</div>
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

  <div id="results">
    <div class="card">
      <div class="card-label">02 &mdash; Score Dashboard</div>
      <div class="score-wrap">
        <div class="score-main">
          <svg id="gauge" viewBox="0 0 220 134" role="img" aria-label="Policy score gauge">
            <g id="gauge-track"></g>
            <path id="gauge-fill" fill="none" stroke-width="13" stroke-linecap="round"/>
            <g id="gauge-needle">
              <line x1="110" y1="112" x2="42" y2="112" stroke="#c8d8e8" stroke-width="2.5"/>
            </g>
            <circle cx="110" cy="112" r="6.5" fill="#0f1520" stroke="#c8d8e8" stroke-width="2"/>
          </svg>
          <div class="score-readout">
            <span class="score-value" id="score-value">&mdash;</span><span class="score-denom"> / 1000</span>
          </div>
          <span class="score-band" id="score-band"></span>
        </div>
        <div class="score-side">
          <div class="score-device" id="score-device" style="display:none;">// device: <b id="device-name"></b></div>
          <div class="score-math" id="score-math"></div>
          <div class="score-legend">critical &minus;6 &middot; high &minus;4 &middot; medium &minus;2 &middot; low &minus;1 per finding</div>
        </div>
        <div class="score-actions">
          <button class="btn btn-secondary btn-sm" id="exec-report-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
              <polyline points="14 2 14 8 20 8"/>
              <line x1="8" y1="13" x2="16" y2="13"/>
              <line x1="8" y1="17" x2="13" y2="17"/>
            </svg>
            Executive Report
          </button>
          <button class="btn btn-secondary btn-sm" id="eng-report-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/>
            </svg>
            Engineer Cleanup Plan
          </button>
        </div>
      </div>
      <div class="cat-grid" id="cat-grid"></div>
    </div>

    <div class="card">
      <div class="card-label">03 &mdash; Findings &middot; <span id="cat-title"></span></div>
      <div id="select-info" style="display:none;"></div>
      <div id="report-area"></div>
      <div class="actions actions-row" id="download-actions" style="display:none;">
        <button class="btn btn-primary" id="recommend-btn" disabled style="display:none;">
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
          Export Category CSV
        </button>
        <button class="btn btn-secondary" id="download-all-btn">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Export All Findings CSV
        </button>
      </div>
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
  const scoreValue = document.getElementById('score-value');
  const scoreBand = document.getElementById('score-band');
  const gaugeFill = document.getElementById('gauge-fill');
  const gaugeNeedle = document.getElementById('gauge-needle');
  const gaugeNeedleLine = gaugeNeedle.querySelector('line');
  const scoreDevice = document.getElementById('score-device');
  const deviceName = document.getElementById('device-name');
  const scoreMath = document.getElementById('score-math');
  const catGrid = document.getElementById('cat-grid');
  const catTitle = document.getElementById('cat-title');
  const reportArea = document.getElementById('report-area');
  const downloadActions = document.getElementById('download-actions');
  const downloadBtn = document.getElementById('download-btn');
  const downloadAllBtn = document.getElementById('download-all-btn');
  const recommendBtn = document.getElementById('recommend-btn');
  const selectInfo = document.getElementById('select-info');
  const recModal = document.getElementById('rec-modal');
  const recClose = document.getElementById('rec-close');
  const recSub = document.getElementById('rec-sub');
  const recArea = document.getElementById('rec-area');
  const recActions = document.getElementById('rec-actions');
  const recDownloadBtn = document.getElementById('rec-download-btn');

  let auditData = null;         // full audit result from the latest scan
  let activeCat = null;         // key of the category shown in the findings table
  let currentFlagged = [];      // bi-directional rules (feed the recommendations flow)
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
      const findings = data.categories.reduce((sum, c) => sum + c.count, 0);
      setStatus('ok', `Done — score ${data.score}/${data.starting_score}, ${findings} finding(s) across ${data.total_rules} rule(s).`);
    } catch (err) {
      setStatus('error', 'Error: ' + err.message);
    } finally {
      scanBtn.disabled = false;
    }
  });

  // Score bands: >950 green, >800 yellow, 600–800 orange, <600 red.
  function bandFor(score) {
    if (score > 950) return { color: '#00ff9d', label: 'Excellent' };
    if (score > 800) return { color: '#ffd166', label: 'Good' };
    if (score >= 600) return { color: '#ff6b35', label: 'At Risk' };
    return { color: '#ff4757', label: 'Critical' };
  }

  // ── Speedometer gauge ─────────────────────────────────────────
  // Semicircle centred at (110,112), radius 90; fraction 0 is the left end,
  // fraction 1 the right end.
  function gaugePoint(f, r) {
    const th = Math.PI * (1 - f);
    return [110 + r * Math.cos(th), 112 - r * Math.sin(th)];
  }
  function gaugeArc(f1, f2, r) {
    const [x1, y1] = gaugePoint(f1, r), [x2, y2] = gaugePoint(f2, r);
    return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
  }
  (function initGauge() {
    // Dim track segments showing the score bands, threshold ticks, end labels.
    const bands = [[0, 0.6, '#ff4757'], [0.6, 0.8, '#ff6b35'], [0.8, 0.95, '#ffd166'], [0.95, 1, '#00ff9d']];
    let html = '';
    bands.forEach(([f1, f2, color]) => {
      html += `<path d="${gaugeArc(f1, f2, 90)}" fill="none" stroke="${color}" stroke-opacity="0.22" stroke-width="13"/>`;
    });
    [[0.6, '600'], [0.8, '800'], [0.95, '950']].forEach(([f, label]) => {
      const [x1, y1] = gaugePoint(f, 81), [x2, y2] = gaugePoint(f, 99);
      html += `<line x1="${x1.toFixed(2)}" y1="${y1.toFixed(2)}" x2="${x2.toFixed(2)}" y2="${y2.toFixed(2)}" stroke="#4a6080" stroke-width="1"/>`;
      const [tx, ty] = gaugePoint(f, 108);
      html += `<text x="${tx.toFixed(2)}" y="${ty.toFixed(2)}" text-anchor="middle" dominant-baseline="middle">${label}</text>`;
    });
    html += '<text x="20" y="129" text-anchor="middle">0</text><text x="200" y="129" text-anchor="middle">1000</text>';
    document.getElementById('gauge-track').innerHTML = html;
  })();

  function renderResults(data) {
    auditData = data;
    const bidir = data.categories.find(c => c.key === 'bidirectional');
    currentFlagged = bidir ? bidir.rules : [];

    const band = bandFor(data.score);
    scoreValue.textContent = data.score;
    scoreValue.style.color = band.color;
    scoreValue.style.textShadow = `0 0 24px ${band.color}55`;
    scoreBand.textContent = band.label;
    scoreBand.style.color = band.color;

    const f = Math.max(0, Math.min(1, data.score / data.starting_score));
    gaugeFill.setAttribute('d', f > 0.001 ? gaugeArc(0, f, 90) : '');
    gaugeFill.setAttribute('stroke', band.color);
    gaugeFill.style.filter = `drop-shadow(0 0 5px ${band.color})`;
    gaugeNeedle.style.transform = `rotate(${(180 * f).toFixed(1)}deg)`;
    gaugeNeedleLine.setAttribute('stroke', band.color);

    if (data.devices && data.devices.length) {
      deviceName.textContent = data.devices.join(', ');
      deviceName.style.color = band.color;
      deviceName.style.textShadow = `0 0 18px ${band.color}55`;
      scoreDevice.style.display = 'block';
    } else {
      scoreDevice.style.display = 'none';
    }

    scoreMath.textContent = `${data.starting_score} start − ${data.deductions} deducted · ${data.total_rules} rule(s) scanned`;

    const firstWithFindings = data.categories.find(c => c.count > 0);
    activeCat = (firstWithFindings || data.categories[0]).key;
    renderCatGrid();
    renderCategory(activeCat);

    resultsEl.classList.add('visible');
    resultsEl.scrollIntoView({ behavior: 'smooth' });
  }

  function renderCatGrid() {
    catGrid.innerHTML = auditData.categories.map(c => `
      <div class="cat-card sev-${c.severity.toLowerCase()}${c.key === activeCat ? ' active' : ''}${c.count ? '' : ' clean'}" data-key="${c.key}">
        <span class="cat-count">${c.count}</span>
        <span class="cat-label">${escapeHtml(c.label)}</span>
        <span class="cat-sev">${c.severity} · −${c.points} each</span>
      </div>`).join('');
  }

  catGrid.addEventListener('click', e => {
    const card = e.target.closest('.cat-card');
    if (!card || !auditData) return;
    activeCat = card.dataset.key;
    renderCatGrid();
    renderCategory(activeCat);
  });

  function renderCategory(key) {
    const cat = auditData.categories.find(c => c.key === key);
    const isBidir = key === 'bidirectional';
    const totalFindings = auditData.categories.reduce((sum, c) => sum + c.count, 0);
    catTitle.textContent = `${cat.label} — ${cat.severity}`;
    recommendBtn.style.display = (isBidir && cat.count) ? 'inline-flex' : 'none';
    selectInfo.style.display = (isBidir && cat.count) ? 'block' : 'none';

    if (!cat.count) {
      reportArea.innerHTML = `<div class="empty">✓ No findings in this category.</div>`;
      downloadBtn.style.display = 'none';
      downloadActions.style.display = totalFindings ? 'flex' : 'none';
      return;
    }

    const cols = auditData.columns;
    let html = '<div class="table-wrap"><table><thead><tr>';
    if (isBidir) html += '<th class="check-cell"><input type="checkbox" id="select-all" title="Select all"></th>';
    cols.forEach(c => { html += `<th>${escapeHtml(c)}</th>`; });
    html += '</tr></thead><tbody>';
    cat.rules.forEach((r, i) => {
      html += '<tr>';
      if (isBidir) html += `<td class="check-cell"><input type="checkbox" class="row-check" data-idx="${i}"></td>`;
      cols.forEach(c => { html += `<td>${escapeHtml(r[c])}</td>`; });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    reportArea.innerHTML = html;
    downloadBtn.style.display = 'inline-flex';
    downloadActions.style.display = 'flex';
    if (isBidir) updateSelection();
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

  async function postDownload(endpoint, filename, extra) {
    if (!fileInput.files.length) return;
    const fd = new FormData();
    fd.append('file', fileInput.files[0]);
    Object.entries(extra || {}).forEach(([k, v]) => fd.append(k, v));
    const res = await fetch(endpoint, { method: 'POST', body: fd });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }
  downloadBtn.addEventListener('click', () =>
    postDownload('/scan_download', `policy_audit_${activeCat}.csv`, { category: activeCat }));
  downloadAllBtn.addEventListener('click', () =>
    postDownload('/scan_download', 'policy_audit_all_findings.csv'));
  document.getElementById('exec-report-btn').addEventListener('click', () =>
    postDownload('/report_executive', 'executive_report.html'));
  document.getElementById('eng-report-btn').addEventListener('click', () =>
    postDownload('/report_engineer', 'engineer_cleanup_plan.html'));

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
        return jsonify(audit_policy(header, data))
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
    category = (request.form.get("category") or "").strip() or None
    if category and category not in {c["key"] for c in AUDIT_CATEGORIES}:
        return jsonify({"error": f"Unknown category: {category}"}), 400
    try:
        header, data = parse_policy_csv(f)
        result = audit_policy(header, data)
        csv_data = audit_to_csv(result, category_key=category)
        buf = io.BytesIO(csv_data.encode("utf-8"))
        buf.seek(0)
        return send_file(
            buf,
            mimetype="text/csv",
            as_attachment=True,
            download_name=(f"policy_audit_{category}.csv" if category
                           else "policy_audit_all_findings.csv")
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _report_response(f, generator, download_name):
    """Shared parse → audit → HTML-report-download flow for the report routes."""
    header, data = parse_policy_csv(f)
    result = audit_policy(header, data)
    buf = io.BytesIO(generator(result).encode("utf-8"))
    buf.seek(0)
    return send_file(
        buf,
        mimetype="text/html",
        as_attachment=True,
        download_name=download_name
    )


@app.route("/report_executive", methods=["POST"])
def report_executive_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        return _report_response(request.files["file"], generate_executive_report,
                                "executive_report.html")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/report_engineer", methods=["POST"])
def report_engineer_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        return _report_response(request.files["file"], generate_engineer_report,
                                "engineer_cleanup_plan.html")
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
