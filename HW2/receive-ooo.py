#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import argparse
from collections import defaultdict
from scapy.all import *
from datetime import datetime
from zoneinfo import ZoneInfo

LB_META_ETYPE = 0x1235

# LoadBalancing header corresponds to lb_meta_t in P4
class LoadBalancing(Packet):
    name = "LoadBalancing"
    fields_desc = [
        ByteField("mode", 1),   # 1 per-flow ECMP, 2 per-packet, 3 flowlet switching
        IntField("flow_id", 0),
        IntField("seq", 0),
    ]

bind_layers(Ether, LoadBalancing, type=LB_META_ETYPE)
bind_layers(LoadBalancing, IP)

# Global inversion helpers
def _merge_count(left, right):
    i = j = inv = 0
    out = []
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            out.append(left[i]); i += 1
        else:
            out.append(right[j]); j += 1
            inv += len(left) - i
    out.extend(left[i:]); out.extend(right[j:])
    return out, inv

def count_inversions(arr):
    n = len(arr)
    if n <= 1:
        return arr, 0
    mid = n // 2
    L, li = count_inversions(arr[:mid])
    R, ri = count_inversions(arr[mid:])
    M, mi = _merge_count(L, R)
    return M, li + ri + mi

def global_inversions(arr):
    _, inv = count_inversions(arr)
    return inv

def local_inversions(arr):
    return sum(1 for i in range(len(arr)-1) if arr[i] > arr[i+1])

def main():
    ap = argparse.ArgumentParser(description="Measure out-of-order delivery per flow")
    ap.add_argument("--iface", default="eth0", help="H2 interface to sniff on")
    ap.add_argument("--log", default="reorder_report.log", help="Output log file")
    ap.add_argument("--verbose", default=True, help="Print raw sequence lists per flow")

    args = ap.parse_args()

    print(f"[i] Sniffing on {args.iface} ...")
    print("[i] Press Ctrl-C to stop and print the report.")

    # Create data structures to track flows
    # Key: flow_id, Value: list of seq numbers seen
    flows = defaultdict(list)
    pkts_seen = 0

    def handle(pkt):
        nonlocal pkts_seen
        if LoadBalancing in pkt:
            lb = pkt[LoadBalancing]
            flows[lb.flow_id].append(lb.seq)
            pkts_seen += 1

    # Creates a Berkeley Packet Filter (BPF) string
    # Only capture packets whose Ethernet Ethertype field is 0x1235
    bpf = f"ether proto 0x{LB_META_ETYPE:04x}"

    try:
        sniff(iface=args.iface, prn=handle, store=False, filter=bpf)
    except KeyboardInterrupt:
        pass

    # Compute metrics and generate report
    lines = []
    lines.append("\n====== Packet Reordering Report ======")
    lines.append(datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S %Z"))
    lines.append(f"Captured packets: {pkts_seen}, flows observed: {len(flows)}")

    # Print raw sequence lists per flow
    if args.verbose:
        lines.append("\n--- Raw sequence lists per flow ---")
        for fid, seqs in flows.items():
                lines.append(f"Flow {fid}: {len(seqs)} packets")
                lines.append("  Seqs: " + ", ".join(map(str, seqs)))
        lines.append("----------------------------------------")

    # Count global and local inversions per flow
    overall_global = 0
    overall_local = 0
    overall_pkts = 0

    for fid, seqs in flows.items():
        global_inv = global_inversions(seqs)
        local_inv = local_inversions(seqs)
        n = len(seqs)
        overall_global += global_inv
        overall_local += local_inv
        overall_pkts += n

        lines.append(f"Flow {fid:10d}: packets={n:4d} | global_inv={global_inv:5d} | local_inv={local_inv:5d}")

    if overall_pkts > 0:
        lines.append("----------------------------------------")
        lines.append(f"TOTAL: packets={overall_pkts} | global_inv={overall_global} | local_inv={overall_local}")
    lines.append("========================================")

    report = "\n".join(lines)
    print(report)
    with open(args.log, "a") as f:
        f.write(report + "\n")

if __name__ == "__main__":
    main()