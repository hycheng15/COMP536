#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
import argparse, random, time
from datetime import datetime
from zoneinfo import ZoneInfo
from scapy.all import *

LOG_FILE = "random_flows.log"

# Helper function to log to both console and file
def out(msg=""):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

FIRST_HOP_ETYPE = 0x1234
LB_META_ETYPE = 0x1235
QUERY_ETYPE = 0x1236

# ===== Define custom headers =====

# LoadBalancing header corresponds to lb_meta_t in P4
class LoadBalancing(Packet):
    name = "LoadBalancing"
    fields_desc = [
        ByteField("mode", 1),      # 1 per-flow ECMP, 2 per-packet
        IntField("flow_id", 0),
        IntField("seq", 0),
    ]

# First-hop header corresponds to first_hop_t in P4
class FirstHop(Packet):
    name = "FirstHop"
    fields_desc = [ ByteField("tag", 1) ]   # 1 means should be processed by S1

# Query header corresponds to query_t in P4
class Query(Packet):
    name = "Query"
    fields_desc = [
        LongField("port_2_bytes", 0),
        LongField("port_3_bytes", 0)
    ]

# Bind the custom Ethertypes

# For H1 → S1
bind_layers(Ether, FirstHop, type=FIRST_HOP_ETYPE)
bind_layers(FirstHop, LoadBalancing)
bind_layers(LoadBalancing, IP)

# For S1 → … → H2
bind_layers(Ether, LoadBalancing, type=LB_META_ETYPE)
bind_layers(LoadBalancing, IP)

# For querying S1
bind_layers(Ether, Query, type=QUERY_ETYPE)
bind_layers(FirstHop, IP)

# Get interface to send/receive packets
def get_if():
    ifs = get_if_list()
    iface = None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        out("Cannot find eth0 interface")
        exit(1)
    return iface

# Return (p2, p3) bytes from S1 counters
def do_query(iface, dst="ff:ff:ff:ff:ff:ff", tries=2, timeout=2):
    out("[i] Querying S1 for port byte counters...")
    mac = get_if_hwaddr(iface)

    req = Ether(src=mac, dst=dst, type=QUERY_ETYPE) / Query(
        port_2_bytes=0,
        port_3_bytes=0
    )
    ans = None

    # Try sending query multiple times if no response
    for _ in range(tries):
        ans = srp1(req, iface=iface, timeout=timeout, verbose=False)
        if ans and Query in ans:
            break
    if not ans or Query not in ans:
        return None
    return (int(ans[Query].port_2_bytes), int(ans[Query].port_3_bytes))

# Build a packet with given 5-tuple and payload length
def build_pkt(iface, mode, flow_id, seq, dst_ip, l4proto, sport, dport, paylen):
    mac = get_if_hwaddr(iface)
    pkt = (
        Ether(type=FIRST_HOP_ETYPE, dst="ff:ff:ff:ff:ff:ff", src=mac)
        / FirstHop(tag=1)
        / LoadBalancing(mode=mode, flow_id=flow_id, seq=seq)
        / IP(dst=dst_ip)
        / (UDP(sport=sport, dport=dport) if l4proto=="udp"
           else TCP(sport=sport, dport=dport, flags="PA", seq=random.randrange(1, 2**32)))
        / Raw(b"X" * paylen)
    )
    return pkt

def main():
    # Record current time in log
    now = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S %Z")
    header = f"\n===== New Run: {now} ====="
    out(header)

    ap = argparse.ArgumentParser(description="Send random flows and measure ECMP split")
    ap.add_argument("--dst", default="10.0.2.2", help="Receiver IP (H2)")
    ap.add_argument("--mode",type=int,choices=[1, 2], required=True, help="Load balancing mode: 1 = per-flow ECMP, 2 = per-packet")
    ap.add_argument("--flows", type=int, default=50, help="# of flows")
    ap.add_argument("--min-pkts", type=int, default=5, help="Min packets per flow")
    ap.add_argument("--max-pkts", type=int, default=30, help="Max packets per flow")
    ap.add_argument("--min-len", type=int, default=64, help="Min payload bytes")
    ap.add_argument("--max-len", type=int, default=600, help="Max payload bytes")
    ap.add_argument("--proto", choices=["mix","udp","tcp"], default="mix", help="L4 protocol choices")
    ap.add_argument("--pace", type=float, default=0.0, help="Sleep seconds between packets (e.g., 0.001)")
    ap.add_argument("--seed", type=int, default=None, help="Set random seed for reproducibility (default = current time)")
    args = ap.parse_args()

    if args.seed is None:
        args.seed = int(time.time())
    random.seed(args.seed)
    out(f"[i] Using random seed = {args.seed}")

    iface = get_if()
    out(f"[i] Using iface={iface}")
    out(f"[i] Load balancing mode = {'per-flow ECMP' if args.mode==1 else 'per-packet'}")

    # Read baseline counters (bytes leaving S1 ports 2 & 3)
    before = do_query(iface)
    if before is None:
        out("[!] No response to query from S1. Is the P4 program running and query logic enabled?")
        return
    b2, b3 = before
    out(f"[i] Baseline S1 bytes: port2={b2}, port3={b3}")

    # Generate and send flows
    sent_pkts = 0
    for f in range(args.flows):
        # Generate random 5-tuple (same tuple within a flow to emulate a flow)
        if args.proto == "mix":
            l4proto = random.choice(["udp", "tcp"])
        else:
            l4proto = args.proto

        flow_id = random.getrandbits(32)
        sport = random.randint(1024, 65535)
        dport = random.randint(1024, 65535)
        pkts_in_flow = random.randint(args.min_pkts, args.max_pkts)
        paylen = random.randint(args.min_len, args.max_len)
        out(f"[i] Flow {f+1}: {l4proto.upper()} {sport} → {dport}, {pkts_in_flow} pkts, {paylen} bytes each, flow_id={flow_id}")

        seq = 0  # Sequence starts at 0 for this flow
        # Send this flow's packets
        for _ in range(pkts_in_flow):
            pkt = build_pkt(
                iface=iface,
                mode=args.mode,
                flow_id=flow_id,
                seq=seq,
                dst_ip=args.dst,
                l4proto=l4proto,
                sport=sport,
                dport=dport,
                paylen=paylen
            )
            sendp(pkt, iface=iface, verbose=False)
            sent_pkts += 1
            seq += 1  # increment per packet

            if args.pace > 0:
                time.sleep(args.pace)

    # Read counters again
    after = do_query(iface)
    if after is None:
        out("[!] No response to query from S1 after sending.")
        return
    a2, a3 = after

    # Compute deltas (bytes this run)
    d2 = a2 - b2
    d3 = a3 - b3
    total_bytes_from_src = d2 + d3

    out("\n------- ECMP Load-Balance Report -------")
    out(f"Packets sent: {sent_pkts}")
    out(f"Total bytes (as counted at S1 egress): {total_bytes_from_src}")
    out(f"Upper path (port 3): {d3} bytes")
    out(f"Lower path (port 2): {d2} bytes")
    if total_bytes_from_src > 0:
        r3 = 100.0 * d3 / total_bytes_from_src
        r2 = 100.0 * d2 / total_bytes_from_src
        out(f"Split: port3={r3:.2f}%  |  port2={r2:.2f}%")
    else:
        out("Split: 0% / 0% (no bytes observed)")
    out("============================================")

if __name__ == "__main__":
    main()