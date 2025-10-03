// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_FIRST_HOP = 0x1234;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;   // Standard BMv2 uses 9 bits for egress_spec
typedef bit<48> macAddr_t;      // Ethernet MAC address
typedef bit<32> ip4Addr_t;      // IPv4 address

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// First hop header tag for ECMP
// S1 removes this header and forwards the packet as usual
header first_hop_t {
    bit<8>   tag;     // Use bit<8> for alignment purposes
}

struct metadata {
    bit<8> ecmp_bucket;   // 0..NUM_PATHS-1
}

struct headers {
    ethernet_t   ethernet;
    first_hop_t  first_hop;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_FIRST_HOP: parse_first_hop;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_first_hop {
        packet.extract(hdr.first_hop);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6:  parse_tcp;      // TCP
            17: parse_udp;      // UDP
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Action to set next hop info and update TTL
    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;

        // Update the MAC address
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;    // New src becomes old dst
        hdr.ethernet.dstAddr = dstAddr;                 // New dst is still original dst

        // Decrement TTL
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // S1 has two next hops (to S2 and S3)
    const bit<32> NUM_PATHS = 2;

    // Helper function to compute hash for ECMP using TCP/IP 5-tuple
    action compute_ecmp_hash() {
        bit<32> h;

        // Check which L4 protocol is in use and extract ports accordingly
        bit<16> l4srcPort = (hdr.tcp.isValid()) ? hdr.tcp.srcPort
                            : ((hdr.udp.isValid()) ? hdr.udp.srcPort : (bit<16>)0);
        bit<16> l4dstPort = (hdr.tcp.isValid()) ? hdr.tcp.dstPort
                            : ((hdr.udp.isValid()) ? hdr.udp.dstPort : (bit<16>)0);

        // v1model hash extern: base=0 (no salt), data={fields}, max=0 (no max limit)
        hash(h, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr,
                                          hdr.ipv4.dstAddr,
                                          hdr.ipv4.protocol,
                                          l4srcPort, l4dstPort }, (bit<32>)0);

        meta.ecmp_bucket = (bit<8>)(h % NUM_PATHS);
    }

    // Action to strip first_hop header and restore EtherType to IPv4
    action strip_first_hop() {
        hdr.first_hop.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    table ecmp_select {
        key = {
            meta.ecmp_bucket: exact;    // 0..NUM_PATHS-1
        }
        actions = {
            set_nhop;
            drop;
            NoAction;
        }
        size = 3;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            // At S1, use ECMP forwarding
            if (hdr.first_hop.isValid()) {
                compute_ecmp_hash();
                ecmp_select.apply();
                strip_first_hop();
            }
            else {
                // At S2-S4, use regular destination-based forwarding
                ipv4_lpm.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
* The deparser serializes headers back onto the packet in order.         *
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.first_hop);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
    
}

/*************************************************************************
***********************  S W I T C H  ***********************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
