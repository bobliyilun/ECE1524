//
// Copyright (c) 2017 Stephen Ibanez, 2021 Theo Jepsen
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"),
// as part of the DARPA MRC research programme.
//


#include <core.p4>
#include <v1model.p4>


typedef bit<9>  port_t;
typedef bit<48> EthAddr_t;
typedef bit<32> IPv4Addr_t;

const bit<16> IP_TYPE = 16w0x0800;
const bit<16> ARP_TYPE = 16w0x0806;

const bit<4> IPv4 = 4w0x4;

const bit<16> ARP_HTYPE = 1;
const bit<16> ARP_PTYPE = IP_TYPE;
const bit<8> ARP_HLEN = 6;
const bit<8> ARP_PLEN = 4;
const bit<16> OPER_REQUEST = 1;
const bit<16> OPER_REPLY = 2;

const port_t CPU_PORT = 1;

typedef bit<8> digCode_t;
const digCode_t DIG_LOCAL_IP = 1;
const digCode_t DIG_ARP_MISS = 2;
const digCode_t DIG_ARP_REPLY = 3;
const digCode_t DIG_TTL_EXCEEDED = 4;
const digCode_t DIG_NO_ROUTE = 5;

// standard Ethernet header
header Ethernet_h {
    EthAddr_t dstAddr;
    EthAddr_t srcAddr;
    bit<16> etherType;
}

// TODO: What other headers do you need to add support for?
header IPv4_h {
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
    IPv4Addr_t srcAddr;
    IPv4Addr_t dstAddr;
}

header ARP_h {
    bit<16>     HTYPE;
    bit<16>     PTYPE;
    bit<8>      HLEN;
    bit<8>      PLEN;
    bit<16>     OPER;
    EthAddr_t   SHA;
    IPv4Addr_t  SPA;
    EthAddr_t   THA;
    IPv4Addr_t  TPA;
}
/* Here we define a digest_header type. This header contains information
 * that we want to send to the control-plane. This header should be
 * prepended to all packets sent to the control-plane.
 */
// Digest header
header digest_header_h {
    bit<16>   src_port;
    bit<8>   digest_code;
}

// List of all recognized headers
struct Parsed_packet {
    Ethernet_h ethernet;
    IPv4_h ip;
    ARP_h arp;
    digest_header_h digest;
}

// user defined metadata: can be used to shared information between
// MyParser, MyIngress, and MyDeparser
struct user_metadata_t {
}

// Parser Implementation
parser MyParser(packet_in b,
                 out Parsed_packet p,
                 inout user_metadata_t user_metadata,
                 inout standard_metadata_t standard_metadata) {
    // TODO: Parse any additional headers that you add
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        b.extract(p.ethernet);
        transition select(p.ethernet.etherType) {
            IP_TYPE: parse_ipv4;
            ARP_TYPE: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        b.extract(p.ip);
        transition accept;
    }

    state parse_arp {
        b.extract(p.arp);
        transition select(p.arp.OPER) {
            OPER_REQUEST: accept;
            OPER_REPLY: accept;
        }
    }
}

control MyVerifyChecksum(inout Parsed_packet p, inout user_metadata_t meta) {
    apply {
        // TODO: Verify the IPv4 checksum
            verify_checksum(
            p.ip.isValid(),
            { p.ip.version,
              p.ip.ihl,
              p.ip.diffserv,
              p.ip.totalLen,
              p.ip.identification,
              p.ip.flags,
              p.ip.fragOffset,
              p.ip.ttl,
              p.ip.protocol,
              p.ip.srcAddr,
              p.ip.dstAddr },
            p.ip.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// match-action pipeline
control MyIngress(inout Parsed_packet p,
                inout user_metadata_t user_metadata,
                  inout standard_metadata_t standard_metadata) {

    // TODO: Declare your actions and tables
    IPv4Addr_t next_hop_ipv4 = 0;
    EthAddr_t next_hop_mac = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action send_to_cpu(digCode_t dig_code) {
        standard_metadata.egress_spec = CPU_PORT;
        p.digest.src_port = (bit<16>)standard_metadata.ingress_port; 
        p.digest.digest_code = dig_code;
        p.digest.setValid();
    }

    action ipv4_forward(port_t port, IPv4Addr_t next) {
        standard_metadata.egress_spec = port;
        next_hop_ipv4 = next;
    }

    action arp_respond(EthAddr_t result) {
        if (p.ip.isValid()) {
            next_hop_mac = result;
        }
        else if (p.arp.isValid()) {
            p.arp.OPER = OPER_REPLY;
            p.arp.THA = p.arp.SHA;
            p.ethernet.dstAddr = p.ethernet.srcAddr;
            p.arp.SHA = result;
            p.ethernet.srcAddr = result;
            standard_metadata.egress_spec = standard_metadata.ingress_port;
        }
    }

    action arp_miss() {
        send_to_cpu(DIG_ARP_MISS);
    }

    action local_hit() {
        send_to_cpu(DIG_LOCAL_IP);
    }

    action route_miss() {
        send_to_cpu(DIG_NO_ROUTE);
    }

    // TODO: Is this what the routing table is supposed to look like?
    table routing_table {
        key = {
            p.ip.dstAddr: ternary;
        }
        actions = {
            ipv4_forward;
            route_miss;
        }
        size = 1024;
        default_action = route_miss();
    }

    table arp_cache_table {
        key = {
            next_hop_ipv4: exact;
        }
        actions = {
            arp_respond;
            arp_miss;
        }
        size = 1024;
        default_action = arp_miss();
    }

    table local_ip_table {
        key = {
            p.ip.dstAddr: exact;
        }
        actions = {
            local_hit;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    apply {
        // TODO: Define your control flow
        if (p.ip.isValid()) {
            p.ip.ttl = p.ip.ttl - 1;
            if (p.ip.ttl <= 0) {
                send_to_cpu(DIG_TTL_EXCEEDED);
            }
            else {
                if (local_ip_table.apply().miss){
                    routing_table.apply();
                }
            }
        }
        else if (p.arp.isValid()) {
            if (p.arp.OPER == OPER_REPLY) {
                send_to_cpu(DIG_ARP_REPLY);
            }
            else { 
                next_hop_ipv4 = p.arp.TPA;
                // ARP_table.apply();
            }
        }
        if ((standard_metadata.egress_spec != CPU_PORT) && (next_hop_ipv4 != 0)) {
            if (arp_cache_table.apply().hit && p.ip.isValid()) {
                p.ethernet.srcAddr = p.ethernet.dstAddr;
                p.ethernet.dstAddr = next_hop_mac;
            }
        }                   
    }
}

// Deparser Implementation
control MyDeparser(packet_out b,
                    in Parsed_packet p) {
    apply {
        // TODO: Emit other headers you've defined
        b.emit(p.digest);
        b.emit(p.ethernet);
        b.emit(p.ip);
        b.emit(p.arp);
    }
}

control MyEgress(inout Parsed_packet hdr,
                 inout user_metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout Parsed_packet hdr, inout user_metadata_t meta) {
    apply {
        // TODO: compute the IPv4 checksum
        update_checksum(
        hdr.ip.isValid(),
            { hdr.ip.version,
              hdr.ip.ihl,
              hdr.ip.diffserv,
              hdr.ip.totalLen,
              hdr.ip.identification,
              hdr.ip.flags,
              hdr.ip.fragOffset,
              hdr.ip.ttl,
              hdr.ip.protocol,
              hdr.ip.srcAddr,
              hdr.ip.dstAddr },
            hdr.ip.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// Instantiate the switch
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
