/* -*- P4_14 -*- */

#ifdef __TARGET_TOFINO__
#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>
#else
#error This program is intended to compile for Tofino P4 architecture only
#endif

// SMPTE ST 2110-20 Lower Third Example
// Author: Thomas Edwards (thomas.edwards@fox.com)
//
// This P4 program allows the on-switch mixing of certain raster
// rows (a.k.a. scan lines) from one 2110-20 flow with certain
// raster rows from another 2110-20 flow.  (It probably also
// works with the very similar RFC 4175).  The resulting
// combined flow has its destination IP address restamped.
//
// A potential use for this would be the "hard switching" of a
// lower third graphic.
//
// Only the first Sample Row Data (SRD) header in a packet is
// examined.  This technique would work best with 2110-20 systems
// that only have data from a single raster row in a packet.
//
// If you need a SMPTE ST 2110-20 Wireshark dissector, see:
// https://github.com/FOXNEOAdvancedTechnology/smpte2110-20-dissector
//
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

field_list ipv4_checksum_list {
	ipv4.version;
	ipv4.ihl;
	ipv4.diffserv;
	ipv4.totalLen;
	ipv4.identification;
	ipv4.flags;
	ipv4.fragOffset;
	ipv4.ttl;
	ipv4.protocol;
	ipv4.srcAddr;
	ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
	input {
		ipv4_checksum_list;
	}
	algorithm : csum16;
	output_width : 16;
}

calculated_field ipv4.hdrChecksum {
	verify ipv4_checksum;
	update ipv4_checksum;
}

field_list udp_ipv4_checksum_list {
	ipv4.srcAddr;
	ipv4.dstAddr;
	8'0;
	ipv4.protocol;
	ipv4.totalLen;
	udp.srcPort;
	udp.dstPort;
	udp.length_;
	payload;
}

field_list_calculation udp_ipv4_checksum {
	input {
		udp_ipv4_checksum_list;
	}
	algorithm : csum16;
	output_width : 16;
}

calculated_field udp.checksum {
	update udp_ipv4_checksum;
}
    
header_type rtp_t {
    fields {
        version : 2;
        padding : 1;
        extension : 1;
        CSRC_count : 4;
        marker : 1;
        payload_type : 7;
        sequence_number : 16;
        timestamp : 32;
        SSRC : 32;
    }
} 

header_type s2110_t {
    fields {
	extended_sequence_number : 16;
	SRD_Length : 16;
	field : 1;
	SRD_Row_Number : 15;
	continuation : 1;
	SRD_Offset : 15;
	// note, only the first SRD header is examined
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

#define ETHERTYPE_IPV4 0x0800

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
   }
}

header ipv4_t ipv4;

#define PROTOCOL_UDP 0x11

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        PROTOCOL_UDP : parse_udp;
	default: ingress;
  }
}

header udp_t udp;

parser parse_udp {
    extract(udp);
    return parse_rtp;
}

header rtp_t rtp;

parser parse_rtp {
    extract(rtp);
    return parse_s2110;
}

header s2110_t s2110;

parser parse_s2110 {
    extract(s2110);
    return ingress;
}

counter my_direct_counter {
    type: bytes;
    direct: schedule_table;
}

action take_video(dst_ip,dport) {
//    BMV2 version
//    modify_field(standard_metadata.egress_spec,dport);

      modify_field(ig_intr_md_for_tm.ucast_egress_port,dport);
      modify_field(ipv4.dstAddr,dst_ip);
}

action _drop() {
    drop();
}

table schedule_table {
    reads {
	ipv4.dstAddr: exact;
        s2110.SRD_Row_Number: range;
    }
    actions {
        take_video; 
        _drop;
    }
    size : 16384;
}

control ingress {
    apply(schedule_table);
}

control egress {
}
