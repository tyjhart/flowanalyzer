# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import sys, struct
from xdrlib import Unpacker
from sflow_parsers import * # Functions to parse headers and format numbers

# Parse raw Ethernet header
def parse_eth_header(header_string):
	ord_dest_mac = [ord(x) for x in [header_string[0],header_string[1],header_string[2],header_string[3],header_string[4],header_string[5]]]
	dest_mac = mac_parse(ord_dest_mac)
	ord_src_mac = [ord(x) for x in [header_string[6],header_string[7],header_string[8],header_string[9],header_string[10],header_string[11]]]
	src_mac = mac_parse(ord_src_mac)
	return [dest_mac,src_mac]

### FLOW SAMPLES START ###

# Raw Packet Header (Flow, Enterprise 0, Format 1)
def raw_packet_header(data):
	sample_data = {}
	sample_data["Header Protocol Number"] = data.unpack_uint()
	sample_data["Header Protocol"] = parse_header_prot_name(sample_data["Header Protocol Number"])
	sample_data["Frame Length"] = data.unpack_uint()
	sample_data["Stripped"] = data.unpack_uint()
	sample_data["Header Size"] = data.unpack_uint()
	sample_data["Header"] = (data.unpack_fopaque(sample_data["Header Size"])).decode('iso-8859-1')
	if sample_data["Header Protocol Number"] == 1:
		mac_addresses = parse_eth_header(sample_data["Header"])
		sample_data["Destination MAC"] = mac_addresses[0]
		sample_data["Source MAC"] = mac_addresses[1]
	return sample_data

# Ethernet Frame Data (Flow, Enterprise 0, Format 2)
def eth_frame_data(data):
	sample_data = {}
	sample_data["Packet Length"] = data.unpack_uint()
	sample_data["Source MAC"] = data.unpack_string()
	sample_data["Destination MAC"] = data.unpack_string()
	sample_data["Type"] = data.unpack_uint()
	return sample_data

# IPv4 Data (Flow, Enterprise 0, Format 3)
def ipv4_data(data):
	sample_data = {}
	sample_data["IP Packet Length"] = data.unpack_uint()
	sample_data["IP Protocol"] = data.unpack_uint()
	sample_data["IPv4 Source IP"] = data.unpack_string()
	sample_data["IPv4 Destination IP"] = data.unpack_string()
	sample_data["Source Port"] = data.unpack_uint()
	sample_data["Destination Port"] = data.unpack_uint()
	sample_data["TCP Flags"] = data.unpack_uint()
	sample_data["Type of Service"] = data.unpack_uint()
	return sample_data

# IPv6 Data (Flow, Enterprise 0, Format 4)
def ipv6_data(data):
	sample_data = {}
	sample_data["Packet Length"] = data.unpack_uint()
	sample_data["IP Next Header"] = data.unpack_uint()
	sample_data["IPv6 Source IP"] = data.unpack_string()
	sample_data["IPv6 Destination IP"] = data.unpack_string()
	sample_data["Source Port"] = data.unpack_uint()
	sample_data["Destination Port"] = data.unpack_uint()
	sample_data["TCP Flags"] = data.unpack_uint()
	sample_data["IP Priority"] = data.unpack_uint()
	return sample_data

# Extended Switch Data (Flow, Enterprise 0, Format 1001)
def extended_switch_data(data):
	sample_data = {}
	sample_data["Source VLAN"] = data.unpack_uint()
	sample_data["Source Priority"] = data.unpack_uint()
	sample_data["Destination VLAN"] = data.unpack_uint()
	sample_data["Destination Priority"] = data.unpack_uint()
	return sample_data

# Extended Router Data (Flow, Enterprise 0, Format 1002)
def extended_router_data(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended Gateway Data (Flow, Enterprise 0, Format 1003)
def extended_gateway_data(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended User Data (Flow, Enterprise 0, Format 1004)
def extended_user_data(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended URL Data (Flow, Enterprise 0, Format 1005)
def extended_url_data(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended MPLS Data (Flow, Enterprise 0, Format 1006)
def extended_mpls_data(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended NAT Data (Flow, Enterprise 0, Format 1007)
def extended_nat_data(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended MPLS Tunnel (Flow, Enterprise 0, Format 1008)
def extended_mpls_tunnel(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended MPLS VC (Flow, Enterprise 0, Format 1009)
def extended_mpls_vc(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended MPLS FEC (Flow, Enterprise 0, Format 1010)
def exteded_mpls_fec(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended MPLS LVP FEC (Flow, Enterprise 0, Format 1011)
def extended_mpls_lvp_fec(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

# Extended VLAN Tunnel (Flow, Enterprise 0, Format 1012)
def extended_vlan_tunnel(data):
	sample_data = {}
	sample_data["header_protocol"] = int(data.unpack_uint())
	return sample_data

### FLOW SAMPLES END ###
#
#
### COUNTER SAMPLES START ###

# Generic Interface Counter (Enterprise 0, Format 1)
def gen_int_counter(data):
	sample_data = {}
	sample_data["ifIndex"] = int(data.unpack_uint())
	sample_data["ifType"] = iana_interface_type(int(data.unpack_uint()))
	sample_data["ifSpeed"] = data.unpack_hyper()

	ifDirection = int(data.unpack_uint())
	if ifDirection == 0:
		sample_data["ifDirection"] = "unknown"
	elif ifDirection == 1:
		sample_data["ifDirection"] = "full-duplex"
	elif ifDirection == 2:
		sample_data["ifDirection"] = "half-duplex"
	elif ifDirection == 3:
		sample_data["ifDirection"] = "in"
	elif ifDirection == 4:
		sample_data["ifDirection"] = "out"
	else:
		sample_data["ifDirection"] = "unknown"

	# http://sflow.org/developers/diagrams/sFlowV5CounterData.pdf FIX!
	ifStatus = int(data.unpack_uint())
	if ifStatus == 0:
		sample_data["ifStatus"] = "unknown"
	elif ifStatus == 1:
		sample_data["ifStatus"] = "full-duplex"
	else:
		sample_data["ifStatus"] = "unknown"

	sample_data["ifInOctets"] = data.unpack_hyper()
	sample_data["ifInUcastPkts"] = int(data.unpack_uint())
	sample_data["ifInMulticastPkts"] = int(data.unpack_uint())
	sample_data["ifInBroadcastPkts"] = int(data.unpack_uint())
	sample_data["ifInDiscards"] = int(data.unpack_uint())
	sample_data["ifInErrors"] = int(data.unpack_uint())
	sample_data["ifInUnknownProtos"] = int(data.unpack_uint())
	sample_data["ifOutOctets"] = data.unpack_hyper()
	sample_data["ifOutUcastPkts"] = int(data.unpack_uint())
	sample_data["ifOutMulticastPkts"] = int(data.unpack_uint())
	sample_data["ifOutBroadcastPkts"] = int(data.unpack_uint())
	sample_data["ifOutDiscards"] = int(data.unpack_uint())
	sample_data["ifOutErrors"] = int(data.unpack_uint())
	sample_data["ifPromiscuousMode"] = int(data.unpack_uint()) 
	return sample_data

# Ethernet Interface Counters (Enterprise 0, Format 2)
def eth_int_counter(data):
	sample_data = {}
	sample_data["dot3StatsAlignmentErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsFCSErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsSingleCollisionFrames"] = int(data.unpack_uint())
	sample_data["dot3StatsMultipleCollisionFrames"] = int(data.unpack_uint())
	sample_data["dot3StatsSQETestErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsDeferredTransmissions"] = int(data.unpack_uint())
	sample_data["dot3StatsLateCollisions"] = int(data.unpack_uint())
	sample_data["dot3StatsExcessiveCollisions"] = int(data.unpack_uint())
	sample_data["dot3StatsInternalMacTransmitErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsCarrierSenseErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsFrameTooLongs"] = int(data.unpack_uint())
	sample_data["dot3StatsInternalMacReceiveErrors"] = int(data.unpack_uint())
	sample_data["dot3StatsSymbolErrors"] = int(data.unpack_uint())
	return sample_data

# Token Ring Counters (Enterprise 0, Format 3)
def token_ring_counter(data):
	sample_data = {}
	sample_data["dot5StatsLineErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsACErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsAbortTransErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsInternalErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsLostFrameErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsReceiveCongestions"] = int(data.unpack_uint())
	sample_data["dot5StatsFrameCopiedErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsTokenErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsSoftErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsHardErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsSignalLoss"] = int(data.unpack_uint())
	sample_data["dot5StatsTransmitBeacons"] = int(data.unpack_uint())
	sample_data["dot5StatsRecoverys"] = int(data.unpack_uint())
	sample_data["dot5StatsLobeWires"] = int(data.unpack_uint())
	sample_data["dot5StatsBurstErrors"] = int(data.unpack_uint())
	sample_data["dot5StatsRemoves"] = int(data.unpack_uint())
	sample_data["dot5StatsSingles"] = int(data.unpack_uint())
	sample_data["dot5StatsFreqErrors"] = int(data.unpack_uint())
	return sample_data

# 100 BaseVG Interface Counters (Enterprise 0, Format 4)
def basevg_int_counter(data):
	sample_data = {}
	sample_data["dot12InHighPriorityFrames"] = int(data.unpack_uint())
	sample_data["dot12InHighPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12InNormPriorityFrames"] = int(data.unpack_uint())
	sample_data["dot12InNormPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12InIPMErrors"] = int(data.unpack_uint())
	sample_data["dot12InOversizeFrameErrors"] = int(data.unpack_uint())
	sample_data["dot12InDataErrors"] = int(data.unpack_uint())
	sample_data["dot12InNullAddressedFrames"] = int(data.unpack_uint())
	sample_data["dot12OutHighPriorityFrames"] = int(data.unpack_uint())
	sample_data["dot12OutHighPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12TransitionIntoTrainings"] = int(data.unpack_uint())
	sample_data["dot12HCInHighPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12HCInNormPriorityOctets"] = data.unpack_hyper()
	sample_data["dot12HCOutHighPriorityOctets"] = data.unpack_hyper()
	return sample_data

# VLAN Counters (Enterprise 0, Format 5)
def vlan_counter(data):
	sample_data = {}
	sample_data["vlan_id"] = int(data.unpack_uint())
	sample_data["octets"] = data.unpack_hyper()
	sample_data["ucastPkts"] = int(data.unpack_uint())
	sample_data["multicastPkts"] = int(data.unpack_uint())
	sample_data["broadcastPkts"] = int(data.unpack_uint())
	sample_data["discards"] = int(data.unpack_uint())
	return sample_data

# Processor Information (Enterprise 0, Format 1001)
def proc_info(data):
	sample_data = {}
	sample_data["5s cpu percentage"] = int(data.unpack_uint())
	sample_data["1m cpu percentage"] = int(data.unpack_uint())
	sample_data["5m cpu percentage"] = int(data.unpack_uint())
	sample_data["total memory"] = data.unpack_hyper()
	sample_data["free memory"] = data.unpack_hyper()
	return sample_data

### COUNTER SAMPLES END ###