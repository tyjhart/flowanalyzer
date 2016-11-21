# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import struct
import sys
from xdrlib import Unpacker

from sflow_parsers import *  # Functions to parse headers and format numbers

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
	
	data.done()
	return sample_data

# Ethernet Frame Data (Flow, Enterprise 0, Format 2)
def eth_frame_data(data):
	sample_data = {}
	sample_data["Packet Length"] = data.unpack_uint()
	sample_data["Source MAC"] = data.unpack_string()
	sample_data["Destination MAC"] = data.unpack_string()
	sample_data["Type"] = data.unpack_uint()
	data.done()
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
	data.done()
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
	data.done()
	return sample_data

# Extended Switch Data (Flow, Enterprise 0, Format 1001)
def extended_switch_data(data):
	sample_data = {}
	sample_data["Source VLAN"] = data.unpack_uint()
	sample_data["Source Priority"] = data.unpack_uint()
	sample_data["Destination VLAN"] = data.unpack_uint()
	sample_data["Destination Priority"] = data.unpack_uint()
	data.done()
	return sample_data

# Extended Router Data (Flow, Enterprise 0, Format 1002)
def extended_router_data(data):
	sample_data = {}
	sample_data["Next Hop IP Version"] = int(data.unpack_uint())
	
	if sample_data["Next Hop IP Version"] == 1:
		sample_data["Next Hop IP Address"] = inet_ntoa(data.unpack_fstring(4)) # IPv4
	elif sample_data["Next Hop IP Version"] == 2:
		sample_data["Next Hop IP Address"] = inet_ntop(data.unpack_fstring(16)) # IPv6
	else:
		sample_data["Next Hop IP Address"] = False

	sample_data["Source Mask Length"] = int(data.unpack_uint())
	sample_data["Destination Mask Length"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Extended Gateway Data (Flow, Enterprise 0, Format 1003)
def extended_gateway_data(data):
	sample_data = {}
	data.done()
	return sample_data

# Extended User Data (Flow, Enterprise 0, Format 1004)
def extended_user_data(data):
	sample_data = {}
	data.done()
	return sample_data

# Extended URL Data (Flow, Enterprise 0, Format 1005)
def extended_url_data(data):
	sample_data = {}
	sample_data["Connection Direction"] = url_direction(int(data.unpack_uint()))
	sample_data["URL"] = data.unpack_string()
	sample_data["Host"] = data.unpack_string()
	data.done()
	return sample_data

# Extended MPLS Data (Flow, Enterprise 0, Format 1006)
def extended_mpls_data(data):
	sample_data = {}
	data.done()
	return sample_data

# Extended NAT Data (Flow, Enterprise 0, Format 1007)
def extended_nat_data(data):
	sample_data = {}
	data.done()
	return sample_data

# Extended MPLS Tunnel (Flow, Enterprise 0, Format 1008)
def extended_mpls_tunnel(data):
	sample_data = {}
	sample_data["Tunnel LSP Name"] = data.unpack_string()
	sample_data["Tunnel ID"] = int(data.unpack_uint())
	sample_data["Tunnel COS"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Extended MPLS VC (Flow, Enterprise 0, Format 1009)
def extended_mpls_vc(data):
	sample_data = {}
	sample_data["VC Instance Name"] = data.unpack_string()
	sample_data["VLL VC Instance ID"] = int(data.unpack_uint())
	sample_data["VC Label COS"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Extended MPLS FEC (Flow, Enterprise 0, Format 1010)
def exteded_mpls_fec(data):
	sample_data = {}
	sample_data["MPLS FTN Description"] = data.unpack_string()
	sample_data["MPLS FTN Mask"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Extended MPLS LVP FEC (Flow, Enterprise 0, Format 1011)
def extended_mpls_lvp_fec(data):
	sample_data = {}
	sample_data["MPLS FEC Address Prefix Length"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Extended VLAN Tunnel (Flow, Enterprise 0, Format 1012)
def extended_vlan_tunnel(data):
	sample_data = {}
	sample_data["VLAN Stack"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Extended 802.11 Payload (Flow, Enterprise 0, Format 1013)
def extended_wlan_payload(data):
	sample_data = {}
	data.done()
	return sample_data

# Extended 802.11 RX (Flow, Enterprise 0, Format 1014)
def extended_wlan_rx(data):
	sample_data = {}
	sample_data["SSID"] = data.unpack_fstring(32)
	sample_data["BSSID"] = data.unpack_string()
	sample_data["802.11 Version"] = wlan_version(int(data.unpack_uint()))
	sample_data["802.11 Channel"] = int(data.unpack_uint())
	sample_data["Speed"] = data.unpack_uhyper()
	sample_data["RSNI"] = int(data.unpack_uint())
	sample_data["RCPI"] = int(data.unpack_uint())
	sample_data["Packet Duration"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Extended 802.11 TX (Flow, Enterprise 0, Format 1015)
def extended_wlan_tx(data):
	sample_data = {}
	sample_data["SSID"] = data.unpack_fstring(32)
	sample_data["BSSID"] = data.unpack_string()
	sample_data["802.11 Version"] = wlan_version(int(data.unpack_uint()))
	sample_data["Transmissions"] = wlan_transmissions(int(data.unpack_uint()))
	sample_data["Packet Duration"] = int(data.unpack_uint())
	sample_data["Retransmission Duration"] = int(data.unpack_uint())
	sample_data["802.11 Channel"] = int(data.unpack_uint())
	sample_data["Speed"] = data.unpack_uhyper()
	sample_data["Power mW"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Extended 802.11 Aggregation (Flow, Enterprise 0, Format 1016)
def extended_wlan_aggregation(data):
	sample_data = {}
	data.done()
	return sample_data

# IPv4 Socket (Flow, Enterprise 0, Format 2100)
def ipv4_socket(data):
	sample_data = {}
	sample_data["Protocol Number"] = int(data.unpack_uint())
	sample_data["Protocol"] = iana_protocol_name(sample_data["Protocol Number"]) # Parse IANA-registered protocol name
	sample_data["Category"] = protocol_category(sample_data["Protocol Number"]) # Parse protocol category, or "Other"
	sample_data["Source IP"] = inet_ntoa(data.unpack_fstring(4)) # IPv4
	sample_data["Destination IP"] = inet_ntoa(data.unpack_fstring(4)) # IPv4
	sample_data["Source Port"] = int(data.unpack_uint())
	sample_data["Destination Port"] = int(data.unpack_uint())
	# Need to add category based on source / dest port - FIX
	data.done()
	return sample_data

# IPv6 Socket (Flow, Enterprise 0, Format 2101)
def ipv6_socket(data):
	sample_data = {}
	sample_data["Protocol Number"] = int(data.unpack_uint())
	sample_data["Protocol"] = iana_protocol_name(sample_data["Protocol Number"]) # Parse IANA-registered protocol name
	sample_data["Category"] = protocol_category(sample_data["Protocol Number"]) # Parse protocol category, or "Other"
	sample_data["Source IP"] = inet_ntop(data.unpack_fstring(16)) # IPv6
	sample_data["Destination IP"] = inet_ntop(data.unpack_fstring(16)) # IPv6
	sample_data["Source Port"] = int(data.unpack_uint())
	sample_data["Destination Port"] = int(data.unpack_uint())
	# Need to add category based on source / dest port - FIX
	data.done()
	return sample_data

# Extended TCP Information (Flow, Enterprise 0, Format 2209)
def extended_tcp_info(data):
	datagram = {}
	datagram["Packet Direction"] = packet_direction(data.unpack_uint()) # Parsed packet direction
	datagram["Cached Effective MSS"] = packet_direction(data.unpack_uint())
	datagram["Max Received Segment Size"] = packet_direction(data.unpack_uint())
	datagram["Un-ACKed Packets"] = packet_direction(data.unpack_uint())
	datagram["Lost Packets"] = packet_direction(data.unpack_uint())
	datagram["Retransmitted Packets"] = packet_direction(data.unpack_uint())
	datagram["PMTU"] = packet_direction(data.unpack_uint())
	datagram["RTT ms"] = packet_direction(data.unpack_uint())
	datagram["RTT Variance ms"] = packet_direction(data.unpack_uint())
	datagram["Sending Congestion Window"] = packet_direction(data.unpack_uint())
	datagram["Reordering"] = packet_direction(data.unpack_uint())
	datagram["Minimum RTT ms"] = packet_direction(data.unpack_uint())
	data.done()
	return datagram