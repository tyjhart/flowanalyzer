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
	sample_data["Next Hop IP Version"] = int(data.unpack_uint())
	
	if sample_data["Next Hop IP Version"] == 1:
		sample_data["Next Hop IP Address"] = inet_ntoa(data.unpack_fstring(4)) # IPv4
	elif sample_data["Next Hop IP Version"] == 2:
		sample_data["Next Hop IP Address"] = inet_ntop(data.unpack_fstring(16)) # IPv6
	else:
		sample_data["Next Hop IP Address"] = False

	sample_data["Source Mask Length"] = int(data.unpack_uint())
	sample_data["Destination Mask Length"] = int(data.unpack_uint())
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
	return sample_data