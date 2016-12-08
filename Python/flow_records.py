# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import struct
import sys
from xdrlib import Unpacker

from parser_modules import mac_address # Field parsing functions
from sflow_parsers import *  # Functions to parse headers and format numbers

# Raw Packet Header (Flow, Enterprise 0, Format 1)
def raw_packet_header(
	data # type: "XDR Data"
	):
	"""Raw Packet Header - Type: Flow, Enterprise: 0, Format: 1"""
	sample_data = {} # Cache
	sample_data["Header Protocol Number"] = data.unpack_uint()
	sample_data["Header Protocol"] = parse_header_prot_name(sample_data["Header Protocol Number"])
	sample_data["Frame Length"] = data.unpack_uint()
	sample_data["Stripped"] = data.unpack_uint()
	sample_data["Header Size"] = data.unpack_uint()
	sample_data["Header"] = (data.unpack_fopaque(sample_data["Header Size"])).decode('iso-8859-1')
	if sample_data["Header Protocol Number"] == 1:
		mac_addresses = parse_eth_header(sample_data["Header"])
		sample_data["Destination MAC"] = mac_addresses[0]
		sample_data["Destination MAC OUI"] = mac_addresses[2]
		sample_data["Source MAC"] = mac_addresses[1]
		sample_data["Source MAC OUI"] = mac_addresses[3]
	
	data.done() # Verify all data unpacked
	return sample_data

# Ethernet Frame Data (Flow, Enterprise 0, Format 2)
def eth_frame_data(
	data # type: "XDR Data"
	):
	"""Ethernet Frame Data - Type: Flow, Enterprise: 0, Format: 2"""
	sample_data = {} # Cache
	sample_data["Packet Length"] = data.unpack_uint()
	sample_data["Source MAC"] = data.unpack_string()
	sample_data["Destination MAC"] = data.unpack_string()
	sample_data["Type"] = data.unpack_uint()
	data.done() # Verify all data unpacked
	return sample_data

# IPv4 Data (Flow, Enterprise 0, Format 3)
def ipv4_data(
	data # type: "XDR Data"
	):
	"""IPv4 Data - Type: Flow, Enterprise: 0, Format: 3"""
	sample_data = {} # Cache
	sample_data["IP Packet Length"] = data.unpack_uint()
	sample_data["IP Protocol"] = data.unpack_uint()
	sample_data["IPv4 Source IP"] = data.unpack_string()
	sample_data["IPv4 Destination IP"] = data.unpack_string()
	sample_data["Source Port"] = data.unpack_uint()
	sample_data["Destination Port"] = data.unpack_uint()
	sample_data["TCP Flags"] = data.unpack_uint()
	sample_data["Type of Service"] = data.unpack_uint()
	data.done() # Verify all data unpacked
	return sample_data

# IPv6 Data (Flow, Enterprise 0, Format 4)
def ipv6_data(
	data # type: "XDR Data"
	):
	"""IPv6 Data - Type: Flow, Enterprise: 0, Format: 4"""
	sample_data = {} # Cache
	sample_data["Packet Length"] = data.unpack_uint()
	sample_data["IP Next Header"] = data.unpack_uint()
	sample_data["IPv6 Source IP"] = data.unpack_string()
	sample_data["IPv6 Destination IP"] = data.unpack_string()
	sample_data["Source Port"] = data.unpack_uint()
	sample_data["Destination Port"] = data.unpack_uint()
	sample_data["TCP Flags"] = data.unpack_uint()
	sample_data["IP Priority"] = data.unpack_uint()
	data.done() # Verify all data unpacked
	return sample_data

# Extended Switch Data (Flow, Enterprise 0, Format 1001)
def extended_switch_data(
	data # type: "XDR Data"
	):
	"""Extended Switch Data - Type: Flow, Enterprise: 0, Format: 1001"""
	sample_data = {} # Cache
	sample_data["Source VLAN"] = data.unpack_uint()
	sample_data["Source Priority"] = data.unpack_uint()
	sample_data["Destination VLAN"] = data.unpack_uint()
	sample_data["Destination Priority"] = data.unpack_uint()
	data.done() # Verify all data unpacked
	return sample_data

# Extended Router Data (Flow, Enterprise 0, Format 1002)
def extended_router_data(
	data # type: "XDR Data"
	):
	"""Extended Router Data - Type: Flow, Enterprise: 0, Format: 1002"""
	sample_data = {} # Cache
	sample_data["Next Hop IP Version"] = int(data.unpack_uint())
	
	if sample_data["Next Hop IP Version"] == 1:
		sample_data["Next Hop IP Address"] = inet_ntoa(data.unpack_fstring(4)) # IPv4
	elif sample_data["Next Hop IP Version"] == 2:
		sample_data["Next Hop IP Address"] = inet_ntop(data.unpack_fstring(16)) # IPv6
	else:
		sample_data["Next Hop IP Address"] = False

	sample_data["Source Mask Length"] = int(data.unpack_uint())
	sample_data["Destination Mask Length"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended Gateway Data (Flow, Enterprise 0, Format 1003)
def extended_gateway_data(
	data # type: "XDR Data"
	):
	"""Extended Gateway Data - Type: Flow, Enterprise: 0, Format: 3"""
	sample_data = {} # Cache
	data.done() # Verify all data unpacked
	return sample_data

# Extended User Data (Flow, Enterprise 0, Format 1004)
def extended_user_data(
	data # type: "XDR Data"
	):
	"""Extended User Data - Type: Flow, Enterprise: 0, Format: 1004"""
	sample_data = {} # Cache
	sample_data["Source Charset"] = int(data.unpack_uint())
	sample_data["Source User"] = data.unpack_string()
	sample_data["Destination Charset"] = int(data.unpack_uint())
	sample_data["Destination User"] = data.unpack_string()
	data.done() # Verify all data unpacked
	return sample_data

# Extended URL Data (Flow, Enterprise 0, Format 1005)
def extended_url_data(
	data # type: "XDR Data"
	):
	"""Extended URL Data - Type: Flow, Enterprise: 0, Format: 1005"""
	sample_data = {} # Cache
	sample_data["Connection Direction"] = url_direction(int(data.unpack_uint()))
	sample_data["URL"] = data.unpack_string()
	sample_data["Host"] = data.unpack_string()
	data.done() # Verify all data unpacked
	return sample_data

# Extended MPLS Data (Flow, Enterprise 0, Format 1006)
def extended_mpls_data(
	data # type: "XDR Data"
	):
	"""Extended MPLS Data - Type: Flow, Enterprise: 0, Format: 1006"""
	sample_data = {} # Cache
	data.done() # Verify all data unpacked
	return sample_data

# Extended NAT Data (Flow, Enterprise 0, Format 1007)
def extended_nat_data(
	data # type: "XDR Data"
	):
	"""Extended NAT Data - Type: Flow, Enterprise: 0, Format: 1007"""
	sample_data = {} # Cache
	data.done() # Verify all data unpacked
	return sample_data

# Extended MPLS Tunnel (Flow, Enterprise 0, Format 1008)
def extended_mpls_tunnel(
	data # type: "XDR Data"
	):
	"""Extended MPLS Tunnel Data - Type: Flow, Enterprise: 0, Format: 1008"""
	sample_data = {} # Cache
	sample_data["Tunnel LSP Name"] = data.unpack_string()
	sample_data["Tunnel ID"] = int(data.unpack_uint())
	sample_data["Tunnel COS"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended MPLS VC (Flow, Enterprise 0, Format 1009)
def extended_mpls_vc(
	data # type: "XDR Data"
	):
	"""Extended MPLS VC Data - Type: Flow, Enterprise: 0, Format: 1009"""
	sample_data = {} # Cache
	sample_data["VC Instance Name"] = data.unpack_string()
	sample_data["VLL VC Instance ID"] = int(data.unpack_uint())
	sample_data["VC Label COS"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended MPLS FEC (Flow, Enterprise 0, Format 1010)
def exteded_mpls_fec(
	data # type: "XDR Data"
	):
	"""Extended MPLS FEC Data - Type: Flow, Enterprise: 0, Format: 1010"""
	sample_data = {} # Cache
	sample_data["MPLS FTN Description"] = data.unpack_string()
	sample_data["MPLS FTN Mask"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended MPLS LVP FEC (Flow, Enterprise 0, Format 1011)
def extended_mpls_lvp_fec(
	data # type: "XDR Data"
	):
	"""Extended MPLS LVP FEC Data - Type: Flow, Enterprise: 0, Format: 1011"""
	sample_data = {} # Cache
	sample_data["MPLS FEC Address Prefix Length"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended VLAN Tunnel (Flow, Enterprise 0, Format 1012)
def extended_vlan_tunnel(
	data # type: "XDR Data"
	):
	"""Extended VLAN Tunnel Data - Type: Flow, Enterprise: 0, Format: 1012"""
	sample_data = {} # Cache
	vlan_int = int(data.unpack_uint())
	sample_data["VLAN Stack"] = data.unpack_array(vlan_int)
	data.done() # Verify all data unpacked
	return sample_data

# Extended 802.11 Payload (Flow, Enterprise 0, Format 1013)
def extended_wlan_payload(
	data # type: "XDR Data"
	):
	"""Extended WLAN Payload - Type: Flow, Enterprise: 0, Format: 1013"""
	sample_data = {} # Cache
	data.done() # Verify all data unpacked
	return sample_data

# Extended 802.11 RX (Flow, Enterprise 0, Format 1014)
def extended_wlan_rx(
	data # type: "XDR Data"
	):
	"""Extended WLAN RX - Type: Flow, Enterprise: 0, Format: 1014"""
	sample_data = {} # Cache
	sample_data["SSID"] = data.unpack_fstring(32)
	sample_data["BSSID"] = data.unpack_string()
	sample_data["802.11 Version"] = wlan_version(int(data.unpack_uint()))
	sample_data["802.11 Channel"] = int(data.unpack_uint())
	sample_data["Speed"] = data.unpack_uhyper()
	sample_data["RSNI"] = int(data.unpack_uint())
	sample_data["RCPI"] = int(data.unpack_uint())
	sample_data["Packet Duration"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended 802.11 TX (Flow, Enterprise 0, Format 1015)
def extended_wlan_tx(
	data # type: "XDR Data"
	):
	"""Extended WLAN TX - Type: Flow, Enterprise: 0, Format: 1015"""
	sample_data = {} # Cache
	sample_data["SSID"] = data.unpack_fstring(32)
	sample_data["BSSID"] = data.unpack_string()
	sample_data["802.11 Version"] = wlan_version(int(data.unpack_uint()))
	sample_data["Transmissions"] = wlan_transmissions(int(data.unpack_uint()))
	sample_data["Packet Duration"] = int(data.unpack_uint())
	sample_data["Retransmission Duration"] = int(data.unpack_uint())
	sample_data["802.11 Channel"] = int(data.unpack_uint())
	sample_data["Speed"] = data.unpack_uhyper()
	sample_data["Power mW"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended 802.11 Aggregation (Flow, Enterprise 0, Format 1016)
def extended_wlan_aggregation(
	data # type: "XDR Data"
	):
	"""Extended WLAN Aggregation - Type: Flow, Enterprise: 0, Format: 1016"""
	sample_data = {} # Cache
	data.done() # Verify all data unpacked
	return sample_data

# Slow Packet Data Path (Flow, Enterprise 0, Format 1020)
def slow_packet_data_path(
	data # type: "XDR Data"
	):
	"""Slow Packet Data Path - Type: Flow, Enterprise: 0, Format: 1020"""
	sample_data = {} # Cache

	def slow_path_reason(
		reason_int # type: int
		):
		if reason_int == 0:
			return "Unknown"
		elif reason_int == 1:
			return "Other"
		elif reason_int == 2:
			return "CAM Miss"
		elif reason_int == 3:
			return "CAM Full"
		elif reason_int == 4:
			return "No Hardware Support"
		elif reason_int == 5:
			return "CNTRL"
		else:
			return "Unknown"

	sample_data["Slow Path Reason"] = slow_path_reason(int(data.unpack_uint()))
	data.done() # Verify all data unpacked
	return sample_data

# Extended InfiniBand Local Routing Header (Flow, Enterprise 0, Format 1031)
def extended_ib_lrh(
	data # type: "XDR Data"
	):
	"""Extended InfiniBand Local Routing Header - Type: Flow, Enterprise: 0, Format: 1031"""
	sample_data = {} # Cache
	sample_data["Source Virtual Lane"] = int(data.unpack_uint())
	sample_data["Source Service Level"] = int(data.unpack_uint())
	sample_data["Source Destination-Local-ID"] = int(data.unpack_uint())
	sample_data["Source Source-Local-ID"] = int(data.unpack_uint())
	sample_data["Source Link Next Header"] = int(data.unpack_uint())
	sample_data["Destination Virtual Lane"] = int(data.unpack_uint())
	sample_data["Destination Service Level"] = int(data.unpack_uint())
	sample_data["Destination Destination-Local-ID"] = int(data.unpack_uint())
	sample_data["Destination Source-Local-ID"] = int(data.unpack_uint())
	sample_data["Destination Link Next Header"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended InfiniBand Base Transport Header (Flow, Enterprise 0, Format 1033)
def extended_ib_brh(
	data # type: "XDR Data"
	):
	"""Extended InfiniBand Base Transport Header - Type: Flow, Enterprise: 0, Format: 1033"""
	sample_data = {} # Cache
	sample_data["Partition Key"] = int(data.unpack_uint())
	sample_data["Destination Queue Pair"] = int(data.unpack_uint())
	sample_data["IBA Packet Type"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Generic Transaction Record (Flow, Enterprise 0, Format 2000)
def generic_transaction_record(
	data # type: "XDR Data"
	):
	"""Generic Transaction Record - Type: Flow, Enterprise: 0, Format: 2000"""
	sample_data = {} # Cache
	sample_data["Service Direction"] = service_direction(int(data.unpack_uint()))
	sample_data["Wait Time ms"] = int(data.unpack_uint())
	sample_data["Duration Time ms"] = int(data.unpack_uint())
	sample_data["Status"] = status_value(int(data.unpack_uint()))
	sample_data["Bytes In"] = data.unpack_uhyper()
	sample_data["Bytes Out"] = data.unpack_uhyper()
	data.done() # Verify all data unpacked
	return sample_data

# Extended NFS Storage Transaction (Flow, Enterprise 0, Format 2001)
def ext_nfs_storage_trans(
	data # type: "XDR Data"
	):
	"""Extended NFS Storage Transaction - Type: Flow, Enterprise: 0, Format: 2001"""
	sample_data = {} # Cache
	sample_data["Path"] = str(data.unpack_opaque())
	sample_data["Operation"] = int(data.unpack_uint())
	sample_data["Status"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended SCSI Transaction (Flow, Enterprise 0, Format 2002)
def ext_scsi_storage_trans(
	data # type: "XDR Data"
	):
	"""Extended SCSI Storage Transaction - Type: Flow, Enterprise: 0, Format: 2002"""
	sample_data = {} # Cache
	sample_data["LUN"] = int(data.unpack_uint())
	sample_data["Operation"] = int(data.unpack_uint())
	sample_data["Status"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Extended Web Transaction (Flow, Enterprise 0, Format 2003)
def extended_web_trans(
	data # type: "XDR Data"
	):
	"""Extended Web Transaction - Type: Flow, Enterprise: 0, Format: 2003"""
	sample_data = {} # Cache
	sample_data["URL"] = data.unpack_string()
	sample_data["Host"] = data.unpack_string()
	sample_data["Referer"] = data.unpack_string()
	sample_data["User Agent"] = data.unpack_string()
	sample_data["User"] = data.unpack_string()
	sample_data["Status Code"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# IPv4 Socket (Flow, Enterprise 0, Format 2100)
def ipv4_socket(
	data # type: "XDR Data"
	):
	"""IPv4 Socket - Type: Flow, Enterprise: 0, Format: 2100"""
	sample_data = {} # Cache
	sample_data["Protocol Number"] = int(data.unpack_uint())
	sample_data["Protocol"] = iana_protocol_name(sample_data["Protocol Number"]) # Parse IANA-registered protocol name
	sample_data["Category"] = protocol_category(sample_data["Protocol Number"]) # Parse protocol category, or "Other"
	sample_data["Source IP"] = inet_ntoa(data.unpack_fstring(4)) # IPv4
	sample_data["Destination IP"] = inet_ntoa(data.unpack_fstring(4)) # IPv4
	sample_data["Source Port"] = int(data.unpack_uint())
	sample_data["Destination Port"] = int(data.unpack_uint())
	# Need to add category based on source / dest port - FIX
	data.done() # Verify all data unpacked
	return sample_data

# IPv6 Socket (Flow, Enterprise 0, Format 2101)
def ipv6_socket(
	data # type: "XDR Data"
	):
	"""IPv6 Socket - Type: Flow, Enterprise: 0, Format: 2101"""
	sample_data = {} # Cache
	sample_data["Protocol Number"] = int(data.unpack_uint())
	sample_data["Protocol"] = iana_protocol_name(sample_data["Protocol Number"]) # Parse IANA-registered protocol name
	sample_data["Category"] = protocol_category(sample_data["Protocol Number"]) # Parse protocol category, or "Other"
	sample_data["Source IP"] = inet_ntop(data.unpack_fstring(16)) # IPv6
	sample_data["Destination IP"] = inet_ntop(data.unpack_fstring(16)) # IPv6
	sample_data["Source Port"] = int(data.unpack_uint())
	sample_data["Destination Port"] = int(data.unpack_uint())
	# Need to add category based on source / dest port - FIX
	data.done() # Verify all data unpacked
	return sample_data

# Extended TCP Information (Flow, Enterprise 0, Format 2209)
def extended_tcp_info(
	data # type: "XDR Data"
	):
	"""Extended TCP Information - Type: Flow, Enterprise: 0, Format: 2209"""
	datagram = {}
	datagram["Packet Direction"] = packet_direction(data.unpack_uint()) # Parsed packet direction
	datagram["Cached Effective MSS"] = int(data.unpack_uint())
	datagram["Max Received Segment Size"] = int(data.unpack_uint())
	datagram["Un-ACKed Packets"] = int(data.unpack_uint())
	datagram["Lost Packets"] = int(data.unpack_uint())
	datagram["Retransmitted Packets"] = int(data.unpack_uint())
	datagram["PMTU"] = int(data.unpack_uint())
	datagram["RTT ms"] = int(data.unpack_uint())
	datagram["RTT Variance ms"] = int(data.unpack_uint())
	datagram["Sending Congestion Window"] = int(data.unpack_uint())
	datagram["Reordering"] = int(data.unpack_uint())
	datagram["Minimum RTT ms"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return datagram

# Broadcom Selected Egress Queue (Flow, Enterprise 4413, Format 1)
def broad_sel_egress_queue(
	data # type: "XDR Data"
	):
	"""Broadcom Selected Egress Queue - Type: Flow, Enterprise: 4413, Format: 1"""
	datagram = {}
	datagram["Queue"] = packet_direction(data.unpack_uint())
	data.done() # Verify all data unpacked
	return datagram

# Extended Class (Flow, Enterprise 8800, Format 1) for Vyatta, VyOS, Ubiquiti
# Documented pmacct bug https://github.com/pmacct/pmacct/issues/71
def extended_class(
	data # type: "XDR Data"
	):
	"""PMACCT Extended Class - Type: Flow, Enterprise: 8800, Format: 1"""
	datagram = {}
	datagram["Class"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return datagram

# Extended Tag (Flow, Enterprise 8800, Format 2) for Vyatta, VyOS, Ubiquiti
# Documented pmacct bug https://github.com/pmacct/pmacct/issues/71
def extended_tag(
	data # type: "XDR Data"
	):
	"""PMACCT Extended Tag - Type: Flow, Enterprise: 8800, Format: 2"""
	datagram = {}
	datagram["Tag"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return datagram