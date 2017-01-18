# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

import sys, struct
from xdrlib import Unpacker

# Windows socket.inet_ntop support via win_inet_pton
try:
	import win_inet_pton
except ImportError:
	pass

from socket import inet_ntoa,inet_ntop
from protocol_numbers import *

from parser_modules import mac_address

# Parse IANA interface types
# See https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
def iana_interface_type(
	num # type: int
	):
	"""Parse IANA-defined interface types"""
	if num == 1:
		return "Other"
	elif num == 2:
		return "BBN 1822"
	elif num == 3:
		return "HDH 1822"
	elif num == 4:
		return "DDN X.25"
	elif num == 5:
		return "RFC-877 X.25"
	
	# For all Ethernet-like CSMA-CD interfaces per IANA
	elif num == 6:
		return "Ethernet"
	
	# Deprecated, should use 6 per IANA
	elif num == 7:
		return "Ethernet"
	elif num == 8:
		return "Token Bus"
	elif num == 9:
		return "Token Ring"
	elif num == 10:
		return "ISO88026Man"
	elif num == 11:
		return "Star LAN"
	elif num == 12:
		return "Proteon 10Mbit"
	elif num == 13:
		return "Proteon 80Mbit"
	elif num == 14:
		return "Hyperchannel"
	elif num == 15:
		return "FDDI"
	elif num == 16:
		return "LAPB"
	elif num == 17:
		return "SDLC"
	elif num == 18:
		return "DS1"
	elif num == 19:
		return "E1"
	elif num == 20:
		return "Basic ISDN"
	elif num == 21:
		return "Primary ISDN"
	elif num == 22:
		return "Prop Point To Point Serial"
	elif num == 23:
		return "PPP"
	elif num == 24:
		return "Software Loopback"
	elif num == 25:
		return "EON"
	elif num == 26:
		return "Ethernet 3Mbit"
	elif num == 27:
		return "NSIP"
	elif num == 28:
		return "SLIP"
	elif num == 29:
		return "Ultra"
	elif num == 30:
		return "DS3"
	elif num == 31:
		return "SIP"
	elif num == 32:
		return "Frame Relay"
	elif num == 33:
		return "RS232"
	elif num == 34:
		return "PARA"
	elif num == 35:
		return "ARCNet"
	elif num == 36:
		return "ARCNet Plus"
	elif num == 37:
		return "ATM"
	elif num == 38:
		return "MIOX25"
	elif num == 39:
		return "SONET"
	else:
		return "Other"

# Parse Enterprise and Format numbers
def enterprise_format_numbers(
	unparsed_int # type: int
	):
	"""Unpack and parse [enterprise,format] numbers"""
	sample_type_binary = '{0:032b}'.format(unparsed_int) # Break out the binary
	enterprise_num = int(sample_type_binary[:20],2) # Enterprise number first 20 bits
	sample_data_format = int(sample_type_binary[20:32],2) # Format number last 12 bits
	return [enterprise_num,sample_data_format] # Return [enterprise number, format number]

# Sample Source Type / Index parser
def source_type_index_parser(
	unparsed_int # type: int
	):
	"""Parse [source_type,source_index] of interface numbers"""
	source_type = unparsed_int >> 24
	source_index = unparsed_int & 0xfff
	return [int_source_id_type(source_type), source_index]

# Source ID type parser
def int_source_id_type(
	id # type: int
	):
	"""Parse source ID types defined by InMon"""
	if id == 0:
		return "ifIndex"
	elif id == 1:
		return "smonVlanDataSource"
	elif id == 2:
		return "entPhysicalEntry"
	else:
		return False

# Parse raw Ethernet header
def parse_eth_header(
	header_string # type: list
	):
	"""Get MAC addresses from Ethernet header string"""

	mac_parser_class = mac_address() # MAC parser class
	
	# Destination MAC
	ord_dest_mac = [ord(x) for x in [header_string[0],header_string[1],header_string[2],header_string[3],header_string[4],header_string[5]]]
	dest_mac = mac_parser_class.mac_parse(ord_dest_mac) # Get MAC and MAC OUI

	# Source MAC
	ord_src_mac = [ord(x) for x in [header_string[6],header_string[7],header_string[8],header_string[9],header_string[10],header_string[11]]]
	src_mac = mac_parser_class.mac_parse(ord_src_mac) # Get MAC and MAC OUI
	
	return (dest_mac[0],src_mac[0],dest_mac[1],src_mac[1]) # DST MAC, SRC MAC, DST MAC OUI, SRC MAC OUI

# Parse header protocol name from protocol number
def parse_header_prot_name(
	protocol_int # type: int
	):
	"""Parse InMon-defined header protocol names"""
	if protocol_int == 1:
		protocol_name = "Ethernet"
	elif protocol_int == 2:
		protocol_name = "Token Bus"
	elif protocol_int == 3:
		protocol_name = "Token Ring"
	elif protocol_int == 4:
		protocol_name = "FDDI"
	elif protocol_int == 5:
		protocol_name = "Frame Relay"
	elif protocol_int == 6:
		protocol_name = "X.25"
	elif protocol_int == 7:
		protocol_name = "PPP"
	elif protocol_int == 8:
		protocol_name = "SMDS"
	elif protocol_int == 9:
		protocol_name = "AAL5"
	elif protocol_int == 10:
		protocol_name = "AAL5-IP"
	elif protocol_int == 11:
		protocol_name = "IPv4"
	elif protocol_int == 12:
		protocol_name = "IPv6"
	elif protocol_int == 13:
		protocol_name = "MPLS"
	elif protocol_int == 14:
		protocol_name = "POS"
	elif protocol_int == 15:
		protocol_name = "802.11 MAC"
	elif protocol_int == 16:
		protocol_name = "802.11 AMPDU"
	elif protocol_int == 17:
		protocol_name = "802.11 AMSDU Subframe"
	elif protocol_int == 18:
		protocol_name = "InfiniBand"
	else:
		protocol_name = "Unknown"
	
	return protocol_name

# Parse Operating System name
def enum_os_name(
	os_int # type: int
	):
	"""Parse InMon-defined Operating System names"""
	if os_int == 0:
		os_name = "Unknown"
	elif os_int == 1:
		os_name = "Other"
	elif os_int == 2:
		os_name = "Linux"
	elif os_int == 3:
		os_name = "Windows"
	elif os_int == 4:
		os_name = "Darwin"
	elif os_int == 5:
		os_name = "HP-UX"
	elif os_int == 6:
		os_name = "AIX"
	elif os_int == 7:
		os_name = "Dragonfly"
	elif os_int == 8:
		os_name = "FreeBSD"
	elif os_int == 9:
		os_name = "NetBSD"
	elif os_int == 10:
		os_name = "OpenBSD"
	elif os_int == 11:
		os_name = "OSF"
	elif os_int == 12:
		os_name = "Solaris"
	elif os_int == 13:
		os_name = "Java"
	else:
		os_name = "Unknown"
	
	return os_name

# Parse machine architecture
def enum_machine_type(
	os_arch # type: int
	):
	"""Parse InMon-defined system architectures"""
	if os_arch == 0:
		machine_type = "Unknown"
	elif os_arch == 1:
		machine_type = "Other"
	elif os_arch == 2:
		machine_type = "x86"
	elif os_arch == 3:
		machine_type = "x86_64"
	elif os_arch == 4:
		machine_type = "ia64"
	elif os_arch == 5:
		machine_type = "SPARC"
	elif os_arch == 6:
		machine_type = "Alpha"
	elif os_arch == 7:
		machine_type = "PowerPC"
	elif os_arch == 8:
		machine_type = "M68K"
	elif os_arch == 9:
		machine_type = "MIPS"
	elif os_arch == 10:
		machine_type = "ARM"
	elif os_arch == 11:
		machine_type = "HPPA"
	elif os_arch == 12:
		machine_type = "S390"
	else:
		machine_type = "Unknown"
	
	return machine_type

# Parse IANA protocol name
def iana_protocol_name(
	protocol_int # type: int
	):
	"""Reconcile IANA-defined protocol numbers to names"""
	try:
		return protocol_type[protocol_int]["Name"]
	except:
		return "Unknown"

# Parse IANA protocol name
def protocol_category(
	protocol_int # type: int
	):
	"""Reconcile IANA-defined protocol numbers to categories (Web, Email, etc)"""
	try:
		return protocol_type[protocol_int]["Category"]
	except:
		return "Other"

# Packet direction
def packet_direction(
	direction_int # type: int
	):
	if direction_int == 0:
		return "Unknown"
	elif direction_int == 1:
		return "Received"
	elif direction_int == 2:
		return "Sent"
	else:
		return "Unknown"

# Service direction
def service_direction(
	direction_int # type: int
	):
	"""Parse InMon-defined service direction"""
	if direction_int == 1:
		return "Client"
	elif direction_int == 2:
		return "Server"
	else:
		return "Unknown"

# Status Value
def status_value(
	status_int # type: int
	):
	"""Parse InMon-defined transaction status"""
	if status_int == 0:
		return "Succeeded"
	elif status_int == 1:
		return "Generic Failure"
	elif status_int == 2:
		return "Out of Memory"
	elif status_int == 3:
		return "Timeout"
	elif status_int == 4:
		return "Not Permitted"
	else:
		return "Unknown"

# URL direction
def url_direction(
	direction_int # type: int
	):
	"""Parse InMon-defined URL direction"""
	if direction_int == 1:
		return "Source"
	elif direction_int == 2:
		return "Destination"
	else:
		return "Unknown"

# IEEE 802.11 versions
def wlan_version(
	version_num # type: int
	):
	"""Reconcile InMon-defined 802.11 WLAN version numbers to WiFi letter designations"""
	if version_num == 1:
		return "A"
	elif version_num == 2:
		return "B"
	elif version_num == 3:
		return "G"
	elif version_num == 4:
		return "N"
	else:
		return "Other"

# IEEE 802.11 WLAN Transmissions
def wlan_transmissions(
	transmission_int # type: int
	):
	"""Parse InMon-defined WLAN transmission status"""
	if transmission_int == 0:
		return "Unknown"
	elif transmission_int == 1:
		return "Successfully Transmitted"
	elif transmission_int > 1:
		return str(int(transmission_int-1) + " retransmissions")
	else:
		return "Unknown"

# IEEE 802.3ad Link Aggregation Port State
# FIX!
def agg_port_state(
	port_state_num # type: int
	):
	"""Parse 802.3ad aggregation port state"""
	return 

# Parse the sFlow datagram
def datagram_parse(
	data # type: "XDR Data"
	):
	"""Parse an sFlow high-level datagram"""
	datagram = {}
	datagram["sFlow Version"] = int(data.unpack_uint()) # sFlow Version
	datagram["IP Version"] = data.unpack_uint() # Agent IP version
			
	if datagram["IP Version"] == 1:
		datagram["Agent IP"] = inet_ntoa(data.unpack_fstring(4)) # sFlow Agent IP (IPv4)
	else:
		datagram["Agent IP"] = inet_ntop(data.unpack_fstring(16)) # sFlow Agent IP (IPv6)
		pass
	
	datagram["Sub Agent"] = data.unpack_uint() # Sub Agent ID
	datagram["Datagram Sequence Number"] = int(data.unpack_uint()) # Datagram Seq. Number
	datagram["Switch Uptime ms"] = int(data.unpack_uint()) # Switch Uptime (ms)
	datagram["Sample Count"] = int(data.unpack_uint()) # Samples in datagram
	return datagram

# HTTP Methods
def inmon_http_method(
	method_int # type: int
	):
	"""Parse InMon-defined HTTP method numbers"""
	if method_int == 0:
		return "Other"
	elif method_int == 1:
		return "Options"
	elif method_int == 2:
		return "Get"
	elif method_int == 3:
		return "Head"
	elif method_int == 4:
		return "Post"
	elif method_int == 5:
		return "Put"
	elif method_int == 6:
		return "Delete"
	elif method_int == 7:
		return "Trace"
	elif method_int == 8:
		return "Connect"
	else:
		return "Other"