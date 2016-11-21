# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import sys, struct
from xdrlib import Unpacker
from socket import inet_ntoa#,inet_ntop
from protocol_numbers import *

# Parse IANA interface types
# See https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
def iana_interface_type(num):
	if num == 1:
		return "Other"
	elif num == 2:
		return "regular1822"
	elif num == 3:
		return "hdh1822"
	elif num == 4:
		return "ddnX25"
	elif num == 5:
		return "rfc877x25"
	elif num == 6:
		return "ethernetCsmacd"
	elif num == 7:
		return "iso88023Csmacd"
	elif num == 8:
		return "iso88024TokenBus"
	elif num == 9:
		return "iso88025TokenRing"
	elif num == 10:
		return "iso88026Man"
	elif num == 11:
		return "starLan"
	elif num == 12:
		return "proteon10Mbit"
	elif num == 13:
		return "proteon80Mbit"
	elif num == 14:
		return "hyperchannel"
	elif num == 15:
		return "fddi"
	elif num == 16:
		return "lapb"
	elif num == 17:
		return "sdlc"
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
		return "softwareLoopback"
	elif num == 25:
		return "eon"
	elif num == 26:
		return "ethernet3Mbit"
	elif num == 27:
		return "nsip"
	elif num == 28:
		return "SLIP"
	elif num == 29:
		return "ultra"
	elif num == 30:
		return "ds3"
	elif num == 31:
		return "sip"
	elif num == 32:
		return "Frame Relay"
	elif num == 33:
		return "RS232"
	elif num == 34:
		return "para"
	elif num == 35:
		return "arcnet"
	elif num == 36:
		return "arcnetPlus"
	elif num == 37:
		return "atm"
	elif num == 38:
		return "miox25"
	elif num == 39:
		return "SONET"
	else:
		return "Other"

# Parse Enterprise and Format numbers
def enterprise_format_numbers(unparsed_int):
	sample_type_binary = '{0:032b}'.format(unparsed_int) # Break out the binary
	enterprise_num = int(sample_type_binary[:20],2) # Enterprise number first 20 bits
	sample_data_format = int(sample_type_binary[20:32],2) # Format number last 12 bits
	return [enterprise_num,sample_data_format] # Return [enterprise number, format number]

# Sample Source Type / Index parser
def source_type_index_parser(unparsed_int):
	source_type = unparsed_int >> 24
	source_index = unparsed_int & 0xfff
	return [int_source_id_type(source_type), source_index]

# Source ID type parser
def int_source_id_type(id):
	if id == 0:
		return "ifIndex"
	elif id == 1:
		return "smonVlanDataSource"
	elif id == 2:
		return "entPhysicalEntry"
	else:
		return False

# MAC address parser
def mac_parse(mac):
	mac_list = []
	for mac_item in mac:
		mac_item_formatted = hex(mac_item).replace('0x','')
		#if mac_item_formatted == '0':
			#mac_item_formatted = "00"
		if len(mac_item_formatted) == 1:
			mac_item_formatted = str("0" + mac_item_formatted)
		mac_list.append(mac_item_formatted)
	flow_payload = (':'.join(mac_list)).upper()
	
	if flow_payload == '00:00:00:00:00:00' or flow_payload == 'FF:FF:FF:FF:FF:FF':
		return False
	else:
		return flow_payload

# Parse raw Ethernet header
def parse_eth_header(header_string):
	ord_dest_mac = [ord(x) for x in [header_string[0],header_string[1],header_string[2],header_string[3],header_string[4],header_string[5]]]
	dest_mac = mac_parse(ord_dest_mac)
	ord_src_mac = [ord(x) for x in [header_string[6],header_string[7],header_string[8],header_string[9],header_string[10],header_string[11]]]
	src_mac = mac_parse(ord_src_mac)
	return [dest_mac,src_mac]

# Parse header protocol name from protocol number
def parse_header_prot_name(protocol_int):
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
		protocol_name = "X25"
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
	else:
		protocol_name = "Unknown"
	
	return protocol_name

# Parse Operating System name
def enum_os_name(os_int):
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
	else:
		os_name = "Unknown"
	
	return os_name

# Parse machine architecture
def enum_machine_type(os_arch):
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
		machine_type = "m68k"
	elif os_arch == 9:
		machine_type = "MIPS"
	elif os_arch == 10:
		machine_type = "ARM"
	elif os_arch == 11:
		machine_type = "HPPA"
	elif os_arch == 12:
		machine_type = "s390"
	else:
		machine_type = "Unknown"
	
	return machine_type

# Parse IANA protocol name
def iana_protocol_name(protocol_int):
	try:
		return protocol_type[protocol_int]["Name"]
	except:
		return "Undefined"

# Parse IANA protocol name
def protocol_category(protocol_int):
	try:
		return protocol_type[protocol_int]["Category"]
	except:
		return "Other"

# Packet direction
def packet_direction(direction_int):
	if direction_int == 0:
		return "Unknown"
	elif direction_int == 1:
		return "Received"
	elif direction_int == 2:
		return "Sent"
	else:
		return "Unknown"

# URL direction
def url_direction(direction_int):
	if direction_int == 1:
		return "Source"
	elif direction_int == 2:
		return "Destination"
	else:
		return "Unknown"

# IEEE 802.11 versions
def wlan_version(version_num):
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
def wlan_transmissions(transmission_int):
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
def agg_port_state(port_state_num):
		return 

# Parse the sFlow datagram
def datagram_parse(data):
	datagram = {}
	datagram["sFlow Version"] = int(data.unpack_uint()) # sFlow Version
	datagram["IP Version"] = data.unpack_uint() # Agent IP version
			
	if datagram["IP Version"] == 1:
		datagram["Agent IP"] = inet_ntoa(data.unpack_fstring(4)) # sFlow Agent IP (IPv4)
	else:
		#datagram["Agent IP"] = inet_ntop(data.unpack_fstring(16)) # sFlow Agent IP (IPv6)
		pass
	
	datagram["Sub Agent"] = data.unpack_uint() # Sub Agent ID
	datagram["Datagram Sequence Number"] = int(data.unpack_uint()) # Datagram Seq. Number
	datagram["Switch Uptime ms"] = int(data.unpack_uint()) # Switch Uptime (ms)
	datagram["Sample Count"] = int(data.unpack_uint()) # Samples in datagram
	return datagram