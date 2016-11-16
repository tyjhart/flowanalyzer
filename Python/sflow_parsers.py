# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import sys, struct
from xdrlib import Unpacker

# Parse IANA interface types
# See https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
def iana_interface_type(num):
	if num == 1:
		return "other"
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
		return "ds1"
	elif num == 19:
		return "e1"
	elif num == 20:
		return "basicISDN"
	elif num == 21:
		return "primaryISDN"
	elif num == 22:
		return "propPointToPointSerial"
	elif num == 23:
		return "ppp"
	elif num == 24:
		return "softwareLoopback"
	elif num == 25:
		return "eon"
	elif num == 26:
		return "ethernet3Mbit"
	elif num == 27:
		return "nsip"
	elif num == 28:
		return "slip"
	elif num == 29:
		return "ultra"
	elif num == 30:
		return "ds3"
	elif num == 31:
		return "sip"
	elif num == 32:
		return "frameRelay"
	elif num == 33:
		return "rs232"
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
		return "sonet"
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
		if mac_item_formatted == '0':
			mac_item_formatted = "00"
		if len(mac_item_formatted) == 1:
			mac_item_formatted = str("0" + mac_item_formatted)
		mac_list.append(mac_item_formatted)
	flow_payload = (':'.join(mac_list)).upper()
	
	if flow_payload == '00:00:00:00:00:00' or flow_payload == 'FF:FF:FF:FF:FF:FF':
		return False
	else:
		return flow_payload

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
	else:
		protocol_name = "Unknown"
	
	return protocol_name