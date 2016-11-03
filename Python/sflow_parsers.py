# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import sys, struct
from xdrlib import Unpacker

# Parse Enterprise and Format numbers
def enterprise_format_numbers(unparsed_int):
	sample_type_binary = '{0:032b}'.format(unparsed_int) # Break out the binary
	enterprise_num = int(sample_type_binary[:20],2) # Enterprise number first 20 bits
	sample_data_format = int(sample_type_binary[20:32],2) # Format number last 12 bits
	enterprise_format_num = [enterprise_num,sample_data_format] # Flow or Counter-type sample
	return enterprise_format_num # Return [enterprise number, format number]

# Sample Source Type / Index parser
def source_type_index_parser(unparsed_int):
	source_type = unparsed_int >> 24
	source_index = unparsed_int & 0xfff
	return [source_type, source_index]

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