# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import struct, sys, binascii, uuid
from xdrlib import Unpacker
from struct import *

from parser_modules import mac_address # Field parsing functions
from sflow_parsers import *  # Functions to parse headers and format numbers

# Generic Interface (Counter, Enterprise 0, Format 1)
def gen_int_counter(data):
	sample_data = {} # Cache
	sample_data["Interface Index"] = int(data.unpack_uint())
	sample_data["Interface Type"] = iana_interface_type(int(data.unpack_uint()))
	sample_data["Interface Speed"] = data.unpack_hyper()

	ifDirection = int(data.unpack_uint())
	if ifDirection == 0:
		sample_data["Interface Direction"] = "Unknown"
	elif ifDirection == 1:
		sample_data["Interface Direction"] = "Full-duplex"
	elif ifDirection == 2:
		sample_data["Interface Direction"] = "Half-duplex"
	elif ifDirection == 3:
		sample_data["Interface Direction"] = "Ingress"
	elif ifDirection == 4:
		sample_data["Interface Direction"] = "Egress"
	else:
		sample_data["Interface Direction"] = "Unknown"

	# http://sflow.org/developers/diagrams/sFlowV5CounterData.pdf FIX!!!
	ifStatus = int(data.unpack_uint())
	if ifStatus == 0:
		sample_data["Interface Status"] = "Unknown"
	elif ifStatus == 1:
		sample_data["Interface Status"] = "Full-duplex"
	else:
		sample_data["Interface Status"] = "Unknown"

	sample_data["Bytes In"] = data.unpack_hyper()
	sample_data["Unicast Packets In"] = int(data.unpack_uint())
	sample_data["Multicast Packets In"] = int(data.unpack_uint())
	sample_data["Broadcast Packets In"] = int(data.unpack_uint())
	sample_data["Discards In"] = int(data.unpack_uint())
	sample_data["Errors In"] = int(data.unpack_uint())
	sample_data["Unknown Protocols In"] = int(data.unpack_uint())
	sample_data["Bytes Out"] = data.unpack_hyper()
	sample_data["Unicast Packets Out"] = int(data.unpack_uint())
	sample_data["Multicast Packets Out"] = int(data.unpack_uint())
	sample_data["Broadcast Packets Out"] = int(data.unpack_uint())
	sample_data["Discards Out"] = int(data.unpack_uint())
	sample_data["Errors Out"] = int(data.unpack_uint())
	sample_data["Promiscuous Mode"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Ethernet Interface (Counter, Enterprise 0, Format 2)
def eth_int_counter(data):
	sample_data = {} # Cache
	sample_data["Alignment Errors"] = int(data.unpack_uint())
	sample_data["FCS Errors"] = int(data.unpack_uint())
	sample_data["Single Collision Frames"] = int(data.unpack_uint())
	sample_data["Multiple Collision Frames"] = int(data.unpack_uint())
	sample_data["SQE Test Errors"] = int(data.unpack_uint())
	sample_data["Deferred Transmissions"] = int(data.unpack_uint())
	sample_data["Late Collisions"] = int(data.unpack_uint())
	sample_data["Excessive Collisions"] = int(data.unpack_uint())
	sample_data["Internal MAC Transmit Errors"] = int(data.unpack_uint())
	sample_data["Carrier Sense Errors"] = int(data.unpack_uint())
	sample_data["Frame Too Longs"] = int(data.unpack_uint())
	sample_data["Internal MAC Receive Errors"] = int(data.unpack_uint())
	sample_data["Symbol Errors"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Token Ring (Counter, Enterprise 0, Format 3)
def token_ring_counter(data):
	sample_data = {} # Cache
	sample_data["Line Errors"] = int(data.unpack_uint())
	sample_data["AC Errors"] = int(data.unpack_uint())
	sample_data["Abort Trans Errors"] = int(data.unpack_uint())
	sample_data["Internal Errors"] = int(data.unpack_uint())
	sample_data["Lost Frame Errors"] = int(data.unpack_uint())
	sample_data["Receive Congestions"] = int(data.unpack_uint())
	sample_data["Frame Copied Errors"] = int(data.unpack_uint())
	sample_data["Token Errors"] = int(data.unpack_uint())
	sample_data["Soft Errors"] = int(data.unpack_uint())
	sample_data["Hard Errors"] = int(data.unpack_uint())
	sample_data["Signal Loss"] = int(data.unpack_uint())
	sample_data["Transmit Beacons"] = int(data.unpack_uint())
	sample_data["Recoverys"] = int(data.unpack_uint())
	sample_data["Lobe Wires"] = int(data.unpack_uint())
	sample_data["Burst Errors"] = int(data.unpack_uint())
	sample_data["Removes"] = int(data.unpack_uint())
	sample_data["Singles"] = int(data.unpack_uint())
	sample_data["Freq Errors"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# 100 BaseVG Interface (Counter, Enterprise 0, Format 4)
def basevg_int_counter(data):
	sample_data = {} # Cache
	sample_data["High Priority Frames In"] = int(data.unpack_uint())
	sample_data["High Priority Bytes In"] = data.unpack_hyper()
	sample_data["Norm Priority Frames In"] = int(data.unpack_uint())
	sample_data["Norm Priority Bytes In"] = data.unpack_hyper()
	sample_data["IPM Errors In"] = int(data.unpack_uint())
	sample_data["Oversize Frame Errors In"] = int(data.unpack_uint())
	sample_data["Data Errors In"] = int(data.unpack_uint())
	sample_data["Null Addressed Frames In"] = int(data.unpack_uint())
	sample_data["Out High Priority Frames"] = int(data.unpack_uint())
	sample_data["Out High Priority Bytes"] = data.unpack_hyper()
	sample_data["Transition Into Trainings"] = int(data.unpack_uint())
	sample_data["HC In High Priority Bytes"] = data.unpack_hyper()
	sample_data["HC In Norm Priority Bytes"] = data.unpack_hyper()
	sample_data["HC Out High Priority Bytes"] = data.unpack_hyper()
	data.done() # Verify all data unpacked
	return sample_data

# VLAN (Counter, Enterprise 0, Format 5)
def vlan_counter(data):
	sample_data = {} # Cache
	sample_data["VLAN ID"] = int(data.unpack_uint())
	sample_data["Bytes"] = data.unpack_hyper()
	sample_data["Unicast Packets"] = int(data.unpack_uint())
	sample_data["Multicast Packets"] = int(data.unpack_uint())
	sample_data["Broadcast Packets"] = int(data.unpack_uint())
	sample_data["Discards"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# IEEE 802.11 Counters (Counter, Enterprise 0, Format 6)
def wlan_counters(data):
	sample_data = {} # Cache
	sample_data["Transmitted Fragments"] = int(data.unpack_uint())
	sample_data["Multicast Transmitted Frames"] = int(data.unpack_uint())
	sample_data["Failures"] = int(data.unpack_uint())
	sample_data["Retries"] = int(data.unpack_uint())
	sample_data["Multiple Retries"] = int(data.unpack_uint())
	sample_data["Frame Duplicates"] = int(data.unpack_uint())
	sample_data["RTS Successes"] = int(data.unpack_uint())
	sample_data["RTS Failures"] = int(data.unpack_uint())
	sample_data["ACK Failures"] = int(data.unpack_uint())
	sample_data["Received Fragments"] = int(data.unpack_uint())
	sample_data["Multicast Received Frames"] = int(data.unpack_uint())
	sample_data["FCS Errors"] = int(data.unpack_uint())
	sample_data["Transmitted Frames"] = int(data.unpack_uint())
	sample_data["WEP Undecryptables"] = int(data.unpack_uint())
	sample_data["QoS Discarded Fragments"] = int(data.unpack_uint())
	sample_data["Associated Stations"] = int(data.unpack_uint())
	sample_data["QoS CF Polls Received"] = int(data.unpack_uint())
	sample_data["QoS CF Polls Unused"] = int(data.unpack_uint())
	sample_data["QoS CF Polls Unusables"] = int(data.unpack_uint())
	sample_data["QoS CF Polls Lost"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data	

# IEEE 802.3ad LAG Port Statistics (Counter, Enterprise 0, Format 7)
def lag_port_stats(data):
	sample_data = {} # Cache
	sample_data["dot3adAggPortActorSystemID"] = data.unpack_string()
	sample_data["dot3adAggPortPartnerOperSystemID"] = data.unpack_string()
	sample_data["dot3adAggPortAttachedAggID"] = int(data.unpack_uint())
	sample_data["dot3adAggPortState"] = data.unpack_fopaque(4)
	sample_data["dot3adAggPortStatsLACPDUsRx"] = int(data.unpack_uint())
	sample_data["dot3adAggPortStatsMarkerPDUsRx"] = int(data.unpack_uint())
	sample_data["dot3adAggPortStatsMarkerResponsePDUsRx"] = int(data.unpack_uint())
	sample_data["dot3adAggPortStatsUnknownRx"] = int(data.unpack_uint())
	sample_data["dot3adAggPortStatsIllegalRx"] = int(data.unpack_uint())
	sample_data["dot3adAggPortStatsLACPDUsTx"] = int(data.unpack_uint())
	sample_data["dot3adAggPortStatsMarkerPDUsTx"] = int(data.unpack_uint())
	sample_data["dot3adAggPortStatsMarkerResponsePDUsTx"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Slow Path Counts (Counter, Enterprise 0, Format 8)
# https://groups.google.com/forum/#!topic/sflow/4JM1_Mmoz7w
def slow_path_stats(data):
	sample_data = {} # Cache
	sample_data["Unknown"] = int(data.unpack_uint())
	sample_data["Other"] = int(data.unpack_uint())
	sample_data["CAM Miss"] = int(data.unpack_uint())
	sample_data["CAM Full"] = int(data.unpack_uint())
	sample_data["No Hardware Support"] = int(data.unpack_uint())
	sample_data["CNTRL"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# InfiniBand Counters (Counter, Enterprise 0, Format 9)
def infiniband_counters(data):
	sample_data = {} # Cache
	sample_data["Port Transmitted Data"] = data.unpack_hyper()
	sample_data["Port Received Data"] = data.unpack_hyper()
	sample_data["Port Transmitted Packets"] = data.unpack_hyper()
	sample_data["Port Received Packets"] = data.unpack_hyper()
	sample_data["Symbol Error Count"] = int(data.unpack_uint())
	sample_data["Link Error Recovery Counter"] = int(data.unpack_uint())
	sample_data["Link Downed Counter"] = int(data.unpack_uint())
	sample_data["Receive Errors"] = int(data.unpack_uint())
	sample_data["Receive Remote Physical Errors"] = int(data.unpack_uint())
	sample_data["Receive Switch Relay Errors"] = int(data.unpack_uint())
	sample_data["Transmit Discards"] = int(data.unpack_uint())
	sample_data["Transmit Constraint Errors"] = int(data.unpack_uint())
	sample_data["Receive Constraint Errors"] = int(data.unpack_uint())
	sample_data["Local Link Integrity Errors"] = int(data.unpack_uint())
	sample_data["Excessive Buffer Overrun Errors"] = int(data.unpack_uint())
	sample_data["VL15 Dropped"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# SFP Optical Interfaces Counters (Counter, Enterprise 0, Format 10)
def sfp_optical_counters(data):
	sample_data = {} # Cache
	sample_data["Module ID"] = int(data.unpack_uint())
	sample_data["Module Lane Numbers"] = int(data.unpack_uint())
	sample_data["Module Supply Voltage mV"] = int(data.unpack_uint())
	sample_data["Module Temperature"] = int(data.unpack_int())
	sample_data["dot3adAggPortStatsMarkerResponsePDUsTx"] = int(data.unpack_uint())
	
	def lane_parse():
		lane = {}
		lane["TX Bias Current uA"] = int(data.unpack_uint())
		lane["TX Power uW"] = int(data.unpack_uint())		
		lane["TX Power Min uW"] = int(data.unpack_uint())
		lane["TX Power Max uW"] = int(data.unpack_uint())
		lane["TX Wavelength nM"] = int(data.unpack_uint())
		lane["RX Power uW"] = int(data.unpack_uint())		
		lane["RX Power Min uW"] = int(data.unpack_uint())
		lane["RX Power Max uW"] = int(data.unpack_uint())
		lane["RX Wavelength nM"] = int(data.unpack_uint())
		return lane

	sample_data["Lanes"] = {}
	for lane_num in range(0,sample_data["Module Lane Numbers"]):
		sample_data["Lanes"][lane_num+1] = lane_parse()
	
	data.done() # Verify all data unpacked
	return sample_data

# Processor Information (Counter, Enterprise 0, Format 1001)
def proc_info(data):
	sample_data = {} # Cache
	sample_data["5s CPU Percentage"] = int(data.unpack_uint())
	sample_data["1m CPU Percentage"] = int(data.unpack_uint())
	sample_data["5m CPU Percentage"] = int(data.unpack_uint())
	sample_data["Total Memory"] = data.unpack_hyper()
	sample_data["Free Memory"] = data.unpack_hyper()
	data.done() # Verify all data unpacked
	return sample_data

# 802.11 Radio Utilization (Counter, Enterprise 0, Format 1002)
def radio_util(data):
	sample_data = {} # Cache
	sample_data["Elapsed Time Milliseconds"] = int(data.unpack_uint())
	sample_data["On Channel Time Milliseconds"] = int(data.unpack_uint())
	sample_data["On Channel Busy Time Milliseconds"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Queue Length Histogram Counters (Counter, Enterprise 0, Format 1003)
def queue_len_histogram_counters(data):
	sample_data = {} # Cache
	sample_data["Queue Index"] = int(data.unpack_uint())
	sample_data["Segment Size"] = int(data.unpack_uint())
	sample_data["Queue Segments"] = int(data.unpack_uint())
	sample_data["Queue Length 0"] = int(data.unpack_uint())
	sample_data["Queue Length 1"] = int(data.unpack_uint())
	sample_data["Queue Length 2"] = int(data.unpack_uint())
	sample_data["Queue Length 4"] = int(data.unpack_uint())
	sample_data["Queue Length 8"] = int(data.unpack_uint())
	sample_data["Queue Length 32"] = int(data.unpack_uint())
	sample_data["Queue Length 128"] = int(data.unpack_uint())
	sample_data["Queue Length 1024"] = int(data.unpack_uint())
	sample_data["Queue Length More"] = int(data.unpack_uint())
	sample_data["Dropped"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Host Description (Counter, Enterprise 0, Format 2000)
def host_description(data):
	sample_data = {} # Cache
	sample_data["Hostname"] = data.unpack_string()
	sample_data["UUID"] = str(uuid.UUID(bytes_le=data.unpack_fopaque(16)))
	sample_data["Machine Type"] = enum_machine_type(int(data.unpack_uint()))
	sample_data["OS Name"] = enum_os_name(int(data.unpack_uint()))
	sample_data["OS Release"] = data.unpack_string()
	data.done() # Verify all data unpacked
	return sample_data

# Host Adapter (Counter, Enterprise 0, Format 2001)
def host_adapter(data,agent,subagent):
	mac_parser_class = mac_address() # MAC parser class
	sample_data = {} # Cache
	num_adapters = int(data.unpack_uint())
	for _ in range(0,num_adapters):
		interface_index = int(data.unpack_uint())
		interface_hash = hash(str(agent)+str(subagent)+str(interface_index))
		sample_data[interface_hash] = {}
		sample_data[interface_hash]["Index"] = interface_index
		mac_count = int(data.unpack_uint())
		for _ in range(0,mac_count):
			a = data.unpack_fopaque(6)
			ord_mac = [ord(x) for x in [a[0],a[1],a[2],a[3],a[4],a[5]]]
			parsed_mac = mac_parser_class.mac_parse(ord_mac)
			sample_data[interface_hash]["MAC"] = parsed_mac[0]
			sample_data[interface_hash]["MAC OUI"] = parsed_mac[1]
	data.done() # Verify all data unpacked
	return sample_data

# Host Parent (Counter, Enterprise 0, Format 2002)
def host_parent(data):
	sample_data = {} # Cache
	sample_data["Container Type"] = int(data.unpack_uint())
	sample_data["Container Index"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Physical Server CPU (Counter, Enterprise 0, Format 2003)
def physical_host_cpu(data):
	sample_data = {} # Cache
	sample_data["Load One"] = float(data.unpack_float())
	sample_data["Load Five"] = float(data.unpack_float())
	sample_data["Load Fifteen"] = float(data.unpack_float())
	sample_data["Running Processes"] = int(data.unpack_uint())
	sample_data["Total Processes "] = int(data.unpack_uint())
	sample_data["CPU Count"] = int(data.unpack_uint())
	sample_data["CPU MHz"] = int(data.unpack_uint())
	sample_data["Uptime"] = int(data.unpack_uint())
	sample_data["CPU User Time"] = int(data.unpack_uint())
	sample_data["CPU Nice Time"] = int(data.unpack_uint())
	sample_data["CPU System Time"] = int(data.unpack_uint())
	sample_data["CPU Idle Time"] = int(data.unpack_uint())
	sample_data["CPU Time Waiting"] = int(data.unpack_uint())
	sample_data["CPU Time Servicing INT"] = int(data.unpack_uint())
	sample_data["CPU Time Servicing SINT"] = int(data.unpack_uint())
	sample_data["Interrupts"] = int(data.unpack_uint())
	sample_data["Context Switch Count"] = int(data.unpack_uint())
	#data.done() # Verify all data unpacked # Not sure why this kills it, Python behaving badly or bad exports from device
	return sample_data

# Physical Server Memory (Counter, Enterprise 0, Format 2004)
def physical_host_memory(data):
	sample_data = {} # Cache
	sample_data["Memory Total"] = data.unpack_hyper()
	sample_data["Memory Free"] = data.unpack_hyper()
	#sample_data["Percentage Memory Free"] = sample_data["Memory Free"]/sample_data["Memory Total"]
	sample_data["Memory Shared"] = data.unpack_hyper()
	sample_data["Memory Buffers"] = data.unpack_hyper()
	sample_data["Memory Cached"] = data.unpack_hyper()
	sample_data["Swap Total"] = data.unpack_hyper()
	sample_data["Swap Free"] = data.unpack_hyper()
	sample_data["Page In"] = int(data.unpack_uint())
	sample_data["Page Out"] = int(data.unpack_uint())
	sample_data["Swap In"] = int(data.unpack_uint())
	sample_data["Swap Out"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Physical Server Disk I/O (Counter, Enterprise 0, Format 2005)
def physical_host_diskio(data):
	sample_data = {} # Cache
	sample_data["Disk Total"] = data.unpack_hyper()
	sample_data["Disk Free"] = data.unpack_hyper()
	sample_data["Percentage Max Used"] = int(data.unpack_uint())
	sample_data["Reads"] = int(data.unpack_uint())
	sample_data["Bytes Read"] = data.unpack_hyper()
	sample_data["Read Time"] = int(data.unpack_uint())
	sample_data["Writes"] = int(data.unpack_uint())
	sample_data["Bytes Written"] = data.unpack_hyper()
	sample_data["Write Time"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Physical Server Network I/O (Counter, Enterprise 0, Format 2006)
def physical_host_netio(data):
	sample_data = {} # Cache
	sample_data["Bytes In"] = data.unpack_hyper()
	sample_data["Packets In"] = int(data.unpack_uint())
	sample_data["Errors In"] = int(data.unpack_uint())
	sample_data["Drops In"] = int(data.unpack_uint())
	sample_data["Bytes Out"] = data.unpack_hyper()
	sample_data["Packets Out"] = int(data.unpack_uint())
	sample_data["Errors Out"] = int(data.unpack_uint())
	sample_data["Drops Out"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# MIB2 IP Group (Counter, Enterprise 0, Format 2007)
def mib2_ip_group(data):
	sample_data = {} # Cache
	sample_data["IP Forwarding"] = int(data.unpack_uint())
	sample_data["IP Default TTL"] = int(data.unpack_uint())
	sample_data["IP In Receives"] = int(data.unpack_uint())
	sample_data["IP In Header Errors"] = int(data.unpack_uint())
	sample_data["IP In Address Errors"] = int(data.unpack_uint())
	sample_data["IP Forward Datagrams"] = int(data.unpack_uint())
	sample_data["IP In Unknown Protos"] = int(data.unpack_uint())
	sample_data["IP In Discards"] = int(data.unpack_uint())
	sample_data["IP In Delivers"] = int(data.unpack_uint())
	sample_data["IP Out Requests"] = int(data.unpack_uint())
	sample_data["IP Out Discards"] = int(data.unpack_uint())
	sample_data["IP Out No Routes"] = int(data.unpack_uint())
	sample_data["IP Reassemble Timeout"] = int(data.unpack_uint())
	sample_data["IP Reassemble Requireds"] = int(data.unpack_uint())
	sample_data["IP Reassemble OKs"] = int(data.unpack_uint())
	sample_data["IP Reassemble Fails"] = int(data.unpack_uint())
	sample_data["IP Fragment OKs"] = int(data.unpack_uint())
	sample_data["IP Fragment Fails"] = int(data.unpack_uint())
	sample_data["IP Fragment Creates"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# MIB2 ICMP Group (Counter, Enterprise 0, Format 2008)
def mib2_icmp_group(data):
	sample_data = {} # Cache
	sample_data["ICMP In Messages"] = int(data.unpack_uint())
	sample_data["ICMP In Errors"] = int(data.unpack_uint())
	sample_data["ICMP In Destination Unreachables"] = int(data.unpack_uint())
	sample_data["ICMP In Time Exceeded"] = int(data.unpack_uint())
	sample_data["ICMP In Parameter Problems"] = int(data.unpack_uint())
	sample_data["ICMP In Source Quenches"] = int(data.unpack_uint())
	sample_data["ICMP In Redirects"] = int(data.unpack_uint())
	sample_data["ICMP In Echos"] = int(data.unpack_uint())
	sample_data["ICMP In Echo Replies"] = int(data.unpack_uint())
	sample_data["ICMP In Timestamps"] = int(data.unpack_uint())
	sample_data["ICMP In Address Masks"] = int(data.unpack_uint())
	sample_data["ICMP In Address Mask Replies"] = int(data.unpack_uint())
	sample_data["ICMP Out Messages"] = int(data.unpack_uint())
	sample_data["ICMP Out Errors"] = int(data.unpack_uint())
	sample_data["ICMP Out Destination Unreachables"] = int(data.unpack_uint())
	sample_data["ICMP Out Time Exceeded"] = int(data.unpack_uint())
	sample_data["ICMP Out Parameter Problems"] = int(data.unpack_uint())
	sample_data["ICMP Out Source Quenches"] = int(data.unpack_uint())
	sample_data["ICMP Out Redirects"] = int(data.unpack_uint())
	sample_data["ICMP Out Echos"] = int(data.unpack_uint())
	sample_data["ICMP Out Echo Replies"] = int(data.unpack_uint())
	sample_data["ICMP Out Timestamps"] = int(data.unpack_uint())
	sample_data["ICMP Out Timestamp Replies"] = int(data.unpack_uint())
	sample_data["ICMP Out Address Masks"] = int(data.unpack_uint())
	sample_data["ICMP Out Address Mask Replies"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# MIB2 TCP Group (Counter, Enterprise 0, Format 2009)
def mib2_tcp_group(data):
	sample_data = {} # Cache
	sample_data["TCP Retrasmission Timeout Algorithm"] = int(data.unpack_uint())
	sample_data["TCP Retrasmission Timeout Min"] = int(data.unpack_uint())
	sample_data["TCP Retrasmission Timeout Max"] = int(data.unpack_uint())
	sample_data["TCP Max Connections"] = int(data.unpack_uint())
	sample_data["TCP Active Opens"] = int(data.unpack_uint())
	sample_data["TCP Passive Opens"] = int(data.unpack_uint())
	sample_data["TCP Attempt Fails"] = int(data.unpack_uint())
	sample_data["TCP Established Resets"] = int(data.unpack_uint())
	sample_data["TCP Current Established"] = int(data.unpack_uint())
	sample_data["TCP In Segments"] = int(data.unpack_uint())
	sample_data["TCP Out Segments"] = int(data.unpack_uint())
	sample_data["TCP Retransmit Segments"] = int(data.unpack_uint())
	sample_data["TCP In Errors"] = int(data.unpack_uint())
	sample_data["TCP Out Resets"] = int(data.unpack_uint())
	sample_data["TCP In Checksum Errors"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# MIB2 UDP Group (Counter, Enterprise 0, Format 2010)
def mib2_udp_group(data):
	sample_data = {} # Cache
	sample_data["UDP In Datagrams"] = int(data.unpack_uint())
	sample_data["UDP No Ports"] = int(data.unpack_uint())
	sample_data["UDP In Errors"] = int(data.unpack_uint())
	sample_data["UDP Out Datagrams"] = int(data.unpack_uint())
	sample_data["UDP Receive Buffer Errors"] = int(data.unpack_uint())
	sample_data["UDP Send Buffer Errors"] = int(data.unpack_uint())
	sample_data["UDP In Checksum Errors"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Virtual Node Statistics (Counter, Enterprise 0, Format 2100)
def virtual_node_stats(data):
	sample_data = {} # Cache
	sample_data["CPU MHz"] = int(data.unpack_uint())
	sample_data["CPU Count"] = int(data.unpack_uint())
	sample_data["Memory Total"] = data.unpack_hyper()
	sample_data["Memory Free"] = data.unpack_hyper()
	sample_data["Domains"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Virtual Domain CPU statistics (Counter, Enterprise 0, Format 2101)
def virtual_domain_cpu_stats(data):
	sample_data = {} # Cache
	sample_data["State"] = int(data.unpack_uint())
	sample_data["CPU Time ms"] = int(data.unpack_uint())
	sample_data["Virtual CPU Count"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Virtual Domain Memory statistics (Counter, Enterprise 0, Format 2102)
def virtual_domain_mem_stats(data):
	sample_data = {} # Cache
	sample_data["Memory Used"] = data.unpack_uhyper()
	sample_data["Memory Total"] = data.unpack_uhyper()
	data.done() # Verify all data unpacked
	return sample_data

# Virtual Domain Disk statistics (Counter, Enterprise 0, Format 2103)
def virtual_domain_disk_stats(data):
	sample_data = {} # Cache
	sample_data["Total Capacity"] = data.unpack_uhyper()
	sample_data["Current Allocation"] = data.unpack_uhyper()
	sample_data["Total Available"] = data.unpack_uhyper()
	sample_data["Read Requests"] = int(data.unpack_uint())
	sample_data["Bytes Read"] = data.unpack_uhyper()
	sample_data["Write Requests"] = int(data.unpack_uint())
	sample_data["Bytes Written"] = data.unpack_uhyper()
	sample_data["Errors"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Virtual Domain Network statistics (Counter, Enterprise 0, Format 2104)
def virtual_domain_net_stats(data):
	sample_data = {} # Cache
	sample_data["Bytes In"] = data.unpack_uhyper()
	sample_data["Packets In"] = int(data.unpack_uint())
	sample_data["Errors In"] = int(data.unpack_uint())
	sample_data["Drops In"] = int(data.unpack_uint())
	sample_data["Bytes Out"] = data.unpack_uhyper()
	sample_data["Packets Out"] = int(data.unpack_uint())
	sample_data["Errors Out"] = int(data.unpack_uint())
	sample_data["Drops Out"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# JVM Runtime Attributes (Counter, Enterprise 0, Format 2105)
def jvm_runtime_attr(data):
	sample_data = {} # Cache
	sample_data["VM Name"] = data.unpack_string()
	sample_data["VM Vendor"] = data.unpack_string()
	sample_data["VM Version"] = data.unpack_string()
	data.done() # Verify all data unpacked
	return sample_data

# JVM Statistics (Counter, Enterprise 0, Format 2106)
def jvm_stats(data):
	sample_data = {} # Cache
	sample_data["Heap Initial Memory Requested"] = data.unpack_uhyper()
	sample_data["Heap Memory Used"] = data.unpack_uhyper()
	sample_data["Heap Memory Committed"] = data.unpack_uhyper()
	sample_data["Heap Maximum Space"] = data.unpack_uhyper()
	sample_data["Non-Heap Initial Memory Requested"] = data.unpack_uhyper()
	sample_data["Non-Heap Memory Used"] = data.unpack_uhyper()
	sample_data["Non-Heap Memory Committed"] = data.unpack_uhyper()
	sample_data["Non-Heap Maximum Space"] = data.unpack_uhyper()
	sample_data["GC Count"] = int(data.unpack_uint())
	sample_data["GC Time ms"] = int(data.unpack_uint())
	sample_data["Classes Loaded"] = int(data.unpack_uint())
	sample_data["Total Classes"] = int(data.unpack_uint())
	sample_data["Unloaded Classes"] = int(data.unpack_uint())
	sample_data["Compilation Time ms"] = int(data.unpack_uint())
	sample_data["Live Threads"] = int(data.unpack_uint())
	sample_data["Live Daemon Threads"] = int(data.unpack_uint())
	sample_data["Total Threads Started"] = int(data.unpack_uint())
	sample_data["Open File Descriptors"] = int(data.unpack_uint())
	sample_data["Maximum File Descriptors"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Energy Consumption Statistics (Counter, Enterprise 0, Format 3000)
def energy_consumption(data):
	sample_data = {} # Cache
	sample_data["Voltage mV"] = int(data.unpack_uint())
	sample_data["Current mA"] = int(data.unpack_uint())
	sample_data["Real Power mW"] = int(data.unpack_uint())
	sample_data["Power Factor"] = int(data.unpack_int())/100
	sample_data["Energy mJ"] = int(data.unpack_uint())
	sample_data["Energy Errors"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Temperature Statistics (Counter, Enterprise 0, Format 3001)
def temperature_counter(data):
	sample_data = {} # Cache
	sample_data["Minimum Temperature"] = int(data.unpack_int())
	sample_data["Maximum Temperature"] = int(data.unpack_int())
	sample_data["Temperature Errors"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Humidity Statistics (Counter, Enterprise 0, Format 3002)
def humidity_counter(data):
	sample_data = {} # Cache
	sample_data["Relative Humidity"] = int(data.unpack_int())
	data.done() # Verify all data unpacked
	return sample_data

# Cooling Statistics (Counter, Enterprise 0, Format 3003)
def cooling_counter(data):
	sample_data = {} # Cache
	sample_data["Total Fans"] = int(data.unpack_uint())
	sample_data["Failed Fans"] = int(data.unpack_uint())
	sample_data["Average Fan Speed Percentage"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# Broadcom Switch Device Buffer Utilization (Counter, Enterprise 4413, Format 1)
# http://www.sflow.org/sflow_broadcom_tables.txt
def broad_switch_dev_buffer_util(data):
	sample_data = {} # Cache
	sample_data["Unicast Buffers Utilization"] = int(data.unpack_uint())/100
	sample_data["Multicast Buffers Utilization"] = int(data.unpack_uint())/100
	data.done() # Verify all data unpacked
	return sample_data

# Broadcom Switch Port Level Buffer Utilization (Counter, Enterprise 4413, Format 2)
# http://www.sflow.org/sflow_broadcom_tables.txt
def broad_switch_port_buff_util(data):
	sample_data = {} # Cache
	sample_data["Ingress Unicast Buffer Utilization"] = int(data.unpack_uint())/100
	sample_data["Ingress Multicast Buffers Utilization"] = int(data.unpack_uint())/100
	sample_data["Egress Unicast Buffer Utilization"] = int(data.unpack_uint())/100
	sample_data["Egress Multicast Buffer Utilization"] = int(data.unpack_uint())/100
	sample_data["Per-Egress Queue Unicast Buffer Utilization"] = int(data.unpack_uint())/100
	sample_data["Per-Egress Queue Multicast Buffer Utilization"] = int(data.unpack_uint())/100
	data.done() # Verify all data unpacked
	return sample_data

# Broadcom Switch ASIC Hardware Table Utilization (Counter, Enterprise 4413, Format 3)
# http://www.sflow.org/sflow_broadcom_tables.txt
def asic_hardware_tab_util(data):
	sample_data = {} # Cache
	sample_data["Host Entries"] = int(data.unpack_uint())
	sample_data["Host Entries Max"] = int(data.unpack_uint())
	sample_data["IPv4 Entries"] = int(data.unpack_uint())
	sample_data["IPv4 Entries Max"] = int(data.unpack_uint())
	sample_data["IPv6 Entries"] = int(data.unpack_uint())
	sample_data["IPv6 Entries Max"] = int(data.unpack_uint())
	sample_data["IPv4 IPv6 Entries"] = int(data.unpack_uint())
	sample_data["IPv6 IPv6 Entries Max"] = int(data.unpack_uint())
	sample_data["Long IPv6 Entries"] = int(data.unpack_uint())
	sample_data["Long IPv6 Entries Max"] = int(data.unpack_uint())
	sample_data["Total Routes"] = int(data.unpack_uint())
	sample_data["Total Routes Max"] = int(data.unpack_uint())
	sample_data["ECMP Nexthops"] = int(data.unpack_uint())
	sample_data["ECMP Nexthops Max"] = int(data.unpack_uint())
	sample_data["MAC Entries"] = int(data.unpack_uint())
	sample_data["MAC Entries Max"] = int(data.unpack_uint())
	sample_data["IPv4 Neighbors"] = int(data.unpack_uint())
	sample_data["IPv6 Neighbors"] = int(data.unpack_uint())
	sample_data["IPv4 Routes"] = int(data.unpack_uint())
	sample_data["IPv6 Routes"] = int(data.unpack_uint())
	sample_data["ACL Ingress Entries"] = int(data.unpack_uint())
	sample_data["ACL Ingress Entries Max"] = int(data.unpack_uint())
	sample_data["ACL Ingress Counters"] = int(data.unpack_uint())
	sample_data["ACL Ingress Counters Max"] = int(data.unpack_uint())
	sample_data["ACL Ingress Meters"] = int(data.unpack_uint())
	sample_data["ACL Ingress Meters Max"] = int(data.unpack_uint())
	sample_data["ACL Ingress Slices"] = int(data.unpack_uint())
	sample_data["ACL Ingress Slices Max"] = int(data.unpack_uint())
	sample_data["ACL Egress Entries"] = int(data.unpack_uint())
	sample_data["ACL Egress Entries Max"] = int(data.unpack_uint())
	sample_data["ACL Egress Counters"] = int(data.unpack_uint())
	sample_data["ACL Egress Counters Max"] = int(data.unpack_uint())
	sample_data["ACL Egress Meters"] = int(data.unpack_uint())
	sample_data["ACL Egress Meters Max"] = int(data.unpack_uint())
	sample_data["ACL Egress Slices"] = int(data.unpack_uint())
	sample_data["ACL Egress Slices Max"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data

# NVIDIA GPU statistics (Counter, Enterprise 5703, Format 1)
def nvidia_gpu_stats(data):
	sample_data = {} # Cache
	sample_data["Device Count"] = int(data.unpack_uint())
	sample_data["Processes"] = int(data.unpack_uint())
	sample_data["GPU Time"] = int(data.unpack_uint())
	sample_data["Memory Time ms"] = int(data.unpack_uint())
	sample_data["Total Memory"] = data.unpack_uhyper()
	sample_data["Free Memory"] = data.unpack_uhyper()
	sample_data["ECC Errors"] = int(data.unpack_uint())
	sample_data["Energy mJ"] = int(data.unpack_uint())
	sample_data["Temperature"] = int(data.unpack_uint())
	sample_data["Fan Speed"] = int(data.unpack_uint())
	data.done() # Verify all data unpacked
	return sample_data