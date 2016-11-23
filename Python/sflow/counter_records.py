# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import struct, sys, binascii, uuid
from xdrlib import Unpacker
from struct import *

from sflow_parsers import *  # Functions to parse headers and format numbers

# Generic Interface (Counter, Enterprise 0, Format 1)
def gen_int_counter(data):
	sample_data = {}
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
	data.done()
	return sample_data

# Ethernet Interface (Counter, Enterprise 0, Format 2)
def eth_int_counter(data):
	sample_data = {}
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
	data.done()
	return sample_data

# Token Ring (Counter, Enterprise 0, Format 3)
def token_ring_counter(data):
	sample_data = {}
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
	data.done()
	return sample_data

# 100 BaseVG Interface (Counter, Enterprise 0, Format 4)
def basevg_int_counter(data):
	sample_data = {}
	sample_data["InHigh Priority Frames"] = int(data.unpack_uint())
	sample_data["InHigh Priority Bytes"] = data.unpack_hyper()
	sample_data["InNorm Priority Frames"] = int(data.unpack_uint())
	sample_data["InNorm Priority Bytes"] = data.unpack_hyper()
	sample_data["InIPM Errors"] = int(data.unpack_uint())
	sample_data["InOversize Frame Errors"] = int(data.unpack_uint())
	sample_data["InData Errors"] = int(data.unpack_uint())
	sample_data["InNull Addressed Frames"] = int(data.unpack_uint())
	sample_data["OutHigh Priority Frames"] = int(data.unpack_uint())
	sample_data["OutHigh Priority Bytes"] = data.unpack_hyper()
	sample_data["Transition Into Trainings"] = int(data.unpack_uint())
	sample_data["HC In High Priority Bytes"] = data.unpack_hyper()
	sample_data["HC In Norm Priority Bytes"] = data.unpack_hyper()
	sample_data["HC Out High Priority Bytes"] = data.unpack_hyper()
	data.done()
	return sample_data

# VLAN (Counter, Enterprise 0, Format 5)
def vlan_counter(data):
	sample_data = {}
	sample_data["VLAN ID"] = int(data.unpack_uint())
	sample_data["Bytes"] = data.unpack_hyper()
	sample_data["Unicast Packets"] = int(data.unpack_uint())
	sample_data["Multicast Packets"] = int(data.unpack_uint())
	sample_data["Broadcast Packets"] = int(data.unpack_uint())
	sample_data["Discards"] = int(data.unpack_uint())
	data.done()
	return sample_data

# IEEE 802.11 Counters (Counter, Enterprise 0, Format 6)
def wlan_counters(data):
	sample_data = {}
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
	data.done()
	return sample_data	

# IEEE 802.3ad LAG Port Statistics (Counter, Enterprise 0, Format 7)
def lag_port_stats(data):
	sample_data = {}
	data.done()
	return sample_data

# Slow Path Counts (Counter, Enterprise 0, Format 8)
def slow_path_stats(data):
	sample_data = {}
	data.done()
	return sample_data

# InfiniBand Counters (Counter, Enterprise 0, Format 9)
def infiniband_counters(data):
	sample_data = {}
	data.done()
	return sample_data

# SFP Optical Interfaces Counters (Counter, Enterprise 0, Format 10)
def sfp_optical_counters(data):
	sample_data = {}
	data.done()
	return sample_data

# Processor Information (Counter, Enterprise 0, Format 1001)
def proc_info(data):
	sample_data = {}
	sample_data["5s CPU Percentage"] = int(data.unpack_uint())
	sample_data["1m CPU Percentage"] = int(data.unpack_uint())
	sample_data["5m CPU Percentage"] = int(data.unpack_uint())
	sample_data["Total Memory"] = data.unpack_hyper()
	sample_data["Free Memory"] = data.unpack_hyper()
	data.done()
	return sample_data

# Host Description (Counter, Enterprise 0, Format 2000)
def host_description(data):
	sample_data = {}
	sample_data["Hostname"] = data.unpack_string()
	sample_data["UUID"] = str(uuid.UUID(bytes_le=data.unpack_fopaque(16)))
	sample_data["Machine Type"] = enum_machine_type(int(data.unpack_uint()))
	sample_data["OS Name"] = enum_os_name(int(data.unpack_uint()))
	sample_data["OS Release"] = data.unpack_string()
	data.done()
	return sample_data

# Host Adapter (Counter, Enterprise 0, Format 2001)
def host_adapter(data,agent,subagent):
	sample_data = {}
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
			sample_data[interface_hash]["MAC"] = mac_parse(ord_mac)
	data.done()
	return sample_data

# Host Parent (Counter, Enterprise 0, Format 2002)
def host_parent(data):
	sample_data = {}
	sample_data["Container Type"] = int(data.unpack_uint())
	sample_data["Container Index"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Physical Server CPU (Counter, Enterprise 0, Format 2003)
def physical_host_cpu(data):
	sample_data = {}
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
	#data.done() # Not sure why this kills it, Python behaving badly
	return sample_data

# Physical Server Memory (Counter, Enterprise 0, Format 2004)
def physical_host_memory(data):
	sample_data = {}
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
	data.done()
	return sample_data

# Physical Server Disk I/O (Counter, Enterprise 0, Format 2005)
def physical_host_diskio(data):
	sample_data = {}
	sample_data["Disk Total"] = data.unpack_hyper()
	sample_data["Disk Free"] = data.unpack_hyper()
	sample_data["Percentage Max Used"] = int(data.unpack_uint())
	sample_data["Reads"] = int(data.unpack_uint())
	sample_data["Bytes Read"] = data.unpack_hyper()
	sample_data["Read Time"] = int(data.unpack_uint())
	sample_data["Writes"] = int(data.unpack_uint())
	sample_data["Bytes Written"] = data.unpack_hyper()
	sample_data["Write Time"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Physical Server Network I/O (Counter, Enterprise 0, Format 2006)
def physical_host_netio(data):
	sample_data = {}
	sample_data["Bytes In"] = data.unpack_hyper()
	sample_data["Packets In"] = int(data.unpack_uint())
	sample_data["Errors In"] = int(data.unpack_uint())
	sample_data["Drops In"] = int(data.unpack_uint())
	sample_data["Bytes Out"] = data.unpack_hyper()
	sample_data["Packets Out"] = int(data.unpack_uint())
	sample_data["Errors Out"] = int(data.unpack_uint())
	sample_data["Drops Out"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Virtual Node Statistics (Counter, Enterprise 0, Format 2100)
def virtual_node_stats(data):
	sample_data = {}
	sample_data["CPU MHz"] = int(data.unpack_uint())
	sample_data["CPU Count"] = int(data.unpack_uint())
	sample_data["Memory Total"] = data.unpack_hyper()
	sample_data["Memory Free"] = data.unpack_hyper()
	sample_data["Domains"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Virtual Domain CPU statistics (Counter, Enterprise 0, Format 2101)
def virtual_domain_cpu_stats(data):
	sample_data = {}
	sample_data["State"] = int(data.unpack_uint())
	sample_data["CPU Time ms"] = int(data.unpack_uint())
	sample_data["Virtual CPU Count"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Virtual Domain Memory statistics (Counter, Enterprise 0, Format 2102)
def virtual_domain_mem_stats(data):
	sample_data = {}
	sample_data["Memory Used"] = data.unpack_uhyper()
	sample_data["Memory Total"] = data.unpack_uhyper()
	data.done()
	return sample_data

# Virtual Domain Disk statistics (Counter, Enterprise 0, Format 2103)
def virtual_domain_disk_stats(data):
	sample_data = {}
	sample_data["Total Capacity"] = data.unpack_uhyper()
	sample_data["Current Allocation"] = data.unpack_uhyper()
	sample_data["Total Available"] = data.unpack_uhyper()
	sample_data["Read Requests"] = int(data.unpack_uint())
	sample_data["Bytes Read"] = data.unpack_uhyper()
	sample_data["Write Requests"] = int(data.unpack_uint())
	sample_data["Bytes Written"] = data.unpack_uhyper()
	sample_data["Errors"] = int(data.unpack_uint())
	data.done()
	return sample_data

# Virtual Domain Network statistics (Counter, Enterprise 0, Format 2104)
def virtual_domain_net_stats(data):
	sample_data = {}
	sample_data["Bytes In"] = data.unpack_uhyper()
	sample_data["Packets In"] = int(data.unpack_uint())
	sample_data["Errors In"] = int(data.unpack_uint())
	sample_data["Drops In"] = int(data.unpack_uint())
	sample_data["Bytes Out"] = data.unpack_uhyper()
	sample_data["Packets Out"] = int(data.unpack_uint())
	sample_data["Errors Out"] = int(data.unpack_uint())
	sample_data["Drops Out"] = int(data.unpack_uint())
	data.done()
	return sample_data