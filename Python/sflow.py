# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Import what we need
import time, datetime, socket, struct, sys, os, json, socket, collections, itertools, logging, logging.handlers, getopt
from struct import *

# Windows socket.inet_ntop support via win_inet_pton
try:
	import win_inet_pton
except ImportError:
	pass

from socket import inet_ntoa,inet_ntop
from elasticsearch import Elasticsearch,helpers
from IPy import IP
from xdrlib import Unpacker

from netflow_options import * # Flow Options

### Get the command line arguments ###
try:
	arguments = getopt.getopt(sys.argv[1:],"hl:",["--help","log="])
	
	for option_set in arguments:
		for opt,arg in option_set:
						
			if opt in ('-l','--log'): # Log level
				arg = arg.upper() # Uppercase for matching and logging.basicConfig() format
				if arg in ["CRITICAL","ERROR","WARNING","INFO","DEBUG"]:
					log_level = arg # Use what was passed in arguments

			elif opt in ('-h','--help'): # Help file
				with open("./help.txt") as help_file:
					print(help_file.read())
				sys.exit()

			else: # No options
				pass

except:
    sys.exit("Unsupported or badly formed options, see -h for available arguments.") 

# Set the logging level per https://docs.python.org/2/howto/logging.html
try: 
	log_level # Check if log level was passed in from command arguments
except NameError:
	log_level="WARNING" # Use default logging level

logging.basicConfig(level=str(log_level)) # Set the logging level
logging.warning('Log level set to ' + str(log_level) + " - OK") # Show the logging level for debug

### DNS Lookups ###
#
# Reverse lookups
try:
	if dns is False:
		logging.warning("DNS reverse lookups disabled - DISABLED")
	elif dns is True:
		logging.warning("DNS reverse lookups enabled - OK")
	else:
		logging.warning("DNS enable option incorrectly set - DISABLING")
		dns = False
except:
	logging.warning("DNS enable option not set - DISABLING")
	dns = False

# RFC-1918 reverse lookups
try:
	if lookup_internal is False:
		logging.warning("DNS local IP reverse lookups disabled - DISABLED")
	elif lookup_internal is True:
		logging.warning("DNS local IP reverse lookups enabled - OK")
	else:
		logging.warning("DNS local IP reverse lookups incorrectly set - DISABLING")
		lookup_internal = False
except:
	logging.warning("DNS local IP reverse lookups not set - DISABLING")
	lookup_internal = False

# Check if the sFlow port is specified
try:
	sflow_port
except NameError: # Not specified, use default
	sflow_port = 6343
	logging.warning("sFlow port not set in netflow_options.py, defaulting to " + str(sflow_port) + " - OK")

# Set up socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', sflow_port))
	logging.warning('Bound to UDP port ' + str(sflow_port) + ' - OK')
except ValueError as socket_error:
	logging.critical('Could not open or bind a socket on port ' + str(sflow_port))
	logging.critical(str(socket_error))
	sys.exit("Could not open or bind a socket on port " + str(sflow_port))

### Elasticsearch ###
es = Elasticsearch([elasticsearch_host])

### sFlow Collector ###
if __name__ == "__main__":
	from counter_records import * 	# Functions to parse counter record structures
	from flow_records import * 		# Functions to parse flow record structures
	from sflow_parsers import * 	# Functions to parse headers and misc data chunks
	from sflow_samples import * 	# Functions to parse sFlow samples
	
	global sflow_data
	sflow_data = [] # For bulk upload to Elasticsearch

	global uuid_cache
	uuid_cache = {}

	record_num = 0 # Record index number for the record cache
	
	# Continue to run
	while True: 
		
		# Listen for packets inbound
		sflow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)

		### sFlow Datagram Start ###
		try:
			unpacked_data = Unpacker(sflow_packet_contents) # Unpack XDR datagram
			datagram_info = datagram_parse(unpacked_data) # Parse the datagram
			
			logging.debug(str(datagram_info))
			logging.info("Unpacked an sFlow datagram from " + str(sensor_address[0]) + " - OK")
		
		except Exception as datagram_unpack_error:
			logging.warning("Unable to unpack the sFlow datagram - FAIL")
			logging.warning(str(datagram_unpack_error))
			continue

		if datagram_info["sFlow Version"] != 5:
			logging.warning("Not an sFlow v5 datagram - SKIPPING")
			continue
		### sFlow Datagram End ###

		### sFlow Samples Start ###			
		for sample_num in range(0,datagram_info["Sample Count"]): # For each sample in the datagram

			### Sample Header Start ###
			enterprise_format_num = enterprise_format_numbers(unpacked_data.unpack_uint()) # Enterprise number and format
			sample_length = int(unpacked_data.unpack_uint()) # Sample Length		
			
			logging.info("Sample " + str(sample_num+1) + " of " + str(datagram_info["Sample Count"]) + ", type " + str(enterprise_format_num) + " length " + str(sample_length))

			try:
				unpacked_sample_data = Unpacker(unpacked_data.unpack_fopaque(sample_length)) # Unpack the sample data block	
				logging.info("Unpacked opaque sample data chunk - OK")
			except Exception as unpack_error:
				logging.warning("Failed to unpack opaque sample data - FAIL")
				continue
			### Sample Header Finish ###

			### Sample Parsing Start ###
			flow_sample_cache = sample_picker(enterprise_format_num,unpacked_sample_data) # Get the opaque flow sample cache
			
			if flow_sample_cache is False:
				logging.warning("Unable to parse the sample cache, type " + str([enterprise_format_num,unpacked_sample_data]) + " from " + str(datagram_info["Agent IP"]) + " - SKIPPING")
				continue
			else:
				logging.info(str(flow_sample_cache))
			
			### Flow Sample ###
			if enterprise_format_num in [[0,1], [0,3]]: # Flow Sample

				# Iterate through the flow records
				for record_counter_num in range(0,flow_sample_cache["Record Count"]): # For each staged sample
					record_ent_form_number = enterprise_format_numbers(unpacked_sample_data.unpack_uint()) # [Enterprise, Format] numbers
					counter_data_length = int(unpacked_sample_data.unpack_uint()) # Length of record
					current_position = int(unpacked_sample_data.get_position()) # Current unpack buffer position
					skip_position = current_position + counter_data_length # Bail out position if unpack fails for skipping
					
					logging.info(
						"Flow record " + 
						str(record_counter_num+1) + 
						" of " + 
						str(flow_sample_cache["Record Count"]) + 
						", type " + 
						str(record_ent_form_number) + 
						", length " + 
						str(counter_data_length) + 
						", XDR position " + 
						str(current_position) + 
						", skip position " + 
						str(skip_position)
						)
					
					# Unpack the opaque flow record
					unpacked_record_data = Unpacker(unpacked_sample_data.unpack_fopaque(counter_data_length))
					
					# Parse the flow record
					try:
						now = datetime.datetime.utcnow() # Get the current UTC time
						
						flow_index = {
						"_index": str("sflow-" + now.strftime("%Y-%m-%d")),
						"_type": "Flow",
						"_source": {
						"Flow Type": "sFlow Flow",
						"Sensor": datagram_info["Agent IP"],
						"Sub Agent": datagram_info["Sub Agent"],
						"Enterprise, Format": record_ent_form_number,
						"Data Length": counter_data_length,
						"Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z",
						}
						}
						
						flow_index["_source"].update(flow_sample_cache) # Add sample header info to each record
						
						if record_ent_form_number == [0,1]: # Raw packet header
							flow_index["_source"].update(raw_packet_header(unpacked_record_data))
						
						elif record_ent_form_number == [0,2]: # Ethernet frame data
							flow_index["_source"].update(eth_frame_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,3]: # IPv4 data
							flow_index["_source"].update(ipv4_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,4]: # IPv6 data
							flow_index["_source"].update(ipv6_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,1001]: # Extended switch data
							flow_index["_source"].update(extended_switch_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,1002]: # Extended router data
							flow_index["_source"].update(extended_router_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,1003]: # Extended gateway data
							flow_index["_source"].update(extended_gateway_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,1004]: # Extended user data
							flow_index["_source"].update(extended_user_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,1005]: # Extended URL data
							flow_index["_source"].update(extended_url_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,1006]: # Extended MPLS data
							flow_index["_source"].update(extended_mpls_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,1007]: # Extended NAT data
							flow_index["_source"].update(extended_nat_data(unpacked_record_data))
						
						elif record_ent_form_number == [0,1008]: # Extended MPLS tunnel data
							flow_index["_source"].update(extended_mpls_tunnel(unpacked_record_data))
						
						elif record_ent_form_number == [0,1009]: # Extended MPLS VC data
							flow_index["_source"].update(extended_mpls_vc(unpacked_record_data))
						
						elif record_ent_form_number == [0,1010]: # Extended MPLS FEC data
							flow_index["_source"].update(exteded_mpls_fec(unpacked_record_data))
						
						elif record_ent_form_number == [0,1011]: # Extended MPLS LVP FEC data
							flow_index["_source"].update(extended_mpls_lvp_fec(unpacked_record_data))
						
						elif record_ent_form_number == [0,1012]: # Extended VLAN tunnel data
							flow_index["_source"].update(extended_vlan_tunnel(unpacked_record_data))

						# Requires special parsing, still working on this
						#elif record_ent_form_number == [0,1013]: # Extended 802.11 Payload
							#flow_index["_source"].update(extended_vlan_tunnel(unpacked_record_data))

						elif record_ent_form_number == [0,1014]: # Extended 802.11 RX
							flow_index["_source"].update(extended_wlan_rx(unpacked_record_data))

						elif record_ent_form_number == [0,1015]: # Extended 802.11 TX
							flow_index["_source"].update(extended_wlan_tx(unpacked_record_data))

						# Requires special parsing, still working on this
						#elif record_ent_form_number == [0,1016]: # Extended 802.11 Aggregation
							#flow_index["_source"].update(extended_wlan_aggregation(unpacked_record_data))

						elif record_ent_form_number == [0,1020]: # Slow Packet Data Path
							flow_index["_source"].update(slow_packet_data_path(unpacked_record_data))

						elif record_ent_form_number == [0,1031]: # Extended InfiniBand Local Routing Header
							flow_index["_source"].update(extended_ib_lrh(unpacked_record_data))

						elif record_ent_form_number == [0,1033]: # Extended InfiniBand Base Transport Header
							flow_index["_source"].update(extended_ib_brh(unpacked_record_data))
						
						elif record_ent_form_number == [0,2000]: # Generic Transaction Record
							flow_index["_source"].update(generic_transaction_record(unpacked_record_data))

						elif record_ent_form_number == [0,2001]: # Extended NFS Storage Transaction
							flow_index["_source"].update(ext_nfs_stroage_trans(unpacked_record_data))

						elif record_ent_form_number == [0,2002]: # Extended SCSI Storage Transaction
							flow_index["_source"].update(ext_scsi_stroage_trans(unpacked_record_data))

						elif record_ent_form_number == [0,2003]: # Extended Web Transaction
							flow_index["_source"].update(extended_web_trans(unpacked_record_data))
						
						elif record_ent_form_number == [0,2100]: # IPv4 Socket
							flow_index["_source"].update(ipv4_socket(unpacked_record_data))

						elif record_ent_form_number == [0,2101]: # IPv6 Socket
							flow_index["_source"].update(ipv6_socket(unpacked_record_data))

						elif record_ent_form_number == [0,2206]: # HTTP Request
							flow_index["_source"].update(http_request(unpacked_record_data))
						
						# 2207 Extended Proxy Request
						
						elif record_ent_form_number == [0,2208]: # Extended Navigation Timing
							flow_index["_source"].update(extended_nav_timing(unpacked_record_data))
						
						elif record_ent_form_number == [0,2209]: # Extended TCP Information
							flow_index["_source"].update(extended_tcp_info(unpacked_record_data))

						elif record_ent_form_number == [4413, 1]: # Broadcom selected egress queue
							flow_index["_source"].update(broad_sel_egress_queue(unpacked_record_data))
						
						# Documented pmacct bug https://github.com/pmacct/pmacct/issues/71
						#elif record_ent_form_number == [8800,1]: # Extended Class
							#flow_index["_source"].update(extended_class(unpacked_record_data))
						
						# Documented pmacct bug https://github.com/pmacct/pmacct/issues/71
						#elif record_ent_form_number == [8800,2]: # Extended Tag
							#flow_index["_source"].update(extended_tag(unpacked_record_data))
						
						else: # Something we don't know about - SKIP it
							unpacked_sample_data.set_position(skip_position) # Skip the unknown type
							logging.info("Received unknown flow record type " + str(record_ent_form_number) + " from " + str(datagram_info["Agent IP"]) + " (sub agent " + str(datagram_info["Sub Agent"]) + ") - SKIPPING")
							flow_index = False

					except Exception as flow_unpack_error:
						flow_index = False
						unpacked_sample_data.set_position(skip_position) # Skip the unknown type
						logging.warning(str(flow_unpack_error))
						logging.warning("Failed to unpack Flow record " + str(record_ent_form_number) + " - FAIL")

					# Append the record to sflow_data for bulk upload
					if flow_index is not False:
						logging.debug(str(flow_index))
						sflow_data.append(flow_index)
						
					flow_index = {} # Reset the flow_index
					
					record_num += 1 # Increment the record counter
				### Flow Records End ###
			### Flow Sample End ###
			
			### Counter Sample ###
			elif enterprise_format_num in [[0,2], [0,4]]: # Counter Sample
				
				# Iterate through the counter records
				for record_counter_num in range(0,flow_sample_cache["Record Count"]):
					record_ent_form_number = enterprise_format_numbers(unpacked_sample_data.unpack_uint()) # [Enterprise, Format] numbers
					counter_data_length = int(unpacked_sample_data.unpack_uint()) # Length of record
					current_position = int(unpacked_sample_data.get_position()) # Current unpack buffer position
					skip_position = current_position + counter_data_length # Bail out position if unpack fails for skipping
					
					logging.info("Found counter record " + str(record_counter_num+1) + " of " + str(flow_sample_cache["Record Count"]) + ", type " + str(record_ent_form_number) + ", length " + str(counter_data_length) + ", XDR current position " + str(current_position) + ", skip position " + str(skip_position))
					
					# Unpack the opaque counter record
					unpacked_record_data = Unpacker(unpacked_sample_data.unpack_fopaque(counter_data_length)) 

					# Parse the counter record
					try:
						now = datetime.datetime.utcnow() # Get the current UTC time
						
						flow_index = {
						"_index": str("sflow-" + now.strftime("%Y-%m-%d")),
						"_type": "Counter",
						"_source": {
						"Flow Type": "sFlow Counter",
						"Sensor": datagram_info["Agent IP"],
						"Sub Agent": datagram_info["Sub Agent"],
						"Enterprise, Format": record_ent_form_number,
						"Data Length": counter_data_length,
						"Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z",
						}
						}
						
						flow_index["_source"].update(flow_sample_cache) # Add sample header info to each record

						if record_ent_form_number == [0, 1]: # Generic interface counter
							flow_index["_source"].update(gen_int_counter(unpacked_record_data))

						elif record_ent_form_number == [0, 2]: # Ethernet interface counter
							flow_index["_source"].update(eth_int_counter(unpacked_record_data))

						elif record_ent_form_number == [0, 3]: # Token ring interface counter
							flow_index["_source"].update(token_ring_counter(unpacked_record_data))

						elif record_ent_form_number == [0, 4]: # BaseVG interface counter
							flow_index["_source"].update(basevg_int_counter(unpacked_record_data))

						elif record_ent_form_number == [0, 5]: # VLAN Counters
							flow_index["_source"].update(vlan_counter(unpacked_record_data))

						elif record_ent_form_number == [0, 6]: # 802.11 Counters
							flow_index["_source"].update(wlan_counters(unpacked_record_data))

						elif record_ent_form_number == [0, 7]: # 802.3ad LAG Port Statistics
							flow_index["_source"].update(lag_port_stats(unpacked_record_data))

						elif record_ent_form_number == [0, 8]: # Slow Path Counts
							flow_index["_source"].update(slow_path_stats(unpacked_record_data))

						elif record_ent_form_number == [0, 9]: # InfiniBand Counters
							flow_index["_source"].update(infiniband_counters(unpacked_record_data))

						elif record_ent_form_number == [0, 10]: # SFP Optical Interface Counters
							flow_index["_source"].update(sfp_optical_counters(unpacked_record_data))

						elif record_ent_form_number == [0, 1001]: # Processor info
							flow_index["_source"].update(proc_info(unpacked_record_data))

						elif record_ent_form_number == [0, 1002]: # 802.11 Radio Utilization
							flow_index["_source"].update(radio_util(unpacked_record_data))

						elif record_ent_form_number == [0, 1003]: # Queue Length Histogram Counters
							flow_index["_source"].update(queue_len_histogram_counters(unpacked_record_data))

						elif record_ent_form_number == [0, 2000]: # Host Description
							flow_index["_source"].update(host_description(unpacked_record_data))

						elif record_ent_form_number == [0, 2001]: # Host Adapter
							mac_cache = host_adapter(unpacked_record_data,datagram_info["Agent IP"],datagram_info["Sub Agent"])
							uuid_cache.update(mac_cache)
							logging.info("Updated MAC cache: " + str(mac_cache))
							flow_index = False

						elif record_ent_form_number == [0, 2002]: # Host Parent
							flow_index["_source"].update(host_parent(unpacked_record_data))

						elif record_ent_form_number == [0, 2003]: # Physical Host CPU
							flow_index["_source"].update(physical_host_cpu(unpacked_record_data))

						elif record_ent_form_number == [0, 2004]: # Physical Host Memory
							flow_index["_source"].update(physical_host_memory(unpacked_record_data))

						elif record_ent_form_number == [0, 2005]: # Physical Host Disk I/O
							flow_index["_source"].update(physical_host_diskio(unpacked_record_data))

						elif record_ent_form_number == [0, 2006]: # Physical Host Network I/O
							flow_index["_source"].update(physical_host_netio(unpacked_record_data))

						elif record_ent_form_number == [0, 2007]: # MIB2 IP Group
							flow_index["_source"].update(mib2_ip_group(unpacked_record_data))

						elif record_ent_form_number == [0, 2008]: # MIB2 ICMP Group
							flow_index["_source"].update(mib2_icmp_group(unpacked_record_data))

						elif record_ent_form_number == [0, 2009]: # MIB2 TCP Group
							flow_index["_source"].update(mib2_tcp_group(unpacked_record_data))

						elif record_ent_form_number == [0, 2010]: # MIB2 UDP Group
							flow_index["_source"].update(mib2_udp_group(unpacked_record_data))

						elif record_ent_form_number == [0, 2100]: # Virtual Node Statistics
							flow_index["_source"].update(virtual_node_stats(unpacked_record_data))

						elif record_ent_form_number == [0, 2101]: # Virtual Node CPU Statistics
							flow_index["_source"].update(virtual_domain_cpu_stats(unpacked_record_data))

						elif record_ent_form_number == [0, 2102]: # Virtual Node Memory Statistics
							flow_index["_source"].update(virtual_domain_mem_stats(unpacked_record_data))

						elif record_ent_form_number == [0, 2103]: # Virtual Node Disk Statistics
							flow_index["_source"].update(virtual_domain_disk_stats(unpacked_record_data))

						elif record_ent_form_number == [0, 2104]: # Virtual Node Network Statistics
							flow_index["_source"].update(virtual_domain_net_stats(unpacked_record_data))

						elif record_ent_form_number == [0, 2105]: # JVM Runtime Attributes 
							flow_index["_source"].update(jvm_runtime_attr(unpacked_record_data))

						elif record_ent_form_number == [0, 2106]: # JVM Statistics 
							flow_index["_source"].update(jvm_stats(unpacked_record_data))

						elif record_ent_form_number == [0, 3000]: # Energy Consumption Statistics 
							flow_index["_source"].update(energy_consumption(unpacked_record_data))

						elif record_ent_form_number == [0, 3001]: # Temperature Statistics 
							flow_index["_source"].update(temperature_counter(unpacked_record_data))

						elif record_ent_form_number == [0, 3002]: # Humidity Statistics 
							flow_index["_source"].update(humidity_counter(unpacked_record_data))

						elif record_ent_form_number == [0, 3003]: # Cooling (Fan) Statistics 
							flow_index["_source"].update(cooling_counter(unpacked_record_data))
							
						elif record_ent_form_number == [4413, 1]: # Broadcom Switch Device Buffer Utilization
							flow_index["_source"].update(broad_switch_dev_buffer_util(unpacked_record_data))

						elif record_ent_form_number == [4413, 2]: # Broadcom Switch Port Level Buffer Utilization
							flow_index["_source"].update(broad_switch_port_buff_util(unpacked_record_data))
						
						elif record_ent_form_number == [4413, 3]: # Broadcom Switch ASIC Hardware Table Utilization
							flow_index["_source"].update(asic_hardware_tab_util(unpacked_record_data))

						elif record_ent_form_number == [5703, 1]: # NVIDIA GPU Statistics
							flow_index["_source"].update(nvidia_gpu_stats(unpacked_record_data))

						else:
							unpacked_sample_data.set_position(skip_position) # Skip the unknown type
							logging.info("Received unknown counter record type " + str(record_ent_form_number) + " from " + str(datagram_info["Agent IP"]) + " (sub agent " + str(datagram_info["Sub Agent"]) + ") - SKIPPING")
							flow_index = False

					except Exception as flow_unpack_error:
						flow_index = False
						unpacked_sample_data.set_position(skip_position) # Skip it
						logging.warning(str(flow_unpack_error))
						logging.warning("Failed to unpack Counter record " + str(record_ent_form_number) + " - FAIL")

					# Append the record to sflow_data for bulk upload
					if flow_index is not False:
						logging.debug(str(flow_index))
						sflow_data.append(flow_index)
					
					flow_index = {} # Reset the flow_index

					record_num += 1 # Increment the record counter
				
				### Counter Records End ###
			
			### Counter Sample End ###
			
			### Something else ###
			else:
				logging.warning("Unknown [Enterprise, Format] " + str(enterprise_format_num) + " not defined in sFlow standard - FAIL")		
		
		### Sample Parsing Finish ###

		# Verify XDR data has been completely unpacked	
		try:
			unpacked_data.done()
		except Exception as unpack_done_error:
			logging.warning(str(unpack_done_error))
			logging.warning("Failed to completely unpack sample data - FAIL")
		
		### sFlow Samples End ###

		# Elasticsearch bulk upload
		if record_num >= bulk_insert_count:

			# Perform the bulk upload to the index
			try:
				helpers.bulk(es,sflow_data) # Call Elasticsearch bulk upload API
				logging.info(str(record_num) + " record(s) uploaded to Elasticsearch - OK")
			
			except ValueError as bulk_index_error:
				logging.critical(bulk_index_error)
				logging.critical(str(record_num) + " record(s) DROPPED, unable to index flows - FAIL")
			
			sflow_data = [] # Reset sflow_data cache
			record_num = 0 # Reset flow counter