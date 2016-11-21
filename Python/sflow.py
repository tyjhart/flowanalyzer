# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Import what we need
import time, datetime, socket, struct, sys, os, json, socket, collections, itertools, logging, logging.handlers, getopt
from struct import *
from socket import inet_ntoa#,inet_ntop
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from IPy import IP
from xdrlib import Unpacker

from netflow_options import * # Flow Options

# DNS Resolution
import dns_base
import dns_ops

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
	log_level="INFO" # Use default logging level

logging.basicConfig(level=str(log_level)) # Set the logging level
logging.warning('Log level set to ' + str(log_level) + " - OK") # Show the logging level for debug

# Initialize the DNS global reverse lookup cache
dns_base.init()
logging.warning("Initialized the DNS reverse lookup cache - OK")

if dns is False:
	logging.warning("DNS reverse lookups disabled - DISABLED")
else:
	logging.warning("DNS reverse lookups enabled - OK")

if lookup_internal is False:
	logging.warning("DNS local IP reverse lookups disabled - DISABLED")
else:
	logging.warning("DNS local IP reverse lookups enabled - OK")

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

# Spin up ES instance
try:
	es = Elasticsearch([elasticsearch_host])
	logging.warning("Connected to Elasticsearch at " + str(elasticsearch_host) + ' - OK')
except ValueError as elasticsearch_connect_error:
	logging.critical("Could not connect to Elasticsearch at " + str(elasticsearch_host))
	logging.critical(str(elasticsearch_connect_error))
	sys.exit("Could not connect to Elasticsearch at " + str(elasticsearch_host))

# sFlow collector
if __name__ == "__main__":
	from sflow.counter_records import * # Functions to parse headers and format numbers
	from sflow.flow_records import * # Functions to parse headers and format numbers
	from sflow.sflow_parsers import * # Functions to parse headers and format numbers
	from sflow.sflow_samples import * # Functions to parse headers and format numbers
	
	global sflow_data
	sflow_data = [] # For bulk upload to Elasticsearch
	
	while True: 
		
		# Listen for packets inbound
		sflow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
		logging.debug("Got something from " + sensor_address[0])

		record_num = 0 # Record index number for the record cache

		### sFlow Datagram Start ###
		try:
			logging.info("Starting to unpack an sFlow datagram from " + str(sensor_address[0]))
			
			unpacked_data = Unpacker(sflow_packet_contents) # Unpack XDR datagram
			datagram_info = datagram_parse(unpacked_data) # Unpack the datagram
			
			logging.debug(str(datagram_info))
			logging.info("Finished unpacking the sFlow datagram from " + str(sensor_address[0]) + " - OK")
		
		except Exception as datagram_unpack_error:
			logging.warning("Unable to unpack the datagram - FAIL")
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

			logging.info("Unpacking opaque sample data")
			try:
				unpacked_sample_data = Unpacker(unpacked_data.unpack_fopaque(sample_length)) # Unpack the sample data block	
				logging.info("Unpacked opaque sample data chunk - OK")
			except Exception as unpack_error:
				logging.warning("Failed to unpack the opaque sample data - FAIL")
				continue
			### Sample Header Finish ###

			### Sample Parsing Start ###
			flow_sample_cache = sample_picker(enterprise_format_num,unpacked_sample_data) # Get the opaque flow sample cache
			
			if flow_sample_cache is False:
				logging.warning("Unable to parse the sample cache, type " + str([enterprise_format_num,unpacked_sample_data]) + " from " + str(datagram_info["Agent IP"]) + " - SKIPPING")
				continue

			logging.info("Sample header: " + str(flow_sample_cache))
			
			### Flow Sample ###
			if enterprise_format_num in [[0,1], [0,3]]: # Flow Sample

				for record_counter_num in range(0,flow_sample_cache["Record Count"]): # For each staged sample
					logging.info("Unpacking flow record " + str(record_counter_num+1) + " of " + str(flow_sample_cache["Record Count"]))
					
					record_ent_form_number = enterprise_format_numbers(unpacked_sample_data.unpack_uint()) # [Enterprise, Format] numbers
					counter_data_length = int(unpacked_sample_data.unpack_uint()) # Length of record
					logging.info("Found record type " + str(record_ent_form_number) + ", length " + str(counter_data_length))
					
					current_position = int(unpacked_sample_data.get_position()) # Current unpack buffer position
					skip_position = current_position + counter_data_length # Bail out position if unpack fails for skipping
					
					logging.info("XDR current position " + str(current_position) + ", skip position " + str(skip_position))
					
					# Unpack the opaque flow record
					unpacked_record_data = Unpacker(unpacked_sample_data.unpack_fopaque(counter_data_length))
					
					# Parse the flow record
					try:
						now = datetime.datetime.utcnow() # Get the current UTC time
						
						flow_index = {
						"_index": str("flow-" + now.strftime("%Y-%m-%d")),
						"_type": "Flow",
						"_source": {
						"Flow Type": "sFlow Flow",
						"Sensor": datagram_info["Agent IP"],
						#"Sequence": packet_attributes["sequence_number"],
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

						elif record_ent_form_number == [0,2100]: # IPv4 Socket
							flow_index["_source"].update(ipv4_socket(unpacked_record_data))

						elif record_ent_form_number == [0,2101]: # IPv6 Socket
							flow_index["_source"].update(ipv6_socket(unpacked_record_data))

						elif record_ent_form_number == [0,2209]: # Extended TCP Information
							flow_index["_source"].update(extended_tcp_info(unpacked_record_data))
						
						else: # Something we don't know about - SKIP it
							unpacked_sample_data.set_position(skip_position) # Skip the unknown type
							logging.warning("Received unknown [Enterprise,Format] flow record types: " + str(record_ent_form_number) + " - SKIPPING")

					except Exception as flow_unpack_error:
						flow_index = False
						unpacked_sample_data.set_position(skip_position) # Skip the unknown type
						logging.warning(str(flow_unpack_error))
						logging.warning("Failed to unpack flow [Enterprise,Format]: " + str(record_ent_form_number) + " - FAIL")

					# Append the record to sflow_data for bulk upload
					if flow_index is not False:
						logging.debug(str(flow_index))
						sflow_data.append(flow_index)
						
					flow_index = {} # Reset the flow_index
					
					record_num += 1 # Increment the record counter

			### Counter Sample ###
			elif enterprise_format_num in [[0,2], [0,4]]: # Counter Sample
				
				for record_counter_num in range(0,flow_sample_cache["Record Count"]):
					logging.info("Unpacking counter sample " + str(record_counter_num+1) + " of " + str(flow_sample_cache["Record Count"]))
					
					record_ent_form_number = enterprise_format_numbers(unpacked_sample_data.unpack_uint()) # [Enterprise, Format] numbers
					counter_data_length = int(unpacked_sample_data.unpack_uint()) # Length of record
					logging.info("Found record type " + str(record_ent_form_number) + ", length " + str(counter_data_length))
										
					current_position = int(unpacked_sample_data.get_position()) # Current unpack buffer position
					skip_position = current_position + counter_data_length # Bail out position if unpack fails for skipping
					
					logging.info("XDR current position " + str(current_position) + ", skip position " + str(skip_position))
					
					# Unpack the opaque counter record
					unpacked_record_data = Unpacker(unpacked_sample_data.unpack_fopaque(counter_data_length)) 

					# Parse the counter record
					try:
						now = datetime.datetime.utcnow() # Get the current UTC time
						
						flow_index = {
						"_index": str("flow-" + now.strftime("%Y-%m-%d")),
						"_type": "Counter",
						"_source": {
						"Flow Type": "sFlow Counter",
						"Sensor": datagram_info["Agent IP"],
						#"Sequence": packet_attributes["sequence_number"],
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

						elif record_ent_form_number == [0, 5]: # VLAN counter
							flow_index["_source"].update(vlan_counter(unpacked_record_data))

						elif record_ent_form_number == [0, 1001]: # Processor info
							flow_index["_source"].update(proc_info(unpacked_record_data))

						elif record_ent_form_number == [0, 2000]: # Host Description
							flow_index["_source"].update(host_description(unpacked_record_data))

						elif record_ent_form_number == [0, 2001]: # Host Adapter
							flow_index["_source"].update(host_adapter(unpacked_record_data))

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

						else:
							unpacked_sample_data.set_position(skip_position) # Skip the unknown type
							logging.warning("Received unknown [Enterprise,Format] counter record types: " + str(record_ent_form_number) + " - SKIPPING")

					except Exception as flow_unpack_error:
						flow_index = False
						unpacked_sample_data.set_position(skip_position) # Skip the unknown type
						logging.warning(str(flow_unpack_error))
						logging.warning("Failed to unpack flow [Enterprise,Format]: " + str(record_ent_form_number) + " - FAIL")

					# Append the record to sflow_data for bulk upload
					if flow_index is not False:
						logging.debug(str(flow_index))
						sflow_data.append(flow_index)
					
					flow_index = {} # Reset the flow_index

					record_num += 1 # Increment the record counter

			### Something else ###
			else:
				logging.warning("Oops - Unknown [Enterprise, Format] " + str(enterprise_format_num) + " - exiting.")
				sys.exit("Unknown enterprise and format number - exiting.")
			### Sample Parsing Finish ###

		# Verify all data has been unpacked	
		try:
			unpacked_data.done()
		except:
			logging.warning("Failed to completely unpack sample data - FAIL")
		
		### sFlow Samples End ###

		# Have enough flows to do a bulk index to Elasticsearch
		if len(sflow_data) >= bulk_insert_count:
							
			# Perform the bulk upload to the index
			try:
				helpers.bulk(es,flow_dic)
				logging.info(str(len(flow_dic)) + " flow(s) uploaded to Elasticsearch - OK")
			except ValueError as bulk_index_error:
				logging.critical(str(len(flow_dic)) + " flow(s) DROPPED, unable to index flows - FAIL")
				logging.critical(bulk_index_error)
				sys.exit()
				
			# Reset sflow_data
			sflow_data = []