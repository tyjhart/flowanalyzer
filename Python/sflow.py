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

from sflow_parsers import * # Functions to parse headers and format numbers
from sflow_samples import * # Functions to parse samples
from sflow_records import * # Functions to parse records in samples

### Get the command line arguments ###
try:
	arguments = getopt.getopt(sys.argv[1:],"hl:",["--help","log="])
	
	for option_set in arguments:
		for opt,arg in option_set:
						
			if opt in ('-l','--log'): # Log level
				arg = arg.upper() # Uppercase for matching and logging.basicConfig() format
				if arg in ["CRITICAL","ERROR","WARNING","INFO","DEBUG"]:
					log_level = arg # Use what was passed in arguments
				
				else:
					log_level = "WARNING" # Default logging level

			elif opt in ('-h','--help'): # Help file
				with open("./help.txt") as help_file:
					print(help_file.read())
				sys.exit()

			else: # No options
				pass

except Exception:
    sys.exit("Unsupported or badly formed options, see -h for available arguments.") 

# Set the logging level per https://docs.python.org/2/howto/logging.html
try: 
	log_level # Check if log level was passed in from command arguments
except NameError:
	log_level="DEBUG" # Use default logging level

logging.basicConfig(level=str(log_level)) # Set the logging level
logging.critical('Log level set to ' + str(log_level) + " - OK") # Show the logging level for debug

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
#try:
	#es = Elasticsearch([elasticsearch_host])
	#logging.warning("Connected to Elasticsearch at " + str(elasticsearch_host) + ' - OK')
#except ValueError as elasticsearch_connect_error:
	#logging.critical("Could not connect to Elasticsearch at " + str(elasticsearch_host))
	#logging.critical(str(elasticsearch_connect_error))
	#sys.exit("Could not connect to Elasticsearch at " + str(elasticsearch_host))

# sFlow collector
def sflow_collector():
	
	while True: 
		
		# Listen for packets inbound
		sflow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
		logging.debug("Got something from " + sensor_address[0])

		sflow_data = {}

		record_num = 0 # Record index number for the record cache
		record_cache = {} # Record cache for bulk upload

		try:
			logging.info("Starting to unpack an sFlow datagram from " + str(sensor_address[0]))
			unpacked_data = Unpacker(sflow_packet_contents) # Unpack XDR datagram
			
			### sFlow Datagram Start ###
			sflow_data["Datagram"] = {}
			sflow_data["Datagram"]["sFlow Version"] = int(unpacked_data.unpack_uint()) # sFlow Version

			if sflow_data["Datagram"]["sFlow Version"] != 5:
				logging.warning("Not an sFlow v5 datagram - SKIPPING")
				continue

			sflow_data["Datagram"]["IP Version"] = unpacked_data.unpack_uint() # Agent IP version
					
			if sflow_data["Datagram"]["IP Version"] == 1:
				sflow_data["Datagram"]["Agent IP"] = inet_ntoa(unpacked_data.unpack_fstring(4)) # sFlow Agent IP (IPv4)
			else:
				sflow_data["Datagram"]["Agent IP"] = unpacked_data.unpack_fstring(16) # sFlow Agent IP (IPv6)
			
			sflow_data["Datagram"]["Sub Agent"] = unpacked_data.unpack_uint() # Sub Agent ID
			sflow_data["Datagram"]["Datagram Sequence Number"] = int(unpacked_data.unpack_uint()) # Datagram Seq. Number
			sflow_data["Datagram"]["Switch Uptime ms"] = int(unpacked_data.unpack_uint()) # Switch Uptime (ms)
			sflow_data["Datagram"]["Sample Count"] = int(unpacked_data.unpack_uint()) # Samples in datagram

			logging.debug(str(sflow_data["Datagram"]))
			logging.info("Finished unpacking the sFlow datagram from " + str(sensor_address[0]) + " - OK")
		
		except Exception as datagram_unpack_error:
			logging.warning("Unable to unpack the datagram - FAIL")
			logging.warning(str(datagram_unpack_error))
			continue
		### sFlow Datagram End ###

		
		### sFlow Samples Start ###			
		for sample_num in range(0,sflow_data["Datagram"]["Sample Count"]): # For each sample in the datagram

			### Sample Header Start ###
			logging.info("Examining sample " + str(sample_num) + " of " + str(sflow_data["Datagram"]["Sample Count"]))
			
			enterprise_format_num = enterprise_format_numbers(unpacked_data.unpack_uint()) # Enterprise number and format
			sample_length = int(unpacked_data.unpack_uint()) # Sample Length		
			logging.info("Found sample type " + str(enterprise_format_num) + " length " + str(sample_length))

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
				logging.warning("Unable to parse the sample cache, type " + str(enterprise_format_num) + " from " + str(sflow_data["Datagram"]["Agent IP"]) + " - SKIPPING")
				continue

			logging.debug("Flow header data: " + str(flow_sample_cache))
			
			if enterprise_format_num in [[0,1], [0,3]]: # Flow Sample

				for record_counter_num in range(0,flow_sample_cache["Record Count"]): # For each staged sample
					
					record_ent_form_number = enterprise_format_numbers(unpacked_sample_data.unpack_uint()) # [Enterprise, Format] numbers
					counter_data_length = int(unpacked_sample_data.unpack_uint()) # Length of record
					logging.info("Found record type " + str(record_ent_form_number) + ", length " + str(counter_data_length))
					
					record_cache[record_num] = {}
					record_cache[record_num]["Sensor"] = sflow_data["Datagram"]["Agent IP"]
					record_cache[record_num]["Sub Agent"] = sflow_data["Datagram"]["Sub Agent"]
					record_cache[record_num]["Enterprise, Format"] = record_ent_form_number # [Enterprise, Format] numbers
					record_cache[record_num]["Data Length"] = counter_data_length # Data length
					
					current_position = int(unpacked_sample_data.get_position()) # Current unpack buffer position
					skip_position = current_position + counter_data_length # Bail out position if unpack fails for skipping
					logging.info("XDR current position " + str(current_position) + ", skip position " + str(skip_position))
					
					logging.info("Unpacking counter record data, number " + str(record_counter_num) + " of " + str(flow_sample_cache["Record Count"]))
					
					unpacked_record_data = Unpacker(unpacked_sample_data.unpack_fopaque(counter_data_length)) # Unpack the opaque record

					if record_ent_form_number == [0,1]: # Raw packet header
						record_cache[record_num]["Record"] = raw_packet_header(unpacked_record_data)
					
					elif record_ent_form_number == [0,2]: # Ethernet frame data
						record_cache[record_num]["Record"] = eth_frame_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,3]: # IPv4 data
						record_cache[record_num]["Record"] = ipv4_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,4]: # IPv6 data
						record_cache[record_num]["Record"] = ipv6_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,1001]: # Extended switch data
						record_cache[record_num]["Record"] = extended_switch_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,1002]: # Extended router data
						record_cache[record_num]["Record"] = extended_router_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,1003]: # Extended gateway data
						record_cache[record_num]["Record"] = extended_gateway_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,1004]: # Extended user data
						record_cache[record_num]["Record"] = extended_user_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,1005]: # Extended URL data
						record_cache[record_num]["Record"] = extended_url_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,1006]: # Extended MPLS data
						record_cache[record_num]["Record"] = extended_mpls_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,1007]: # Extended NAT data
						record_cache[record_num]["Record"] = extended_nat_data(unpacked_record_data)
					
					elif record_ent_form_number == [0,1008]: # Extended MPLS tunnel data
						record_cache[record_num]["Record"] = extended_mpls_tunnel(unpacked_record_data)
					
					elif record_ent_form_number == [0,1009]: # Extended MPLS VC data
						record_cache[record_num]["Record"] = extended_mpls_vc(unpacked_record_data)
					
					elif record_ent_form_number == [0,1010]: # Extended MPLS FEC data
						record_cache[record_num]["Record"] = exteded_mpls_fec(unpacked_record_data)
					
					elif record_ent_form_number == [0,1011]: # Extended MPLS LVP FEC data
						record_cache[record_num]["Record"] = extended_mpls_lvp_fec(unpacked_record_data)
					
					elif record_ent_form_number == [0,1012]: # Extended VLAN tunnel data
						record_cache[record_num]["Record"] = extended_vlan_tunnel(unpacked_record_data)
					
					else: # Something we don't know about - SKIP it
						unpacked_sample_data.set_position(skip_position) # Skip the unknown type
						logging.warning("Received unknown [Enterprise,Format] flow record types: " + str(record_ent_form_number) + " - SKIPPING.")

					logging.debug("Record data: " + str(record_cache[record_num]))
					
					record_num += 1 # Increment the record counter

			### Counter Sample ###
			elif enterprise_format_num in [[0,2], [0,4]]: # Counter Sample
				
				for record_counter_num in range(0,flow_sample_cache["Record Count"]):
					
					record_ent_form_number = enterprise_format_numbers(unpacked_sample_data.unpack_uint()) # [Enterprise, Format] numbers
					counter_data_length = int(unpacked_sample_data.unpack_uint()) # Length of record
					logging.info("Found record type " + str(record_ent_form_number) + ", length " + str(counter_data_length))
					
					record_cache[record_num] = {}
					record_cache[record_num]["Sensor"] = sflow_data["Datagram"]["Agent IP"]
					record_cache[record_num]["Sub Agent"] = sflow_data["Datagram"]["Sub Agent"]
					record_cache[record_num]["Enterprise, Format"] = record_ent_form_number # [Enterprise, Format] numbers
					record_cache[record_num]["Data Length"] = counter_data_length # Data length
					
					current_position = int(unpacked_sample_data.get_position()) # Current unpack buffer position
					skip_position = current_position + counter_data_length # Bail out position if unpack fails for skipping
					logging.info("XDR current position " + str(current_position) + ", skip position " + str(skip_position))
					
					logging.info("Unpacking counter record data, number " + str(record_counter_num) + " of " + str(flow_sample_cache["Record Count"]))
					
					unpacked_record_data = Unpacker(unpacked_sample_data.unpack_fopaque(counter_data_length)) # Unpack the opaque record
					
					if record_ent_form_number == [0, 1]: # Generic interface counter
						record_cache[record_num]["Record"] = gen_int_counter(unpacked_record_data)

					elif record_ent_form_number == [0, 2]: # Ethernet interface counter
						record_cache[record_num]["Record"] = eth_int_counter(unpacked_record_data)

					elif record_ent_form_number == [0, 3]: # Token ring interface counter
						record_cache[record_num]["Record"] = token_ring_counter(unpacked_record_data)

					elif record_ent_form_number == [0, 4]: # BaseVG interface counter
						record_cache[record_num]["Record"] = basevg_int_counter(unpacked_record_data)

					elif record_ent_form_number == [0, 5]: # VLAN counter
						record_cache[record_num]["Record"] = vlan_counter(unpacked_record_data)

					elif record_ent_form_number == [0, 1001]: # Processor info
						record_cache[record_num]["Record"] = proc_info(unpacked_record_data)
					
					else:
						logging.warning("Received unknown [Enterprise,Format] counter record types: " + str(record_ent_form_number) + " - SKIPPING")
						unpacked_sample_data.set_position(skip_position) # Skip the unknown type
						
					logging.debug("Record data: " + str(record_cache[record_num]))

					record_num += 1 # Increment the record counter

			### Something else ###
			else:
				logging.warning("Oops - Received [Enterprise, Format] " + str(enterprise_format_num) + " - exiting.")
				sys.exit("Unknown enterprise and format number - exiting.")
			### Sample Parsing Finish ###

		# Verify all data has been unpacked	
		try:
			unpacked_data.done()
		except:
			logging.warning("Failed to completely unpack sample data - FAIL")
			sys.exit("Failed to completely unpack sample data - FAIL")
		
		### sFlow Samples End ###
		
		print(json.dumps(record_cache, indent=4, sort_keys=True))

	# End of sflow_collector()	
	return

# Start sFlow collector
sflow_collector()