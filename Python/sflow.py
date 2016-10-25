# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Import what we need
import time, datetime, socket, struct, sys, os, json, socket, collections, itertools, logging, logging.handlers
from struct import *
from socket import inet_ntoa,inet_ntop
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from IPy import IP
from xdrlib import Unpacker

# Flow Options
from netflow_options import *

from flow_samples import *

# Set the logging level per https://docs.python.org/2/library/logging.html#levels
# Levels include DEBUG, INFO, WARNING, ERROR, CRITICAL (case matters)
logging.basicConfig(level=logging.DEBUG)

# Set up socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', 6343))
	logging.warning('Bound to UDP port ' + str(6343) + ' - OK')
except ValueError as socket_error:
	logging.critical('Could not open or bind a socket on port ' + str(6343))
	logging.critical(str(socket_error))
	sys.exit("Could not open or bind a socket on port " + str(6343))

# Spin up ES instance
try:
	es = Elasticsearch([elasticsearch_host])
	logging.warning("Connected to Elasticsearch at " + str(elasticsearch_host) + ' - OK')
except ValueError as elasticsearch_connect_error:
	logging.critical("Could not connect to Elasticsearch at " + str(elasticsearch_host))
	logging.critical(str(elasticsearch_connect_error))
	sys.exit("Could not connect to Elasticsearch at " + str(elasticsearch_host))

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

# sFlow collector
def sflow_collector():
	
	while True:
		
		# Listen for packets inbound
		sflow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
		logging.debug("Got something from " + sensor_address[0])

		sflow_data = {}

		unpacked_data = Unpacker(sflow_packet_contents) # Unpack XDR datagram
		
		### sFlow Datagram Start ###
		sflow_data["Datagram"] = {}
		sflow_data["Datagram"]["sFlow Version"] = int(unpacked_data.unpack_int()) # sFlow Version

		if sflow_data["Datagram"]["sFlow Version"] != 5:
			logging.warning("Not sFlow v5 - exiting.")
			sys.exit("Only sFlow verson 5 is supported - exiting.")

		sflow_data["Datagram"]["IP Version"] = unpacked_data.unpack_int() # Agent IP version
				
		if sflow_data["Datagram"]["IP Version"] == 1:
			sflow_data["Datagram"]["Agent IP"] = inet_ntoa(unpacked_data.unpack_fstring(4)) # sFlow Agent IP (IPv4)
		else:
			sflow_data["Datagram"]["Agent IP"] = unpacked_data.unpack_fstring(16) # sFlow Agent IP (IPv6)
		
		agent_ip = sflow_data["Datagram"]["Agent IP"] 
		
		sflow_data["Datagram"]["Sub Agent"] = unpacked_data.unpack_int() # Sub Agent ID
		sflow_data["Datagram"]["Datagram Sequence Number"] = int(unpacked_data.unpack_int()) # Datagram Seq. Number
		sflow_data["Datagram"]["Switch Uptime ms"] = int(unpacked_data.unpack_int()) # Switch Uptime (ms)
		datagram_sample_count = int(unpacked_data.unpack_int()) # Samples in datagram

		logging.debug("Datagram: " + str(sflow_data["Datagram"]))
		### sFlow Datagram End ###

		
		### sFlow Samples Start ###	
		sflow_data["Samples"] = {} # Samples overall home

		for sample_num in range(1,datagram_sample_count): # For each sample in the datagram
			logging.debug("Sample #" + str(sample_num))

			sflow_data["Samples"][sample_num] = {} # Per sample

			enterprise_format_num = enterprise_format_numbers(unpacked_data.unpack_int()) # Enterprise number and format
			
			sample_length = int(unpacked_data.unpack_int()) # Sample Length
			
			unpacked_sample_data = Unpacker(unpacked_data.unpack_fopaque(sample_length)) # Unpack the sample data block
			
			if enterprise_format_num == [0,1]: # Flow Sample
				logging.debug("Received sample type " + str(enterprise_format_num))
				sflow_data["Samples"][sample_num]["Flow Samples"] = {}
				sflow_data["Samples"][sample_num]["Flow Samples"]["Sequence Number"] = unpacked_sample_data.unpack_uint()
				source_type_index = source_type_index_parser(unpacked_sample_data.unpack_uint())
				sflow_data["Samples"][sample_num]["Flow Samples"]["Source Type"] = source_type_index[0]
				sflow_data["Samples"][sample_num]["Flow Samples"]["Source Index"] = source_type_index[1]
				sflow_data["Samples"][sample_num]["Flow Samples"]["Sampling Rate"] = unpacked_sample_data.unpack_uint()
				sflow_data["Samples"][sample_num]["Flow Samples"]["Sample Pool"] = unpacked_sample_data.unpack_uint()
				sflow_data["Samples"][sample_num]["Flow Samples"]["Drops"] = unpacked_sample_data.unpack_uint()
				sflow_data["Samples"][sample_num]["Flow Samples"]["Input SNMP Index"] = unpacked_sample_data.unpack_uint()
				sflow_data["Samples"][sample_num]["Flow Samples"]["Output SNMP Index"] = unpacked_sample_data.unpack_uint()
				sflow_data["Samples"][sample_num]["Flow Samples"]["Flow Records"] = unpacked_sample_data.unpack_uint()

				logging.debug("Flow sample: " + str(sflow_data["Samples"][sample_num]["Flow Samples"]))

				for flow_sample_data_num in range(1,sflow_data["Samples"][sample_num]["Flow Samples"]["Flow Records"]): # For each staged sample
					logging.debug("Flow sample #" + str(flow_sample_data_num))

					sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = {}

					flow_format = enterprise_format_numbers(unpacked_sample_data.unpack_uint()) # [Enterprise, Format] numbers
					logging.debug("Found flow record type " + str(flow_format))

					sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num]["Enterprise, Format Numbers"] = flow_format # [Enterprise, Format] numbers
										
					flow_data_length = int(unpacked_sample_data.unpack_uint())
					sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num]["Flow Data Length"] = flow_data_length

					current_position = unpacked_sample_data.get_position() # Current unpack buffer position
					skip_position = current_position + flow_data_length # Bail out position if unpack fails for skipping
					
					unpacked_flow_record_data = Unpacker(unpacked_sample_data.unpack_fopaque(flow_data_length))

					if flow_format == [0,1]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = raw_packet_header(unpacked_flow_record_data)
					
					elif flow_format == [0,2]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = eth_frame_data(unpacked_flow_record_data)
					
					elif flow_format == [0,3]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = ipv4_data(unpacked_flow_record_data)
					
					elif flow_format == [0,4]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = ipv6_data(unpacked_flow_record_data)
					
					elif flow_format == [0,1001]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_switch_data(unpacked_flow_record_data)
					
					elif flow_format == [0,1002]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_router_data(unpacked_flow_record_data)
					
					elif flow_format == [0,1003]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_gateway_data(unpacked_flow_record_data)
					
					elif flow_format == [0,1004]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_user_data(unpacked_flow_record_data)
					
					elif flow_format == [0,1005]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_url_data(unpacked_flow_record_data)
					
					elif flow_format == [0,1006]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_mpls_data(unpacked_flow_record_data)
					
					elif flow_format == [0,1007]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_nat_data(unpacked_flow_record_data)
					
					elif flow_format == [0,1008]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_mpls_tunnel(unpacked_flow_record_data)
					
					elif flow_format == [0,1009]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_mpls_vc(unpacked_flow_record_data)
					
					elif flow_format == [0,1010]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = exteded_mpls_fec(unpacked_flow_record_data)
					
					elif flow_format == [0,1011]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_mpls_lvp_fec(unpacked_flow_record_data)
					
					elif flow_format == [0,1012]:
						sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num] = extended_vlan_tunnel(unpacked_flow_record_data)
					
					else:
						logging.warning("Received unknown [Enterprise,Format] flow record types: " + str(flow_format) + " - skipping.")
						logging.debug("Current unpack position: " + str(unpacked_sample_data.get_position()))
						unpacked_sample_data.set_position(skip_position)
						logging.debug("Skipped unpack position: " + str(unpacked_sample_data.get_position()))

					logging.debug(sflow_data["Samples"][sample_num]["Flow Samples"][flow_sample_data_num])

			elif enterprise_format_num == [0,2]: # Counter Sample
				logging.debug("Received sample type " + str(enterprise_format_num))
				sflow_data["Samples"][sample_num]["Counter Samples"] = {}
				sflow_data["Samples"][sample_num]["Counter Samples"]["Sequence Number"] = unpacked_sample_data.unpack_uint()
				sflow_data["Samples"][sample_num]["Counter Samples"]["Source ID Type"] = unpacked_sample_data.unpack_uint()
				sflow_data["Samples"][sample_num]["Counter Samples"]["Source ID Index"] = unpacked_sample_data.unpack_uint()
				sflow_data["Samples"][sample_num]["Counter Samples"]["Counter Records"] = unpacked_sample_data.unpack_uint()
				
				logging.debug(sflow_data["Samples"][sample_num]["Counter Samples"])
				
				unpacked_counter_sample_data = Unpacker(unpacked_sample_data.unpack_opaque())
				
				sflow_data["Samples"][sample_num]["Counter Samples"] = {}
				
				for counter_sample_num in range(1,sflow_data["Counter Samples"]["Counter Records"]):
					logging.debug("Counter sample #" + str(counter_sample_num))
					
					sflow_data["Samples"][sample_num]["Counter Samples"][counter_sample_num] = {}

					# Get the enterprise, format numbers
					counter_format = enterprise_format_numbers(int(unpacked_counter_sample_data.unpack_uint()))
					logging.debug("Found counter record type " + str(counter_format))

					counter_data_length = int(unpacked_counter_sample_data.unpack_uint())

					if counter_format == [0, 1]:
						sflow_data["Samples"][sample_num]["Counter Samples"][counter_sample_num] = gen_int_counter(unpacked_counter_sample_data)

					elif counter_format == [0, 2]:
						sflow_data["Samples"][sample_num]["Counter Samples"][counter_sample_num] = eth_int_counter(unpacked_counter_sample_data)

					elif counter_format == [0, 3]:
						sflow_data["Samples"][sample_num]["Counter Samples"][counter_sample_num] = token_ring_counter(unpacked_counter_sample_data)

					elif counter_format == [0, 4]:
						sflow_data["Samples"][sample_num]["Counter Samples"][counter_sample_num] = basevg_int_counter(unpacked_counter_sample_data)

					elif counter_format == [0, 5]:
						sflow_data["Samples"][sample_num]["Counter Samples"][counter_sample_num] = vlan_counter(unpacked_counter_sample_data)

					elif counter_format == [0, 1001]:
						sflow_data["Samples"][sample_num]["Counter Samples"][counter_sample_num] = proc_info(unpacked_counter_sample_data)
					
					else:
						logging.warning("Received unknown [Enterprise,Format] counter record types: " + str(counter_format))
						sys.exit()

			elif enterprise_format_num == [0,3]: # Expanded Flow Sample
				logging.debug("Received sample type " + str(enterprise_format_num))
				return

			elif enterprise_format_num == [0,4]: # Expanded Counter Sample
				logging.debug("Received sample type " + str(enterprise_format_num))
				return

			else:
				logging.warning("Oops - Received [Enterprise, Format] " + str(enterprise_format_num) + " - exiting.")
				sys.exit("Unknown enterprise and format number - exiting.")
		
		#try:
			#unpacked_data.done()
		#except:
			#sys.exit("Didn't complete unpacking sample data - exiting.")
		
		### sFlow Samples End ###
		
		print(json.dumps(sflow_data, indent=4, sort_keys=True))

	# End of sflow_collector()	
	return

# Start sFlow collector
sflow_collector()