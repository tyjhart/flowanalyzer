# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

### Imports ###
import time, datetime, socket, struct, sys, json, socket, collections, itertools, logging, logging.handlers, getopt
from struct import *

# Windows socket.inet_ntop support via win_inet_pton
try:
	import win_inet_pton
except ImportError:
	pass

from socket import inet_ntoa,inet_ntop
from elasticsearch import Elasticsearch,helpers
from IPy import IP

# Parsing functions
from parser_modules import mac_address, icmp_parse, ip_parse, netflowv9_parse, int_parse, ports_and_protocols, name_lookups

# Field types, ports, etc
from field_types import ipfix_fields
from netflow_options import *
from protocol_numbers import *

### Get command line arguments ###
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

except Exception as argument_error:
	sys.exit("Unsupported or badly formed options, see -h for available arguments - EXITING")

### Logging level ###
# Set the logging level per https://docs.python.org/2/howto/logging.html
try: 
	log_level # Check if log level was passed in from command arguments
except NameError:
	log_level="WARNING" # Use default logging level

logging.basicConfig(level=str(log_level)) # Set the logging level
logging.critical('Log level set to ' + str(log_level) + " - OK") # Show the logging level for debug

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

### IPFIX port ###
try:
	ipfix_port
except NameError: # Not specified, use default
	ipfix_port = 4739
	logging.warning("IPFIX port not set in netflow_options.py, defaulting to " + str(ipfix_port) + " - OK")

### Socket listener ###
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', ipfix_port))
	logging.warning("Bound to port " + str(ipfix_port) + " - OK")
except ValueError as socket_error:
	logging.critical("Could not open or bind a socket on port " + str(ipfix_port))
	logging.critical(str(socket_error))
	sys.exit()

### Elasticsearch instance ###
es = Elasticsearch([elasticsearch_host])

# IPFIX server
if __name__ == "__main__":
	
	flow_dic = [] # Stage the flows for the bulk API index operation
	
	template_list = {} # Cache the IPFIX templates, in orderedDict to decode the data flows

	record_num = 0 # Record counter for Elasticsearch bulk upload API
	
	# Classes for parsing fields
	icmp_parser = icmp_parse() # Class for parsing ICMP Types and Codes
	ip_parser = ip_parse() # Class for unpacking IPv4 and IPv6 addresses
	mac = mac_address() # Class for parsing MAC addresses and OUIs
	int_un = int_parse() # Class for parsing integers
	ports_protocols_parser = ports_and_protocols() # Class for parsing ports and protocols
	name_lookups = name_lookups() # Class for DNS lookups
	
	while True: # Continually collect packets
		
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565) # Listen for packets inbound
		
		### Unpack the flow packet header ###
		try:
			packet_attributes = {} # Flow header attributes cache	
			
			(
			packet_attributes["netflow_version"], 
			packet_attributes["ipfix_flow_bytes"],
			packet_attributes["export_time"],
			packet_attributes["sequence_number"],
			packet_attributes["observation_id"]
			) = struct.unpack('!HHLLL',flow_packet_contents[0:16]) # Unpack header

			packet_attributes["sensor"] = sensor_address[0] # For debug purposes

			logging.info("Unpacking header: " + str(packet_attributes))
		
		# Error unpacking the header
		except Exception as flow_header_error:
			logging.warning("Failed unpacking flow header from " + str(sensor_address[0]) + " - FAIL")
			logging.warning(flow_header_error)
			continue
		
		### Check IPFIX version ###
		if int(packet_attributes["netflow_version"]) != 10:
			logging.warning("Received a non-IPFIX packet from " + str(sensor_address[0]) + " - DROPPING")
			continue
			
		byte_position = 16 # Position after the standard protocol header
		
		### Iterate through total flows in the packet ###
		#
		# Can be any combination of templates and data flows, any lengths
		while True: 
			
			### Unpack the flow set ID and the length ###
			#
			# Determine if it's a template set or a data set and the size
			try:
				logging.info("Unpacking ID and length at byte position " + str(byte_position))
				(flow_set_id, flow_set_length) = struct.unpack('!HH',flow_packet_contents[byte_position:byte_position+4])
				logging.info("Flow ID, Length " + str((flow_set_id, flow_set_length)))
			except Exception as id_unpack_error:
				logging.info("Out of bytes to unpack, breaking")
				break # Done with the packet
			
			# Advance past the initial header of ID and length
			byte_position += 4 
			
			### Parse sets based on Set ID ###
			# ID 0 and 1 are not used
			# ID 2 is a Template
			# ID 3 is an Options Template
			# IDs > 255 are flow data
			
			# IPFIX template set (ID 2)
			if flow_set_id == 2:
				template_position = byte_position
				final_template_position = (byte_position + flow_set_length)-4

				# Cache for the following templates
				template_cache = {}

				while template_position < final_template_position:
					logging.info("Unpacking template set at " + str(template_position))
					(template_id, template_id_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
					logging.info("Found (ID, Elements) -- " + str((template_id, template_id_length)))
					
					template_position += 4 # Advance

					# Template for flow data set
					if template_id > 255:
											
						# Produce unique hash to identify unique template ID and sensor
						hashed_id = hash(str(sensor_address[0])+str(template_id)) 
						
						# Cache to upload to template store
						template_cache[hashed_id] = {}
						template_cache[hashed_id]["Sensor"] = str(sensor_address[0])
						template_cache[hashed_id]["Template ID"] = template_id
						template_cache[hashed_id]["Length"] = template_id_length
						template_cache[hashed_id]["Definitions"] = collections.OrderedDict() # ORDER MATTERS
						
						# Iterate through template lines
						for _ in range(0,template_id_length):

							# Unpack template element number and length
							(template_element, template_element_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
							
							# Cache each Element and its Length
							template_cache[hashed_id]["Definitions"][template_element] = template_element_length 
							
							# Advance
							template_position += 4 
					
					template_list.update(template_cache) # Add template to the template cache	
					logging.debug(str(template_list))
					logging.info("Template " + str(template_id) + " parsed successfully")
				
				logging.info("Finished parsing templates at byte " + str(template_position) + " of " + str(final_template_position))
				
				byte_position = (flow_set_length + byte_position)-4 # Advance to the end of the flow
				
			# IPFIX options template set (ID 3)
			elif flow_set_id == 3:
				logging.info("Unpacking Options Template set at " + str(byte_position))
				logging.warning("Received IPFIX Options Template, not currently supported - SKIPPING")
				byte_position = (flow_set_length + byte_position)-4
				logging.info("Finished Options Template set at " + str(byte_position))
				break # Code to parse the Options Template will go here eventually

			# Received an IPFIX flow data set, corresponding with a template
			elif flow_set_id > 255:
				
				# Compute the template hash ID
				hashed_id = hash(str(sensor_address[0])+str(flow_set_id))
				
				# Check if there is a template
				if hashed_id in template_list.keys():

					logging.info("Parsing data flow " + str(flow_set_id) + " at byte " + str(byte_position))
					
					now = datetime.datetime.utcnow() # Get the current UTC time for the flows
					data_position = byte_position # Temporary counter
					
					# Iterate through flow bytes until we run out
					while data_position+4 <= (flow_set_length + (byte_position-4)):						
						
						logging.info("Parsing flow " + str(flow_set_id) + " at " + str(data_position) + ", sequence " + str(packet_attributes["sequence_number"]))

						# Cache the flow data, to be appended to flow_dic[]						
						flow_index = {
						"_index": str("flow-" + now.strftime("%Y-%m-%d")),
						"_type": "Flow",
						"_source": {
						"Flow Type": "IPFIX",
						"Sensor": sensor_address[0],
						"Sequence": str(packet_attributes["sequence_number"]),
						"Observation Domain": str(packet_attributes["observation_id"]),
						"Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z",
						}
						}

						# Iterate through template elements
						for template_key, field_size in template_list[hashed_id]["Definitions"].iteritems():
							
							# IPv4 Address
							if ipfix_fields[template_key]["Type"] == "IPv4":
								flow_payload = ip_parser.parse_ipv4(flow_packet_contents,data_position,field_size)
								flow_index["_source"]["IP Protocol Version"] = 4
								
							# IPv6 Address
							elif ipfix_fields[template_key]["Type"] == "IPv6":
								flow_payload = ip_parser.parse_ipv6(flow_packet_contents,data_position,field_size)
								flow_index["_source"]["IP Protocol Version"] = 6	
							
							# Integer type field, parse further
							elif ipfix_fields[template_key]["Type"] == "Integer":
								
								# Unpack the integer
								flow_payload = int_un.integer_unpack(flow_packet_contents,data_position,field_size)
								
								# IANA protocol number
								if template_key == 4:
									flow_index["_source"]['Protocol Number'] = flow_payload
								
								# Do the special calculations for ICMP Code and Type (% operator)
								elif template_key in [32,139]:
									flow_index["_source"]['ICMP Type'] = int(flow_payload)//256
									flow_index["_source"]['ICMP Code'] = int(flow_payload)%256

								# Not a specially parsed integer field, just ignore and log the payload
								else:
									pass
									
								# Apply friendly Options name if available
								if "Options" in ipfix_fields[template_key]:	
									flow_index["_source"][ipfix_fields[template_key]["Index ID"]] = ipfix_fields[template_key]['Options'][int(flow_payload)]
									
									# Advance the position for the field
									data_position += field_size
									continue # Skip the rest, it's fully parsed			
								
								# No "Options" specified for this field type
								else:
									pass
									
							# MAC Address
							elif ipfix_fields[template_key]["Type"] == "MAC":
								
								# Parse MAC
								parsed_mac = mac.mac_packed_parse(flow_packet_contents,data_position,field_size)
								flow_payload = parsed_mac[0] # Parsed MAC address
							
							# Check if we've been passed a "Vendor Proprietary" field, and if so log it and skip it
							elif ipfix_fields[template_key]["Type"] == "Vendor Proprietary":
								logging.info(
								"Received vendor proprietary field, " + 
								str(template_key) + 
								", in " + 
								str(flow_set_id) + 
								" from " + 
								str(sensor_address[0])
								)
							
							# Something we haven't accounted for yet						
							else:
								try:
									flow_payload = struct.unpack('!%dc' % field_size,flow_packet_contents[data_position:(data_position+field_size)])
								except Exception as unpack_error:
									logging.debug(
									"Error unpacking generic field number " + 
									str(ipfix_fields[field_definition]) + 
									", error messages: " + 
									str(unpack_error)
									)
							
							# Add the friendly Index ID and value (flow_payload) to flow_index
							flow_index["_source"][ipfix_fields[int(template_key)]["Index ID"]] = flow_payload
							
							# Move the byte position the number of bytes we just parsed
							data_position += field_size
						
						### Traffic and Traffic Category tagging ###
						#
						# Transport protocols eg TCP, UDP, etc
						if int(flow_index["_source"]['Protocol Number']) in (6, 17, 33, 132):
							traffic_tags = ports_protocols_parser.port_traffic_classifier(flow_index["_source"]["Source Port"],flow_index["_source"]["Destination Port"])
							flow_index["_source"]["Traffic"] = traffic_tags["Traffic"]
							flow_index["_source"]["Traffic Category"] = traffic_tags["Traffic Category"]
						
						# Non-transport protocols eg OSPF, VRRP, etc
						else:
							try: 
								flow_index["_source"]["Traffic Category"] = ports_protocols_parser.protocol_traffic_category(flow_index["_source"]['Protocol Number'])
							except:
								flow_index["_source"]["Traffic Category"] = "Uncategorized"
						
						### DNS Domain and FQDN tagging ###
						if dns is True:

							# Source DNS
							if "IPv4 Source" in flow_index["_source"]:
								source_lookups = name_lookups.ip_names(4,flow_index["_source"]["IPv4 Source"])
							elif "IPv6 Source" in flow_index["_source"]:
								source_lookups = name_lookups.ip_names(6,flow_index["_source"]["IPv6 Source"])
							
							flow_index["_source"]["Source FQDN"] = source_lookups["FQDN"]
							flow_index["_source"]["Source Domain"] = source_lookups["Domain"]

							# Destination DNS
							if "IPv4 Destination" in flow_index["_source"]:
								destination_lookups = name_lookups.ip_names(4,flow_index["_source"]["IPv4 Destination"])
							elif "IPv6 Destination" in flow_index["_source"]:
								destination_lookups = name_lookups.ip_names(6,flow_index["_source"]["IPv6 Destination"])

							flow_index["_source"]["Destination FQDN"] = destination_lookups["FQDN"]
							flow_index["_source"]["Destination Domain"] = destination_lookups["Domain"]

							# Content
							src_dest_categories = [source_lookups["Content"],destination_lookups["Content"]]
							
							try: # Pick unique domain Content != "Uncategorized"
								unique_content = [category for category in src_dest_categories if category != "Uncategorized"]
								flow_index["_source"]["Content"] = unique_content[0]
							except: # No unique domain Content
								flow_index["_source"]["Content"] = "Uncategorized"
						
						# Append this single flow to the flow_dic[] for bulk upload
						logging.debug(str(flow_index))
						flow_dic.append(flow_index)

						logging.info("Finished sequence " + str(packet_attributes["sequence_number"]) + " at byte " + str(data_position))

						record_num += 1 # Increment record counter
						packet_attributes["sequence_number"] += 1 # Increment sequence number, per IPFIX standard

				# No template, drop the flow per the standard and advanced the byte position
				else:
					byte_position += flow_set_length
					logging.warning(
					"Missing template " + 
					str(flow_set_id) + 
					" from " + 
					str(sensor_address[0]) + 
					", sequence " + 
					str(packet_attributes["sequence_number"]) + 
					" - DROPPING"
					)
					break
				
				byte_position = (flow_set_length + byte_position)-4 # Advance to the end of the flow
				logging.info("Ending data set at " + str(byte_position))
				
			# Received a flow set ID we haven't accounted for
			else:
				logging.warning("Unknown flow ID " + str(flow_set_id) + " from " + str(sensor_address[0]))
				break # Bail out
		
		# Have enough flows to do a bulk index to Elasticsearch
		if record_num >= bulk_insert_count:
			
			# Perform the bulk upload to the index
			try:
				helpers.bulk(es,flow_dic)
				logging.info(str(record_num) + " flow(s) uploaded to Elasticsearch - OK")
			except ValueError as bulk_index_error:
				logging.critical(str(record_num) + " flow(s) DROPPED, unable to index flows - FAIL")
				logging.critical(bulk_index_error)
				
			flow_dic = [] # Reset flow_dic

			record_num = 0 # Reset record counter