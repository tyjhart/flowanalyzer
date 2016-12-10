# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Import what we need
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

# Field parsing functions
from parser_modules import mac_address,icmp_parse

# Field types, ports, etc
from defined_ports import registered_ports,other_ports
from field_types import ipfix_fields
from netflow_options import *
from protocol_numbers import *

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

except Exception as argument_error:
	logging.exit("Unsupported or badly formed options, see -h for available arguments - EXITING")

# Set the logging level per https://docs.python.org/2/howto/logging.html
try: 
	log_level # Check if log level was passed in from command arguments
except NameError:
	log_level="WARNING" # Use default logging level

logging.basicConfig(level=str(log_level)) # Set the logging level
logging.critical('Log level set to ' + str(log_level) + " - OK") # Show the logging level for debug

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

# Check if the IPFIX port is specified
try:
	ipfix_port
except NameError: # Not specified, use default
	ipfix_port = 4739
	logging.warning("IPFIX port not set in netflow_options.py, defaulting to " + str(ipfix_port) + " - OK")

# Set up socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', ipfix_port))
	logging.warning("Bound to port " + str(ipfix_port) + " - OK")
except ValueError as socket_error:
	logging.critical("Could not open or bind a socket on port " + str(ipfix_port))
	logging.critical(str(socket_error))
	sys.exit()

# Spin up ES instance
es = Elasticsearch([elasticsearch_host])

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

# IPFIX server
if __name__ == "__main__":
	
	flow_dic = [] # Stage the flows for the bulk API index operation
	
	template_list = {} # Cache the IPFIX templates, in order to decode the data flows
	
	# Class for parsing ICMP Types and Codes
	icmp_parser = icmp_parse()

	# Class for parsing MAC addresses and OUIs
	mac = mac_address()
	
	while True: # Continually collect packets
		
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565) # Listen for packets inbound
		
		# Get the Netflow version and flow size, or just continue listening
		try:
			logging.info("Unpacking header from " + str(sensor_address[0])) # Unpack the header
			
			packet_attributes = {} # Flow attributes in the header
			
			(
			packet_attributes["netflow_version"], 
			packet_attributes["ipfix_flow_bytes"],
			packet_attributes["export_time"],
			packet_attributes["sequence_number"],
			packet_attributes["observation_id"]
			) = struct.unpack('!HHLLL',flow_packet_contents[0:16])

			logging.info("Received sequence " + str(packet_attributes["sequence_number"]) + ", observation ID " + str(packet_attributes["observation_id"]) + " from " + str(sensor_address[0]))
			logging.debug(str(packet_attributes))
			logging.info("Finished unpacking header")
		
		# Something went wrong unpacking the header
		except Exception as flow_header_error:
			logging.warning("Failed unpacking flow header from " + str(sensor_address[0]) + " - " + str(flow_header_error))
			continue
				
		if int(packet_attributes["netflow_version"]) == 10: # Check IPFIX version
			
			byte_position = 16 # Position the byte counter after the standard protocol header
			
			# Iterate through the total flows in the packet overall, could be any length
			# Can be any combination of templates and data flows
			while True: 
				
				# Unpack the flow set ID and the length, to determine if it's a template set or a data set, and the size
				try:
					logging.info("Unpacking ID and length at byte position " + str(byte_position))
					(flow_set_id, flow_set_length) = struct.unpack('!HH',flow_packet_contents[byte_position:byte_position+4])
					logging.info("Found ID " + str(flow_set_id) + ", " + str(flow_set_length) + " bytes long (" + str(int(flow_set_length)+16) + " including header)")
				except Exception as id_unpack_error:
					logging.info("Out of bytes to unpack, breaking")
					break # Done with the packet
				
				# Advance past the initial header of ID and length
				byte_position += 4 
				
				# IPFIX template set (ID 2)
				if flow_set_id == 2:
					logging.info("Unpacking template set at " + str(byte_position))
					temp_template_cache = {}
					template_position = byte_position
					while template_position <= flow_set_length:
						(template_id, template_id_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
						if template_id > 255:
							logging.info("Received template " + str(template_id) + ", sequence " + str(packet_attributes["sequence_number"]))
							
							# Produce unique hash to identify unique template ID and sensor
							hashed_id = hash(str(sensor_address[0])+str(template_id)) 
							temp_template_cache[hashed_id] = {}
							temp_template_cache[hashed_id]["Sensor"] = str(sensor_address[0])
							temp_template_cache[hashed_id]["Template ID"] = template_id
							temp_template_cache[hashed_id]["Length"] = template_id_length
							temp_template_cache[hashed_id]["Definitions"] = collections.OrderedDict() # ORDER MATTERS
							for template_line in range(0,template_id_length):
								template_position += 4
								(template_element, template_element_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
								temp_template_cache[hashed_id]["Definitions"][template_element] = template_element_length # Cache each line
						template_position += 4
					template_list.update(temp_template_cache)	
					byte_position = (flow_set_length + byte_position)-4
					logging.info("Finished template set at " + str(byte_position))
					logging.debug("Current cached templates: " + str(template_list)) # Templates cached
					
				# IPFIX options template set (ID 3)
				elif flow_set_id == 3:
					logging.info("Unpacking Options Template set at " + str(byte_position))
					logging.warning("Received IPFIX Options Template, not currently supported - SKIPPING")
					byte_position = (flow_set_length + byte_position)-4
					logging.info("Finished Options Template set at " + str(byte_position))
					break # Code to parse the Options Template will go here eventually

				# Received an IPFIX flow data set, corresponding with a template
				elif flow_set_id > 255:
					logging.info("Parsing data flow " + str(flow_set_id) + " at byte " + str(byte_position))
					
					# Compute the template hash ID
					hashed_id = hash(str(sensor_address[0])+str(flow_set_id))
					
					# Check if there is a template
					if hashed_id in template_list.keys():
						logging.info("Using template hash " + str(hashed_id) + " at byte " + str(byte_position))
						
						# Get the current UTC time for the flows
						now = datetime.datetime.utcnow()
							
						data_position = byte_position # Temporary counter
						while data_position+4 <= (flow_set_length + (byte_position-4)):
							
							logging.info("Building flow_index dictionary at byte " + str(data_position))

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

							# Iterate through lines in the template to parse flow payloads
							for template_key, field_size in template_list[hashed_id]["Definitions"].iteritems():
								
								# IPv4 Address
								if ipfix_fields[template_key]["Type"] == "IPv4":
									flow_payload = inet_ntoa(flow_packet_contents[data_position:(data_position+field_size)])
									flow_index["_source"]["IP Protocol Version"] = 4

									# Domain and FQDN lookups for IPv4
									if dns is True:

										# IPv4 Source IP
										if template_key == 8:
											if flow_payload == "255.255.255.255": # Ignore broadcast traffic
												pass
											else:
												source_ip = IP(str(flow_payload)+"/32")
												if lookup_internal is False and source_ip.iptype() == 'PRIVATE':
													pass
												else:
													resolved_fqdn_dict = dns_ops.dns_add_address(flow_payload)
													flow_index["_source"]["Source FQDN"] = resolved_fqdn_dict["FQDN"]
													flow_index["_source"]["Source Domain"] = resolved_fqdn_dict["Domain"]
													if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
														flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]
										
										# IPv4 Destination IP
										elif template_key == 12:
											if flow_payload == "255.255.255.255": # Ignore broadcast traffic
												pass
											else: 
												destination_ip = IP(str(flow_payload)+"/32")
												if lookup_internal is False and destination_ip.iptype() == 'PRIVATE':
													pass
												else:
													resolved_fqdn_dict = dns_ops.dns_add_address(flow_payload)
													flow_index["_source"]["Destination FQDN"] = resolved_fqdn_dict["FQDN"]
													flow_index["_source"]["Destination Domain"] = resolved_fqdn_dict["Domain"]
													if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
														flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]

										# Not source or destination IP, don't resolve it
										else:
											pass
									
								# IPv6 Address
								elif ipfix_fields[template_key]["Type"] == "IPv6":
									flow_payload = inet_ntop(socket.AF_INET6,flow_packet_contents[data_position:(data_position+field_size)])
									flow_index["_source"]["IP Protocol Version"] = 6

									# Domain and FQDN lookups for IPv6
									if dns is True:

										# IPv6 Source IP
										if template_key == 27:
											resolved_fqdn_dict = dns_ops.dns_add_address(flow_payload)
											flow_index["_source"]["Source FQDN"] = resolved_fqdn_dict["FQDN"]
											flow_index["_source"]["Source Domain"] = resolved_fqdn_dict["Domain"]
											if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
													flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]
										
										# IPv6 Destination IP
										elif template_key == 28:
											resolved_fqdn_dict = dns_ops.dns_add_address(flow_payload)
											flow_index["_source"]["Destination FQDN"] = resolved_fqdn_dict["FQDN"]
											flow_index["_source"]["Destination Domain"] = resolved_fqdn_dict["Domain"]
											if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
													flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]

										# Not source or destination IP, don't resolve it
										else:
											pass	
								
								# Integer type field, parse further
								elif ipfix_fields[template_key]["Type"] == "Integer":
									
									# Unpack the integer so we can process it
									if field_size == 1:
										flow_payload = struct.unpack('!B',flow_packet_contents[data_position:(data_position+field_size)])[0]
									elif field_size == 2:
										flow_payload = struct.unpack('!H',flow_packet_contents[data_position:(data_position+field_size)])[0]	
									elif field_size == 4:
										flow_payload = struct.unpack('!I',flow_packet_contents[data_position:(data_position+field_size)])[0]
									elif field_size == 8:
										flow_payload = struct.unpack('!Q',flow_packet_contents[data_position:(data_position+field_size)])[0]
									else:
										logging.warning("Failed to unpack an integer for " + str(ipfix_fields[template_key]["Index ID"]) + " - SKIPPING")
										data_position += field_size
										continue # Bail out	
									
									# Set the IANA protocol number for the index, in case the customer wants to sort by protocol number instead of name
									if template_key == 4:
										flow_index["_source"]['Protocol Number'] = flow_payload
										
										# Add "Category" of the protocol if there is one ("Routing", "ICMP", etc.)
										if "Category" in protocol_type[flow_payload]:
											flow_index["_source"]['Traffic Category'] = protocol_type[flow_payload]["Category"] 
										else:
											flow_index["_source"]['Traffic Category'] = "Other" # To normalize graphs
									
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
									try:
										mac_objects = struct.unpack('!%dB' % field_size,flow_packet_contents[data_position:(data_position+field_size)])
										mac_address = mac_parse(mac_objects)
										if mac_address is False:
											data_position += field_size
											continue
										else:
											flow_payload = mac_address	
									except Exception as mac_parse_error:
										logging.warning("Unable to parse MAC field, number " + str(template_key) + " from " + str(sensor_address[0]))
								
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
							
							# If TCP, UDP, DCCP, or SCTP (transport) try to classify the service based on IANA port numbers
							# http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
							if flow_index["_source"]['Protocol Number'] in [6,17,33,132]: 						

								# Registered IANA ports < 1024 - Source Port
								if flow_index["_source"]['Source Port'] in registered_ports:

									# Tag the service
									flow_index["_source"]['Traffic'] = registered_ports[flow_index["_source"]['Source Port']]["Name"]
									
									# Tag the service category
									if "Category" in registered_ports[flow_index["_source"]['Source Port']]:
										flow_index["_source"]['Traffic Category'] = registered_ports[int(flow_index["_source"]['Source Port'])]["Category"]
								
								# Not a registered port, check if it's a popular port - Source Port
								elif flow_index["_source"]['Source Port'] in other_ports:
									
									# Tag the service
									flow_index["_source"]['Traffic'] = other_ports[flow_index["_source"]['Source Port']]["Name"]
									
									# Tag the service category
									if "Category" in other_ports[flow_index["_source"]['Source Port']]:
										flow_index["_source"]['Traffic Category'] = other_ports[int(flow_index["_source"]['Source Port'])]["Category"]
								
								# Registered IANA ports < 1024 - Destination Port
								elif flow_index["_source"]['Destination Port'] in registered_ports:

									# Tag the service
									flow_index["_source"]['Traffic'] = registered_ports[flow_index["_source"]['Destination Port']]["Name"]
									
									# Tag the service category
									if "Category" in registered_ports[flow_index["_source"]['Destination Port']]:
										flow_index["_source"]['Traffic Category'] = registered_ports[int(flow_index["_source"]['Destination Port'])]["Category"]
								
								# Not a registered port, check if it's a popular port - Destination Port
								elif flow_index["_source"]['Destination Port'] in other_ports:
									
									# Tag the service
									flow_index["_source"]['Traffic'] = other_ports[flow_index["_source"]['Destination Port']]["Name"]
									
									# Tag the service category
									if "Category" in other_ports[flow_index["_source"]['Destination Port']]:
										flow_index["_source"]['Traffic Category'] = other_ports[int(flow_index["_source"]['Destination Port'])]["Category"]
								
								# Not a categorized port
								else:
									pass
							
							# Set Traffic and Traffic Category to "Other" if not already defined, to normalize graphs
							if "Traffic" not in flow_index["_source"]:
								flow_index["_source"]["Traffic"] = "Other"
							if "Traffic Category" not in flow_index["_source"]:
								flow_index["_source"]["Traffic Category"] = "Other"
							
							# Append this single flow to the flow_dic[] for bulk upload
							logging.debug(str(flow_index))
							flow_dic.append(flow_index)

							logging.info("Finished flow at byte " + str(data_position))

					#logging.debug("Finished flow " + str(flow_set_id) + " at byte position " + str(byte_position))
						
					# No template, drop the flow per the standard and advanced the byte position
					else:
						byte_position += flow_set_length
						logging.warning(
						"Missing template for flow set " + 
						str(flow_set_id) + 
						" from " + 
						str(sensor_address[0]) + 
						", sequence " + 
						str(packet_attributes["sequence_number"]) + 
						" - dropping per IPFIX standard"
						)
						break
					
					byte_position = (flow_set_length + byte_position)-4 # Advance to the end of the flow
					logging.info("Ending data set at " + str(byte_position))
					
				# Received a flow set ID we haven't accounted for
				else:
					logging.warning("Unknown flow ID " + str(flow_set_id) + " from " + str(sensor_address[0]))
					break # Bail out
			
			# Have enough flows to do a bulk index to Elasticsearch
			if len(flow_dic) >= bulk_insert_count:
				
				# Perform the bulk upload to the index
				try:
					helpers.bulk(es,flow_dic)
					logging.info(str(len(flow_dic)) + " flow(s) uploaded to Elasticsearch - OK")
				except ValueError as bulk_index_error:
					logging.critical(str(len(flow_dic)) + " flow(s) DROPPED, unable to index flows - FAIL")
					logging.critical(bulk_index_error)
					
				flow_dic = [] # Reset flow_dic

				# Prune DNS to remove stale records
				if dns is True:	
					dns_ops.dns_prune() # Check if the DNS records need to be pruned
				
		# Not IPFIX packet
		else:
			logging.info("Received a non-IPFIX packet from " + str(sensor_address[0]))
			continue