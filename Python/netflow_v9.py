# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

import time, datetime, socket, struct, sys, os, json, socket, collections, itertools, logging, logging.handlers, getopt
from struct import *
from socket import inet_ntoa,inet_ntop
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from IPy import IP

# Field parsing functions
from parser_modules import mac_address,icmp_parse

# Field types, ports, etc
from defined_ports import registered_ports,other_ports
from field_types import v9_fields
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

except Exception:
    sys.exit("Unsupported or badly formed options, see -h for available arguments.") 

# Set the logging level per https://docs.python.org/2/howto/logging.html
try: 
	log_level # Check if log level was passed in from command arguments
except NameError:
	log_level="WARNING" # Use default logging level

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

# Check if the Netflow v9 port is specified
try:
	netflow_v9_port
except NameError: # Not specified, use default
	netflow_v9_port = 9995
	logging.warning("Netflow v9 port not set in netflow_options.py, defaulting to " + str(netflow_v9_port) + " - OK")

# Set up socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', netflow_v9_port))
	logging.warning("Bound to port " + str(netflow_v9_port) + " - OK")
except ValueError as socket_error:
	logging.critical("Could not open or bind a socket on port " + str(netflow_v9_port) + " - FAIL")
	logging.critical(str(socket_error))
	sys.exit()

# Spin up ES instance
try:
	es = Elasticsearch([elasticsearch_host])
	logging.warning("Connected to Elasticsearch at " + str(elasticsearch_host) + " - OK")
except ValueError as elasticsearch_connect_error:
	logging.critical("Could not connect to Elasticsearch at " + str(elasticsearch_host) + " - FAIL")
	logging.critical(str(elasticsearch_connect_error))
	sys.exit()

# Parsing template flowset
def template_flowset_parse(packed_data,sensor,pointer,length):
	cache = {}
	while pointer < length:
		(template_id, template_field_count) = struct.unpack('!HH',packed_data[pointer:pointer+4])
		pointer += 4 # Advance the field
		
		logging.info("Template number " + str(template_id) + ", field count " + str(template_field_count) + ", position " + str(pointer))

		hashed_id = hash(str(sensor)+str(template_id))
		cache[hashed_id] = {}
		cache[hashed_id]["Sensor"] = str(sensor)
		cache[hashed_id]["Template ID"] = template_id
		cache[hashed_id]["Length"] = template_field_count # Field count
		cache[hashed_id]["Type"] = "Flow Data"
		cache[hashed_id]["Definitions"] = collections.OrderedDict()

		for _ in range(0,template_field_count): # Iterate through each line in the template
			(element, element_length) = struct.unpack('!HH',packed_data[pointer:pointer+4])
			
			if element in v9_fields: # Fields we know about and support
				cache[hashed_id]["Definitions"][element] = element_length
			
			else: # Proprietary or undocumented field
				logging.warning("Unsupported field " + str(element) + " in template ID " + str(template_id) + " from " + str(sensor))
			
			pointer += 4 # Advance the field

		logging.debug(str(cache[hashed_id]))
		logging.info(str(hashed_id) + " hash added to cache, template ID " + str(template_id))
		
	return cache

# Parsing option template
def option_template_parse(packed_data,sensor,pointer):	
	(option_template_id,option_scope_length,option_length) = struct.unpack('!HHH',packed_data[pointer:pointer+6])
	pointer += 6 # Move ahead 6 bytes
	
	cache = {}
	hashed_id = hash(str(sensor)+str(option_template_id)) # Hash for individual sensor and template ID
	cache[hashed_id] = {}
	cache[hashed_id]["Sensor"] = str(sensor)
	cache[hashed_id]["Template ID"] = option_template_id
	cache[hashed_id]["Type"] = "Options Template"
	cache[hashed_id]["Scope Fields"] = collections.OrderedDict()
	cache[hashed_id]["Option Fields"] = collections.OrderedDict()

	for x in range(pointer,pointer+option_scope_length,4):
		(scope_field_type,scope_field_length) = struct.unpack('!HH',packed_data[x:x+4])
		cache[hashed_id]["Scope Fields"][scope_field_type] = scope_field_length
	
	pointer += option_scope_length

	for x in range(pointer,pointer+option_length,4):
		(option_field_type,option_field_length) = struct.unpack('!HH',packed_data[x:x+4])
		cache[hashed_id]["Option Fields"][option_field_type] = option_field_length
	
	pointer += option_length
	return cache

def parse_ipv4(packed_data,pointer,field_size):
	payload = inet_ntoa(packed_data[pointer:pointer+field_size])
	return payload

def parse_ipv6(packed_data,pointer,field_size):
	payload = inet_ntop(socket.AF_INET6,packed_data[pointer:pointer+field_size])
	return payload

def integer_unpack(packed_data,pointer,field_size):
	if field_size == 1:
		return struct.unpack('!B',packed_data[pointer:pointer+field_size])[0]
	elif field_size == 2:
		return struct.unpack('!H',packed_data[pointer:pointer+field_size])[0]	
	elif field_size == 4:
		return struct.unpack('!I',packed_data[pointer:pointer+field_size])[0]
	elif field_size == 8:
		return struct.unpack('!Q',packed_data[pointer:pointer+field_size])[0]
	else:
		return False

#IPv4 lookup
def ipv4_dns():
	# Resolve IPv4 Source IP
	if "IPv4 Source" in flow_index["_source"]:
		dns_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv4 Source"])
		if dns_dict == False:
			pass
		else:
			flow_index["_source"]["Source FQDN"] = dns_dict["FQDN"]
			flow_index["_source"]["Source Domain"] = dns_dict["Domain"]
			if "Content" not in flow_index["_source"] or dns_dict["Category"] == "Uncategorized":
				flow_index["_source"]["Content"] = dns_dict["Category"]	
	
	# Resolve IPv4 Destination IP
	if "IPv4 Destination" in flow_index["_source"]:
		dns_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv4 Destination"])
		if dns_dict == False:
			pass
		else:
			flow_index["_source"]["Destination FQDN"] = dns_dict["FQDN"]
			flow_index["_source"]["Destination Domain"] = dns_dict["Domain"]
			if "Content" not in flow_index["_source"] or dns_dict["Category"] == "Uncategorized":
				flow_index["_source"]["Content"] = dns_dict["Category"]
	return

# IPv6 lookup
def ipv6_dns():
	# Resolve IPv6 Source IP
	if "IPv6 Source" in flow_index["_source"]:
		dns_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv6 Source"])
		flow_index["_source"]["Source FQDN"] = dns_dict["FQDN"]
		flow_index["_source"]["Source Domain"] = dns_dict["Domain"]
		if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
				flow_index["_source"]["Content"] = dns_dict["Category"]
	
	# Resolve IPv6 Destination IP
	if "IPv6 Destination" in flow_index["_source"]:
		dns_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv6 Destination"])
		flow_index["_source"]["Destination FQDN"] = dns_dict["FQDN"]
		flow_index["_source"]["Destination Domain"] = dns_dict["Domain"]
		if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
				flow_index["_source"]["Content"] = dns_dict["Category"]
	return

# Tag "Traffic Category" by Protocol classification ("Routing", "ICMP", etc.)
def protocol_traffic_category(protocol_number):
	try:
		return protocol_type[protocol_number]["Category"]
	except (NameError,KeyError):
		return "Other"

# Tag traffic by SRC and DST port
def port_traffic_classifier(src_port,dst_port):
	traffic = {}

	# SRC Port
	if src_port in registered_ports:
		traffic["Traffic"] = registered_ports[src_port]["Name"]

		if "Category" in registered_ports[src_port]:
			traffic["Traffic Category"] = registered_ports[src_port]["Category"]

	elif src_port in other_ports:
		traffic["Traffic"] = other_ports[src_port]["Name"]

		if "Category" in other_ports[src_port]:
			traffic["Traffic Category"] = other_ports[src_port]["Category"]

	else:
		pass
	
	# DST Port
	if dst_port in registered_ports:
		traffic["Traffic"] = registered_ports[dst_port]["Name"]

		if "Category" in registered_ports[dst_port]:
			traffic["Traffic Category"] = registered_ports[dst_port]["Category"]

	elif dst_port in other_ports:
		traffic["Traffic"] = other_ports[dst_port]["Name"]

		if "Category" in other_ports[dst_port]:
			traffic["Traffic Category"] = other_ports[dst_port]["Category"]
	
	else:
		pass
	
	try: # Set as "Other" if not already set
		traffic["Traffic"]
	except (NameError,KeyError):
		traffic["Traffic"] = "Other"

	try: # Set as "Other" if not already set
		traffic["Traffic Category"]
	except (NameError,KeyError):
		traffic["Traffic Category"] = "Other"
	
	return traffic

### Netflow v9 server ###
if __name__ == "__main__":
	
	# Stage individual flow
	global flow_index
	flow_index = {}
	flow_index["_source"] = {}
	
	# Stage multiple flows for the bulk Elasticsearch API index operation
	global flow_dic
	flow_dic = []
	
	# Cache the Netflow v9 templates in received order to decode the data flows. ORDER MATTERS FOR TEMPLATES.
	global template_list
	template_list = {}

	# Class for parsing ICMP Types and Codes
	icmp_parser = icmp_parse()

	# Class for parsing MAC addresses and OUIs
	mac = mac_address()
	
	# Continually run
	while True:

		pointer = 0 # Tracking location in the packet
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565) # Listen for packets inbound
		
		# Get the Netflow version and flow size, or just continue listening
		try:
			# Unpack the header
			logging.info("Unpacking header from " + str(sensor_address[0]))
			
			# Flow attributes in the Netflow packet header
			packet = {}			
			(
			packet["netflow_version"],
			packet["total_flow_count"],
			packet["sys_uptime"],
			packet["unix_secs"],
			packet["sequence_number"],
			packet["source_id"]
			) = struct.unpack('!HHLLLL',flow_packet_contents[0:20])	

			packet["Sensor"] = str(sensor_address[0])
			pointer += 20 # Move past the packet header
		
		# Something went wrong unpacking the header, bail out
		except Exception as flow_header_error:
			logging.warning("Failed unpacking flow header from " + str(sensor_address[0]) + " - " + str(flow_header_error))
			continue	

		# Check Netflow version
		if int(packet["netflow_version"]) != 9:
			logging.warning("Received a non-Netflow v9 packet from " + str(sensor_address[0]) + " - SKIPPING PACKET")
			continue # Bail out

		flow_counter = 0 # For debug purposes only
		
		while True: # Iterate through all flows in the packet
			
			# Unpack flow set ID and the length
			try:
				(flow_set_id, flow_set_length) = struct.unpack('!HH',flow_packet_contents[pointer:pointer+4])
				logging.info("Found flow ID " + str(flow_set_id) + ", length " + str(flow_set_length) + " at " + str(pointer))
			except:
				logging.info("Out of bytes to unpack, stopping - OK")
				break
			
			pointer += 4 # Advance past the flow ID and Length
			
			logging.info("Finshed, position " + str(pointer))
			
			if flow_set_id == 0: # Template flowset
				logging.info("Unpacking template flowset " + str(flow_set_id) + ", position " + str(pointer))
				
				parsed_templates = template_flowset_parse(flow_packet_contents,sensor_address[0],pointer,flow_set_length) # Parse templates
				template_list.update(parsed_templates) # Add the new template(s) to the working template list					

				logging.debug(str(parsed_templates))

				# Advance to the end of the flow
				pointer = (flow_set_length + pointer)-4
				logging.info("Finished, position " + str(pointer))

				flow_counter += 1
									
			elif flow_set_id == 1: # Options template set
				logging.warning("Unpacking Options template set, position " + str(pointer))
				
				option_templates = option_template_parse(flow_packet_contents,sensor_address[0],pointer)
				template_list.update(option_templates) # Add the new Option template(s) to the working template list

				logging.debug(str(template_list))
				pointer = (flow_set_length + pointer)-4
				logging.info("Finished, position " + str(pointer))

				flow_counter += 1

			# Flow data set
			elif flow_set_id > 255:
				logging.info("Unpacking data set " + str(flow_set_id) + ", position " + str(pointer))
				
				hashed_id = hash(str(sensor_address[0])+str(flow_set_id))
				if hashed_id in template_list:
					data_position = pointer
					
					# Get the current UTC time for the flows
					now = datetime.datetime.utcnow()
					
					if template_list[hashed_id]["Type"] == "Flow Data":

						while data_position+4 <= (flow_set_length + (pointer-4)):
							
							# Cache the flow data, to be appended to flow_dic[]	
							global flow_index					
							flow_index = {
							"_index": str("flow-" + now.strftime("%Y-%m-%d")),
							"_type": "Flow",
							"_source": {
							"Sensor": sensor_address[0],
							"Sequence": packet["sequence_number"],
							"Source ID": packet["source_id"],
							"Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z",
							}
							}
							
							flow_counter += 1
							flow_index["_source"]["Flow Type"] = "Netflow v9" # Note the type

							logging.info("Data flow number " + str(flow_counter) + ", set ID " + str(flow_set_id) + " from " + str(sensor_address[0])) 
							
							# Iterate through fields in the matching template
							for template_key, field_size in template_list[hashed_id]["Definitions"].iteritems():
								
								# IPv4 Address type field
								if v9_fields[template_key]["Type"] == "IPv4":
									flow_payload = parse_ipv4(flow_packet_contents,data_position,field_size)
									flow_index["_source"]["IP Protocol Version"] = 4
									
								# IPv6 Address type field
								elif v9_fields[template_key]["Type"] == "IPv6":
									flow_payload = parse_ipv6(flow_packet_contents,data_position,field_size)
									flow_index["_source"]["IP Protocol Version"] = 6
									
								# Integer type field, parse further
								elif v9_fields[template_key]["Type"] == "Integer":

									flow_payload = integer_unpack(flow_packet_contents,data_position,field_size) # Unpack the integer
										
									# IANA protocol number in case the customer wants to sort by protocol number
									if template_key == 4:							
										flow_index["_source"]['Protocol Number'] = flow_payload	
											
									# Do the special calculations for ICMP Code and Type (% operator)
									elif template_key in [32,139]:
										num_icmp = icmp_parser.icmp_num_type_code(flow_payload)
										flow_index["_source"]['ICMP Type'] = num_icmp[0]
										flow_index["_source"]['ICMP Code'] = num_icmp[1]

										human_icmp = icmp_parser.icmp_human_type_code(flow_payload)
										flow_index["_source"]['ICMP Parsed Type'] = human_icmp[0]
										flow_index["_source"]['ICMP Parsed Code'] = human_icmp[1]

									# Not a specially parsed field, just ignore
									else:
										pass
										
								# MAC Address
								elif v9_fields[template_key]["Type"] == "MAC":
									
									# Returns (Parsed MAC, MAC OUI)
									parsed_mac = mac.mac_packed_parse(flow_packet_contents,data_position,field_size)
									flow_payload = parsed_mac[0] # Parsed MAC address
									
									# Incoming Source MAC
									if template_key == 56:							
										flow_index["_source"]['Incoming Source MAC OUI'] = parsed_mac[1]
									
									# Outgoing Destination MAC
									elif template_key == 57:							
										flow_index["_source"]['Outgoing Destination MAC OUI'] = parsed_mac[1]
									
									# Incoming Destination MAC
									elif template_key == 80:							
										flow_index["_source"]['Incoming Destination MAC OUI'] = parsed_mac[1]
									
									# Outgoing Source MAC
									elif template_key == 81:							
										flow_index["_source"]['Outgoing Source MAC OUI'] = parsed_mac[1]

									# Station MAC Address
									elif template_key == 365:							
										flow_index["_source"]['Station MAC Address OUI'] = parsed_mac[1]

									# WTP MAC Address
									elif template_key == 367:							
										flow_index["_source"]['WTP MAC Address OUI'] = parsed_mac[1]

									# Dot1q Customer Source MAC Address
									elif template_key == 414:							
										flow_index["_source"]['Dot1q Customer Source MAC Address OUI'] = parsed_mac[1]

									# Dot1q Customer Destination MAC Address
									elif template_key == 415:							
										flow_index["_source"]['Dot1q Customer Destination MAC Address OUI'] = parsed_mac[1]
									
									else:
										pass

								# Something we haven't accounted for yet						
								else:
									logging.warning("Unsupported field number " + str(template_key) + ", size " + str(field_size) + " from " + str(sensor_address[0]) + " in sequence " + str(packet["sequence_number"]))

									data_position += field_size
									continue # Bail out of this field, either undefined or proprietary
								
								# Add the friendly Index ID and value (flow_payload) to flow_index
								if "Options" in v9_fields[template_key]: # Integer fields with pre-defined values in the v9 standard	
									try:
										flow_index["_source"][v9_fields[template_key]["Index ID"]] = v9_fields[template_key]['Options'][int(flow_payload)]
									except Exception as option_warning:
										logging.warning("Failed to parse human option, template key " + str(template_key) + ", option key " + str(flow_payload) + ", from " + str(sensor_address[0]) + " - USING INTEGER VALUE")
										flow_index["_source"][v9_fields[template_key]["Index ID"]] = flow_payload

								else: # Some other field with a human-friendly name
									flow_index["_source"][v9_fields[template_key]["Index ID"]] = flow_payload

								# Move the byte position the number of bytes in the field we just parsed
								data_position += field_size
								
							# Tag "Traffic" and "Traffic Category" for TCP/UDP:
							if int(flow_index["_source"]['Protocol Number']) in (6, 17, 33, 132):
								traffic_tags = port_traffic_classifier(flow_index["_source"]["Source Port"],flow_index["_source"]["Destination Port"])
								flow_index["_source"]["Traffic"] = traffic_tags["Traffic"]
								flow_index["_source"]["Traffic Category"] = traffic_tags["Traffic Category"]
							
							
							else:
								flow_index["_source"]["Traffic"] = None # No tagged traffic types for non-TCP/UDP protocols
								flow_index["_source"]["Source Port"] = None # Not a transport protocol
								flow_index["_source"]["Destination Port"] = None # Not a transport protocol
								
								# Tag the protocol's "Category" if defined, otherwise tag "Other"
								try: 
									flow_index["_source"]["Traffic Category"]
								except (NameError,KeyError):
									flow_index["_source"]["Traffic Category"] = protocol_traffic_category(flow_index["_source"]['Protocol Number'])
							
							#logging.critical(str({"Protocol":flow_index["_source"]['Protocol Number'],"Traffic":flow_index["_source"]["Traffic"],"Traffic Category":flow_index["_source"]["Traffic Category"]}))
							
							# Tag the flow with Source and Destination FQDN and Domain info (if enabled and available)
							if dns is True:

								if flow_index["_source"]['IP Protocol Version'] == 4: 
									ipv4_dns() # IPv4 hosts
								
								elif flow_index["_source"]['IP Protocol Version'] == 6:
									ipv6_dns() # IPv6 hosts
								
								else:
									pass

							# Append this parsed flow to the flow_dic[] for bulk upload
							flow_dic.append(flow_index)
							logging.debug(str(flow_index))	
							logging.info("Ending data flow " + str(flow_counter))	
					
					elif template_list[hashed_id]["Type"] == "Options Template":
						flow_counter += 1
						logging.info("Creating Netflow v9 Options flow number " + str(flow_counter) + ", set ID " + str(flow_set_id) + " from " + str(sensor_address[0]))
						flow_index["_source"]["Flow Type"] = "Netflow v9 Options" # Note the type

						for scope_field in template_list[hashed_id]["Scope Fields"]:
							logging.debug(str(scope_field))

						for option_field in template_list[hashed_id]["Option Fields"]:
							logging.debug(str(option_field))

						logging.info("Ending Netflow v9 Options flow " + str(flow_counter))

					else:
						pass

				# No template, drop the flow per the standard and advanced the byte position
				else:
					logging.warning("Missing template for flow set " + 	str(flow_set_id) + " from " + str(sensor_address[0]) + ", sequence " + str(packet["sequence_number"]) + " - DROPPING")
					
				# Advance to the end of the flow
				pointer = (flow_set_length + pointer)-4
				logging.info("Finished, position " + str(pointer))
			
			# Rcvd a flow set ID we haven't accounted for
			else:
				logging.warning("Unknown flow ID " + str(flow_set_id) + " from " + str(sensor_address[0]) + " - FAIL")
				pointer = (flow_set_length + pointer)-4
				flow_counter += 1
				continue
			
		packet["Reported Flow Count"] = flow_counter	
		
		logging.debug("Cached templates: " + str(template_list)) # Dump active templates for debug

		# Have enough flows to do a bulk index to Elasticsearch
		if len(flow_dic) >= bulk_insert_count:
							
			# Perform the bulk upload to the index
			try:
				helpers.bulk(es,flow_dic)
				logging.info(str(len(flow_dic)) + " flow(s) uploaded to Elasticsearch - OK")
			except ValueError as bulk_index_error:
				logging.critical(str(len(flow_dic)) + " flow(s) DROPPED, unable to index flows - FAIL")
				logging.critical(bulk_index_error)
				
			# Reset flow_dic
			flow_dic = []
			
			# Prune DNS to remove stale records
			if dns is True:	
				dns_ops.dns_prune() # Check if the DNS records need to be pruned