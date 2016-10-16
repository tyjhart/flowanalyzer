# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Import what we need
import time, datetime, socket, struct, sys, json, socket, collections, itertools, logging, logging.handlers
from struct import *
from socket import inet_ntoa,inet_ntop
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from IPy import IP

# Field types, ports, etc
from defined_ports import registered_ports,other_ports
from field_types import ipfix_fields
from netflow_options import *
from protocol_numbers import *

# DNS Resolution
import dns_base
import dns_ops

# Logging
import logging_ops

# Initialize the DNS global
dns_base.init()

# Set the logging level per https://docs.python.org/2/library/logging.html#levels
# Levels include DEBUG, INFO, WARNING, ERROR, CRITICAL (case matters)
logging.basicConfig(level=logging.WARNING)

# Set up socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', ipfix_port))
	logging.warning(' Bound to port ' + str(ipfix_port) + ' - OK')
except ValueError as socket_error:
	logging.critical(' Could not open or bind a socket on port ' + str(ipfix_port))
	logging.critical(str(socket_error))
	sys.exit()

# Spin up ES instance
try:
	es = Elasticsearch([elasticsearch_host])
	logging.warning(' Connected to Elasticsearch at ' + elasticsearch_host + ' - OK')
except ValueError as elasticsearch_connect_error:
	logging.critical(' Could not connect to Elasticsearch at ' + elasticsearch_host')
	logging.critical(" " + str(elasticsearch_connect_error))
	sys.exit()
	
# IPFIX server
def ipfix_server():
	
	# Stage the flows for the bulk API index operation
	flow_dic = []
	
	# Cache the IPFIX templates, in order to decode the data flows
	template_list = {}
	
	# Continually run
	while True:
		
		# Listen for packets inbound
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
		
		# Get the Netflow version and flow size, or just continue listening
		try:
			(netflow_version, ipfix_flow_bytes) = struct.unpack('!HH',flow_packet_contents[0:4])
		
		# Something went wrong or we're being fuzzed, reset
		except:
			logging.critical(str(" Unable to parse IPFIX version and bytes"))
			continue
				
		# Is it a IPFIX (Netflow v10) packet?
		if int(netflow_version) == 10:
			
			# Packet attributes
			packet_attributes = {}
			packet_attributes["Total Bytes"] = ipfix_flow_bytes
			
			# Unpack the rest of the packet
			(packet_attributes["export_time"], packet_attributes["sequence_number"], packet_attributes["observation_id"]) = struct.unpack('!LLL',flow_packet_contents[4:16])
			logging.debug(" Sequence Number: " + str(packet_attributes["sequence_number"]) + ", " + "Observation Domain ID: " + str(packet_attributes["observation_id"]))
				
			# Position the byte counter after the standard protocol header
			byte_position = 16
			logging.debug(" End of header, byte position " + str(byte_position))
			
			# Iterate through the total flows in the packet overall, could be any length
			# Can be any combination of templates and data flows
			while True:
			
				logging.debug(" Start of flow with " + str(ipfix_flow_bytes) + " total bytes, at position " + str(byte_position)) 
				
				# Unpack the flow set ID and the length, to determine if it's a template set or a data set, and the size
				logging.debug(" Unpacking ID and length at byte position " + str(byte_position))
				try:
					(flow_set_id, flow_set_length) = struct.unpack('!HH',flow_packet_contents[byte_position:byte_position+4])
					logging.debug(" Found ID " + str(flow_set_id) + ", length " + str(flow_set_length))
				except:
					logging.debug(" Out of bytes to unpack, breaking")
					break # Done with the packet
				
				# Advance past the initial header of ID and length
				byte_position += 4 
				
				# Is it an IPFIX template set (ID 2)?
				if flow_set_id == 2:
					logging.debug(" Unpacking template set at " + str(byte_position))
					temp_template_cache = {}
					template_position = byte_position
					while template_position <= flow_set_length:
						(template_id, template_id_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
						if template_id > 255:
							logging.debug(" Rcvd template " + str(template_id) + ", sequence " + str(packet_attributes["sequence_number"]))
							
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
					logging.debug(" Finished template set at " + str(byte_position))
					logging.debug(" Working templates: " + str(template_list))
					
				# Is it an IPFIX options template set (ID 3)?
				elif flow_set_id == 3:
					break # Code to parse the Options Template will go here eventually

				# Received an IPFIX flow data set, corresponding with a template that should have already been rcvd
				elif flow_set_id > 255:
					logging.debug(" Processing data flow " + str(flow_set_id) + " at byte position " + str(byte_position))
					
					# Compute the template hash ID
					hashed_id = hash(str(sensor_address[0])+str(flow_set_id))
					
					# Check if there is a template
					if hashed_id in template_list.keys():
						logging.debug(" Using template hash " + str(hashed_id))
						
						# Get the current UTC time for the flows
						now = datetime.datetime.utcnow()
							
						data_position = byte_position # Temporary counter
						while data_position+4 <= (flow_set_length + (byte_position-4)):
							
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
										logging.warning(" Failed to unpack an integer for " + str(ipfix_fields[template_key]["Index ID"]))
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
									elif template_key == 32 or template_key == 139:
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
										mac_payload = struct.unpack('!%dB' % field_size,flow_packet_contents[data_position:(data_position+field_size)])
										mac_list = []
										for mac_item in mac_payload:
											mac_item_formatted = hex(mac_item).replace('0x','')
											if mac_item_formatted == '0':
												mac_item_formatted = "00"
											mac_list.append(mac_item_formatted)
										if mac_list == ["00","00","00","00","00","00"]:
											flow_payload = ""
										else:
											flow_payload = (':'.join(mac_list)).upper()	
								
								# Check if we've been passed a "Vendor Proprietary" field, and if so log it and skip it
								elif ipfix_fields[template_key]["Type"] == "Vendor Proprietary":
									logging.info(
									
									" Rcvd vendor proprietary field, " + 
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
									except Exception, unpack_error:
										logging.debug(
										
										" Error unpacking generic field number " + 
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
							if (flow_index["_source"]['Protocol Number'] == 6 or 
							flow_index["_source"]['Protocol Number'] == 17 or 
							flow_index["_source"]['Protocol Number'] == 33 or 
							flow_index["_source"]['Protocol Number'] == 132): 						

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
							flow_dic.append(flow_index)
							logging.debug(" " + str(flow_index))
							logging.debug(" Finished flow " + str(flow_set_id) + " at byte position " + str(byte_position))
						
					# No template, drop the flow per the standard and advanced the byte position
					else:
						byte_position += flow_set_length
						logging.info("Dropping flow ID " + str(flow_set_id) + " from " + str(sensor_address[0]) + " - No template provided")
						break
					
					# Advance to the end of the flow
					byte_position = (flow_set_length + byte_position)-4
					logging.debug(" Ending Data set at " + str(byte_position))
					
				# Rcvd a flow set ID we haven't accounted for
				else:
					logging.warning(" Unknown flow ID " + str(flow_set_id) + " from " + str(sensor_address[0]))
					break # Bail out
			
			logging.debug(" " + str(packet_attributes))
			
			# Have enough flows to do a bulk index to Elasticsearch
			if len(flow_dic) >= bulk_insert_count:
				
				# For the counter below
				flow_dic_length = len(flow_dic)
				
				# Perform the bulk upload to the index
				try:
					helpers.bulk(es,flow_dic)
					logging.info(str(flow_dic_length) + " flow(s) uploaded to Elasticsearch")
				except ValueError as bulk_index_error:
					logging.error(str(flow_dic_length) + " flow(s) DROPPED - Unable to index flows")
					logging.error(bulk_index_error)
					for flow_debug in flow_dic:
						logging.error(flow_debug)
					
				# Reset flow_dic
				flow_dic = []
				
		# Not IPFIX packet
		else:
			logging.info("Netflow version " + str(int(netflow_version)) + " packet from " + str(sensor_address[0]))
			continue
	
	# End of ipfix_server()	
	return

# Start IPFIX listener	
ipfix_server()