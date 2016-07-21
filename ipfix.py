# Copyright 2016, Manito Networks, LLC. All rights reserved
#
# Last modified 6/9/2016

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
#logging.basicConfig(level=logging.DEBUG) # For logging to a file in PROD
logging.basicConfig(filename='/opt/manitonetworks/flow/ipfix.log',level=logging.WARNING)
logger = logging.getLogger('IPFIX')

# Set up socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', ipfix_port))
	logger.info(logging_ops.log_time() + ' Listening on port ' + str(ipfix_port))
except ValueError as socket_error:
	logger.critical(logging_ops.log_time() + ': Could not open or bind a socket on port ' + str(ipfix_port))
	logger.critical(logging_ops.log_time() + str(socket_error))
	sys.exit()

# Spin up ES instance
try:
	es = Elasticsearch([elasticsearch_host])
	logger.info(logging_ops.log_time() + ' Connected to Elasticsearch')
except ValueError as elasticsearch_connect_error:
	logger.critical(logging_ops.log_time() + ': Could not connect to Elasticsearch')
	logger.critical(logging_ops.log_time() + str(elasticsearch_connect_error))
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
		
		# Something went wrong, reset
		except:
			continue
				
		# Is it a IPFIX (Netflow v10) packet?
		if int(netflow_version) == 10:
			
			# Packet attributes
			packet_attributes = {}
			packet_attributes["Total Bytes"] = ipfix_flow_bytes
			
			# Unpack the rest of the packet
			(packet_attributes["export_time"], packet_attributes["sequence_number"], packet_attributes["observation_id"]) = struct.unpack('!LLL',flow_packet_contents[4:16])
			logger.debug(logging_ops.log_time() + " Sequence Number: " + str(packet_attributes["sequence_number"]) + ", " + "Observation Domain ID: " + str(packet_attributes["observation_id"]))
				
			# Position the byte counter after the standard protocol header
			byte_position = 16
			logger.debug(logging_ops.log_time() + " End of header, byte position " + str(byte_position))
			
			# Iterate through the total flows in the packet overall
			while True:
			
				logger.debug(logging_ops.log_time() + " Start of flow with " + str(ipfix_flow_bytes) + " total bytes, at position " + str(byte_position)) 
				
				# Unpack the flow set ID and the length, to determine if it's a template set or a data set, and the size
				logger.debug(logging_ops.log_time() + " Unpacking ID and length at byte position " + str(byte_position))
				try:
					(flow_set_id, flow_set_length) = struct.unpack('!HH',flow_packet_contents[byte_position:byte_position+4])
					logger.debug(logging_ops.log_time() + " Found ID " + str(flow_set_id) + ", length " + str(flow_set_length))
				except:
					logger.debug(logging_ops.log_time() + " Out of bytes to unpack, breaking")
					break
				byte_position += 4
				
				# Is it an IPFIX template set (ID 2)?
				if flow_set_id == 2:
					logger.debug(logging_ops.log_time() + " Unpacking template set at " + str(byte_position))
					temp_template_cache = {}
					template_position = byte_position
					while template_position <= flow_set_length:
						(template_id, template_id_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
						if template_id > 255:
							logger.debug(logging_ops.log_time() + " Rcvd template " + str(template_id) + ", sequence " + str(packet_attributes["sequence_number"]))
							hashed_id = hash(str(sensor_address[0])+str(template_id))
							temp_template_cache[hashed_id] = {}
							temp_template_cache[hashed_id]["Sensor"] = str(sensor_address[0])
							temp_template_cache[hashed_id]["Template ID"] = template_id
							temp_template_cache[hashed_id]["Length"] = template_id_length
							temp_template_cache[hashed_id]["Definitions"] = collections.OrderedDict()
							template_line_counter = 1
							while template_line_counter <= template_id_length:
								template_position += 4
								(template_element, template_element_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
								temp_template_cache[hashed_id]["Definitions"][template_element] = template_element_length
								template_line_counter += 1
						template_position += 4
					template_list.update(temp_template_cache)	
					byte_position = (flow_set_length + byte_position)-4
					logger.debug(logging_ops.log_time() + " Finished template set at " + str(byte_position))
					logger.debug(logging_ops.log_time() + " Working templates: " + str(template_list))
					
				# Is it an IPFIX options template set (ID 3)?
				elif flow_set_id == 3:
					break # Code to parse the Options Template will go here eventually

				# Received an IPFIX flow data set, corresponding with a template that should have already been rcvd
				elif flow_set_id > 255:
					logger.debug(logging_ops.log_time() + " Processing data flow " + str(flow_set_id) + " at byte position " + str(byte_position))
					
					# Compute the template hash ID
					hashed_id = hash(str(sensor_address[0])+str(flow_set_id))
					
					# Check if there is a template
					if hashed_id in template_list.keys():
						logger.debug(logging_ops.log_time() + " Using template hash " + str(hashed_id))
						
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
							"Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z",
							}
							}

							# Iterate through lines in the template to parse flow payloads
							for template_key, field_size in template_list[hashed_id]["Definitions"].iteritems():
								
								# IPv4 Address
								if ipfix_fields[template_key]["Type"] == "IPv4":
									flow_payload = inet_ntoa(flow_packet_contents[data_position:(data_position+field_size)])
									flow_index["_source"]["IP Protocol Version"] = 4
									
								# IPv6 Address
								elif ipfix_fields[template_key]["Type"] == "IPv6":
									flow_payload = inet_ntop(socket.AF_INET6,flow_packet_contents[data_position:(data_position+field_size)])
									flow_index["_source"]["IP Protocol Version"] = 6	
								
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
										logger.warning(logging_ops.log_time() + " Failed to unpack an integer for " + str(ipfix_fields[template_key]["Index ID"]))
										data_position += field_size
										continue	
									
									# Set the IANA protocol number for the index, in case the customer wants to sort by protocol number instead of name
									if template_key == 4:
										flow_index["_source"]['Protocol Number'] = flow_payload
										
										# Add "Category" of the protocol if there is one ("Routing", "ICMP", etc.)
										if "Category" in protocol_type[flow_payload]:
											flow_index["_source"]['Traffic Category'] = protocol_type[flow_payload]["Category"] 
										else:
											flow_index["_source"]['Traffic Category'] = "Other" # To normalize graphs

									# Based on TCP and UDP source / destination ports try to classify the service
									elif (template_key == 7 or template_key == 11) and "Traffic" not in flow_index["_source"]:							
										
										# Registered IANA ports < 1024
										if flow_payload in registered_ports:

											# Tag the service
											flow_index["_source"]['Traffic'] = registered_ports[flow_payload]["Name"]
											
											# Tag the service category
											if "Category" in registered_ports[flow_payload]:
												flow_index["_source"]['Traffic Category'] = registered_ports[int(flow_payload)]["Category"]
										
										# Not a registered port, check if it's a popular port
										elif flow_payload in other_ports:
											
											# Tag the service
											flow_index["_source"]['Traffic'] = other_ports[flow_payload]["Name"]
											
											# Tag the service category
											if "Category" in other_ports[flow_payload]:
												flow_index["_source"]['Traffic Category'] = other_ports[int(flow_payload)]["Category"]
										
										# Not a categorized port
										else:
											pass
									
									# Do the special calculations for ICMP Code and Type (% operator)
									elif template_key == 32 or template_key == 139:
										flow_index["_source"]['ICMP Type'] = int(flow_payload)//256
										flow_index["_source"]['ICMP Code'] = int(flow_payload)%256

									# Not a specially parsed field, just ignore and log the payload
									else:
										pass
										
									if "Options" in ipfix_fields[template_key]:	
										flow_index["_source"][ipfix_fields[template_key]["Index ID"]] = ipfix_fields[template_key]['Options'][int(flow_payload)]
										
										# Advance the position for each field and skip the rest
										data_position += field_size
										continue			
									
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
									logger.info(
									logging_ops.log_time() + 
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
										logger.debug(
										logging_ops.log_time() + 
										" Error unpacking generic field number " + 
										str(ipfix_fields[field_definition]) + 
										", error messages: " + 
										str(unpack_error)
										)
								
								# Add the friendly Index ID and value (flow_payload) to flow_index
								flow_index["_source"][ipfix_fields[int(template_key)]["Index ID"]] = flow_payload
								
								# Tag the flow with Source and Destination FQDN and Domain info (if available)
								if dns is True:

									# IPv4 Source IP
									if template_key == 8:
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
										destination_ip = IP(str(flow_payload)+"/32")
										if lookup_internal is False and destination_ip.iptype() == 'PRIVATE':
											pass
										else:
											resolved_fqdn_dict = dns_ops.dns_add_address(flow_payload)
											flow_index["_source"]["Destination FQDN"] = resolved_fqdn_dict["FQDN"]
											flow_index["_source"]["Destination Domain"] = resolved_fqdn_dict["Domain"]
											if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
												flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]			
									
									# IPv6 Source IP
									elif template_key == 27:
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

									else:
										pass
								
								# Move the byte position the number of bytes we just parsed
								data_position += field_size
							
							# Append this single flow to the flow_dic[] for bulk upload
							flow_dic.append(flow_index)
							logger.debug(logging_ops.log_time() + " " + str(flow_index))
							logger.debug(logging_ops.log_time() + " Finished flow " + str(flow_set_id) + " at byte position " + str(byte_position))
						
					# No template, drop the flow per the standard and advanced the byte position
					else:
						byte_position += flow_set_length
						logger.info("Dropping flow ID " + str(flow_set_id) + " from " + str(sensor_address[0]) + " - No template provided")
						break
					
					# Advance to the end of the flow
					byte_position = (flow_set_length + byte_position)-4
					logger.debug(logging_ops.log_time() + " Ending Data set at " + str(byte_position))
					
				# Rcvd a flow set ID we haven't accounted for
				else:
					logger.warning(logging_ops.log_time() + " Unknown flow ID " + str(flow_set_id) + " from " + str(sensor_address[0]))
					break
			
			logger.debug(logging_ops.log_time() + " " + str(packet_attributes))
			
			# Have enough flows to do a bulk index to Elasticsearch
			if len(flow_dic) >= bulk_insert_count:
				
				# For the counter below
				flow_dic_length = len(flow_dic)
				
				# Set Traffic and Traffic Category to "Other" if not already defined, to normalize graphs
				for bulk_index_line in range(0,flow_dic_length):
					if "Traffic" not in flow_dic[bulk_index_line]["_source"]:
						flow_dic[bulk_index_line]["_source"]["Traffic"] = "Other"
					#if "Traffic Category" not in flow_dic[bulk_index_line]["_source"]:
						#flow_dic[bulk_index_line]["_source"]["Traffic Category"] = "Other"
				
				# Perform the bulk upload to the index
				try:
					helpers.bulk(es,flow_dic)
					logger.info(str(len(flow_dic)) + " flow(s) uploaded to Elasticsearch")
				except ValueError as bulk_index_error:
					logger.error(str(len(flow_dic)) + " flow(s) DROPPED - Unable to index flows")
					logger.error(bulk_index_error)
					for flow_debug in flow_dic:
						logger.error(flow_debug)
					
				# Reset flow_dic
				flow_dic = []
				
		# Not IPFIX packet
		else:
			logger.info("Netflow version " + str(int(netflow_version)) + " packet from " + str(sensor_address[0]))
			continue
	
	# End of ipfix_server()	
	return

# Start IPFIX listener	
ipfix_server()