# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Import what we need
import time, datetime, socket, struct, sys, os, json, socket, collections, itertools, logging, logging.handlers
from struct import *
from socket import inet_ntoa,inet_ntop
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from IPy import IP

# Field types, ports, etc
from defined_ports import registered_ports,other_ports
from field_types import v9_fields
from netflow_options import *
from protocol_numbers import *

# DNS Resolution
import dns_base
import dns_ops

# Initialize the DNS global
dns_base.init()

# Set the logging level per https://docs.python.org/2/library/logging.html#levels
# Levels include DEBUG, INFO, WARNING, ERROR, CRITICAL (case matters)
logging.basicConfig(level=logging.WARNING)

# Set up socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', netflow_v9_port))
	logging.warning(' Bound to port ' + str(netflow_v9_port) + ' - OK')
except ValueError as socket_error:
	logging.critical(' Could not open or bind a socket on port ' + str(netflow_v9_port))
	logging.critical(str(socket_error))
	sys.exit("Could not open or bind a socket on port " + str(netflow_v9_port))

# Spin up ES instance
try:
	es = Elasticsearch([elasticsearch_host])
	logging.warning(' Connected to Elasticsearch at ' + str(elasticsearch_host) + ' - OK')
except ValueError as elasticsearch_connect_error:
	logging.critical(' Could not connect to Elasticsearch at ' + str(elasticsearch_host))
	logging.critical(" " + str(elasticsearch_connect_error))
	sys.exit("Could not connect to Elasticsearch at " + str(elasticsearch_host))

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

# Netflow server
def netflow_v9_server():
	
	# Stage the flows for the bulk API index operation
	flow_dic = []
	
	# Cache the Netflow v9 templates in received order to decode the data flows. ORDER MATTERS FOR TEMPLATES.
	template_list = {}
	
	while True:
		
		# Listen for packets inbound
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
		
		# Get the Netflow version and flow count per packet
		(netflow_version, total_flow_count) = struct.unpack('!HH',flow_packet_contents[0:4])	
		
		# Is it a Netflow v9 packet?
		if int(netflow_version) == 9:
		
			# For debug purposes only
			flow_counter = 0
		
			# Packet attributes in the header
			packet_attributes = {}
			packet_attributes["Observed Flow Count"] = total_flow_count
			
			(
			packet_attributes["sys_uptime"],
			packet_attributes["unix_secs"],
			packet_attributes["sequence_number"],
			packet_attributes["source_id"]
			) = struct.unpack('!LLLL',flow_packet_contents[4:20])
			
			# Counter for total bytes in the packet, at current position after header
			byte_position = 20
			
			# Iterate through the total flows in the packet overall
			while True:
				
				# Unpack the flow set ID and the length
				logging.debug(" Unpacking flow header at " + str(byte_position))
				try:
					(flow_set_id, flow_set_length) = struct.unpack('!HH',flow_packet_contents[byte_position:byte_position+4])
					logging.debug(" Found ID " + str(flow_set_id) + ", length " + str(flow_set_length))
				except:
					logging.debug(" Out of bytes to unpack, breaking")
					break
				byte_position += 4
				logging.debug(" Finshed unpacking flow header at " + str(byte_position))
				
				if flow_set_id == 0: # Template data set
					logging.debug(" Unpacking template set at " + str(byte_position))
					temp_template_cache = {}
					
					for template_position in range(byte_position,flow_set_length,4):
						(template_id, template_id_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
						
						if template_id > 255: # Flow data template 
							flow_counter += 1
							logging.debug(" Rcvd template " + str(template_id) + ", sequence " + str(packet_attributes["sequence_number"]))
							hashed_id = hash(str(sensor_address[0])+str(template_id))
							temp_template_cache[hashed_id] = {}
							temp_template_cache[hashed_id]["Sensor"] = str(sensor_address[0])
							temp_template_cache[hashed_id]["Template ID"] = template_id
							temp_template_cache[hashed_id]["Length"] = template_id_length
							temp_template_cache[hashed_id]["Definitions"] = collections.OrderedDict()

							for _ in range(0,template_id_length): # Iterate through each line in the template
								template_position += 4
								(template_element, template_element_length) = struct.unpack('!HH',flow_packet_contents[template_position:template_position+4])
								
								if template_element in v9_fields: # Fields we know about and support
									temp_template_cache[hashed_id]["Definitions"][template_element] = template_element_length
								
								else: # Proprietary or undocumented field
									logging.warning(
									" Rcvd unsupported field " + 
									str(template_element) + 
									", in template ID " + 
									str(template_id) + 
									" from " + 
									str(sensor_address[0])	
									)
						
						template_list.update(temp_template_cache) # Add the new template to the working template list
							
					byte_position = (flow_set_length + byte_position)-4 # Move location for next flow or template
					
					logging.debug(" Finished template set at " + str(byte_position))
					logging.debug(" Working templates: " + str(template_list))
										
				# Options template set
				elif flow_set_id == 1:
					logging.warning(" Unpacking Options template set at " + str(byte_position))
					
					flow_counter += 1
					
					(options_template_id, options_template_id_length) = struct.unpack('!HH',flow_packet_contents[byte_position:byte_position+4])
					
					logging.warning(" Options Template ID: " + str(options_template_id) + ", length " + str(options_template_id_length)) 
					
					byte_position = (options_template_id_length + byte_position)-4 # Move location for next flow or template
					
					logging.warning(" Ending Options template set at " + str(byte_position))
				
				# Flow data set
				elif flow_set_id > 255:
					logging.debug(" Unpacking Data set at " + str(byte_position))
					hashed_id = hash(str(sensor_address[0])+str(flow_set_id))
					if hashed_id in template_list:
						data_position = byte_position
						
						# Get the current UTC time for the flows
						now = datetime.datetime.utcnow()
						
						while data_position+4 <= (flow_set_length + (byte_position-4)):
							flow_counter += 1
							logging.debug(" Creating data flow number " + str(flow_counter)) 
							
							# Cache the flow data, to be appended to flow_dic[]						
							flow_index = {
							"_index": str("flow-" + now.strftime("%Y-%m-%d")),
							"_type": "Flow",
							"_source": {
							"Flow Type": "Netflow v9",
							"Sensor": sensor_address[0],
							"Sequence": packet_attributes["sequence_number"],
							"Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z",
							}
							}
							
							# Iterate through lines in the template
							for template_key, field_size in template_list[hashed_id]["Definitions"].iteritems():
								
								# IPv4 Address
								if v9_fields[template_key]["Type"] == "IPv4":
									flow_payload = inet_ntoa(flow_packet_contents[data_position:(data_position+field_size)])
									flow_index["_source"]["IP Protocol Version"] = 4
									
								# IPv6 Address
								elif v9_fields[template_key]["Type"] == "IPv6":
									flow_payload = inet_ntop(socket.AF_INET6,flow_packet_contents[data_position:(data_position+field_size)])
									flow_index["_source"]["IP Protocol Version"] = 6
									
								# Integer type field, parse further
								elif v9_fields[template_key]["Type"] == "Integer":

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
										logging.warning(" Failed to unpack an integer for field " + str(template_key) + ", length " + str(field_size) + " from " + str(sensor_address[0]))
										
										# Bail out of this field
										data_position += field_size
										continue
										
									# Set the IANA protocol number for the index, in case the customer wants to sort by protocol number instead of name
									if template_key == 4:							
										flow_index["_source"]['Protocol Number'] = flow_payload
										
										# Add "Category" of the protocol if there is one ("Routing", "ICMP", etc.)
										if "Category" in protocol_type[flow_payload]:
											flow_index["_source"]['Traffic Category'] = protocol_type[flow_payload]["Category"] 	
										
									# Based on source / destination port try to classify as a common service
									elif (template_key == 7 or template_key == 11) and "Traffic" not in flow_index["_source"]:							
										if flow_payload in registered_ports:
											flow_index["_source"]['Traffic'] = registered_ports[flow_payload]["Name"]
											if "Category" in registered_ports[flow_payload]:
												flow_index["_source"]['Traffic Category'] = registered_ports[int(flow_payload)]["Category"]
										elif flow_payload in other_ports:
											flow_index["_source"]['Traffic'] = other_ports[flow_payload]["Name"]
											if "Category" in other_ports[flow_payload]:
												flow_index["_source"]['Traffic Category'] = other_ports[int(flow_payload)]["Category"]
										else:
											pass
											
									# Do the special calculations for ICMP Code and Type (% operator)
									elif template_key == 32 or template_key == 139:
										flow_index["_source"]['ICMP Type'] = int(flow_payload)//256
										flow_index["_source"]['ICMP Code'] = int(flow_payload)%256

									# Not a specially parsed field, just ignore
									else:
										pass
									
									# Special integer-type fields with pre-defined values in the v9 standard
									if "Options" in v9_fields[template_key]:	
										flow_index["_source"][v9_fields[template_key]["Index ID"]] = v9_fields[template_key]['Options'][int(flow_payload)]
										
										# Advance the position for the field and skip the rest, nothing more to parse
										data_position += field_size
										continue
									
									# No "Options" specified for this field type
									else:
										pass 
										
								# MAC Address
								elif v9_fields[template_key]["Type"] == "MAC":
									mac_objects = struct.unpack('!%dB' % field_size,flow_packet_contents[data_position:(data_position+field_size)])
									mac_address = mac_parse(mac_objects)
									if mac_address is False:
										data_position += field_size
										continue
									else:
										flow_payload = mac_address

								# Something we haven't accounted for yet						
								else:
									logging.debug(
									" Unsupported field " + 
									str(template_key) + 
									", size " + 
									str(field_size) +
									", from " +
									str(sensor_address[0]) +
									" in sequence " +
									str(packet_attributes["sequence_number"])
									)

									# Bail out of this field, don't know what it is
									data_position += field_size
									continue
								
								# Add value to the flow_index and move the data pointer
								#
								# Add the friendly Index ID and value (flow_payload) to flow_index
								flow_index["_source"][v9_fields[template_key]["Index ID"]] = flow_payload

								# Move the byte position the number of bytes in the field we just parsed
								data_position += field_size
								
							# Tag the flow with Source and Destination FQDN and Domain info (if available)
							if dns is True:

								if flow_index["_source"]['IP Protocol Version'] == 4: # IPv4 hosts

									# IPv4 Source IP
									if "IPv4 Source" in flow_index["_source"]:
										resolved_fqdn_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv4 Source"])
										if resolved_fqdn_dict == False:
											pass
										else:
											flow_index["_source"]["Source FQDN"] = resolved_fqdn_dict["FQDN"]
											flow_index["_source"]["Source Domain"] = resolved_fqdn_dict["Domain"]
											if "Content" not in flow_index["_source"] or resolved_fqdn_dict["Category"] == "Uncategorized":
												flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]	
									
									# IPv4 Destination IP
									if "IPv4 Destination" in flow_index["_source"]:
										resolved_fqdn_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv4 Destination"])
										if resolved_fqdn_dict == False:
											pass
										else:
											flow_index["_source"]["Destination FQDN"] = resolved_fqdn_dict["FQDN"]
											flow_index["_source"]["Destination Domain"] = resolved_fqdn_dict["Domain"]
											if "Content" not in flow_index["_source"] or resolved_fqdn_dict["Category"] == "Uncategorized":
												flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]			
								
								if flow_index["_source"]['IP Protocol Version'] == 6: # IPv6 hosts

									# IPv6 Source IP
									if "IPv6 Source" in flow_index["_source"]:
										resolved_fqdn_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv6 Source"])
										flow_index["_source"]["Source FQDN"] = resolved_fqdn_dict["FQDN"]
										flow_index["_source"]["Source Domain"] = resolved_fqdn_dict["Domain"]
										if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
												flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]
									
									# IPv6 Destination IP
									if "IPv6 Destination" in flow_index["_source"]:
										resolved_fqdn_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv6 Destination"])
										flow_index["_source"]["Destination FQDN"] = resolved_fqdn_dict["FQDN"]
										flow_index["_source"]["Destination Domain"] = resolved_fqdn_dict["Domain"]
										if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
												flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]

							# Append this parsed flow to the flow_dic[] for bulk upload
							flow_dic.append(flow_index)
							logging.debug(" Flow index: " + str(flow_index))	
					
					# No template, drop the flow per the standard and advanced the byte position
					else:
						logging.warning(
						" Missing template for flow set " + 
						str(flow_set_id) + 
						" from " + 
						str(sensor_address[0]) + 
						", sequence " + 
						str(packet_attributes["sequence_number"]) + 
						" - dropping per v9 standard"
						)
						
					# Advance to the end of the flow
					byte_position = (flow_set_length + byte_position)-4
					logging.debug(" Ending Data set at " + str(byte_position))
				
				# Rcvd a flow set ID we haven't accounted for
				else:
					logging.warning(" Unknown flow ID " + str(flow_set_id) + " from " + str(sensor_address[0]))
					break
				
			packet_attributes["Reported Flow Count"] = flow_counter	
			logging.debug(" " + str(packet_attributes))
			
			# Have enough flows to do a bulk index to Elasticsearch
			if len(flow_dic) >= bulk_insert_count:
								
				# Perform the bulk upload to the index
				try:
					helpers.bulk(es,flow_dic)
					logging.info(str(len(flow_dic)) + " flow(s) uploaded to Elasticsearch")
				except ValueError as bulk_index_error:
					logging.error(str(len(flow_dic)) + " flow(s) DROPPED - Unable to index flows")
					logging.error(bulk_index_error)
					for flow_debug in flow_dic:
						logging.error(flow_debug)
					
				# Reset flow_dic to empty so flow artifacts don't persist
				flow_dic = []
				
				# Check if the DNS records need to be pruned
				dns_ops.dns_prune()
				
		# Not Netflow v9 packet
		else:
			logging.warning(" Not a Netflow v9 packet from " + str(sensor_address[0]) + ", instead rcvd version " + str(netflow_version) + " - dropping")
			continue
	
	# End of netflow_v9_server()	
	return

# Start Netflow v9 listener	
netflow_v9_server()