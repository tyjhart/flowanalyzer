# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Import what we need
import time, datetime, socket, struct, sys, json, socket, logging, logging.handlers
from struct import *
from socket import inet_ntoa
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from IPy import IP

# Protocol numbers and types of traffic for comparison
from protocol_numbers import protocol_type
from defined_ports import registered_ports,other_ports
from netflow_options import *

# DNS Resolution
import dns_base
import dns_ops

# Initialize the DNS global
dns_base.init()

# Set the logging level per https://docs.python.org/2/library/logging.html#levels
# Levels include DEBUG, INFO, WARNING, ERROR, CRITICAL (case matters)
logging.basicConfig(level=logging.WARNING)

# Set packet information variables
# DO NOT modify these variables, Netflow v5 packet structure is STATIC
packet_header_size = 24
flow_record_size = 48

# Set up the socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', netflow_v5_port))
	logging.warning(' Bound to port ' + str(netflow_v5_port) + ' - OK')
except ValueError as socket_error:
	logging.critical(' Could not open or bind a socket on port ' + str(netflow_v9_port))
	logging.critical(str(socket_error))
	sys.exit()

# Spin up ES instance connection
try:
	es = Elasticsearch([elasticsearch_host])
	logging.warning(' Connected to Elasticsearch at ' + elasticsearch_host + ' - OK')
except ValueError as elasticsearch_connect_error:
	logging.critical(' Could not connect to Elasticsearch at ' + elasticsearch_host)
	logging.critical(str(elasticsearch_connect_error))
	sys.exit()

# Netflow server
def netflow_v5_server():
	
	# Stage the flows for the bulk API index operation 
	flow_dic = []
	
	while True:
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
			
		try:
			(netflow_version,
			flow_count,
			sys_uptime,
			unix_secs,
			unix_nsecs,
			flow_seq,
			engine_type,
			engine_id) = struct.unpack('!HHIIIIBB',flow_packet_contents[0:22]) #Version of NF packet and count of Flows in packet
			
			logging.debug("Rcvd " + str(flow_count) + " flow(s) from " + str(sensor_address[0]))
		
		except Exception as flow_header_error:
			logging.warning(" Failed unpacking flow header from " + str(sensor_address[0]) + " - " + str(flow_header_error))
			continue
		
		# Rcvd a Netflow v5 packet, parse it
		if netflow_version == 5:

			# Iterate over flows in packet
			for flow_num in range(0, flow_count):
				now = datetime.datetime.utcnow() # Timestamp for flow rcv
				logging.debug(" Flow " + str(flow_num+1) + " of " + str(flow_count))
				base = packet_header_size + (flow_num * flow_record_size) # Calculate flow starting point
				
				(ip_source,
				ip_destination,
				next_hop,
				input_interface,
				output_interface,
				total_packets,
				total_bytes,
				sysuptime_start,
				sysuptime_stop,
				src_port,
				dest_port,
				pad,
				tcp_flags,
				protocol_num,
				type_of_service,
				source_as,
				destination_as,
				source_mask,
				destination_mask) = struct.unpack('!4s4s4shhIIIIHHcBBBhhBB',flow_packet_contents[base+0:base+46])
				
				# Protocol Name
				try:
					flow_protocol = protocol_type[protocol_num]["Name"]
				except:
					flow_protocol = "Other" # Should never see this unless undefined protocol in use
		
				flow_index = {
				"_index": str("flow-" + now.strftime("%Y-%m-%d")),
				"_type": "Flow",
				"_source": {
				"Flow Type": "Netflow v5",
				"IP Protocol Version": 4,
				"Sensor": sensor_address[0],
				"Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z",
				"IPv4 Source": inet_ntoa(ip_source),
				"Bytes In": total_bytes,
				"TCP Flags": tcp_flags,
				"Packets In": total_packets,
				"Source Port": src_port,
				"IPv4 Destination": inet_ntoa(ip_destination),
				"IPv4 Next Hop": inet_ntoa(next_hop),
				"Input Interface": input_interface,
				"Output Interface": output_interface,
				"Destination Port": dest_port,
				"Protocol": flow_protocol,
				"Protocol Number": protocol_num,
				"Type of Service": type_of_service,
				"Source AS": source_as,
				"Destination AS": destination_as,
				"Source Mask": source_mask,
				"Destination Mask": destination_mask,
				"Engine ID": engine_id
				}
				}

				# Protocol Category for protocols not TCP/UDP
				if "Category" in protocol_type[protocol_num]:
					flow_index["_source"]['Traffic Category'] = protocol_type[protocol_num]["Category"]
				
				# If the protocol is TCP or UDP try to apply traffic labels
				if flow_index["_source"]["Protocol Number"] == 6 or flow_index["_source"]["Protocol Number"] == 17:
					
					source_port = flow_index["_source"]["Source Port"]
					destination_port = flow_index["_source"]["Destination Port"]

					if source_port in registered_ports:
						flow_index["_source"]['Traffic'] = registered_ports[source_port]["Name"]
						if "Category" in registered_ports[source_port]:
							flow_index["_source"]['Traffic Category'] = registered_ports[source_port]["Category"]
					
					elif source_port in other_ports:
						flow_index["_source"]['Traffic'] = other_ports[source_port]["Name"]
						if "Category" in other_ports[source_port]:
							flow_index["_source"]['Traffic Category'] = other_ports[source_port]["Category"]			
					
					elif destination_port in registered_ports:
						flow_index["_source"]['Traffic'] = registered_ports[destination_port]["Name"]
						if "Category" in registered_ports[destination_port]:
							flow_index["_source"]['Traffic Category'] = registered_ports[destination_port]["Category"]
					
					elif destination_port in other_ports:
						flow_index["_source"]['Traffic'] = other_ports[destination_port]["Name"]
						if "Category" in other_ports[destination_port]:
							flow_index["_source"]['Traffic Category'] = other_ports[destination_port]["Category"]
					
					else:
						# To normalize graphs
						flow_index["_source"]['Traffic'] = "Other"

					# Tag Traffic Category as "Other" to normalize graphs
					if "Traffic Category" not in flow_index["_source"]:
						flow_index["_source"]['Traffic Category'] = "Other"		
				
				# Perform DNS lookups if enabled
				if dns is True:	
					
					# Tag the flow with Source FQDN and Domain info (if available)
					resolved_fqdn_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv4 Source"])
					if resolved_fqdn_dict:
						flow_index["_source"]["Source FQDN"] = resolved_fqdn_dict["FQDN"]
						flow_index["_source"]["Source Domain"] = resolved_fqdn_dict["Domain"]
						flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]
					
					# Tag the flow with Source FQDN and Domain info (if available)	
					resolved_fqdn_dict = dns_ops.dns_add_address(flow_index["_source"]["IPv4 Destination"])
					if resolved_fqdn_dict:
						flow_index["_source"]["Destination FQDN"] = resolved_fqdn_dict["FQDN"]
						flow_index["_source"]["Destination Domain"] = resolved_fqdn_dict["Domain"]
						if "Content" not in flow_index["_source"] or flow_index["_source"]["Content"] == "Uncategorized":
							flow_index["_source"]["Content"] = resolved_fqdn_dict["Category"]	
				
				logging.debug(" Flow data: " + str(flow_index))		
				
				# Add the parsed flow to flow_dic for bulk insert
				flow_dic.append(flow_index)
				
			if len(flow_dic) >= bulk_insert_count:
				
				try:
					helpers.bulk(es,flow_dic)
					logging.info(str(len(flow_dic))+" flow(s) uploaded to Elasticsearch")
					flow_dic = []
				except ValueError as bulk_index_error:
					logging.warning(str(len(flow_dic))+" flow(s) DROPPED, unable to index flows")
					logging.warning(bulk_index_error.message)
					flow_dic = []
					pass
				
				# Check if the DNS records need to be pruned
				dns_ops.dns_prune()
			
		# Got something else, drop it
		else:
			logging.warning(" Rcvd non-Netflow v5 packet from " + str(sensor_address[0]))
			continue
		
	return

# Start Netflow v5 listener	
netflow_v5_server()