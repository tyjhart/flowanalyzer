# Copyright 2016, Manito Networks, LLC. All rights reserved
#
# Last modified 6/7/2016

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

# Logging
import logging_ops

# Initialize the DNS global
dns_base.init()

# Set the logging level per https://docs.python.org/2/library/logging.html#levels
# Levels include DEBUG, INFO, WARNING, ERROR, CRITICAL (case matters)
logging.basicConfig(filename='/opt/manitonetworks/flow/netflow_v5.log',level=logging.WARNING)
#logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Netflow v5')

# Set packet information variables
# Do not modify these variables, Netflow v5 packet structure is static
packet_header_size = 24
flow_record_size = 48

# Set up the socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', netflow_v5_port))
	logger.info('Bound to port ' + str(netflow_v5_port))
except ValueError as socket_error:
	logger.critical(': Could not open or bind a socket on port ' + str(netflow_v9_port))
	logger.critical(str(socket_error))
	sys.exit()

# Spin up ES instance connection
try:
	es = Elasticsearch([elasticsearch_host])
	logger.info('Connected to Elasticsearch')
except ValueError as elasticsearch_connect_error:
	logger.critical('Could not connect to Elasticsearch')
	logger.critical(str(elasticsearch_connect_error))
	sys.exit()

# Netflow server
def netflow_v5_server():
	
	# Stage the flows for the bulk API index operation 
	flow_dic = []
	
	while True:
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
			
		try:
			(netflow_version, flow_count) = struct.unpack('!HH',flow_packet_contents[0:4]) #Version of NF packet and count of Flows in packet
			logger.debug("Rcvd " + str(flow_count) + " flow(s) from " + str(sensor_address[0]))
		except:
			logger.warning(logging_ops.log_time() + " Failed unpacking flow header from " + str(sensor_address[0]))
			continue
		
		# Rcvd a Netflow v5 packet, parse it
		if netflow_version == 5:
			
			# Set overall flow counter
			flow_num = 0

			# Iterate over flows in packet
			for flow in range(0, flow_count):
				now = datetime.datetime.utcnow() # Timestamp for flow rcv
				logger.debug(logging_ops.log_time() + " Flow " + str(flow_num+1) + " of " + str(flow_count))
				base = packet_header_size + (flow_num * flow_record_size)
				data = struct.unpack('!IIIIHH',flow_packet_contents[base+16:base+36])
				protocol_number = ord(flow_packet_contents[base+38]) # For protocol name lookup
				
				# Protocol Name
				try:
					flow_protocol = protocol_type[protocol_number]["Name"]
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
				"IPv4 Source": inet_ntoa(flow_packet_contents[base+0:base+4]),
				"Source Port": data[4],
				"IPv4 Destination": inet_ntoa(flow_packet_contents[base+4:base+8]),
				"IPv4 Next Hop": inet_ntoa(flow_packet_contents[base+8:base+12]),
				"Input Interface": struct.unpack('!h',flow_packet_contents[base+12:base+14])[0],
				"Output Interface": struct.unpack('!h',flow_packet_contents[base+14:base+16])[0],
				"Destination Port": data[5],
				"Protocol": flow_protocol,
				"Protocol Number": protocol_number,
				"Type of Service": struct.unpack('!B',flow_packet_contents[base+39])[0],
				"Source AS": struct.unpack('!h',flow_packet_contents[base+40:base+42])[0],
				"Destination AS": struct.unpack('!h',flow_packet_contents[base+42:base+44])[0],
				"Bytes In": data[1]
				}
				}

				# Protocol Category for protocols not TCP/UDP
				if "Category" in protocol_type[protocol_number]:
					flow_index["_source"]['Traffic Category'] = protocol_type[protocol_number]["Category"]
				
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
				
				logger.debug(logging_ops.log_time() + " Flow data: " + str(flow_index))		
				
				# Add the parsed flow to flow_dic for bulk insert
				flow_dic.append(flow_index)
				flow_num += 1
				
			if len(flow_dic) >= bulk_insert_count:
				
				try:
					helpers.bulk(es,flow_dic)
					logger.info(str(len(flow_dic))+" flow(s) uploaded to Elasticsearch")
					flow_dic = []
				except ValueError as bulk_index_error:
					logger.warning(logging_ops.log_time() + " " + str(len(flow_dic))+" flow(s) DROPPED, unable to index flows")
					logger.warning(logging_ops.log_time() + " " + bulk_index_error.message)
					flow_dic = []
					pass
				
				# Check if the DNS records need to be pruned
				dns_ops.dns_prune()
			
		# Got something else, drop it
		else:
			logger.warning(logging_ops.log_time() + " Rcvd non-Netflow v5 packet from " + str(sensor_address[0]))
			continue
		
	return

# Start Netflow v5 listener	
netflow_v5_server()