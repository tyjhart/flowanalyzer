# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

# Import what we need
import time, datetime, socket, struct, sys, json, socket, logging, logging.handlers, getopt, parser_modules
from struct import *
from socket import inet_ntoa
from elasticsearch import Elasticsearch,helpers
from IPy import IP

# Protocol numbers and types of traffic for comparison
from protocol_numbers import protocol_type
from defined_ports import registered_ports,other_ports
from netflow_options import *

### Get the command line arguments ###
try:
	arguments = getopt.getopt(sys.argv[1:],"hl:",["--help","log="])
	
	for option_set in arguments:
		for opt,arg in option_set:
						
			if opt in ('-l','--log'): # Log level
				arg = arg.upper() # Uppercase for matching and logging.basicConfig() format
				if arg in ["CRITICAL","ERROR","WARNING","INFO","DEBUG"]:
					log_level = arg # Use what was passed in arguments

			elif opt in ('-h','--help'):
				with open("./help.txt") as help_file:
					print(help_file.read())
				sys.exit()

			else:
				pass

except Exception:
    sys.exit("Unsupported or badly formed options, see -h for available arguments.") 

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

# Set packet information variables
#
# Netflow v5 packet structure is STATIC - DO NOT MODIFY THESE VALUES
packet_header_size = 24
flow_record_size = 48

# Check if the Netflow v5 port is specified
try:
	netflow_v5_port
except NameError: # Not specified, use default
	netflow_v5_port = 2055
	logging.warning("Netflow v5 port not set in netflow_options.py, defaulting to " + str(netflow_v5_port) + " - OK")

# Set up the socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', netflow_v5_port))
	logging.critical("Bound to port " + str(netflow_v5_port) + " - OK")
except Exception as socket_error:
	logging.critical("Could not open or bind a socket on port " + str(netflow_v9_port))
	logging.critical(str(socket_error))
	sys.exit()

# ElasticSearch class
es = Elasticsearch([elasticsearch_host])

# DNS lookup class
name_lookups = parser_modules.name_lookups()

# TCP / UDP identification class
tcp_udp = parser_modules.ports_and_protocols()

### Netflow v5 Collector ###
if __name__ == "__main__":
	
	# Stage the flows for the bulk API index operation 
	flow_dic = []

	# Number of cached records
	record_num = 0
	
	while True:
		
		flow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)
			
		# Unpack the header
		try:
			logging.info("Unpacking header from " + str(sensor_address[0]))
			packet_keys = ["netflow_version","flow_count","sys_uptime","unix_secs","unix_nsecs","flow_seq","engine_type","engine_id"] # Netflow v5 packet fields
			packet_values = struct.unpack('!HHIIIIBB',flow_packet_contents[0:22]) # Version of NF packet and count of Flows in packet
			packet_contents = dict(zip(packet_keys,packet_values)) # v5 packet fields and values
			logging.info(str(packet_contents))
			logging.info("Finished unpacking header from " + str(sensor_address[0]))
		
		# Failed to unpack the header
		except Exception as flow_header_error:
			logging.warning("Failed unpacking header from " + str(sensor_address[0]) + " - " + str(flow_header_error))
			continue
		
		# Check the Netflow version
		if packet_contents["netflow_version"] != 5:
			logging.warning("Received a non-v5 Netflow packet - SKIPPING")
			continue

		# Iterate over flows in packet
		for flow_num in range(0, packet_contents["flow_count"]):
			now = datetime.datetime.utcnow() # Timestamp for flow rcv
			logging.info("Parsing flow " + str(flow_num+1))
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
			except Exception as protocol_error:
				flow_protocol = "Other" # Should never see this unless undefined protocol in use
				logging.warning("Unknown protocol number - " + str(protocol_num) + ". Please report to the author for inclusion.")
				logging.warning(str(protocol_error))

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
			"Engine Type": packet_contents["engine_type"],
			"Engine ID": packet_contents["engine_id"]
			}
			}

			# Protocol Category for protocols not TCP/UDP
			if "Category" in protocol_type[protocol_num]:
				flow_index["_source"]['Traffic Category'] = protocol_type[protocol_num]["Category"]
			
			# If the protocol is TCP or UDP try to apply traffic labels
			if flow_index["_source"]["Protocol Number"] in [6,17]:		
				traffic_and_category = tcp_udp.port_traffic_classifier(src_port,dest_port)
				flow_index["_source"]["Traffic"] = traffic_and_category["Traffic"]
				flow_index["_source"]["Traffic Category"] = traffic_and_category["Traffic Category"]
			
			# Perform DNS lookups if enabled
			if dns is True:	
				
				# Source DNS
				source_lookups = name_lookups.ip_names(4,flow_index["_source"]["IPv4 Source"])
				flow_index["_source"]["Source FQDN"] = source_lookups["FQDN"]
				flow_index["_source"]["Source Domain"] = source_lookups["Domain"]

				# Destination DNS
				destination_lookups = name_lookups.ip_names(4,flow_index["_source"]["IPv4 Destination"])
				flow_index["_source"]["Destination FQDN"] = destination_lookups["FQDN"]
				flow_index["_source"]["Destination Domain"] = destination_lookups["Domain"]

				# Content
				src_dest_categories = [source_lookups["Content"],destination_lookups["Content"]]
				
				try: # Pick unique domain Content != "Uncategorized"
					unique_content = [category for category in src_dest_categories if category != "Uncategorized"]
					flow_index["_source"]["Content"] = unique_content[0]
				except: # No unique domain Content
					flow_index["_source"]["Content"] = "Uncategorized"
			
			logging.debug("Current flow data: " + str(flow_index))
			logging.info("Finished flow " + str(flow_num+1) + " of " + str(packet_contents["flow_count"]))		
			
			# Add the parsed flow to flow_dic for bulk insert
			flow_dic.append(flow_index)

			# Increment the record counter
			record_num += 1
				
			# Elasticsearch bulk insert
			if record_num >= bulk_insert_count:
				
				try:
					helpers.bulk(es,flow_dic)
					logging.info(str(len(flow_dic))+" flow(s) uploaded to Elasticsearch - OK")
				except ValueError as bulk_index_error:
					logging.critical(str(len(flow_dic))+" flow(s) DROPPED, unable to index flows - FAIL")
					logging.critical(bulk_index_error.message)

				# Reset flow_dic
				flow_dic = []

				# Reset the record counter
				record_num = 0