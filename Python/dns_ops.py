# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

import time, datetime, socket, struct, sys, json, socket, logging, logging.handlers
from struct import *
from socket import inet_ntoa
from IPy import IP

import dns_base
import site_category
from netflow_options import *

def dns_add_address(ip):
	
	# Check if IPv4
	if IP(ip).version() == 4:
		
		# Add a /32 mask to make the address usable
		v4_ip = IP(str(ip)+"/32")

		# Check if broadcast address
		if ip == '255.255.255.255':
			return False

		# Check if it's a local address that we're not looking up
		elif lookup_internal is False and v4_ip.iptype() == 'PRIVATE':
			return False

		else:
			pass

	# IPv6 doesn't need this treatment
	else:
		pass				
	
	# Haven't already resolved the IP - do the lookup and cache the result
	if ip not in dns_base.dns_cache["Records"]:
		
		# Reverse-lookup the new IP using the configured DNS server
		fqdn_lookup = str(socket.getfqdn(ip))
		
		# Give the new record a home
		dns_base.dns_cache["Records"][ip] = {}
		dns_base.dns_cache["Records"][ip]['Expires'] = int(time.time())+1800
		
		# If a name was successfully resolved...
		if ip != fqdn_lookup:
			
			# Update the local cache
			dns_base.dns_cache["Records"][ip]["FQDN"] = fqdn_lookup
			
			# Parse the FQDN for Domain information
			if "." in fqdn_lookup:
				fqdns_exploded = fqdn_lookup.split('.') # Blow it up
				domain = str(fqdns_exploded[-2]) + "." + str(fqdns_exploded[-1]) # Grab TLD and second-level domain
				
				# Check for .co.uk, .com.jp, etc...
				if domain in dns_base.second_level_domains:
					domain = str(fqdns_exploded[-3]) + "." + str(fqdns_exploded[-2]) + "." + str(fqdns_exploded[-1]) 
				
				# Not a .co.uk or .com.jp type domain
				else:
					pass
				
				dns_base.dns_cache["Records"][ip]["Domain"] = domain
						
				# Tag the domain with a category if possible
				if domain in site_category.site_categories:
					dns_base.dns_cache["Records"][ip]["Category"] = site_category.site_categories[domain]
				
				# For graph normalization
				else:
					dns_base.dns_cache["Records"][ip]["Category"] = "Uncategorized"

			# Internal hostname without a domain
			else:
				dns_base.dns_cache["Records"][ip]["Domain"] = "None"
				dns_base.dns_cache["Records"][ip]["Category"] = "Uncategorized"
			
		# No DNS record, lookup returned original IP for the domain
		else:
			dns_base.dns_cache["Records"][ip]["FQDN"] = "No record"
			dns_base.dns_cache["Records"][ip]["Domain"] = "No record"
			dns_base.dns_cache["Records"][ip]["Category"] = "Uncategorized"
	
	# Already have the lookup in the cache and it hasn't been pruned yet
	else:
		pass
		
	return dns_base.dns_cache["Records"][ip]

# Prune resolved DNS names after 30min so we don't keep using stale domain names for tagging				
def dns_prune():
	prune_records = []
	current_time = time.time()
	
	if dns_base.dns_cache["Prune"] < current_time:
		for old_records in dns_base.dns_cache["Records"]:
			if dns_base.dns_cache["Records"][old_records]["Expires"] < current_time:
				prune_records.append(old_records)
		for pop_records in prune_records:
			dns_base.dns_cache["Records"].pop(pop_records)
		dns_base.dns_cache["Prune"] = int(current_time + 1800)	
	return