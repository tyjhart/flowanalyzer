# Copyright 2016, Manito Networks, LLC. All rights reserved
#
# Last modified 6/9/2016

import time, datetime, socket, struct, sys, json, socket, logging, logging.handlers
from struct import *
from socket import inet_ntoa

import dns_base
import site_category

def dns_add_address(ip):
	
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
				fqdns_exploded = fqdn_lookup.split('.')
				domain = str(fqdns_exploded[-2]) + "." + str(fqdns_exploded[-1]) 
				
				# Check for .co.uk, .com.jp, etc...
				if domain in dns_base.second_level_domains:
					domain = str(fqdns_exploded[-3]) + "." + str(fqdns_exploded[-2]) + "." + str(fqdns_exploded[-1]) 
				else:
					pass
				
				dns_base.dns_cache["Records"][ip]["Domain"] = domain
						
				if domain in site_category.site_categories:
					dns_base.dns_cache["Records"][ip]["Category"] = site_category.site_categories[domain]
				else:
					dns_base.dns_cache["Records"][ip]["Category"] = "Uncategorized"

			else:
				dns_base.dns_cache["Records"][ip]["Domain"] = "None"
				dns_base.dns_cache["Records"][ip]["Category"] = "Uncategorized"
			
		else:
			dns_base.dns_cache["Records"][ip]["FQDN"] = "No record"
			dns_base.dns_cache["Records"][ip]["Domain"] = "No record"
			dns_base.dns_cache["Records"][ip]["Category"] = "Uncategorized"
	
	# Already have the lookup in the cache
	else:
		pass
		
	return dns_base.dns_cache["Records"][ip]
				
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
	else:
		return