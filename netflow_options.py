# Copyright 2016, Manito Networks, LLC. All rights reserved
#
# Last modified 4/19/2016 

#### Tuning options for Netflow v5, 9, and 10 (IPFIX) ####
#
#### Bulk Insert Cache ####
# bulk_insert_count sets the amount of flow records that will be cached before bulk indexing into Elasticsearch
# 700 - 800 has been found to be good for smaller WISPs and medium-sized organizations
# ~200 has been found to be good for small organizations
# < 100 will create a large amount of index connections (with only a few flow records in each) and could affect performance
# 1000 or more may be necessary for ISPs and larger organizations
# A good value will balance the amount of flows in a bulk transaction with how often transactions should occur
# A small organization with only a few dozen flows a minute would take forever to fill up a 700 flow cache
# A WISP or large organization would fill up a 300 flow buffer a few times a second, causing a massive bloat in indexing connections
# Tuning is necessary for each organization, set the variable below to a sane integer.
bulk_insert_count = 700

#### Netflow v5 UDP Port ####
# This is the port that the Netflow v5 listener runs on.
# By default the port is set to 2055, the typical Netflow v5 port.
netflow_v5_port = 2055

#### Netflow v9 UDP Port ####
# This is the port that the Netflow v9 listener runs on.
# By default the port is set to 9995, the typical Netflow v9 port.
netflow_v9_port = 9995

#### Netflow v10 (IPFIX) UDP Port ####
# This is the port that the IPFIX listener runs on.
# By default the port is set to 4739, the typical IPFIX port.
ipfix_port = 4739

#### DNS Lookups ####
# The appliance will attempt to do a reverse DNS lookup for IP addresses reported in flows,
# in order to make correlations between traffic and different domains. Traffic to / from certain
# domains is also categorized based on domain name for higher-level reporting. The appliance
# must be pointed to an **INTERNAL** DNS server, which is able to resolve internal addresses, as
# well as addresses outside the organization. While the appliance does cache the reverse-DNS entries
# once they are made, and prunes them automatically much like the real DNS system, turning this on
# can generate a high volume of DNS queries, which is why you must point the appliance to an internal
# DNS server. **DO NOT** point the appliance to an external DNS service like Google's Public DNS, DynDNS,
# or other services - the high volume of requests will most likely result in the appliance's IP getting
# throttled by that DNS resolver, and possibly cut off due to unusually high volumes of requests.
#
# Set to False if you don't want to enable DNS lookups.
dns = False

#### End tuning ####