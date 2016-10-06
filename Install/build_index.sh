# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Build the Netflow index in Elasticsearch
curl -XPOST localhost:9200/_template/flow_template -d '
{
"template": "flow*",
"settings": {
},

"mapping": {
"nested_fields": {
"limit": "150"
}
},

"mappings": {

"Flow": {
"_all": {
"enabled":false
},
"properties": {

"Bytes In": {
"type":"integer"
},
"Bytes Out": {
"type":"integer"
},
"Content": {
"type":"string",
"index":"not_analyzed"
},
"BGP IPv4 Next Hop": {
"type":"ip"
},
"Destination AS": {
"type":"integer"
},
"Destination Domain": {
"type":"string",
"index":"not_analyzed"
},
"Destination FQDN": {
"type":"string",
"index":"not_analyzed"
},
"Destination Mask": {
"type":"integer"
},
"Destination Port": {
"type":"integer"
},
"Destination Type of Service": {
"type":"integer"
},
"Destination VLAN": {
"type":"integer"
},
"Direction": {
"type":"string",
"index":"not_analyzed"
},
"Dot-1q Customer VLAN ID": {
"type":"integer"
},
"Dot-1q VLAN ID": {
"type":"integer"
},
"First Switched": {
"type":"double"
},
"Flows": {
"type":"integer"
},
"Flow End Milliseconds": {
"type":"integer"
},
"Flow End Reason": {
"type":"string",
"index":"not_analyzed"
},
"Flow Sampler ID": {
"type":"integer"
},
"Flow Start Milliseconds": {
"type":"integer"
},
"Flow Type": {
"type":"string",
"index":"not_analyzed"
},
"ICMP Code": {
"type":"integer"
},
"ICMP Type": {
"type":"integer"
},
"Incoming Destination MAC": {
"type":"string",
"index":"not_analyzed"
},
"Incoming Source MAC": {
"type":"string",
"index":"not_analyzed"
},
"Input Interface": {
"type":"integer"
},
"IP Protocol Version": {
"type":"integer"
},
"IPv4 Destination": {
"type":"ip"
},
"IPv4 ICMP Type": {
"type":"integer"
},
"IPv4 Next Hop": {
"type":"ip"
},
"IPv4 Source": {
"type":"ip"
},
"IPv6 Destination": {
"type":"string",
"index":"not_analyzed"
},
"IPv6 Destination Mask": {
"type":"integer"
},
"IPv6 Next Hop": {
"type":"string",
"index":"not_analyzed"
},
"IPv6 Source": {
"type":"string",
"index":"not_analyzed"
},
"IPv6 Source Mask": {
"type":"integer"
},
"Last Switched": {
"type":"double"
},
"Maximum TTL": {
"type":"integer"
},
"Minimum TTL": {
"type":"integer"
},
"MPLS Label Stack Length": {
"type":"integer"
},
"Observation Domain": {
"type":"integer"
},
"Outgoing Destination MAC": {
"type":"string",
"index":"not_analyzed"
},
"Outgoing Source MAC": {
"type":"string",
"index":"not_analyzed"
},
"Output Interface": {
"type":"integer"
},
"Packets In": {
"type":"integer"
},
"Packets Out": {
"type":"integer"
},
"Post-NAT Destination IPv4": {
"type":"ip"
},
"Post-NAT Destination Transport Port": {
"type":"integer"
},
"Post-NAT Source IPv4": {
"type":"ip"
},
"Post-NAT Source Transport Port": {
"type":"integer"
},
"Protocol": {
"type":"string",
"index":"not_analyzed"
},
"Protocol Number": {
"type":"integer"
},
"Sensor": {
"type":"string",
"index":"not_analyzed"
},
"Sequence": {
"type":"integer"
},
"Source AS": {
"type":"integer"
},
"Source Domain": {
"type":"string",
"index":"not_analyzed"
},
"Source FQDN": {
"type":"string",
"index":"not_analyzed"
},
"Source Mask": {
"type":"integer"
},
"Source Port": {
"type":"integer"
},
"Source Type of Service": {
"type":"integer"
},
"Source VLAN": {
"type":"integer"
},
"TCP Flags": {
"type":"integer"
},
"Time": {
"type":"date"
},
"Traffic": {
"type":"string",
"index":"not_analyzed",
"null_value":"Other"
},
"Traffic Category": {
"type":"string",
"index":"not_analyzed",
"null_value":"Other"
},
"Type of Service": {
"type":"integer"
}
},
"dynamic_templates": [
{
"integers": {
"match_mapping_type": "integer",
"mapping": {
"type": "integer"
}
}
},
{
"strings": {
"match_mapping_type": "string",
"mapping": {
"type": "string",
"index":"not_analyzed"
}
}
},
{
"strings": {
"match_mapping_type": "ip",
"mapping": {
"type": "ip"
}
}
},
{
"strings": {
"match_mapping_type": "boolean",
"mapping": {
"type": "boolean"
}
}
}
]
}
}
}'