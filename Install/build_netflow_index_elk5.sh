# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Build the Netflow index in Elasticsearch
curl -XPOST localhost:9200/_template/flow_template -d '
{
"template": "flow*","settings": {},

"mapping": {"nested_fields": {"limit": "150"}},

"mappings": {

"Flow": {"_all": {"enabled":false},

"properties": {

"Bytes In":                             {"type":"integer"},
"Bytes Out":                            {"type":"integer"},
"Content":                              {"type":"keyword"},
"BGP IPv4 Next Hop":                    {"type":"ip"},
"Destination AS":                       {"type":"integer"},
"Destination Domain":                   {"type":"keyword"},
"Destination FQDN":                     {"type":"keyword"},
"Destination Mask":                     {"type":"integer"},
"Destination Port":                     {"type":"integer"},
"Destination Type of Service":          {"type":"integer"},
"Destination VLAN":                     {"type":"integer"},
"Direction":                            {"type":"keyword"},
"Dot-1q Customer VLAN ID":              {"type":"integer"},
"Dot-1q VLAN ID":                       {"type":"integer"},
"First Switched":                       {"type":"double"},
"Flows":                                {"type":"integer"},
"Flow End Milliseconds":                {"type":"integer"},
"Flow End Reason":                      {"type":"keyword"},
"Flow Sampler ID":                      {"type":"integer"},
"Flow Start Milliseconds":              {"type":"integer"},
"Flow Type":                            {"type":"keyword"},
"ICMP Code":                            {"type":"integer"},
"ICMP Type":                            {"type":"integer"},
"Incoming Destination MAC":             {"type":"keyword"},
"Incoming Source MAC":                  {"type":"keyword"},
"Input Interface":                      {"type":"integer"},
"IP Protocol Version":                  {"type":"integer"},
"IPv4 Destination":                     {"type":"ip"},
"IPv4 ICMP Type":                       {"type":"integer"},
"IPv4 Next Hop":                        {"type":"ip"},
"IPv4 Source":                          {"type":"ip"},
"IPv6 Destination":                     {"type":"ip"},
"IPv6 Destination Mask":                {"type":"integer"},
"IPv6 Next Hop":                        {"type":"ip"},
"IPv6 Source":                          {"type":"ip"},
"IPv6 Source Mask":                     {"type":"integer"},
"Last Switched":                        {"type":"double"},
"Maximum TTL":                          {"type":"integer"},
"Minimum TTL":                          {"type":"integer"},
"MPLS Label Stack Length":              {"type":"integer"},
"Observation Domain":                   {"type":"integer"},
"Outgoing Destination MAC":             {"type":"keyword"},
"Outgoing Source MAC":                  {"type":"keyword"},
"Output Interface":                     {"type":"integer"},
"Packets In":                           {"type":"integer"},
"Packets Out":                          {"type":"integer"},
"Post-NAT Destination IPv4":            {"type":"ip"},
"Post-NAT Destination Transport Port":  {"type":"integer"},
"Post-NAT Source IPv4":                 {"type":"ip"},
"Post-NAT Source Transport Port":       {"type":"integer"},
"Protocol":                             {"type":"keyword"},
"Protocol Number":                      {"type":"integer"},
"Sensor":                               {"type":"keyword"},
"Sequence":                             {"type":"integer"},
"Source AS":                            {"type":"integer"},
"Source Domain":                        {"type":"keyword"},
"Source FQDN":                          {"type":"keyword"},
"Source Mask":                          {"type":"integer"},
"Source Port":                          {"type":"integer"},
"Source Type of Service":               {"type":"integer"},
"Source VLAN":                          {"type":"integer"},
"TCP Flags":                            {"type":"integer"},
"Time":                                 {"type":"date"},
"Traffic":                              {"type":"keyword","null_value":"Other"},
"Traffic Category":                     {"type":"keyword","null_value":"Other"},
"Type of Service":                      {"type":"integer"}
},
"dynamic_templates": [
{"integers": {"match_mapping_type":"integer","mapping":{"type":"integer"}}},
{"integers": {"match_mapping_type":"long","mapping":{"type":"long"}}},
{"strings": {"match_mapping_type":"string","mapping":{"type":"keyword","index":"true"}}},
{"strings": {"match_mapping_type":"ip","mapping":{"type":"ip"}}},
{"strings": {"match_mapping_type":"boolean","mapping":{"type":"boolean"}}}
]
}
}
}'