# Copyright (c) 2016, Manito Networks, LLC
# All rights reserved.

# Build the sFlow index in Elasticsearch
curl -XPOST localhost:9200/_template/sflow_template -d '
{
"template": "sflow*",
"settings": {
},

"mapping": {
"nested_fields": {
"limit": "300"
}
},

"mappings": {

"sFlow": {
"_all": {
"enabled":false
},
"properties": {

"BGP IPv4 Next Hop":                    {"type":"ip"},
"Bytes In":                             {"type":"long"},
"Bytes Out":                            {"type":"long"},
"Bytes Read":                           {"type":"long"},
"Bytes Written":                        {"type":"long"},
"Content":                              {"type":"string","index":"not_analyzed"},
"Context Switch Count":                 {"type":"long"},
"CPU Count":                            {"type":"integer"},
"CPU Idle Time":                        {"type":"long"},
"CPU MHz":                              {"type":"integer"},
"CPU Nice Time":                        {"type":"long"},
"CPU System Time":                      {"type":"long"},
"CPU Time Servicing INT":               {"type":"long"},
"CPU Time Servicing SINT":              {"type":"long"},
"CPU Time Waiting":                     {"type":"long"},
"CPU User Time":                        {"type":"long"},
"Data Length":                          {"type":"integer"},
"Destination AS":                       {"type":"integer"},
"Destination Domain":                   {"type":"string","index":"not_analyzed"},
"Destination FQDN":                     {"type":"string","index":"not_analyzed"},
"Destination MAC":                      {"type":"string","index":"not_analyzed"},
"Destination Mask":                     {"type":"integer"},
"Destination Port":                     {"type":"integer"},
"Destination Priority":                 {"type":"integer"},
"Destination Type of Service":          {"type":"integer"},
"Destination VLAN":                     {"type":"integer"},
"Direction":                            {"type":"string","index":"not_analyzed"},
"Disk Free":                            {"type":"long"},
"Disk Total":                           {"type":"long"},
"Dot-1q Customer VLAN ID":              {"type":"integer"},
"Dot-1q VLAN ID":                       {"type":"integer"},
"Drops":                                {"type":"long"},
"Drops In":                             {"type":"long"},
"Drops Out":                            {"type":"long"},
"Enterprise, Format":                   {"type":"string","index":"not_analyzed"},
"Errors In":                            {"type":"long"},
"Errors Out":                           {"type":"long"},
"First Switched":                       {"type":"long"},
"Flows":                                {"type":"integer"},
"Flow End Milliseconds":                {"type":"long"},
"Flow End Reason":                      {"type":"string","index":"not_analyzed"},
"Flow Sampler ID":                      {"type":"integer"},
"Flow Start Milliseconds":              {"type":"long"},
"Flow Type":                            {"type":"string","index":"not_analyzed"},
"Frame Length":                         {"type":"integer"},
"Header":                               {"type":"string","index":"not_analyzed"},
"Header Protocol":                      {"type":"string","index":"not_analyzed"},
"Header Protocol Number":               {"type":"integer"},
"Header Size":                          {"type":"integer"},
"ICMP Code":                            {"type":"integer"},
"ICMP Type":                            {"type":"integer"},
"Incoming Destination MAC":             {"type":"string","index":"not_analyzed"},
"Incoming Source MAC":                  {"type":"string","index":"not_analyzed"},
"Input Interface":                      {"type":"integer"},
"Interface Direction":                  {"type":"string","index":"not_analyzed"},
"Interface Status":                     {"type":"string","index":"not_analyzed"},
"Interface Speed":                      {"type":"long"},
"Interface Type":                       {"type":"string","index":"not_analyzed"},
"Interrupts":                           {"type":"long"},
"IP Protocol Version":                  {"type":"integer"},
"IPv4 Destination":                     {"type":"ip"},
"IPv4 ICMP Type":                       {"type":"integer"},
"IPv4 Next Hop":                        {"type":"ip"},
"IPv4 Source":                          {"type":"ip"},
"IPv6 Destination":                     {"type":"string","index":"not_analyzed"},
"IPv6 Destination Mask":                {"type":"integer"},
"IPv6 Next Hop":                        {"type":"string","index":"not_analyzed"},
"IPv6 Source":                          {"type":"string","index":"not_analyzed"},
"IPv6 Source Mask":                     {"type":"integer"},
"Last Switched":                        {"type":"long"},
"Maximum TTL":                          {"type":"integer"},
"Minimum TTL":                          {"type":"integer"},
"Multicast Packets In":                 {"type":"integer"},
"Multicast Packets Out":                {"type":"integer"},
"MPLS Label Stack Length":              {"type":"integer"},
"Observation Domain":                   {"type":"integer"},
"Outgoing Destination MAC":             {"type":"string","index":"not_analyzed"},
"Outgoing Source MAC":                  {"type":"string","index":"not_analyzed"},
"Output Interface":                     {"type":"integer"},
"Packets In":                           {"type":"integer"},
"Packets Out":                          {"type":"integer"},
"Post-NAT Destination IPv4":            {"type":"ip"},
"Post-NAT Destination Transport Port":  {"type":"integer"},
"Post-NAT Source IPv4":                 {"type":"ip"},
"Post-NAT Source Transport Port":       {"type":"integer"},
"Protocol":                             {"type":"string","index":"not_analyzed"},
"Protocol Number":                      {"type":"integer"},
"Record Count":                         {"type":"integer"},
"Sample Pool":                          {"type":"integer"},
"Sampling Rate":                        {"type":"integer"},
"Sensor":                               {"type":"string","index":"not_analyzed"},
"Sequence":                             {"type":"integer"},
"Source AS":                            {"type":"integer"},
"Source Domain":                        {"type":"string","index":"not_analyzed"},
"Source FQDN":                          {"type":"string","index":"not_analyzed"},
"Source ID Type":                          {"type":"string","index":"not_analyzed"},
"Source MAC":                           {"type":"string","index":"not_analyzed"},
"Source Mask":                          {"type":"integer"},
"Source Port":                          {"type":"integer"},
"Source Type":                          {"type":"string","index":"not_analyzed"},
"Source Type of Service":               {"type":"integer"},
"Source VLAN":                          {"type":"integer"},
"Stripped":                             {"type":"integer"},
"Sub Agent":                            {"type":"integer"},
"TCP Flags":                            {"type":"integer"},
"Time":                                 {"type":"date"},
"Traffic":                              {"type":"string","index":"not_analyzed","null_value":"Other"},
"Traffic Category":                     {"type":"string","index":"not_analyzed","null_value":"Other"},
"Type of Service":                      {"type":"integer"}
},

"dynamic_templates": [
{
"integers": {"match_mapping_type": "integer","mapping": {"type": "integer"}}
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