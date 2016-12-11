# Fields
The Flow Analyzer supports a number of fields, which are used by many vendors and platforms. We've made an effort to
analyze and include the most common fields, though there are certain to be fields in use we haven't seen yet.

The default fields are created in the Elasticsearch Flow index by the [build_index.sh script](../Install/build_index.sh) that
is called by the [ubuntu_install.sh installation script](../Install/ubuntu_install.sh). You don't have to create these fields
manually unless you're using your own Elasticsearch cluster.

Here are the commonly used fields supported out-of-the-box for each respective protocol:

# Netflow v5
Flows exported by Netflow v5 are static, include the following fields in this order, and do not require templates:

Field                     | Description   | Measurement Units     | Supported     | Notes |
---                       | ---           | ---                   | ---           | ---   |
Source IP Address         | ---           | --- | Yes | IPv4 only, combine with Source Mask |
Destination IP Address    | ---           | --- | Yes |  IPv4 only, combine with Source Mask |
Next Hop IP Address       | Next hope router IP | --- | Yes |  IPv4 only |
Input Interface<sup>2</sup> | SNMP interface index | --- | Yes |  --- |
Output Interface<sup>2</sup> | SNMP interface index | --- | Yes |  --- |
Packets | Total packets in the flow | --- | Yes |  --- |
Bytes In | Total L3 bytes in the flow | Bytes | Yes |  Referred to in the standard as "Octets" |
First Switched | System uptime at start of the flow | Milliseconds | Yes |  --- |
Last Switched  | System uptime at end of the flow | Milliseconds | Yes |  --- |
Source Port  | TCP / UDP source port | --- | Yes |  Only applicable for TCP / UDP transport protocols |
Destination Port  | TCP / UDP destination port | --- | Yes |  Only applicable for TCP / UDP transport protocols|
TCP Flags | Cumulative OR of TCP flags | --- | Yes |  Must be parsed using math defined in the standard |
Protocol | IANA protocol number | --- | Yes |  [IANA Protocol List](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) |
TOS | TOS number | --- | Yes |  Must be parsed using math defined in the standard |
Source AS<sup>1</sup>         | BGP source Autonomous System number | --- | Yes |  --- |
Destination AS<sup>1</sup>   | BGP destination Autonomous System number | --- | Yes |  --- |
Source Mask<sup>1</sup>      | IP CIDR mask | --- | Yes |  Eg /30 is reported as "30" |
Destination Mask<sup>1</sup> | IP CIDR mask | --- | Yes |  Eg /30 is reported as "30" |

# Netflow v9
Flows exported by Netflow v9 are based on templates, and fields are defined in [RFC 3954](https://www.ietf.org/rfc/rfc3954.txt). Flows may or may not include the following fields depending on the vendor and configured templates:
| Field                     | Description   | Measurement Units     | Supported     | Notes |
| ---                       | ---           | ---                   | ---           | ---   |
| Bytes In | --- | Bytes | Yes | --- |
| Packets In | --- | --- | Yes | --- |
| Source Type of Service | --- | --- | Yes | Parsed integer |
| TCP Flags | Cumulative OR of TCP flags | --- | Yes | Parsed integer |
| Source Port | --- | --- | Yes | --- |
| IPv4 Source | --- | --- | Yes | --- |
| Source Mask | --- | --- | Yes | --- |
| Input Interface<sup>2</sup> | --- | --- | Yes | --- |
| Destination Port | --- | --- | Yes | --- |
| IPv4 Destination | --- | --- | Yes | --- |
| Destination Mask | --- | --- | Yes | --- |
| Output Interface<sup>2</sup> | --- | --- | Yes | --- |
| IPv4 Next Hop | --- | --- | Yes | --- |
| Source AS<sup>1</sup> | --- | --- | Yes | --- |
| Destination AS<sup>1</sup> | --- | --- | Yes | --- |
| BGP IPv4 Next Hop | --- | --- | Yes | --- |
| Multicast Destination Packets | --- | --- | Yes | --- |
| Multicast Destination Bytes | --- | Bytes | Yes | --- |
| Last Switched | System uptime at flow end | Milliseconds | Yes | --- |
| First Switched | System uptime at flow start | Milliseconds | Yes | Subtract from "Last Switched" field to get flow duration (ms) |
| Bytes Out | --- | Bytes | Yes | --- |
| Packets Out | --- | --- | Yes | --- |
| Minimum Packet Length | --- | Bytes | Yes | Verify per vendor documentation |
| Maximum Packet Length | --- | Bytes | Yes | Verify per vendor documentation |
| IPv6 Source | --- | --- | Yes | --- |
| IPv6 Destination | --- | --- | Yes | --- |
| IPv6 Source Mask | --- | --- | Yes | --- |
| IPv6 Destination Mask | --- | --- | Yes | --- |
| IPv6 Flow Label | --- | --- | Yes | --- |
| ICMP Type-Code | --- | --- | Yes | Integer parsed into "ICMP Type" and "ICMP Code" fields using ((ICMP Type * 256) + ICMP Code) |
| IGMP Type | --- | --- | In Progress | Parsed integer |
| Sampling Interval | --- | _n_ * Packet Count | Yes | --- |
| Sampling Algorithm | --- | --- | Yes | Parsed integer |
| Flow Active Timeout | --- | Seconds | Yes | --- |
| Flow Inactive Timeout | --- | Seconds | Yes | --- |
| Engine Type | --- | --- | Yes | Parsed integer |
| Engine ID<sup>2</sup> | --- | --- | Yes | Most devices default to zero value |
| Total Bytes Exported | --- | Bytes | Yes | --- |
| Total Packets Exported | --- | --- | Yes | --- |
| Flows Exported | --- | --- | Yes | Total flows exported so far |
| MPLS Top Label Type | --- | --- | Yes | --- |
| MPLS Top Label IP | --- | --- | Yes | --- |
| Flow Sampler ID | --- | --- | Yes | Set locally per device, defaults vary between vendors |
| Flow Sampler Mode | --- | --- | Yes | Parsed integer |
| Flow Sampler Random Interval | --- | --- | Yes | --- |
| Minimum TTL | --- | Milliseconds | Yes | --- |
| Maximum TTL | --- | Milliseconds | Yes | --- |
| IPv4 ID | --- | --- | Yes | Flow collector reported source - may not match the "Sensor" field |
| Destination Type of Service | --- | --- | Yes | --- |
| Incoming Source MAC | --- | --- | Yes | --- |
| Outgoing Destination MAC | --- | --- | Yes | --- |
| Source VLAN | --- | --- | Yes | --- |
| Destination VLAN | --- | --- | Yes | --- |
| IP Protocol Version | --- | --- | Yes | --- |
| Direction | --- | --- | Yes | Parsed integer value |
| IPv6 Next Hop | --- | --- | Yes | --- |
| BGP IPv6 Next Hop | --- | --- | Yes | --- |
| IPv6 Option Headers | --- | --- | Yes | --- |
| MPLS Label 1 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 2 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 3 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 4 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 5 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 6 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 7 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 8 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 9 | --- | --- | In Progress | Requires special parsing |
| MPLS Label 10 | --- | --- | In Progress | Requires special parsing |

# IPFIX (aka Netflow v10)
**Field table documentation in progress**
Flows exported by IPFIX are based on templates, and may or may not include the following fields depending on the vendor and configured templates:
| Field                     | Description   | Measurement Units     | Supported     | Notes |
| ---                       | ---           | ---                   | ---           | ---   |

<sup>1</sup> Mikrotik - Exported by Mikrotik as "0", not supported by RouterOS as of November 2016.

<sup>2</sup> Local to the individual collector device, must be combined with the device's IP address or another unique identifier.

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**