# **Fields**

The Flow Analyzer supports a number of fields, which are used by many vendors and platforms. We've made an effort to
analyze and include the most common fields, though there are certain to be fields in use we haven't seen yet.

The default fields are created in the Elasticsearch Flow index by the [build_index.sh script](../Install/build_index.sh) that
is called by the [ubuntu_install.sh installation script](../Install/ubuntu_install.sh). You don't have to create these fields
manually unless you're using your own Elasticsearch cluster.

Here are the commonly used fields supported out-of-the-box:

- Bytes In
- Bytes Out
- Content (Parsed from Source or Destination Domain)
- BGP IPv4 Next Hop
- Destination AS
- Destination Domain (When **dns = True** set in netflow_options.py)
- Destination FQDN (When **dns = True** set in netflow_options.py)
- Destination Mask
- Destination Port
- Destination Type of Service
- Destination VLAN
- Direction
- Dot-1q Customer VLAN ID
- Dot-1q VLAN ID
- First Switched
- Flows
- Flow End Milliseconds
- Flow End Reason
- Flow Sampler ID
- Flow Start Milliseconds
- Flow Type (Netflow v5, Netflow v9, IPFIX)
- ICMP Code
- ICMP Type
- Incoming Destination MAC
- Incoming Source MAC
- Input Interface (SNMP index)
- IP Protocol Version (4 or 6)
- IPv4 Destination
- IPv4 ICMP Type
- IPv4 Next Hop
- IPv4 Source
- IPv6 Destination
- IPv6 Destination Mask
- IPv6 Next Hop
- IPv6 Source
- IPv6 Source Mask
- Last Switched
- Maximum TTL
- Minimum TTL
- MPLS Label Stack Length
- Observation Domain
- Outgoing Destination MAC
- Outgoing Source MAC
- Output Interface (SNMP index)
- Packets In
- Packets Out
- Post-NAT Destination IPv4
- Post-NAT Destination Transport Port
- Post-NAT Source IPv4
- Post-NAT Source Transport Port
- Protocol (Protocol name parsed from Protocol Number)
- Protocol Number
- Sensor (IP address of device sending flow)
- Sequence
- Source AS
- Source Domain (When **dns = True** in netflow_options.py)
- Source FQDN (When **dns = True** in netflow_options.py)
- Source Mask
- Source Port
- Source Type of Service
- Source VLAN
- TCP Flags
- Time (Automatically formatted timestamp in UTC)
- Traffic (HTTP, SSH, SMTP, etc parsed for you)
- Traffic Category (Web, Email, Remote Administration, etc parsed for you)
- Type of Service


**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**