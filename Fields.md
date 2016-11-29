# Fields

The Flow Analyzer supports a number of fields, which are used by many vendors and platforms. We've made an effort to
analyze and include the most common fields, though there are certain to be fields in use we haven't seen yet.

The default fields are created in the Elasticsearch Flow index by the [build_index.sh script](../Install/build_index.sh) that
is called by the [ubuntu_install.sh installation script](../Install/ubuntu_install.sh). You don't have to create these fields
manually unless you're using your own Elasticsearch cluster.

Here are the commonly used fields supported out-of-the-box:

- Bytes In
- Bytes Out<sup>2</sup>
- Content (Parsed from Source or Destination Domain)
- BGP IPv4 Next Hop
- Destination AS<sup>1</sup>
- Destination Domain (When **dns = True** set in netflow_options.py)
- Destination FQDN (When **dns = True** set in netflow_options.py)
- Destination Mask<sup>1</sup>
- Destination Port
- Destination Type of Service
- Destination VLAN
- Direction<sup>2</sup>
- Dot-1q Customer VLAN ID
- Dot-1q VLAN ID
- First Switched
- Flows
- Flow End Milliseconds
- Flow End Reason
- Flow Sampler ID<sup>3</sup>
- Flow Start Milliseconds
- Flow Type (Netflow v5, Netflow v9, IPFIX)
- ICMP Code
- ICMP Type
- Incoming Destination MAC
- Incoming Source MAC
- Input Interface (SNMP index)<sup>3</sup>
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
- Observation Domain<sup>3</sup>
- Outgoing Destination MAC
- Outgoing Source MAC
- Output Interface (SNMP index)<sup>3</sup>
- Packets In
- Packets Out<sup>2</sup>
- Post-NAT Destination IPv4
- Post-NAT Destination Transport Port
- Post-NAT Source IPv4
- Post-NAT Source Transport Port
- Protocol<sup>4</sup> (Protocol name parsed from IANA-registered Protocol Number)
- Protocol Number<sup>4</sup>
- Sensor (IP address of device sending flow)
- Sequence<sup>3</sup>
- Source AS<sup>1</sup>
- Source Domain (When **dns = True** in netflow_options.py) [See Tuning documentation](Tuning.md)
- Source FQDN (When **dns = True** in netflow_options.py) [See Tuning documentation](Tuning.md)
- Source Mask<sup>1</sup>
- Source Port
- Source Type of Service
- Source VLAN<sup>3</sup>
- [TCP Flags](http://www.manitonetworks.com/flow-management/2016/10/16/decoding-tcp-flags)
- Time (Automatically formatted timestamp in UTC)
- Traffic (HTTP, SSH, SMTP, etc parsed for you)
- Traffic Category (Web, Email, Remote Administration, etc parsed for you)
- Type of Service

<sup>1</sup> Mikrotik - Exported by Mikrotik as "0", but not supported yet by RouterOS as of Oct. 2016

<sup>2</sup> Not all platforms support Egress (Direction = Out) flow reporting, most only support Ingress (Direction = In) reporting.

<sup>3</sup> Local to the individual collector devices - match this with the Sensor ID.

<sup>4</sup> IANA-registered protocols only. See the official IANA list of protocol numbers and names.

**Note**: Netflow v5 does not support IPv6.

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**