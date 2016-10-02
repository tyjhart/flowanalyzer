# **Network Flow Basics**

"Network flow data" can mean a few things depending on who you're talking to. In the realm of Netflow and IPFIX, network flow data
is information about the traffic devices are sending on the network. Depening on the flow protocols in use that can include
source and destination addresses, ports, protocols, packet size, VLAN ID, ICMP type and code, and more.

Think of it as metadata about network traffic. Industry-standard protocols export network flow data from devices like routers 
and switches. Those exporters send flow data to a collector, that aggregates the information for analysts to take action on.

The Flow Analyzer aggregates this metadata, applies additional tagging and categorization, then visualizes it for 
your network analysts and administrators.

It's important to note that Netflow and IPFIX are **NOT** Deep Packet Inspection (DPI) - they don't look at the actual data
payloads within packets. IDS, IPS, and Application-layer Firewalls provide the functionality to pick apart the payloads inside a 
packet and make decisions based on rules and signatures.

# **What Are Netflow And IPFIX?**

## **Netflow**

Netflow has many versions, but two have rose to prominence in the industry - v5 and v9. The Flow Analyzer is compatible with both.
Netflow v5 and v9 have very good support in the industry across manufacturers, and they have been reliable standards for quite some time.

### **Netflow v5**

Netflow v5 is the legacy version and only supports IPv4. It is also limited in the types of flow data it can export, and the format
of those fields is static. This makes it easy to export and collect v5 flows, but can limit the usefulness of its flow information.
A crucial difference between v5 and v9 is that v5 is static and doesn't use templates, while v9 is dynamic and requires templates to
decode flow packets.

There are [18 reportable fields](http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186)
in the v5 format, including source and destination IP address and port, AS numbers, protocol, ToS code, and more.

Netflow v5 is a great choice if you're using legacy devices that only support v5, or if you're just starting out in flow monitoring
and want to see if it's right for you without being inundated with data fields. Configuration of Netflow v5 on routers and switches also
tends to be very simple and straightforward.

### **Netflow v9**

Netflow v9 is a standard originally published by Cisco Systems that has been adopted across the industry.

It has [just over 100 fields](http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html) it can report on, 
and unlike v5 it supports both IPv4 and IPv6. While the v9 standard can report on many kinds of flow metrics, not all vendors support 
all fields on every platform. Consult your vendor for a list of the fields that they support on your platforms and software versions.

With Netflow v9 being dynamic a new piece gets thrown into the works - templates. Netflow v9 templates are sent separately from
data flows, and tell the collector what data fields will be in flow packets, how big the fields are, and what order they arrive in.
It's impossible to decode a Netflow v9 data flow without a template, so if a flow packet arrives before a corresponding template is 
received, the v9 standard dictates that it should be dropped.

Netflow v9 collectors often send out templates at startup, and then at pre-defined intervals. Some manufacturers allow you to change
that interval, others don't, and it varies by platform. Having a dynamic, template-based standard allows network professionals to only
report the flow information they care about, and tune flow data to their unique reporting needs.

Some vendors and products make use of non-standard Netflow v9 fields, above those officially defined in the standard. The Cisco ASA
platform has quite a few, as do others. While there is nothing in the standard that prevents this from happening, vendors aren't
always open about the types of data being sent or how to interpret it. Some non-standard fields are supported by the Flow Analyzer, 
but that support is unofficial.

## **IPFIX (aka Netflow v10)**

The IPFIX protocol is commonly referred to as "Netflow v10", even though IPFIX is actually a separate protocol. The two terms are 
often used interchangeably in the industry, just understand that IPFIX is defined in it's own RFC.

IPFIX ([RFC 7011](https://tools.ietf.org/html/rfc7011)) is a modern, open, industry-standard flow monitoring protocol. 
Like Netflow v9 it is a dynamic, template-based protocol. Collectors must create and distribute templates, and if a data 
flow packet arrives before a template it will be dropped, just like Netflow v9.

The IPFIX protocol standard is backwards-compatible with the pre-defined fields in Netflow v9, and it adds additional fields on top
of that - in fact there are [almost 500 currently defined](http://www.iana.org/assignments/ipfix/ipfix.xhtml).

Unlike Netflow v9 though, IPFIX can be used to report other kinds of events besides network flows. IPFIX can be used to send
firewall events, hardware alerts, and more if the vendor supports it. This allows IPFIX to be more than just a network flow reporting
protocol - it can handle all kinds of data. Vendor support for additional reporting varies, and the Flow Analyzer does not support
collection of non-standard IPFIX fields as defined in the [RFC](https://tools.ietf.org/html/rfc7011).

Some vendors have also released their own proprietary field definitions beyond what is supported in the standard. The openness and
availability of these field definitions varies from vendor-to-vendor, and we are exploring what would be required to support
mainstream vendors.