sFlow is a robust, extensible protocol for reporting performance and system counters, as well as network flows. It's important to understand how the sFlow protocol and its structures work, so you can effectively ingest and parse sFlow data.

1. [Structures](#structures)
2. [Samples](#samples)
    1. [Flow Sample](#flow-sample)
    2. [Counter Sample](#counter-sample)
    3. [Expanded Flow Sample](#expanded-flow-sample)
    4. [Expanded Counter Sample](#expanded-counter-sample)
3. [Flow Data](#flow-data)
4. [Counter Data](#counter-data)

# Structures
sFlow structures define specific data sets that follow a defined standard. The Flow Analyzer currently supports most of the standard sFlow-defined structures. Vendors and open source developers are free to define and use their own structures, but support for those structures (especially proprietary, vendor-specific structures) is limited in this project.

A list of the standard, sFlow-defined structures can be found [on the sFlow.org website](http://www.sflow.org/developers/structures.php).

# Samples
The top four structures help define the layout and type of the structures beneat them. Each of these samples tells the collector what type of records are contained inside, as well as the sFlow Agent's IP address, Agent ID, the sequence number, and more. This gives us the "lay of the land" while parsing through the records at a lower level.

The four top sample types are as follows:
Type | Enterprise | Format | Structure Name | Link |
--          | - | -  | --                           | -- |
Sample      | 0 | 1  | Flow Sample                  | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Sample      | 0 | 2  | Counter Sample               | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Sample      | 0 | 3  | Expanded Flow Sample         | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Sample      | 0 | 4  | Expanded Counter Sample      | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |

The **Enterprise** number defines the vendor or developer whose product is exporting information. sFlow protocol developer inMon Corporation is enterprise number zero (0). Broadcom is enterprise number 4413 and Nvidia is enterprise number 5703, just to give two other examples.

The **Format** number defines specific data structures used by the vendor. For example, [ _Enterprise, Format_ ] numbers [_0, 1006_] are defined as the "Extended MPLS" structure by inMon Corporation. Another example would be [ _0, 2101_ ] which is defined as the "Virtual CPU Counter" structure.

When the Enterprise and Format numbers are combined we know what data structure has been sent, and by referencing that defined structure we can parse out the data.

## Flow Sample
Flow Samples [ _0, 1_ ] are pretty much what you'd think they would be if you're familiar with Netflow or IPFIX. This mirrors a lot of the same functionality of Netflow v5, Netflow v9, and IPFIX (aka Netflow v10). Flow samples can include source and destination IP addresses, port numbers, protocols, and packet headers. 

The sFlow protocol then goes quite a bit beyond the typical network flow protocols by reporting application information such as HTTP transactions, NFS storage transactions, NAT, Fibre Channel, and more. This makes sFlow a good protocol for monitoring network flows, and also marrying that information with application-level flows.

## Counter Sample
Counter Samples [ _0, 2_ ] provide numeric information about systems and system performance. Examples of counter information include: 
- Overall CPU count
- Free memory
- Dropped packets
- Bytes out
- Packets out
- Errors

By combining counter information with flow data we can present a wider, more holistic picture of an organization's systems and their performance over time.

## Expanded Flow Sample
The Expanded Flow Sample does what [Flow Samples](#flow-samples) do, but they allow for the use of ifIndex numeric values over 2^24. From the sFlow v5 definition:

> The expanded encodings are provided to support the maximum possible values for ifIndex, even though large ifIndex values are not encouraged.
>
> --<cite>[SFLOW-DATAGRAM5 Documentation File](http://sflow.org/SFLOW-DATAGRAM5.txt)</cite>

## Expanded Counter Sample
The Expanded Counter Sample does for [Counter Samples](#counter-samples) what [Expanded Flow Samples](#expanded-flow-samples) do for regular [Flow Samples](#flow-samples). As networks and systems become larger and faster it's important that protocols can handle very large values.

# Flow Data
The default structures for flow data are shown below:
Type | Enterprise | Format | Name | Supported | Link |
--      | - | -     | --                                | --            | -- |
Flow    | 0 | 1     | Raw Packet Header                 | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 2     | Ethernet Frame Data               | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 3     | Packet IPv4 Data                  | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 4     | Packet IPv6 Data                  | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1001  | Extended Switch                   | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1002  | Extended Router                   | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1003  | Extended Gateway                  | In Progress   | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1004  | Extended User                     | In Progress   | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1005  | Extended URL (deprecated)         | N/A           | N/A |
Flow    | 0 | 1006  | Extended MPLS                     | In Progress   | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1007  | Extended NAT                      | In Progress   | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1008  | Extended MPLS Tunnel              | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1009  | Extended MPLS VC                  | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1010  | Extended MPLS FTN                 | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1011  | Extended MPLS LDP FEC             | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1012  | Extended VLAN Tunnel              | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Flow    | 0 | 1013  | Extended 802.11 Payload           | In Progress   | [sFlow 802.11 Structures](http://www.sflow.org/sflow_80211.txt) |
Flow    | 0 | 1014  | Extended 802.11 RX                | Yes           | [sFlow 802.11 Structures](http://www.sflow.org/sflow_80211.txt) |
Flow    | 0 | 1015  | Extended 802.11 TX                | Yes           | [sFlow 802.11 Structures](http://www.sflow.org/sflow_80211.txt) |
Flow    | 0 | 1016  | Extended 802.11 Aggregation       | In Progress   | [sFlow 802.11 Structures](http://www.sflow.org/sflow_80211.txt) |
Flow    | 0 | 1017  | Extended OpenFlow v1 (deprecated) | N/A           | N/A |
Flow    | 0 | 1018  | Extended Fibre Channel            | In Progress   | []() |
Flow    | 0 | 1019  | Extended Queue Length             | In Progress   | []() |
Flow    | 0 | 1020  | Extended NAT Port                 | In Progress   | [sFlow Port NAT Structure](http://www.sflow.org/sflow_pnat.txt) |
Flow    | 0 | 1021  | Extended L2 Tunnel Egress         | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1022  | Extended L2 Tunnel Ingress        | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1023  | Extended IPv4 Tunnel Egress       | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1024  | Extended IPv4 Tunnel Ingress      | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1025  | Extended IPv6 Tunnel Egress       | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1026  | Extended IPv6 Tunnel Ingress      | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1027  | Extended Decapsulate Egress       | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1028  | Extended Decapsulate Ingress      | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1029  | Extended VNI Egress               | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1030  | Extended VNI Ingress              | In Progress   | [sFlow Tunnel Structure](http://www.sflow.org/sflow_tunnels.txt) |
Flow    | 0 | 1031  | Extended InfiniBand LRH           | In Progress   | []() |
Flow    | 0 | 1032  | Extended InfiniBand GRH           | In Progress   | []() |
Flow    | 0 | 1033  | Extended InfiniBand BRH           | In Progress   | []() |
Flow    | 0 | 2000  | Transaction                       | In Progress   | []() |
Flow    | 0 | 2001  | Extended NFS Storage Transaction  | In Progress   | []() |
Flow    | 0 | 2002  | Extended SCSI Storage Transaction | In Progress   | []() |
Flow    | 0 | 2003  | Extended HTTP Transaction         | In Progress   | []() |
Flow    | 0 | 2100  | Extended Socket IPv4              | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Flow    | 0 | 2101  | Extended Socket IPv6              | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Flow    | 0 | 2102  | Extended Proxy Socket IPv4        | In Progress   | [sFlow HTTP Structures](http://www.sflow.org/sflow_http.txt) |
Flow    | 0 | 2103  | Extended Proxy Socket IPv6        | In Progress   | [sFlow HTTP Structures](http://www.sflow.org/sflow_http.txt) |
Flow    | 0 | 2200  | Memcached Operation               | In Progress   | [http://www.sflow.org/sflow_memcache.txt](http://www.sflow.org/sflow_memcache.txt) |
Flow    | 0 | 2201  | HTTP Request (deprecated)         | N/A           | []() |
Flow    | 0 | 2202  | App Operation                     | In Progress   | [sFlow Application Structures](http://www.sflow.org/sflow_application.txt) |
Flow    | 0 | 2203  | App Parent Context                | In Progress   | [sFlow Application Structures](http://www.sflow.org/sflow_application.txt) |
Flow    | 0 | 2204  | App Initiator                     | In Progress   | [sFlow Application Structures](http://www.sflow.org/sflow_application.txt) |
Flow    | 0 | 2205  | App Target                        | In Progress   | [sFlow Application Structures](http://www.sflow.org/sflow_application.txt) |
Flow    | 0 | 2206  | HTTP Request                      | In Progress   | [sFlow HTTP Structures](http://www.sflow.org/sflow_http.txt) |
Flow    | 0 | 2207  | Extended Proxy Request            | In Progress   | [sFlow HTTP Structures](http://www.sflow.org/sflow_http.txt) |
Flow    | 0 | 2208  | Extended Nav Timing               | In Progress   | []() |
Flow    | 0 | 2209  | Extended TCP Info                 | Yes           | [sFlow Google Group, Peter Phaal](https://groups.google.com/forum/#!topic/sflow/JCG9iwacLZA) |

# Counter Data
The default structures for counter data are shown below:
Type | Enterprise | Format | Name | Supported | Link |
--          | --    | --    | --                                | --            | -- |
Counter     | 0     | 1     | Generic Interface Counters        | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Counter     | 0     | 2     | Ethernet Interface Counters       | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Counter     | 0     | 3     | Token Ring Counters               | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Counter     | 0     | 4     | 100 BaseVG Interface Counters     | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Counter     | 0     | 5     | VLAN Counters                     | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Counter     | 0     | 6     | 802.11 Counters                   | Yes           | [sFlow 802.11 Structures](http://www.sflow.org/sflow_80211.txt) |
Counter     | 0     | 7     | LAG Port Statistics               | In Progress   | [sFlow LAG Port Statistics](http://www.sflow.org/sflow_lag.txt) |
Counter     | 0     | 8     | Slow Path Counts                  | In Progress   | []() |
Counter     | 0     | 9     | InfiniBand Counters               | In Progress   | []() |
Counter     | 0     | 10    | Optical SFP / QSFP Counters       | In Progress   | [sFlow Optical Interface Structures](http://www.sflow.org/sflow_optics.txt) |
Counter     | 0     | 1001  | Processor                         | Yes           | [sFlow Version 5](http://sflow.org/sflow_version_5.txt) |
Counter     | 0     | 1002  | Radio Utilization                 | In Progress   | [sFlow 802.11 Structures](http://www.sflow.org/sflow_80211.txt) |
Counter     | 0     | 1003  | Queue Length                      | In Progress   | []() |
Counter     | 0     | 1004  | OpenFlow Port                     | In Progress   | [sFlow OpenFlow Structures](http://www.sflow.org/sflow_openflow.txt) |
Counter     | 0     | 1005  | OpenFlow Port Name                | In Progress   | [sFlow OpenFlow Structures](http://www.sflow.org/sflow_openflow.txt) |
Counter     | 0     | 2000  | Host Description                  | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2001  | Host Adapters                     | In Progress   | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2002  | Host Parent                       | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2003  | Host CPU                          | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2004  | Host Memory                       | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2005  | Host Disk I/O                     | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2006  | Host Network I/O                  | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2007  | MIB2 IP Group                     | In Progress   | [sFlow Host TCP/IP Counters](http://www.sflow.org/sflow_host_ip.txt) |
Counter     | 0     | 2008  | MIB2 ICMP Group                   | In Progress   | [sFlow Host TCP/IP Counters](http://www.sflow.org/sflow_host_ip.txt) |
Counter     | 0     | 2009  | MIB2 TCP Group                    | In Progress   | [sFlow Host TCP/IP Counters](http://www.sflow.org/sflow_host_ip.txt) |
Counter     | 0     | 2010  | MIB2 UDP Group                    | In Progress   | [sFlow Host TCP/IP Counters](http://www.sflow.org/sflow_host_ip.txt) |
Counter     | 0     | 2100  | Virtual Node                      | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2101  | Virtual CPU                       | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2102  | Virtual Memory                    | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2103  | Virtual Disk I/O                  | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2104  | Virtual Network I/O               | Yes           | [sFlow Host Structures](http://www.sflow.org/sflow_host.txt) |
Counter     | 0     | 2105  | JMX Runtime                       | In Progress   | [sFlow Java Virtual Machine Structures](http://www.sflow.org/sflow_jvm.txt) |
Counter     | 0     | 2106  | JMX Statistics                    | In Progress   | [sFlow Java Virtual Machine Structures](http://www.sflow.org/sflow_jvm.txt) |
Counter     | 0     | 2200  | Memcached Counters (deprecated)   | N/A           | N/A |
Counter     | 0     | 2201  | HTTP Counters                     | In Progress   | [sFlow HTTP Structures](http://www.sflow.org/sflow_http.txt) |
Counter     | 0     | 2202  | App Operations                    | In Progress   | [sFlow Application Structures](http://www.sflow.org/sflow_application.txt) |
Counter     | 0     | 2203  | App Resources                     | In Progress   | [sFlow Application Structures](http://www.sflow.org/sflow_application.txt) |
Counter     | 0     | 2204  | Memcache Counters                 | In Progress   | [http://www.sflow.org/sflow_memcache.txt](http://www.sflow.org/sflow_memcache.txt) |
Counter     | 0     | 2206  | App Workers                       | In Progress   | [sFlow Application Structures](http://www.sflow.org/sflow_application.txt) |
Counter     | 0     | 2207  | OVS DP Statistics                 | In Progress   | []() |
Counter     | 0     | 3000  | Energy                            | In Progress   | []() |
Counter     | 0     | 3001  | Temperature                       | In Progress   | []() |
Counter     | 0     | 3002  | Humidity                          | In Progress   | []() |
Counter     | 0     | 3003  | Fans                              | In Progress   | []() |
Counter     | 4413  | 3     | ASIC Table Utilizations           | Yes           | [sFlow Broadcom Switch ASIC Table Utilization Structures](http://www.sflow.org/sflow_broadcom_tables.txt) |
Counter     | 5703  | 1     | NVIDIA GPU Statistics             | In Progress   | [sFlow NVML GPU Structure](http://www.sflow.org/sflow_nvml.txt) |