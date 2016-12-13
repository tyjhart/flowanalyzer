# Tagging
The Manito Networks Flow Analyzer tags flows with information about the Protocol, Traffic, Traffic Category, and in some cases Content based on DNS domain.

1. [Protocol](#protocol)
2. [Protocol Number](#protocol-number)
2. [Protocol Category](#protocol-category)
3. [Traffic](#traffic)
4. [Traffic Category](#traffic-category)
5. [Content](#content)

# Protocol
Flows are tagged with the name of the Protocol used based on [IANA Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). All registered protocol numbers are supported, though many protocols on the list are no longer used in modern networks. The table below shows examples of modern protocols that do get tagged, and for the full list see [Python/protocol_numbers.py](Python/protocol_numbers.py):

Protocol Number | Protocol |
--- | --- |
1   | ICMP  |
6   | TCP   |
17  | UDP   |
89  | OSPF  |

# Protocol Number
Flows are tagged with both the [Protocol] and the IANA Protocol Number so you can query and graph by both. The Protocol Number is provided by the flow software on your routers, switches, and servers and is not parsed any further.

# Protocol Category
The Protocol Category is used to further categorize Protocols in terms of their purpose. Not all protocols are tagged with a Category, but some examples are shown below. For the full list see [Python/protocol_numbers.py](Python/protocol_numbers.py):

Protocol Number | Protocol | Category |
--- | --- | --- |
1   | ICMP  | ICMP |
6   | TCP   | Transport |
17  | UDP   | Transport |
88  | EIGRP | Routing |
89  | OSPF  | Routing |

# Traffic
The table below shows examples of modern ports that get tagged with a Traffic designation. Not all ports get tagged due to the large amount of legacy registered ports not used in modern networks, though all modern ports like 80, 443, and 22 are supported. For the full list see [Python/defined_ports.py](Python/protocol_numbers.py), and see the table below for examples:

Port | Traffic |
--- | --- |
80   | HTTP  |
443  | HTTPS   |
22  | SSH   |
25  | SMTP  |

# Traffic Category
The table below shows examples of modern ports that get tagged with a Traffic Category designation. Well-known ports having to do with Web, Email, Remote Administration, Tunnels, and more are tagged with those Category names. For the full list see [Python/defined_ports.py](Python/protocol_numbers.py), and see the table below for examples:

Port | Traffic | Traffic Category |
--- | --- | --- |
80   | HTTP  | Web |
443  | HTTPS   | Web |
22  | SSH   | Remote Administrations |
25  | SMTP  | Email |
110  | POP3  | Email |

# Content
If reverse DNS lookups are enabled we're able to do some tagging based on domain name. Only the most popular websites are supported, with some examples shown below. See [Python/site_category.py](Python/site_category.py) for the full list:

Domain | Content |
--- | --- |
netflix.com   | Streaming  |
facebook.com  | Social Media   |
cnn.com  | News   |
youtube.com  | Streaming  |

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**