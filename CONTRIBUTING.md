If you use the Flow Analyzer project to gain insight into your network and also want to contribute we're happy to consider code additions and improvements. Before deciding to fork the project or submit a pull request please read the following guide to contributing to the Flow Analyzer project.

# Features
Ensure that a project proposal or feature request you'd like to propose is in keeping with the project's goals. For example, supporting another open protocol for flow reporting is probably a good idea. Building support for recording Syslog and SNMP data is outside the scope of the project, and there are many other great solutions already available for those protocols.

# Issues
If you find a bug in the code or something missing or wrong in the documentation please create [an Issue](https://gitlab.com/thart/flowanalyzer/issues). Having an Issue on the books allows us to track, assign, and comment on your particular problem or request. It also helps us track who is working on what and when, and keep things straight as the project grows.

If you're reporting a bug please include the following:

 - Protocol (e.g. Netflow v5, v9, IPFIX, sFlow)
 - Flow collector type (e.g. Juniper SRX, Mikrotik, Cisco ASA, Ubiquiti)
 - Debug-level collector log output (see the [debugging documentation](Debug.md)) 
 - Description of the problem you're experiencing

# Code Contributions
We want to make it easy for people who use the project to contribute code, but we also want to ensure that the codebase is lean, documented, and high quality. Interactions between participants should be within the bounds of the [Code of Conduct](Code%20of%20Conduct.md).

## Code Portability
When possible split chunks of functionality out into Python classes and functions that are reusable between the different flow collectors. However, do not split out tiny pieces of functionality just to be splitting things out because that creates unnecessary complexity.

## Comments
Having good comments in code keeps things readable, understandable, and accessible to others who want to contribute. This is particularly important when dealing with complex tasks like parsing template and flow data that can arrive packed in different sizes, in no particular order, and possibly encoded depending on the field.

When in doubt add a comment, either inline with shorter commands or above blocks of code, like in this example from the netflow_v5.py collector:
```
# Iterate over all flows in the packet
for flow_num in range(0, packet_contents["flow_count"]):
    now = datetime.datetime.utcnow() # Timestamp for flow receive
    logging.info("Parsing flow " + str(flow_num+1))
    base = packet_header_size + (flow_num * flow_record_size) # Calculate flow starting point
```

# Documentation
We pride ourselves on having robust documentation that supports the people who use this project. Even the best and most stable code won't get much use if there isn't documentation to back it up. New features should be documented, and when possible usage examples should be provided to support people taking advantage of new developments.

Documentation will be done in [Markdown format](https://gitlab.com/help/user/markdown.md) for maximum portability.

# Code of Conduct
Project participants and developers will conduct themselves in a respectful and adult manner. See our [Code of Conduct](Code%20of%20Conduct.md) document, based on the [TODO Group's Open Code of Conduct](http://todogroup.org/opencodeofconduct/).

# ---
**Copyright (c) 2017, Manito Networks, LLC**
**All rights reserved.**