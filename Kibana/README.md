# Kibana
Kibana is the component of the ELK stack that visualizes data - it is the face of your network flows. Kibana is driven by Searches, Visualizations, and Dashboards.

# Kibana JSON Files
The [Netflow ELK5 JSON file](netflow_elk5.json) provides a solid foundation with preconfigured Dashboards for Netflow and IPFIX flows. The [sFlow ELK5 JSON file](sflow_elk5.json) does the same for sFlow data.

# Searches
Searches do just that - search your flow data. Searches don't visualize or graph the data, but they can drive the Visualizations that make up Dashboards. You can search for a single field or a combination of fields. See the [Kibana Search document](Searches.md) for plenty of examples of Searches you can use.

# Visualizations
Visualizations query Elasticsearch and produce something useful for humans like a bar or line graph. Collections of Visualizations come together to create Dashboards. Visualizations are included to help you build great Dashboards of your own, or expand the included Dashboards.

# Dashboards
Dashboards are collections of Visualizations that produce meaningful insights or at-a-glance performance snapshots. Users should customize or create their own Dashboards to match their duties or workflows.

# ---
**Copyright (c) 2017, Manito Networks, LLC**
**All rights reserved.**