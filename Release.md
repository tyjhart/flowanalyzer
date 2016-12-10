# Release Notes
The following release notes document the changes to the project over time, as well as breaking changes and anything that needs to be done to update functionality.

# v2.0.0 - sFlow, Elasticsearch and Kibana 5
Big changes and upgrades in this release, including breaking changes:

1. [New sFlow Support](#sflow)
2. [Elasticsearch 5 Upgrade (Breaking)](#elasticsearch-5-upgrade)
3. [Kibana 5 Upgrade (Breaking)](#kibana-5-upgrade)

## sFlow
Added an sFlow collector and support for the [structures defined by InMon](http://www.sflow.org/developers/structures.php) (Enterprise 0) and a couple others. See the [sFlow document for more information](sFlow.md) about what is currently supported and what is in development. This has added hugely to the codebase, but it's also added a wealth of information that we can build around to gain more insights into network and system performance.

## Elasticsearch 5 Upgrade
Elasticsearch has been updated to version 5 - see the [Elasticsearch release notes](https://www.elastic.co/guide/en/elasticsearch/reference/current/release-notes-5.0.0.html). There are a number of breaking changes that have occurred between the previous stable release and the current stable release:

- Field mappings previously defined as "String" now are defined as either "Text" or "Keyword" and indexed differently now - many field have had their mapping changed.
- IPv6 wasn't supported before by the IP field type and had to be stored as a String instead. Now IPv4 and IPv6 addresses are supported by the IP type and mappings have had to be updated.
- Curator has been through a significant update and now uses YML-formatted "Action" and "Config" files.
- The Head plugin is no longer supported and has been removed from the installation script.
- Java Heap option settings in /etc/default/elasticsearch have changed (e.g. ES_JAVA_OPTS="-Xms2g -Xmx2g")

## Kibana 5 Upgrade
Kibana has been updated to version 5 - see the [Kibana release notes](https://www.elastic.co/guide/en/kibana/current/release-notes-5.0.0.html). There are a number of significant changes that have occurred between the previous stable release and the current stable release:

- The Kibana UI has changed dramatically.
- sFlow Visualizations and Dashboards have been added, but they are fairly basic.

# v1.0.0 - Initial Release
Initial release with Netflow v5, Netflow v9, and basic IPFIX functionality.