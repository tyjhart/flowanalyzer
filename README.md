# Manito Networks Flow Analyzer

## Features

The Manito Networks Flow Analyzer supports the following:

- Netflow v5
- Netflow v9
- IPFIX (aka Netflow v10)

It ingests Netflow and IPFIX data, parses and tags it, then stores it in Elasticsearch for you to query and graph in Kibana.

## Architecture

Three listeners run in the background as services, one for each of the supported flow standards. If you're not using particular
services you can disable them.