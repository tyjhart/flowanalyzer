# Requirements
At least one Ubuntu Server installation that meets the following **minimum** requirements:

## Hardware
- 4 GB of RAM
- 2 CPU Cores (physical or virtual)

## Storage
A **minimum** of 20GB HDD space is recommended for testing the appliance, but long-term storage requirements will vary depending on a number of factors. The following should be considered when provisioning storage space and additional Elasticsearch nodes:

- Flow data retenion (default 30 days)
- Number of flow exporters (routers, switches, etc)
- Sampling rate for protocols like Netflow v9 and IPFIX
- Average network flow volume
- Peak network flow volume and duration

Every network is different so it's difficult to give a quick suggestion for the right amount of storage for your organization. We recommended that you start small with a couple collectors to determine your average daily index size. Once you have a baseline scale up from there.

## Operating System
The following versions of Ubuntu Server have been tested and verified to work with the [installation](./Install/README.md) script:

- 16.04 LTS
- 16.04.1 LTS
- 16.10

**Note**: The installation script is incompatible with Ubuntu versions prior to 15.04 due to the move to SystemD.

# Elasticsearch Nodes
By default the installation script assumes you're using only one node for the collectors, Elasticsearch, and Kibana. The configuration options are included by the installation script for working in a multi-node cluster but they are commented out. This is fine for proof-of-concept or fairly small networks with low retention requirements, but it will not scale beyond a certain point. 

## Scaling Elasticsearch
Additional Elasticsearch nodes will greatly increase performance and reliability in case of node failure. As your flow volume, data retention, and failover needs increase you can tune the amount of Elasticsearch shards and replicas to meet your needs.

# ---
**Copyright (c) 2017, Manito Networks, LLC**
**All rights reserved.**