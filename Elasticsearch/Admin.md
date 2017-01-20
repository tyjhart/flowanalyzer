# Elasticsearch Maintenance Queries
Here is a collection of queries to help you maintain you Elasticsearch cluster.

## Cluster Health
Shows cluster status (red, yellow, green), number of nodes, pending tasks, and more.
```
curl 'localhost:9200/_cluster/health?pretty&human=true'
```
**NOTE**: Cluster status will always be "yellow" with only one Elasticsearch node, even if it's working perfectly. For Elasticsearch to be "green" there must be two or more healthy nodes.

## Cluster State
See [the Elasticsearch cluster state documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-state.html) for information on all the things this query outputs.
```
curl 'localhost:9200/_cluster/state?pretty&human=true'
```

## Index Sizes
Shows the size of each daily Index. This helps determine the storage requirements for flow growth and increased retention, and for monitoring additional devices. 

For Netflow and IPFIX:
```
curl 'localhost:9200/flow*/_stats/store?pretty&human=true'
```
For sFlow:
```
curl 'localhost:9200/sflow*/_stats/store?pretty&human=true'
```

## Drop Netflow Indexes
The following command deletes all Netflow indexes:
```
curl -XDELETE http://localhost:9200/flow*?pretty
```
**WARNING**: This cannot be undone, all Netflow indexes will be removed.

## Drop sFlow Indexes
The following command deletes all sFlow indexes:
```
curl -XDELETE http://localhost:9200/sflow*?pretty
```
**WARNING**: This cannot be undone, all sFlow indexes will be removed.

# ---
**Copyright (c) 2017, Manito Networks, LLC**
**All rights reserved.**