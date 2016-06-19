# Copyright 2016, Manito Networks, LLC. All rights reserved
#
# Last modified 6/9/2016

# Import what we need
import time, datetime, socket, struct, sys, json, socket, logging, logging.handlers, csv
from struct import *
from socket import inet_ntoa
from elasticsearch import Elasticsearch
from elasticsearch import helpers

# Set the logging level per https://docs.python.org/2/library/logging.html#levels
# Levels include DEBUG, INFO, WARNING, ERROR, CRITICAL (case matters)
logging.basicConfig(filename='./network_deck.log',level=logging.DEBUG)
#logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Network Deck')

csv.register_dialect(
    'mydialect',
    delimiter = ',',
    quotechar = '"',
    doublequote = True,
    skipinitialspace = True,
    lineterminator = '\r\n',
    quoting = csv.QUOTE_MINIMAL
)

# Spin up ES instance connection
try:
	es = Elasticsearch(['127.0.0.1'])
	logger.info('Connected to Elasticsearch')
except ValueError as elasticsearch_connect_error:
	logger.critical('Could not connect to Elasticsearch')
	logger.critical(str(elasticsearch_connect_error))
	sys.exit()

search_results = es.search(index="flow*", body={
    "size": 0,
    "fields": ["IPv4 Source","Bytes In","Source FQDN","Destination FQDN"],
    "aggs": {
        "Destination": {
            "terms": {
                "field":"IPv4 Destination",
                "size":20
            },
            "aggs": {
                "Source": {
                    "terms": {
                        "field":"IPv4 Source",
                        "size":50
                    },
                    "aggs": {
                        "Bytes": {
                            "sum": {"field":"Bytes In"}
                        }
                    }
                }
            }
        }
    },
    "query": {
        "match_all": {}
    }
})

edges = []
nodes = []
edges.append(["Target","Source"])

print(json.dumps(search_results["aggregations"]["Destination"]["buckets"],indent=2))
for destination in search_results["aggregations"]["Destination"]["buckets"]:
    print(destination["key_as_string"])
    nodes.append([destination["key_as_string"]])
    for bucket in destination["Source"]["buckets"]:
        print(str(destination["key_as_string"] + " - " + bucket["key_as_string"]))
        edges.append([destination["key_as_string"],bucket["key_as_string"]])

print(edges)
print(nodes)

with open('edges.csv', 'w') as edgesfile:
    thedatawriter = csv.writer(edgesfile, dialect='mydialect')
    for row in edges:
        thedatawriter.writerow(row)

with open('nodes.csv', 'w') as nodesfile:
    thedatawriter = csv.writer(nodesfile, dialect='mydialect')
    for row in nodes:
        thedatawriter.writerow(row)        