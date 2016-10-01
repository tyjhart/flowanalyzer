# Manito Networks Flow Analyzer

## Features

The Manito Networks Flow Analyzer supports the following:

- Netflow v5
- Netflow v9
- IPFIX (aka Netflow v10)

It ingests Netflow and IPFIX data, parses and tags it, then stores it in Elasticsearch for you to query and graph in Kibana.

## Architecture

Three listeners run in the background as services, one for each of the supported flow standards. Should a service fail they are
configured to restart automatically. If you're not using particular services you can disable them. 

### Services

Service names correspond to their respective protocols:

- netflow_v5
- netflow_v9
- ipfix

You can view the status of the services by running the following:

```
service service_name status
```

### Ports & protocols

All services listen for TCP flow packets on the following ports:

- Netflow v5:   TCP/2055
- Netflow v9:   TCP/9995
- IPFIX:        TCP/4739

These ports can be changed by editing netflow_options.py and restarting the services shown above.