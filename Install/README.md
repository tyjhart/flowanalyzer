# Installation

The installation is orchestrated with Git, Pip, and Bash scripting. The process should require no manual intervention on your part.

### Minimum Requirements

This should be run on a fresh Ubuntu Server installation with the following **minimum** hardware specs:

- 4GB RAM
- 2 CPU Cores
- 90GB HDD space

Additional Elasticsearch nodes will greatly increase performance and reliability in case of node failure.

### Installation Steps

1. Clone the repo via Git
2. Run the installation script
3. Point flow data at the installation

First, navigate to a directory you want to run this from, where you also have full read/write permissions:

```
cd /your/directory/
```

Run the command below to clone the Git repository into your directory:

```
git clone https://gitlab.com/thart/flowanalyzer.git
```

The ubuntu_install.sh script handles almost everything:

```
sh ./Install/ubuntu_install.sh
```

It does the following:

- Updates, upgrades the Ubuntu install
- Installs Elasticsearch pre-reqs
- Creates the following services for Netflow v5/v9 and IPFIX (aka v10):
  - netflow_v5
  - netflow_v9
  - ipfix
- Registers services
- Builds the Flow index in Elasticsearch
- Sets unknown field defaults in Elasticsearch
- Installs Curator for Elasticsearch
- Installs Head plugin for Elasticsearch
- Installs and configures Kibana
- Installs and configures Squid
- Schedules an auto-update Cron job
- Runs a cleanup and reboots the Ubuntu server