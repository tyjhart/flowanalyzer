# **Installation**

The installation is orchestrated with Git, Pip, and Bash scripting. The process should require no manual intervention on your part.

# **Minimum Requirements**

This should be run on a fresh Ubuntu Server installation with the following **minimum** hardware specs:

- 4GB RAM
- 2 CPU Cores
- 90GB HDD space

Additional Elasticsearch nodes will greatly increase performance and reliability in case of node failure. Having additional
Elasticsearch nodes will also allow you to retain more days of flow data.

# **Installation Steps**

1. Installation
  1. Clone the repo via Git
  2. Run the installation script
2. Configure Kibana
  1. Log in to Kibana
  2. Configure the default index pattern
  3. Set special Byte fields
  4. Import Kibana Visualizations and Dashboards
3. Point flow data at the installation

## **Installation**

### **Clone the Git repository**

First, navigate to a directory you want to run this from, where you also have full read/write permissions:

```
cd /your/directory/
```

Run the command below to clone the Git repository into your directory:

```
git clone https://gitlab.com/thart/flowanalyzer.git
```

If you don't have Git available on your Ubuntu Server installation that's OK, just run the following:

```
sudo apt-get install git
```

The download should only take a moment. Move into the repo directory:

```
cd flowanalyzer
```

### **Installation Script**

The ubuntu_install.sh script handles almost everything, just be sure to run it with sudo privileges:

```
sudo sh ./Install/ubuntu_install.sh
```

The ubuntu_install.sh script does the following:

- Moves the Ubuntu Server to UTC time
- Adds software repos for Elasticsearch and Kibana
- Updates the repos for the install
- Installs Elasticsearch pre-reqs (Curl, OpenJDK 8, etc)
- Installs Elasticsearch and Kibana
- Creates the following services for Netflow v5/v9 and IPFIX (aka v10):
  - netflow_v5
  - netflow_v9
  - ipfix
- Registers services
- Builds the Flow index in Elasticsearch
- Sets unknown field defaults in Elasticsearch
- Installs Curator for Elasticsearch
- Installs Head plugin for Elasticsearch
- Installs and configures Squid
- Configures a default Squid user:
  - Username: **admin**
  - Password: **manitonetworks**
- Schedules a weekly auto-update Cron job (/etc/cron/cron.weekly)

## **Configure Kibana**

### **Log in to Kibana**

Browse to Kibana at http://your_server_ip

Log in with the default Squid credentials shown above.

### **Configure the default index pattern**

The installation script has already created the Elasticsearch index, but we need to point Kibana in the right direction.

In Kibana, under **Index name or pattern** enter "flow*" without the quotes.

Leave the automatically selected **Time** field under **Time-field name**.

Click the **Create** button.

Click the **Green Star** button to set the Flow index as the default index.

### **Set special Byte fields**

Sort field names by clicking the **names** heading

Click the **Edit** pencil icon to the right of the **Bytes In** field

Under the **Format** drop-down choose **Bytes** so Kibana will render this field in human-readable sizes (Kb, Mb, Gb, etc)

Click **Update Field**

Perform the same steps above on the **Bytes Out** field.