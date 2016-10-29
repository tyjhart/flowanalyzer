# Debugging the Flow Analyzer

No one likes when things don't work, but eventually something goes wrong. It could be something coded wrong in our project, a misconfiguration of a flow reporting device,
or a device that doesn't stick to the published Netflow, IPFIX, etc standards. Regardless of the root cause, we want to help you identify, correct, and if necessary report 
the issue you're having.

If you're not seeing flow data, or if you're seeing incorrect flow data, there are some quick steps to take before reporting an issue:

1. [Updates](#updates)
2. [Flow Analyzer Limitations](#flow-analyzer-limitations)
3. [Collector Status](#collector-status)
4. [Collector Logs](#collector-logs)
5. [Elasticsearch Status](#elasticsearch-status)
6. [Kibana Status](#kibana-status)
    1. [Squid Status](#squid-status)
7. [Use Collector Debug Options](#use-collector-debug-options)
    1. [Launch Python Collector](#launch-python-collector)
    2. [Debugging Levels](#debugging-levels)
    3. [Output to File](#output-to-file)
8. [Create a Gitlab Issue](#create-a-gitlab-issue)

# Updates

Make sure you're running the latest code - we might have already fixed your issue or added additional debugging tools.

First stop the collectors:
```
sudo systemctl stop netflow_v5
sudo systemctl stop netflow_v9
sudo systemctl stop ipfix
```
Use Git to fetch the latest stable code:
```
cd /your/directory/flowanalyzer
git fetch
```
Start the collectors back up:
```
sudo systemctl start netflow_v5
sudo systemctl start netflow_v9
sudo systemctl start ipfix
```
or just reboot the Flow Analyzer server.

# Flow Analyzer Limitations

Verify you're not using an unsupported protocol or technology before reporting an issue.
At the moment we don't support the following, either because we're still developing a collector or it's a proprietary protocol:

- Cisco [Flexible Netflow](http://www.cisco.com/c/en/us/products/ios-nx-os-software/flexible-netflow/index.html)
- Cisco [ASA Netflow Security Event Logging (NESL)](http://www.cisco.com/c/en/us/td/docs/security/asa/asa82/configuration/guide/config/monitor_nsel.html#wp1111174)
- Cisco NAT Event Logging (NEL)
- Juniper jFlow
- InMon sFlow (collector currently in development)

# Collector Status

Verify that the collector(s) for the flow technology in use on your network are running:
```
systemctl status netflow_v5
systemctl status netflow_v9
systemctl status ipfix
```
Not all of these may apply to your network depending on your products and what they support.

Verify that the service shows as **active (running)**. If it's not running then it's a good idea to check the [collector logs](#collector-logs).

# Collector Logs

The collector's respective logs are handled by SystemD and are easily viewable through the **journalctl** command:
```
journalctl -u netflow_v5
journalctl -u netflow_v9
journalctl -u ipfix
```
Using the **--follow** option you can have journalctl scroll through the log for you as it's updated.
Using the netflow_v5 service as an example:
```
journalctl -u netflow_v5 --follow
```

# Elasticsearch Status

If the Elasticsearch service isn't running in the background it's impossible to store flow data. 
Check the status of the Elasticsearch service and its logs to verify it's online and healthy:
```
systemctl status elasticsearch
journalctl -u elasticsearch
```

# Kibana Status

If the Kibana service isn't running in the background you won't be able to visualize and dashboard data in Elasticsearch. 
Check the status of the Kibana service and its logs to verify it's online and healthy:
```
systemctl status kibana
journalctl -u kibana
```

## Squid Status

If you're using Squid to put authentication in front of Kibana, which is the default configuration for the Flow Analyzer, verify Squid is running. 
Check the status of the Squid service and its logs to verify it's online and healthy:
```
systemctl status squid
journalctl -u squid
```

# Use Collector Debug Options

The flow collectors have debugging options built-in to help you see what the collector is seeing and when. By default they
run without showing any debugging output besides standard service messages, but you can use the debug options to see more.

## Launch Python Collector

First, stop the collector service already running (e.g. Netflow v9) in the background so the port will be available:
```
sudo systemctl netflow_v9 stop
```
Change directory to where the Flow Analyzer is running, then the Python directory:
```
cd /your/directory/flowanalyzer/Python
```
Run the collector Python file using the -l or --log debug options:
```
python netflow_v9.py -l info
```
or...
```
python netflow_v9.py --log=debug
```

## Debugging Levels

Three debugging levels are available to get more or less granular information from the collectors:

Level | Use | Output Granularity, Volume
-------- | -------- | -------- |
Warning | Show issues that would cause flows to be dropped or missed (default level) | Minimal |
Info | All of the above, plus the start and stop of templates and flows | Moderate |
Debug | All of the above, plus the contents of all templates and flows | High |

## Output to file

If you're working with a developer on troubleshooting an issue it's often easiest to use the debug options and output to
a file. This makes things easier and we certainly appreciate it.

Use the following command to take the debug output from the IPFIX collector and send it to a file:
```
python ipfix.py --log=debug &> ipfix_debug.txt
```

# Create a Gitlab Issue

If you're not able to resolve your problem using the steps above it's best to [create an Issue](https://gitlab.com/thart/flowanalyzer/issues) on the [Gitlab project page](https://gitlab.com/thart/flowanalyzer).
[Creating an Issue](https://gitlab.com/thart/flowanalyzer/issues) allows us to track, comment on, and account for the problem you're having. It also gives other users the 
chance to comment if they are seeing the same problem, or already know a good solution.

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**