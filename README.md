# SDN Firewall (Mininet + Ryu)

## Problem Statement
Develop a controller-based firewall to allow or block host traffic using rule-based filtering.

## Objective
Demonstrate SDN behavior in Mininet with an OpenFlow controller:
- Controller-switch interaction
- Explicit match-action flow rules
- Packet_in handling with allow/block logic
- Observable behavior using ping/iperf/flow tables

## Design Overview
- Controller: Ryu OpenFlow 1.3 app at controller/firewall_controller.py
- Topology: one OVS switch (s1) and three hosts (h1, h2, h3) at topology/simple_topology.py
- Rules implemented in controller:
1. IP rule: block ICMP from h1 (10.0.0.1) to h3 (10.0.0.3)
2. MAC rule: block all traffic from h3 MAC (00:00:00:00:00:03)
3. Port rule: block TCP destination port 5001 from h2 to h1

If a packet matches a block rule, controller logs it and installs a high-priority drop flow.

## Prerequisites
- Ubuntu with Mininet and Open vSwitch
- Ryu installed (ryu-manager)
- Python 3

## Setup and Execution
Open two terminals.

Terminal 1:
```bash
cd ~/cn
ryu-manager --ofp-tcp-listen-port 6633 controller/firewall_controller.py
```

Terminal 2:
```bash
cd ~/cn
sudo python3 topology/simple_topology.py
```

## Test Scenarios (Required Validation)
At Mininet prompt:

1. Allowed traffic (PASS expected)
```bash
h1 ping -c 3 h2
```

2. Blocked traffic (FAIL expected)
```bash
h1 ping -c 3 h3
```

3. Blocked port test with iperf (FAIL expected)
```bash
h1 iperf -s -p 5001 &
h2 iperf -c 10.0.0.1 -p 5001 -t 5
```

4. Control test on different port (PASS expected)
```bash
h1 iperf -s -p 5002 &
h2 iperf -c 10.0.0.1 -p 5002 -t 5
```

## Proof of Execution
- Flow table:
```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```
- Blocked packet log:
```bash
cat blocked_packets.log
```
- Optional Wireshark/tcpdump capture for screenshots:
```bash
sudo tcpdump -i any -nn host 10.0.0.3
```

Capture screenshots/logs for:
- Flow tables
- Ping and iperf results

## Basic Regression Step
```bash
sudo mn -c
rm -f blocked_packets.log
```
Rerun controller + topology and repeat tests.

## Expected Output Summary
- h1 to h2 ping succeeds
- h1 to h3 ICMP is blocked
- h2 to h1 TCP/5001 is blocked
- blocked_packets.log contains blocked events
- switch flow table shows drop rules with higher priority

## References
- Ryu documentation: https://ryu.readthedocs.io/
- Mininet walkthrough: http://mininet.org/walkthrough/
- OpenFlow specification (ONF): https://opennetworking.org/sdn-resources/openflow-switch-specification/
