#!/usr/bin/env python3
"""Minimal 3-host Mininet topology for firewall validation."""

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController


def run():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink)

    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")

    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.addLink(h3, s1, bw=10)

    net.start()
    print("Topology started. Switch s1 is using OpenFlow13.")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
