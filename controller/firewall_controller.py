#!/usr/bin/env python3
"""Minimal OpenFlow 1.3 firewall + learning switch controller."""

import logging
from datetime import datetime
from pathlib import Path
from time import monotonic

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_3


class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    MATCH_KEYS = (
        "eth_src",
        "eth_dst",
        "eth_type",
        "ipv4_src",
        "ipv4_dst",
        "ip_proto",
        "tcp_src",
        "tcp_dst",
        "udp_src",
        "udp_dst",
    )

    FIREWALL_RULES = [
        {
            "name": "Block ICMP from h1 to h3",
            "eth_type": 0x0800,
            "ipv4_src": "10.0.0.1",
            "ipv4_dst": "10.0.0.3",
            "ip_proto": 1,
        },
        {
            "name": "Block IPv4 traffic from h3 MAC",
            "eth_type": 0x0800,
            "eth_src": "00:00:00:00:00:03",
        },
        {
            "name": "Block TCP dst 5001 from h2 to h1",
            "eth_type": 0x0800,
            "ipv4_src": "10.0.0.2",
            "ipv4_dst": "10.0.0.1",
            "ip_proto": 6,
            "tcp_dst": 5001,
        },
    ]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        self.mac_to_port = {}
        self.block_log_file = Path("blocked_packets.log")
        self.firewall_rules = list(self.FIREWALL_RULES)
        self._icmp_seen = {}

    def should_trace(self, fields):
        if fields.get("eth_type") != ether_types.ETH_TYPE_IP:
            return False

        dst_mac = (fields.get("eth_dst") or "").lower()
        if dst_mac == "ff:ff:ff:ff:ff:ff" or dst_mac.startswith("33:33") or dst_mac.startswith("01:00:5e"):
            return False

        return True

    def is_ping_request(self, fields):
        return (
            fields.get("eth_type") == ether_types.ETH_TYPE_IP
            and fields.get("ip_proto") == 1
            and fields.get("icmp_type") == 8
            and fields.get("ipv4_src") is not None
            and fields.get("ipv4_dst") is not None
        )

    def is_tcp_demo_traffic(self, fields):
        return (
            fields.get("eth_type") == ether_types.ETH_TYPE_IP
            and fields.get("ip_proto") == 6
            and fields.get("ipv4_src") == "10.0.0.2"
            and fields.get("ipv4_dst") == "10.0.0.1"
            and fields.get("tcp_dst") in (5001, 5002)
        )

    def should_log_ping_request(self, fields):
        if not self.is_ping_request(fields):
            return False

        now = monotonic()
        # Keep a very small recent window to suppress duplicate packet-in logs
        # for the same ICMP request while preserving repeated user tests.
        for key, ts in list(self._icmp_seen.items()):
            if now - ts > 2.0:
                self._icmp_seen.pop(key, None)

        key = (
            fields.get("ipv4_src"),
            fields.get("ipv4_dst"),
            fields.get("icmp_id"),
            fields.get("icmp_seq"),
        )
        ts = self._icmp_seen.get(key)
        if ts is not None and now - ts < 1.0:
            return False

        self._icmp_seen[key] = now
        return True

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        instructions = [
            parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)
        ] if actions else []

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(flow_mod)

    def is_blocked(self, fields):
        for rule in self.firewall_rules:
            if all(fields.get(k) == v for k, v in rule.items() if k != "name"):
                return True, rule
        return False, None

    def build_match_from_rule(self, datapath, fields, rule):
        parser = datapath.ofproto_parser
        match_kwargs = {
            key: fields[key]
            for key in self.MATCH_KEYS
            if key in rule and fields.get(key) is not None
        }
        return parser.OFPMatch(**match_kwargs)

    def log_blocked(self, dpid, fields, rule_name):
        timestamp = datetime.utcnow().isoformat() + "Z"
        line = (
            f"{timestamp} dpid={dpid} rule=\"{rule_name}\" "
            f"src_mac={fields.get('eth_src')} dst_mac={fields.get('eth_dst')} "
            f"src_ip={fields.get('ipv4_src')} dst_ip={fields.get('ipv4_dst')} "
            f"ip_proto={fields.get('ip_proto')} "
            f"tcp_dst={fields.get('tcp_dst')} udp_dst={fields.get('udp_dst')}\n"
        )
        with self.block_log_file.open("a", encoding="utf-8") as handle:
            handle.write(line)

    def extract_fields(self, pkt, eth):
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        icmp_id = None
        icmp_seq = None
        if icmp_pkt is not None and getattr(icmp_pkt, "data", None) is not None:
            icmp_id = getattr(icmp_pkt.data, "id", None)
            icmp_seq = getattr(icmp_pkt.data, "seq", None)

        return {
            "eth_src": eth.src,
            "eth_dst": eth.dst,
            "eth_type": eth.ethertype,
            "ipv4_src": ipv4_pkt.src if ipv4_pkt else None,
            "ipv4_dst": ipv4_pkt.dst if ipv4_pkt else None,
            "ip_proto": ipv4_pkt.proto if ipv4_pkt else None,
            "icmp_type": icmp_pkt.type if icmp_pkt else None,
            "icmp_id": icmp_id,
            "icmp_seq": icmp_seq,
            "tcp_src": tcp_pkt.src_port if tcp_pkt else None,
            "tcp_dst": tcp_pkt.dst_port if tcp_pkt else None,
            "udp_src": udp_pkt.src_port if udp_pkt else None,
            "udp_dst": udp_pkt.dst_port if udp_pkt else None,
        }

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        fields = self.extract_fields(pkt, eth)

        blocked, rule = self.is_blocked(fields)
        if blocked:
            # For ICMP tests, do not cache drop flow so each ping attempt is logged.
            if not self.is_ping_request(fields):
                drop_match = self.build_match_from_rule(datapath, fields, rule)
                self.add_flow(
                    datapath,
                    priority=200,
                    match=drop_match,
                    actions=[],
                    idle_timeout=5,
                    hard_timeout=0,
                )

            if self.should_log_ping_request(fields):
                src = fields.get("ipv4_src")
                dst = fields.get("ipv4_dst")
                self.log_blocked(datapath.id, fields, rule["name"])
                msg = f"BLOCK ping src={src} dst={dst} rule=\"{rule['name']}\""
                print(msg, flush=True)
            elif self.is_tcp_demo_traffic(fields):
                src = fields.get("ipv4_src")
                dst = fields.get("ipv4_dst")
                dport = fields.get("tcp_dst")
                self.log_blocked(datapath.id, fields, rule["name"])
                print(f"BLOCK tcp src={src} dst={dst} dport={dport} rule=\"{rule['name']}\"", flush=True)
            return

        dpid = datapath.id
        table = self.mac_to_port.setdefault(dpid, {})
        table[eth.src] = in_port

        out_port = table.get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if self.should_log_ping_request(fields):
            out_label = "FLOOD" if out_port == ofproto.OFPP_FLOOD else str(out_port)
            src = fields.get("ipv4_src")
            dst = fields.get("ipv4_dst")
            print(f"ALLOW ping src={src} dst={dst} out_port={out_label}", flush=True)
        elif self.is_tcp_demo_traffic(fields):
            out_label = "FLOOD" if out_port == ofproto.OFPP_FLOOD else str(out_port)
            src = fields.get("ipv4_src")
            dst = fields.get("ipv4_dst")
            dport = fields.get("tcp_dst")
            print(f"ALLOW tcp src={src} dst={dst} dport={dport} out_port={out_label}", flush=True)

        # For ICMP tests, avoid caching forwarding flow so each ping is logged.
        if out_port != ofproto.OFPP_FLOOD and not self.is_ping_request(fields):
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
            self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=5)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
