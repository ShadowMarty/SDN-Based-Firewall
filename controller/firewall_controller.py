#!/usr/bin/env python3
"""Minimal OpenFlow 1.3 firewall + learning switch controller."""

from datetime import datetime
from pathlib import Path

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_3


class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.block_log_file = Path("blocked_packets.log")
        self.firewall_rules = [
            {
                "name": "Block ICMP from h1 to h3",
                "eth_type": 0x0800,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.3",
                "ip_proto": 1,
            },
            {
                "name": "Block all traffic from h3 MAC",
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
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
            matched = True
            for key, expected in rule.items():
                if key == "name":
                    continue
                if fields.get(key) != expected:
                    matched = False
                    break
            if matched:
                return True, rule
        return False, None

    def build_match_from_rule(self, datapath, fields, rule):
        parser = datapath.ofproto_parser
        match_kwargs = {}
        for key in (
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
        ):
            if key in rule and fields.get(key) is not None:
                match_kwargs[key] = fields[key]
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        fields = {
            "eth_src": eth.src,
            "eth_dst": eth.dst,
            "eth_type": eth.ethertype,
            "ipv4_src": ipv4_pkt.src if ipv4_pkt else None,
            "ipv4_dst": ipv4_pkt.dst if ipv4_pkt else None,
            "ip_proto": ipv4_pkt.proto if ipv4_pkt else None,
            "tcp_src": tcp_pkt.src_port if tcp_pkt else None,
            "tcp_dst": tcp_pkt.dst_port if tcp_pkt else None,
            "udp_src": udp_pkt.src_port if udp_pkt else None,
            "udp_dst": udp_pkt.dst_port if udp_pkt else None,
        }

        blocked, rule = self.is_blocked(fields)
        if blocked:
            drop_match = self.build_match_from_rule(datapath, fields, rule)
            self.add_flow(
                datapath,
                priority=200,
                match=drop_match,
                actions=[],
                idle_timeout=120,
                hard_timeout=0,
            )
            self.log_blocked(datapath.id, fields, rule["name"])
            self.logger.warning("BLOCKED packet by rule: %s", rule["name"])
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
            self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=300)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
