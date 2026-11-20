import csv
import os
import time
from datetime import datetime

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from os_ken.lib import hub
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import ethernet, packet


class SDNController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    POLL_INTERVAL = 5
    CSV_FILE = "flow_stats.csv"

    def __init__(self, *args, **kwargs):
        super(SDNController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}

        new_file = not os.path.exists(self.CSV_FILE)
        self.csv_file = open(self.CSV_FILE, "a", newline="")
        self.csv_writer = csv.writer(self.csv_file)

        if new_file or os.path.getsize(self.CSV_FILE) == 0:
            self.csv_writer.writerow([
                "timestamp",
                "switch_id",
                "priority",
                "match",
                "packet_count",
                "byte_count",
                "duration_sec",
            ])
            self.csv_file.flush()

        self.stats_thread = hub.spawn(self._poll_stats)
        self.logger.info(
            "SDN controller started; statistics polling every %s seconds",
            self.POLL_INTERVAL,
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=instructions,
        )
        datapath.send_msg(flow_mod)

        self.logger.info(
            "Installed table-miss rule on switch %s",
            datapath.id,
        )

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        self.datapaths[datapath.id] = datapath

    def install_udp_flow(self, datapath, in_port, out_port, src_mac, dst_mac):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=0x0800,
            ip_proto=17,
            udp_dst=5201,
            eth_src=src_mac,
            eth_dst=dst_mac,
        )

        actions = [parser.OFPActionOutput(out_port)]
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=20,
            match=match,
            instructions=instructions,
        )

        datapath.send_msg(flow_mod)
        self.logger.info(
            "Installed UDP/5201 flow: %s -> %s",
            src_mac,
            dst_mac,
        )  
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        self.logger.info("PACKET-IN received on port %s", in_port)
        parsed_pkt = packet.Packet(msg.data)
        eth = parsed_pkt.get_protocol(ethernet.ethernet)

        if eth is None or eth.ethertype == 0x88CC:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(
            eth.dst,
            ofproto.OFPP_FLOOD,
        )
        # Install UDP flows in both directions when both hosts are known.
        if out_port != ofproto.OFPP_FLOOD:
            self.install_udp_flow(
                datapath,
                in_port,
                out_port,
                eth.src,
                eth.dst,
            )

            reverse_in_port = self.mac_to_port[dpid].get(eth.dst)
            reverse_out_port = self.mac_to_port[dpid].get(eth.src)

            if reverse_in_port is not None and reverse_out_port is not None:
                self.install_udp_flow(
                    datapath,
                    reverse_in_port,
                    reverse_out_port,
                    eth.dst,
                    eth.src,
                )
        # Install a dedicated rule for UDP traffic to port 5201 or 9000.
        ipv4_pkt = parsed_pkt.get_protocol(
            __import__("os_ken.lib.packet.ipv4", fromlist=["ipv4"]).ipv4
        )
        udp_pkt = parsed_pkt.get_protocol(
            __import__("os_ken.lib.packet.udp", fromlist=["udp"]).udp
        )
        if udp_pkt is not None:
            self.logger.info(
                "UDP packet detected: dst_port=%s, out_port=%s",
                udp_pkt.dst_port,
                out_port,
            )
        if (
            ipv4_pkt is not None
            and udp_pkt is not None
            and udp_pkt.dst_port in (5201, 9000)
            and out_port != ofproto.OFPP_FLOOD
        ):
            udp_match = parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0800,
                ip_proto=17,
                udp_dst=udp_pkt.dst_port,
                eth_src=eth.src,
                eth_dst=eth.dst,
            )

            udp_actions = [parser.OFPActionOutput(out_port)]
            udp_instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    udp_actions,
                )
            ]

            udp_flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=20,
                match=udp_match,
                instructions=udp_instructions,
            )
            datapath.send_msg(udp_flow_mod)

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=eth.src,
                eth_dst=eth.dst,
            )
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions,
                )
            ]

            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=10,
                match=match,
                instructions=instructions,
            )
            datapath.send_msg(flow_mod)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(packet_out)

    def _poll_stats(self):
        while True:
            for datapath in list(self.datapaths.values()):
                parser = datapath.ofproto_parser
                request = parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(request)

            hub.sleep(self.POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().isoformat(timespec="seconds")
        datapath = ev.msg.datapath

        for stat in ev.msg.body:
            match_text = str(stat.match)

            self.csv_writer.writerow([
                timestamp,
                datapath.id,
                stat.priority,
                match_text,
                stat.packet_count,
                stat.byte_count,
                stat.duration_sec,
            ])

        self.csv_file.flush()
