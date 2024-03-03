# -*- coding: utf-8 -*-

"""
Ryu Template Controller for Static Router coursework

You are not required to use this template, so changes to this code can be made
or you may simply use this as a reference.

Make sure to read though the template to see the `Table` classes that can be
used for static data management. 

Note: Requires Python3.8 or higher (uses the ':=' operator)
"""

from typing import Optional, Tuple, Union

from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import (
    HANDSHAKE_DISPATCHER,
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import in_proto as inet
from ryu.lib.packet import ether_types
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.lib.packet.ipv4 import ipv4
from ryu.lib.packet.ipv6 import ipv6
from ryu.lib.packet.lldp import lldp
from ryu.lib.packet.icmp import icmp
from ryu.lib.packet.tcp import tcp
from ryu.lib.packet.udp import udp
from ryu.lib.dpid import dpid_to_str

import json
import sys
import ipaddress


class Router(RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # A set of protocols that do not need to be forwarded in the SCC365 work.
    # This is not for any particular technical reason other than the fact they
    # can make your controller harder to debug.
    ILLEGAL_PROTOCOLS = [ipv6, lldp]

    def __init__(self, *args, **kwargs):
        """
        Init | Constructor

        Loads in/creates the static tables.
        """
        super(Router, self).__init__(*args, **kwargs)
        try:
            self.arp_table = StaticARPTable()
            self.routing_table = StaticRoutingTable()
            self.interface_table = StaticInterfaceTable()
            self.firewall_rules = FirewallRules()
        except Exception as e:
            self.logger.error("🆘\t{}".format(e))
            sys.exit(1)
        if not (self.arp_table.loaded() and self.routing_table.loaded() and self.interface_table.loaded() and self.firewall_rules.loaded()):
            self.logger.error("🆘\tjson table loading was not successful")
            sys.exit(1)

    # EVENT HANDLER FUNCTIONS
    # -----------------------
    # The functions below use python function decorators so that they can be
    # automatically executed on a given OpenFlow event. They also receive the
    # information of the event as the 'ev' parameter.

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def error_msg_handler(self, ev):
        """
        OpenFlow Error Handler
        If an OpenFlow action taken by the controller results in an error at the
        switch, it will trigger an error event. This error event is caught by
        this function. Thi can drastically aide debugging.
        Event Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPErrorMsg
        """
        error = ev.msg.datapath.ofproto.ofp_error_to_jsondict(ev.msg.type, ev.msg.code)
        self.logger.error("🆘\topenflow error received:\n\t\ttype={}\n\t\tcode={}".format(error.get("type"), error.get("code")))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        """
        Handshake: Features Request Response Handler
        Installs a low priority (0) flow table modification that pushes packets
        to the controller. This acts as a rule for flow-table misses.
        As the `HELLO` message is handled by the `RyuApp` automatically, this is
        the first function in this file that will see each datapath in the
        handshake process.
        Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures
        """
        datapath = ev.msg.datapath
        match = datapath.ofproto_parser.OFPMatch()
        dpid = dpid_to_str(datapath.id)
        self.__request_port_info(datapath)
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.__add_flow(datapath, 0, match, actions)
        self.logger.info("🤝\thandshake taken place with datapath: {}".format(dpid_to_str(datapath.id)))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Packet In Event Handler

        The bulk of your packet processing logic will reside in this function &
        all functions called from this function. There is currently NO logic
        here, so it wont do much until you edit it!

        Event Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPacketIn
        Ryu Packet Documentation:
        https://ryu.readthedocs.io/en/latest/library_packet.html#packet-library
        Ryu Packet API Documentation:
        https://ryu.readthedocs.io/en/latest/library_packet_ref.html#packet-library-api-reference
        Protocol Specific API References:
        https://ryu.readthedocs.io/en/latest/library_packet_ref.html#protocol-header-classes
        Packet Out Message Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPacketOut
        """
        datapath = ev.msg.datapath
        dpid = dpid_to_str(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(ev.msg.data)
        in_port = ev.msg.match["in_port"]

        if self.__illegal_packet(pkt):
            return

        self.logger.info("❗️\tevent 'packet in' from datapath: {}".format(dpid_to_str(datapath.id)))

        return

    # SUPPORT FUNCTIONS
    # -----------------
    # Functions that may help with NAT router implementation
    # The functions below are used in the default NAT router. These
    # functions don't directly handle openflow events, but can be
    # called from functions that do

    def __add_flow(self, datapath, priority, match, actions, idle=60, hard=0):
        """
        Install Flow Table Modification
        Takes a set of OpenFlow Actions and a OpenFlow Packet Match and creates
        the corresponding Flow-Mod. This is then installed to a given datapath
        at a given priority.
        Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPFlowMod
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard,
        )
        self.logger.info(
            "✍️\tflow-Mod written to datapath: {}".format(dpid_to_str(datapath.id))
        )
        datapath.send_msg(mod)

    def __illegal_packet(self, pkt, log=False):
        """
        Illegal Packet Check
        Checks to see if a packet is allowed to be forwarded. You should use
        these pre-populated values in your coursework to avoid issues.
        """
        for proto in self.ILLEGAL_PROTOCOLS:
            if pkt.get_protocol(proto):
                if log:
                    self.logger.debug("🚨\tpacket with illegal protocol seen: {}".format(proto.__name__))
                return True
        return False

    def __request_port_info(self, datapath):
        """
        Request Datapath Port Descriptions
        Create a Port Desc Stats Request and send it to the given datapath. The
        response for this will come in asynchronously in the function that
        handles the event `EventOFPPortDescStatsReply`.
        Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPortDescStatsRequest
        """
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
        self.logger.debug(
            "📤\trequesting datapath port information: {}".format(
                dpid_to_str(datapath.id)
            )
        )

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def __port_info_handler(self, ev):
        """
        Handle a OFPPortDescStatsReply event
        Documentation:
        https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#ryu.ofproto.ofproto_v1_3_parser.OFPPortDescStatsReply
        """
        dpid = dpid_to_str(ev.msg.datapath.id)
        for p in ev.msg.body:
            self.logger.info(p.port_no)
            self.logger.info(p.hw_addr)
        self.logger.debug("❗️\tevent 'PortDescStatsReply' received!")
    

"""
Table

Represents a generic static data table, used by ARP, Routing, and Interface
tables.

As use of this template file is entirely optional, you are of course free to
modify these classes however you desire.
"""


class Table():

    def __init__(self, path: str = ""):
        self._table, from_file = self.__load_data(path)
        self._loaded = from_file
        if not from_file:
            print("using an empty {} table: read from file failed".format(self.__class__.__name__))

    def loaded(self) -> bool:
        """
        Loaded

        Returns True if the table was loaded from file, False otherwise.
        """
        return self._loaded

    def get_table(self) -> dict:
        """
        Get Table

        Returns the entire loaded table (as a dictionary)
        """
        return self._table

    def get_table_for_dpid(self, dpid: str) -> Optional[dict]:
        """
        Get Table for DPID

        Returns the entries in a table associated with a given datapath. Returns
        'None' if the DPID does not exist in the table.
        """
        if dpid in self._table:
            return self._table[dpid]
        return None

    def __load_data(self, path: str) -> Tuple[dict,  bool]:
        try:
            with open(path, 'r') as f:
                return json.load(f), True
        except:
            return {}, False
        
    def dump_table(self):
        """
        Dump Table to Stdout (pretty)

        Prints a dictionary in JSON format to the std out. This is useful for
        debugging.   
        """
        print(
            json.dumps(
                self._table,
                sort_keys=True,
                indent=2,
                separators=(",", ": ")
            )
        )


"""
Static ARP Table (extends Table)

Should contain a table with the static ARP data along with helper functions to
access the data.
"""


class StaticARPTable(Table):

    ARP_PATH = './arp.json'

    def __init__(self, path: str = ARP_PATH):
        super().__init__(path=path)

    def get_ip(self, dpid: str, mac: str) -> Optional[str]:
        """
        Get IP

        Returns the IP address associated with the given MAC address (or 'None')
        """
        for x in self._table[dpid]:
            if x['hw'] == mac:
                return x['ip']
        return None

    def get_hw(self, dpid: str, ip: str) -> Optional[str]:
        """
        Get MAC

        Returns the MAC address associated with the given IP address (or 'None')
        """
        for x in self._table[dpid]:
            if x['ip'] == ip:
                return x['hw']
        return None


"""
Static Routing Table (extends Table)

Should contain a table with the static routing data along with helper functions
to access the data.
"""


class StaticRoutingTable(Table):

    ROUTING_PATH = './routing.json'

    def __init__(self, path=ROUTING_PATH):
        super().__init__(path=path)

    def get_next_hop(self, dpid: str, ip: str) -> Optional[str]:
        """
        Get Next Hop

        Returns the IP address of the next hop towards a given IP address, if
        direct or IP address is not in the table, None is returned.
        """
        for x in self._table[dpid]:
            if any([x['destination'] == ip,
                    ipaddress.ip_address(ip) in ipaddress.ip_network(x['destination'])]):
                return x['hop']
        return None

    def get_route(self, dpid: str, ip: str) -> Tuple[Optional[str], Optional[int], Optional[bool]]:
        """
        Get Route

        Returns the IP address of the next hop towards a given IP address, if
        direct or IP address is not in the table, None is returned.
        """
        for x in self._table[dpid]:
            if any([x['destination'] == ip,
                    ipaddress.ip_address(ip) in ipaddress.ip_network(x['destination'])]):
                return x['hop'], x['out_port'], x['nat']
        return None, None, None


"""
Static Interfaces Table (extends Table)

Should contain a table with the static Interfaces data along with helper
functions to access the data.
"""


class StaticInterfaceTable(Table):

    INTERFACES_PATH = './interfaces.json'

    def __init__(self, path=INTERFACES_PATH):
        super().__init__(path=path)

    def get_interface(self,  dpid: str, port: int) -> Optional[dict]:
        """
        Get Interface

        Retruns an interface entry for a given datapath and port. If no entry
        exists, for the given datapath and port, None is returned.
        """
        for x in self._table[dpid]:
            if x['port'] == port:
                return x
        return None
    
    def get_interface_by_hw(self,  dpid: str, hw: str) -> Optional[dict]:
        """
        Get Interface By HW

        Retruns an interface entry for a given datapath and mac address. If no
        entry exists, for the given datapath and mac address, None is returned.
        """
        for x in self._table[dpid]:
            if x['hw'] == hw:
                return x
        return None
    

"""
Firewall Rules (extends Table)

Represents a set of firewall rules as described in the coursework specification.
Although this is not a table, it shares much of the logic with the tables above,
so it is implemented as a table.
"""

class FirewallRules(Table):

    RULES_PATH = './rules.json'

    def __init__(self, path=RULES_PATH):
        super().__init__(path=path)

    def get_rules(self,  dpid: str) -> Optional[list]:
        """
        Get Rules

        Returns the rules for a given datapath ID (full 16 char string). If the
        rules set does not have ay rules for the given datapath, None is
        returned.
        """
        if dpid in self._table:
            return self._table[dpid]
        return None
