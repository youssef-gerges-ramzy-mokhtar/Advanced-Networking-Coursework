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
        self.__add_flow(datapath, 0, match, actions, idle=0, table_id=1)
        
        # TASK 3: Applying firewall rules before any processing
        # NOTE: All routing rules and flow-table miss rule are in table 1, and table 1 can only be accessed from the rules defined in table 0. And the rules defined in table 0 are the firewall rules
        parser = datapath.ofproto_parser
        self.__apply_firewall_rules(dpid, parser, datapath)

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
        
        print("============= Info =============")
        self.logger.info("❗️\tevent 'packet in' from datapath: {}".format(dpid_to_str(datapath.id)))
        self.logger.info(f"❗️\tPacket Received from in_port: {in_port}")
        self.logger.info(f"❗️\t\n{pkt}")
        print()

        # if arp we just flood (or we could return the mac associated with us not sure!!!)
        # could I used hard-coded conditions like checking the dpid directly
        """
            Later that should be updated to handle 2 cases
                1. If we have received IPs (IPv4) within same subnet act like a learning switch (maybe not as you will decrement the ttl and can act as a normal router)
                    - maybe you can't act normally as IPs within same subnet will net send to the nearest hop see the dst_mac condition will fail and the packet will be dropped
                2. If we have received arp you can directly retrun the mac address from the ARP Table in the router without flooding
                3. As a switch if it received an arp request it should return the mac address from its arp-table
                4. We simply act as a switch if the src and destination ips are within the same subnet and that includes the ip addresses of the router in that subnet
        """
        if pkt.get_protocol(arp):
            data = ev.msg.data if ev.msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ev.msg.buffer_id, in_port=in_port, actions=actions, data=data)
            self.logger.info("Sending packet out ARP or IPs within same subnet")
            datapath.send_msg(out)
            self.__add_flow(datapath, 1, parser.OFPMatch(eth_type=2054), actions)
            return

        # if not self.__valid_packet_dst_mac(dpid, pkt, in_port):
        #     self.logger.info("❗️\tPacket Dropped Destination Mac-Address Mismatch")
        #     return

        self.__create_icmp_packet(pkt, 3, 6)

        actions = []

        # 2. routing the destination ip address
        route = self.__ip_destination_lookup(dpid, pkt, in_port)
        if not route:
            self.logger.info("!\tPacket couldn't be routed")
            return
        
        # 3. ACTION 1: update the destination mac address of the ethernet header
        self.__update_destination_mac(dpid, pkt, route, parser, actions)

        # 4. ACTION 2: update the src mac addres of the ethernet header
        self.__update_source_mac(dpid, route, parser, actions)

        # 5. ACTION 3: decrement ttl
        self.__decrement_ttl(parser, actions)

        # 6. Send the action back to the router
        data = pkt.data if ev.msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        actions.append(datapath.ofproto_parser.OFPActionOutput(route[1]))
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ev.msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.info("!\tSending packet out IPv4")

        # 7. Insert the a new Flow Entry to the local router
        dest_match = self.__get_dest_match(route, pkt.get_protocol(ipv4).dst)
        self.__add_flow(datapath, 1, parser.OFPMatch(eth_type=2048, ipv4_dst=dest_match), actions, table_id=1)
        self.logger.info("!\tFlow Entry Added to Data Path")

    """ Task 3: Firewall Logic """
    
    def __apply_firewall_rules(self, dpid, parser, datapath):
        rules = self.firewall_rules.get_rules(dpid)
        if rules == None:
            return

        for rule in rules:
            # preparing the rule
            self.__prepare_rule(rule)

            # Writing the rule to the flow table (0) in the router
            match = parser.OFPMatch(**rule["match"])
            actions = []
            table_id = 1
            if rule["allow"] == False:
                table_id = None

            self.__add_flow(datapath=datapath, priority=rule["priority"], match=match, actions=actions, go_to_table_id=table_id, idle=0, table_id=0)

    def __prepare_rule(self, rule):
        match = rule["match"]

        # Fixing Naming and Data Types
        if "ip_proto" in match and not isinstance(match["ip_proto"], int):
            match["ip_proto"] = int(match["ip_proto"], 16)
        if "eth_type" in match and not isinstance(match["eth_type"], int):
            match["eth_type"] = int(match["eth_type"], 16)
        
        if "ip_dst" in match:
            match["ipv4_dst"] = match.pop("ip_dst")
        if "ip_src" in match:
            match["ipv4_src"] = match.pop("ip_src")
            
        # Including Pre-requisite OpenFlow Fields
        if "tcp_src" in match or "tcp_dst" in match:
            match["ip_proto"] = 6
    
        if "udp_src" in match or "udp_dst" in match:
            match["ip_proto"] = 17

        if "ipv4_dst" in match or "ipv4_src" in match or "ip_proto" in match:
            match["eth_type"] = 2048
    
    """ Task 3: End Firewall Logic """

    """ Task 2: ICMP Reply Logic """

    def __create_icmp_packet(self, pkt, type, code):
        icmp_pkt = packet.Packet()

        # Extracting old packet headers
        ethernet_header = pkt.get_protocol(ethernet)
        ipv4_header = pkt.get_protocol(ipv4)
        icmp_header = pkt.get_protocol(icmp)
        
        # Adding Ethernet Header
        icmp_pkt.add_protocol(ethernet(
            ethertype = 2048,
            src = ethernet_header.dst,
            dst = ethernet_header.src
        ))

        # Adding IPv4 Header
        icmp_pkt.add_protocol(ipv4(
            ttl = 64,            
            proto = 1, # 1 used to define the icmp protocol
            src = ipv4_header.dst,
            dst = ipv4_header.src
        ))

        # Adding ICMP Header
        # data = None
        # if type == 3:
        #     data = b'\x00\x00\x00\x00' + ipv4_header.serialize(None, None) + icmp_header.serialize(None, None)[:8] # unused + Internet Header + 64 bits of Original Data Datagram
        # elif type == 0 or type == 8:
        #     data = b'' # handle later

        # print(f"Size Byte Array = {data}")

        icmp_pkt.add_protocol(icmp(
            type_ = type,
            code = code,
            csum = 0, # autmatically generate checksum by ryu
            data = b"\x00\x00\x00\x00E\x00\x00T\x06\xf6@\x00@\x01\x92\xfd\n\x00\x00\x8cpa%\xc9\x08\x00\x81\x89\x03U\x00\x00"
        ))

        icmp_pkt.serialize()
        print(f"Very very imp: {packet.Packet(icmp_pkt.data)}")
        # print(f"!!!\tICMP Packet\n{icmp_pkt.data}")



    """ Task 2: ICMP Reply Logic """

    """ Task 1: Routing Logic """

    def __get_dest_match(self, route, pkt_dst_ip):
        hop, out_port, dest_ip = route

        if hop == None:
            return pkt_dst_ip

        dst_ip = ipaddress.ip_network(dest_ip).network_address
        subnet = dest_ip[-2:]
        if subnet == "24":
            return (dst_ip, "255.255.255.0")
        
        return dst_ip

    def __decrement_ttl(self, parser, actions):
        # Adding the change to the list of actions
        actions.append(parser.OFPActionDecNwTtl())

    def __update_source_mac(self, dpid, route, parser, actions):
        # getting the mac address of the output port
        print(f"Route = {route}")
        hop, out_port, dest_ip = route
        src_mac = self.interface_table.get_interface(dpid, out_port)["hw"]

        # Adding the change to the list of actions
        actions.append(parser.OFPActionSetField(eth_src=src_mac))

    def __update_destination_mac(self, dpid, pkt, route, parser, actions):
        ipv4_header = pkt.get_protocol(ipv4)

        # getting the next ip address to forward the packet to
        hop, out_port, dest_ip = route
        next_ip = hop
        if hop == None:
            next_ip = ipv4_header.dst # next ip address is the final destination

        next_ip_mac = self.arp_table.get_hw(dpid, next_ip)

        # Adding the change to the list of actions
        actions.append(parser.OFPActionSetField(eth_dst=next_ip_mac))

    """ Task 1: End Routing Logic """

    # SUPPORT FUNCTIONS
    # -----------------
    # Functions that may help with NAT router implementation
    # The functions below are used in the default NAT router. These
    # functions don't directly handle openflow events, but can be
    # called from functions that do

    def __ip_destination_lookup(self, dpid, pkt, in_port):
        """
            return None if destination ip address is not found in the routing table, or if the packet is not ipv4
            returns icmp packet to destination in case destination ip addres not found
        """

        ipv4_header = pkt.get_protocol(ipv4) # if ipv4_header is not None this implies that eth_type = 2048
        if not ipv4_header:
            return None

        route = self.routing_table.get_route(dpid, ipv4_header.dst)
        if route != None:
            return route

        # Later you should create and return an icmp packet 3/6 to the sender
        # icmp_packet = self.__create_icmp_packet()

    def __valid_packet_dst_mac(self, dpid, pkt, in_port):
        BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
        
        ethernet_header = pkt.get_protocol(ethernet)
        dst_mac = ethernet_header.dst

        if dst_mac == BROADCAST_MAC:
            return True

        if dst_mac == self.interface_table.get_interface(dpid, in_port)["hw"]:
            return True

        print(dst_mac)
        return False

    def __add_flow(self, datapath, priority, match, actions, go_to_table_id=None, idle=60, hard=0, table_id=0):
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
        if go_to_table_id != None:
            inst.append(parser.OFPInstructionGotoTable(go_to_table_id))

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard,
            table_id=table_id
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
                return x['hop'], x['out_port'], x['destination'] # that is a bug
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
