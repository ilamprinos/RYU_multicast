#2551 Isidoros Lamprinos
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import igmp
from ryu.lib.packet import ether_types

"""
fill in the code here (optional)

"""

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #In each of these vectors' names the first number symbolises
        #the switch and second the multicast group. Every time we have
        #a new igmp packet, the switch that received it keeps memory
        #of the inport and of the multicast group. Both switches have
        #as default port 1 for both multicast groups
        self.s21 = [] 
        self.s21.append(1) 
        
        self.s22 = []
        self.s22.append(1)
        
        self.s31 = [] 
        self.s31.append(1)
        
        self.s32 = []
        self.s32.append(1)
                      
    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id

        self.logger.info("Datapath ID is %s", hex(dpid))

        if dpid == 0x1A:
            self.proact(datapath,msg,dpid,"192.168.2.1","00:00:00:00:04:01","00:00:00:00:04:02",4,8)#the last two args are outport and tos
            self.multi_pro(datapath, "239.0.0.1", "00:00:00:00:03:01", "00:00:00:00:03:02", 2, 1)#here they inport and outport 
            self.multi_pro(datapath, "239.0.0.1", "00:00:00:00:01:01", "01:00:5e:00:00:01", 1, 2)
            self.multi_pro(datapath, "239.0.0.2", "00:00:00:00:03:01", "00:00:00:00:03:02", 2, 1)
            self.multi_pro(datapath, "239.0.0.2", "00:00:00:00:01:01", "01:00:5e:00:00:02", 1, 2)

        elif dpid == 0x1B:
            self.proact(datapath,msg,dpid,"192.168.1.1","00:00:00:00:04:02","00:00:00:00:04:01",4,8)#the last two args are outport and tos
            self.multi_pro(datapath, "239.0.0.1", "00:00:00:00:03:02", "00:00:00:00:03:01", 2, 1)#here they inport and outport 
            self.multi_pro(datapath, "239.0.0.1", "00:00:00:00:02:01", "01:00:5e:00:00:01", 1, 2)
            self.multi_pro(datapath, "239.0.0.2", "00:00:00:00:03:02", "00:00:00:00:03:01", 2, 1)
            self.multi_pro(datapath, "239.0.0.2", "00:00:00:00:02:01", "01:00:5e:00:00:02", 1, 2)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp1 = pkt.get_protocol(arp.arp)
                if arp1.opcode == arp.ARP_REQUEST:
                    self.handle_arp(datapath,msg.in_port,eth,arp1)
                
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                pkt_icmp = pkt.get_protocol(icmp.icmp)


                if dstip != "192.168.1.2" and dstip != "192.168.1.3" and dstip != "192.168.2.2" and dstip != "192.168.2.3"  and dstip != "239.0.0.1" and "239.0.0.2":
                    #self.logger.info("------------------------- %s",dstip)
                    self.handle_icmp(msg,datapath,msg.in_port,eth,ip,pkt_icmp,"192.168.1.1")
                    return

                if (eth.src == "00:00:00:00:01:02" or eth.src == "00:00:00:00:01:03") and dstip == "192.168.2.2":
                    
                    actions = []
                    
                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:02"))
                    dst = "00:00:00:00:02:02"
                    out_port = 1
                    
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
                    match = datapath.ofproto_parser.OFPMatch(
                        dl_type=0x0800, nw_dst=dstip ,nw_dst_mask = 0x18,nw_tos = 0)
                    
                    self.add_flow(datapath, match, actions) 
                    
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=data)
                    
                    datapath.send_msg(out)
                
                elif (eth.src == "00:00:00:00:01:02" or eth.src == "00:00:00:00:01:03") and dstip == "192.168.2.3":
                    data = None
                    actions = []

                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:02"))
                    dst = "00:00:00:00:03:02"
                    
                    out_port = 1
                    
                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:01"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
                    match = datapath.ofproto_parser.OFPMatch(
                        dl_type=0x0800, nw_dst=dstip,nw_dst_mask = 0x18,nw_tos = 0)
                    
                    self.add_flow(datapath, match, actions) 
                    
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=data)
                    
                    datapath.send_msg(out)
                
                if eth.src == "00:00:00:00:03:02" and dstip == "192.168.1.2":
                    self.resp(datapath,msg,dpid,ofproto,dstip,"00:00:00:00:01:01","00:00:00:00:01:02")

                if eth.src == "00:00:00:00:03:02" and dstip == "192.168.1.3":
                    self.resp(datapath,msg,dpid,ofproto,dstip,"00:00:00:00:01:01","00:00:00:00:01:03")


                return
            return
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp1 = pkt.get_protocol(arp.arp)
                if arp1.opcode == arp.ARP_REQUEST:
                    self.handle_arp(datapath,msg.in_port,eth,arp1)
                
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                pkt_icmp = pkt.get_protocol(icmp.icmp)
                if dstip != "192.168.1.2" and dstip != "192.168.1.3" and dstip != "192.168.2.2" and dstip != "192.168.2.3" and dstip != "239.0.0.1" and "239.0.0.2":
                    #self.logger.info("------------------------- %s",dstip)
                    self.handle_icmp(msg,datapath,msg.in_port,eth,ip,pkt_icmp,"192.168.2.1")
                    return

                if (eth.src == "00:00:00:00:02:02" or eth.src == "00:00:00:00:02:03") and dstip == "192.168.1.2":
                    data = None
                    actions = []

                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"))
                    dst = "00:00:00:00:03:01"

                    out_port = 1

                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
                    
                    match = datapath.ofproto_parser.OFPMatch(
                        dl_type=0x0800, nw_dst=dstip,nw_dst_mask = 0x18,nw_tos = 0)
                    
                    self.add_flow(datapath, match, actions) 
                    
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=data)
                    
                    datapath.send_msg(out)

                elif (eth.src == "00:00:00:00:02:02" or eth.src == "00:00:00:00:02:03") and dstip == "192.168.1.3":
                    data = None
                    actions = []

                    actions.append(datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:03:01"))
                    dst = "00:00:00:00:03:01"

                    out_port = 1

                    actions.append(datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:03:02"))
                    actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
                    
                    match = datapath.ofproto_parser.OFPMatch(
                        dl_type=0x0800, nw_dst=dstip,nw_dst_mask = 0x18,nw_tos = 0)
                    
                    self.add_flow(datapath, match, actions) 
                    
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=data)
                    
                    datapath.send_msg(out)

                if eth.src == "00:00:00:00:03:01" and dstip == "192.168.2.2":
                    self.resp(datapath,msg,dpid,ofproto,dstip,"00:00:00:00:02:01","00:00:00:00:02:02")

                
                if eth.src == "00:00:00:00:03:01" and dstip == "192.168.2.3":  
                    self.resp(datapath,msg,dpid,ofproto,dstip,"00:00:00:00:02:01","00:00:00:00:02:03")
                return
            return
        

        pkt_igmp = pkt.get_protocol(igmp.igmp)
        dst = eth.dst
        #self.logger.info("-------%s--------",dst[0:14])
        if dpid == 0x2 and dst[0:14] ==  "01:00:5e:00:00":
            if ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip = pkt.get_protocol(ipv4.ipv4)
                if ip.proto == 2 :
                    records = pkt_igmp.records
                    for record in records:
                        address = record.address
                    
                    if address == "239.0.0.1":
                        if msg.in_port in self.s21:
                            return
                        self.s21.append(msg.in_port)

                    elif address == "239.0.0.2":
                        if msg.in_port in self.s22:
                            return
                        self.s22.append(msg.in_port)
                        
                    #self.logger.info("-------%s--------",address)
                    #self.logger.info("")
                    return

                elif ip.proto != 2:
                    if dst == "01:00:5e:00:00:01":
                        self.igmp(datapath,msg,"01:00:5e:00:00:01",2,1)
                    elif dst == "01:00:5e:00:00:02":
                        self.igmp(datapath,msg,"01:00:5e:00:00:02",2,2)
                    return

        if dpid == 0x3 and dst[0:14] ==  "01:00:5e:00:00":
            if ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip = pkt.get_protocol(ipv4.ipv4)
                if ip.proto == 2 :
                    records = pkt_igmp.records
                    for record in records:
                        address = record.address
                    
                    if address == "239.0.0.1":
                        if msg.in_port in self.s31:
                            return
                        self.s31.append(msg.in_port)

                    elif address == "239.0.0.2":
                        if msg.in_port in self.s32:
                            return
                        self.s32.append(msg.in_port)
                        
                    #self.logger.info("-------%s--------",address)
                    #self.logger.info("")
                    return

                elif ip.proto != 2:
                    if dst == "01:00:5e:00:00:01":
                        self.igmp(datapath,msg,"01:00:5e:00:00:01",3,1)
                    elif dst == "01:00:5e:00:00:02":
                        self.igmp(datapath,msg,"01:00:5e:00:00:02",3,2)
                    return

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
    

    def igmp(self,datapath,msg,dstmac,switch,group):
        s = []
        if switch == 2:
            if group == 1:
                s = self.s21
            else:
                s = self.s22
        elif switch == 3:
            if group ==1:
                s = self.s31
            else:
                s = self.s32

        #self.logger.info("=====%s=====",s[0])
        actions = []
        actions.append(datapath.ofproto_parser.OFPActionSetDlDst(dstmac))
        
        for port in s:
            if msg.in_port != port:
                actions.append(datapath.ofproto_parser.OFPActionOutput(port)) 
        
        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port,dl_dst=haddr_to_bin(dstmac))
        
        self.add_flow(datapath, match, actions)

    def resp(self,datapath,msg,dpid,ofproto,dstip,srcmac,dstmac):
        data = None
        actions = []

        actions.append(datapath.ofproto_parser.OFPActionSetDlDst(dstmac))
        dst = dstmac

        out_port = 2

        actions.append(datapath.ofproto_parser.OFPActionSetDlSrc(srcmac))
        actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
        
        match = datapath.ofproto_parser.OFPMatch(
            dl_type=0x0800, nw_dst=dstip)
        
        self.add_flow(datapath, match, actions) 
        
        #data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        
        datapath.send_msg(out)

    def proact(self,datapath,msg,dpid,dstip,srcmac,dstmac, port, tos):
        actions = []
        
        actions.append(datapath.ofproto_parser.OFPActionSetDlDst(dstmac))
        dst = dstmac
        
        
        actions.append(datapath.ofproto_parser.OFPActionSetDlSrc(srcmac))
        actions.append(datapath.ofproto_parser.OFPActionOutput(port))
        match = datapath.ofproto_parser.OFPMatch(
            dl_type=0x0800, nw_dst=dstip ,nw_dst_mask = 0x18 , nw_tos = tos)
        
        self.add_flow(datapath, match, actions)



    def multi_pro(self,datapath,dstip,srcmac,dstmac, inport , outport):
        actions = []
        
        actions.append(datapath.ofproto_parser.OFPActionSetDlDst(dstmac))
        dst = dstmac
        
        
        actions.append(datapath.ofproto_parser.OFPActionSetDlSrc(srcmac))
        actions.append(datapath.ofproto_parser.OFPActionOutput(outport))
        match = datapath.ofproto_parser.OFPMatch(
            in_port=inport,dl_type=0x0800, nw_dst=dstip )
        
        self.add_flow(datapath, match, actions)

    def handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return

        if pkt_arp.dst_ip == "192.168.1.1":
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src="00:00:00:00:01:01"))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac="00:00:00:00:01:01",
                                src_ip="192.168.1.1",
                                dst_mac=pkt_arp.src_mac,
                                dst_ip=pkt_arp.src_ip))
        
        else:
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src="00:00:00:00:02:01"))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac="00:00:00:00:02:01",
                                src_ip="192.168.2.1",
                                dst_mac=pkt_arp.src_mac,
                                dst_ip=pkt_arp.src_ip))


        self._send_packet(datapath, port, pkt)

    def handle_icmp(self,msg, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp,dstip):
        pkt = packet.Packet()
        #self.logger.info("ETH SRC %s",pkt_ethernet.src )
        #self.logger.info("ETH DST %s",pkt_ethernet.dst )
        #self.logger.info("IP SRC %s" ,pkt_ipv4.src )
        #self.logger.info("IP DST %s" ,dstip)

        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=pkt_ethernet.dst))
        
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=dstip,
                                   proto=pkt_ipv4.proto))
        
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_DEST_UNREACH,#icmp.ICMP_ECHO_REPLY,
                                   code=1,
                                   csum=0,
                                   data=icmp.dest_unreach(data=bytearray()+msg.data[14:])))#icmp.dest_unreach(data=msg.data[14:])
        self._send_packet(datapath, port, pkt)


    def _send_packet(self,datapath,port,pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
