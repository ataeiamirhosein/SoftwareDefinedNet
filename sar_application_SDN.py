# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_link, get_host, get_all_host
from ryu.topology import event, switches 
import networkx as nx
import json
import logging
import struct
from webob import Response
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.app.ofctl.api import get_datapath

NUMBER_OF_SWITCH_PORTS = 3

class ZodiacSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_CONTEXTS = {'wsgi': WSGIApplication}

	def __init__(self, *args, **kwargs):
		super(ZodiacSwitch, self).__init__(*args, **kwargs)
		wsgi = kwargs['wsgi']
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.mac_to_port = {}
		self.mac_to_dpid = {}
		self.port_to_mac = {}
		self.ip_to_mac = {}
		self.port_occupied = {}
		self.GLOBAL_VARIABLE = 0

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
											ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
												actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match,
									instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
									match=match, instructions=inst)
		datapath.send_msg(mod)

	def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
		# If it is an ARP request
		if opcode == 1:
			targetMac = "00:00:00:00:00:00"
			targetIp = dstIp
		# If it is an ARP reply
		elif opcode == 2:
			targetMac = dstMac
			targetIp = dstIp

		e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
		a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
		p = Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()
	
		actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
		out = datapath.ofproto_parser.OFPPacketOut(
				datapath=datapath,
				buffer_id=0xffffffff,
				in_port=datapath.ofproto.OFPP_CONTROLLER,
				actions=actions,
				data=p.data)
		datapath.send_msg(out)



	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		# If you hit this you might want to increase
		# the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
						ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return
		dst = eth.dst
		src = eth.src
		dpid_src = datapath.id
		
		
		# TOPOLOGY DISCOVERY------------------------------------------
		
		switch_list = get_switch(self.topology_api_app, None)   
		switches=[switch.dp.id for switch in switch_list]
		if self.GLOBAL_VARIABLE == 0:
			for s in switches:
				for switch_port in range(1, NUMBER_OF_SWITCH_PORTS+1):
					self.port_occupied.setdefault(s, {})
					self.port_occupied[s][switch_port] = 0
			self.GLOBAL_VARIABLE = 1
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links_=[(link.dst.dpid,link.src.dpid,link.dst.port_no) for link in links_list]
		for l in links_:
			self.port_occupied[l[0]][l[2]] = 1
			
	# MAC LEARNING-------------------------------------------------
		
		self.mac_to_port.setdefault(dpid_src, {})
		self.port_to_mac.setdefault(dpid_src, {})
		self.mac_to_port[dpid_src][src] = in_port
		self.mac_to_dpid[src] = dpid_src
		self.port_to_mac[dpid_src][in_port] = src

	# HANDLE ARP PACKETS--------------------------------------------
		   
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			arp_packet = pkt.get_protocol(arp.arp)
			arp_dst_ip = arp_packet.dst_ip
			arp_src_ip = arp_packet.src_ip
			# self.logger.info("It is an ARP packet")	
			# If it is an ARP request
			if arp_packet.opcode == 1:
				# self.logger.info("It is an ARP request")	
				if arp_dst_ip in self.ip_to_mac:
					# self.logger.info("The address is inside the IP TO MAC table")
					srcIp = arp_dst_ip
					dstIp = arp_src_ip
					srcMac = self.ip_to_mac[arp_dst_ip]
					dstMac = src
					outPort = in_port
					opcode = 2
					self.send_arp(datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
					# self.logger.info("packet in %s %s %s %s", srcMac, srcIp, dstMac, dstIp)
				else:
					# self.logger.info("The address is NOT inside the IP TO MAC table")
					srcIp = arp_src_ip
					dstIp = arp_dst_ip
					srcMac = src
					dstMac = dst
					# learn the new IP address
					self.ip_to_mac.setdefault(srcIp, {})
					self.ip_to_mac[srcIp] = srcMac
					# Send and ARP request to all the switches
					opcode = 1
					for id_switch in switches:
						#if id_switch != dpid_src:
						datapath_dst = get_datapath(self, id_switch)
						for po in range(1,len(self.port_occupied[id_switch])+1):
							if self.port_occupied[id_switch][po] == 0:
								outPort = po
								if id_switch == dpid_src:
									if outPort != in_port:
										self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
								else:
									self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
	
			else:
				srcIp = arp_src_ip
				dstIp = arp_dst_ip
				srcMac = src
				dstMac = dst
				if arp_dst_ip in self.ip_to_mac:
					# learn the new IP address
					self.ip_to_mac.setdefault(srcIp, {})
					self.ip_to_mac[srcIp] = srcMac
							# Send and ARP reply to the switch
				opcode = 2
				outPort = self.mac_to_port[self.mac_to_dpid[dstMac]][dstMac]
				datapath_dst = get_datapath(self, self.mac_to_dpid[dstMac])
				self.send_arp(datapath_dst, opcode, srcMac, srcIp, dstMac, dstIp, outPort)
					 
				   
		# HANDLE IP PACKETS-----------------------------------------------
			
		ip4_pkt = pkt.get_protocol(ipv4.ipv4)
		if ip4_pkt:
			src_ip = ip4_pkt.src
			dst_ip = ip4_pkt.dst
			src_MAC = src
			dst_MAC = dst
			proto  = str(ip4_pkt.proto)
			sport = "0"
			dport = "0" 
			if proto == "6":
				tcp_pkt = pkt.get_protocol(tcp.tcp)
				sport = str(tcp_pkt.src_port)
				dport = str(tcp_pkt.dst_port)
				   
			if proto == "17":
				udp_pkt = pkt.get_protocol(udp.udp)
				sport = str(udp_pkt.src_port)
				dport = str(udp_pkt.dst_port)
					
			self.logger.info("Packet in switch: %s, source IP: %s, destination IP: %s, From the port: %s", dpid_src, src_ip, dst_ip, in_port)
			# self.logger.info("Packet in switch: %s, source MAC: %s, destination MAC: %s, From the port: %s", dpid_src, src, dst, in_port)
				
			datapath_dst = get_datapath(self, self.mac_to_dpid[dst_MAC])		
			dpid_dst = datapath_dst.id
			self.logger.info(" --- Destination present on switch: %s", dpid_dst)
				
			# Shortest path computation
			path = nx.shortest_path(self.net,dpid_src,dpid_dst)
			self.logger.info(" --- Shortest path: %s", path)
				
				# Set the flows for different cases
			if len(path) == 1:
				In_Port = self.mac_to_port[dpid_src][src]
				Out_Port = self.mac_to_port[dpid_dst][dst]	
				actions_1 = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
				actions_2 = [datapath.ofproto_parser.OFPActionOutput(In_Port)]
				match_1 = parser.OFPMatch(in_port=In_Port, eth_dst=dst)
				match_2 = parser.OFPMatch(in_port=Out_Port, eth_dst=src)
				self.add_flow(datapath, 1, match_1, actions_1)
				self.add_flow(datapath, 1, match_2, actions_2)

				actions = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
				data = msg.data
				pkt = packet.Packet(data)
				eth = pkt.get_protocols(ethernet.ethernet)[0]
				# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
				pkt.serialize()
				out = datapath.ofproto_parser.OFPPacketOut(
					datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
					actions=actions, data=pkt.data)
				datapath.send_msg(out)
								
			elif len(path) >= 2:
				datapath_src = get_datapath(self, path[0])
				datapath_dst = get_datapath(self, path[len(path)-1])
				dpid_src = datapath_src.id
				#self.logger.info("dpid_src  %s", dpid_src)
				dpid_dst = datapath_dst.id
				#self.logger.info("dpid_dst  %s", dpid_dst)
				In_Port_src = self.mac_to_port[dpid_src][src]
				#self.logger.info("In_Port_src  %s", In_Port_src)
				In_Port_dst = self.mac_to_port[dpid_dst][dst]
				#self.logger.info("In_Port_dst  %s", In_Port_dst)
				Out_Port_src = self.net[path[0]][path[1]]['port']
				#self.logger.info("Out_Port_src  %s", Out_Port_src)
				Out_Port_dst = self.net[path[len(path)-1]][path[len(path)-2]]['port']
				#self.logger.info("Out_Port_dst  %s", Out_Port_dst)
				
				actions_1_src = [datapath.ofproto_parser.OFPActionOutput(Out_Port_src)]
				match_1_src = parser.OFPMatch(in_port=In_Port_src, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
				self.add_flow(datapath_src, 1, match_1_src, actions_1_src)
				
				actions_2_src = [datapath.ofproto_parser.OFPActionOutput(In_Port_src)]
				match_2_src = parser.OFPMatch(in_port=Out_Port_src, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
				self.add_flow(datapath_src, 1, match_2_src, actions_2_src)
				self.logger.info("Install the flow on switch %s", path[0])
				
				actions_1_dst = [datapath.ofproto_parser.OFPActionOutput(Out_Port_dst)]
				match_1_dst = parser.OFPMatch(in_port=In_Port_dst, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
				self.add_flow(datapath_dst, 1, match_1_dst, actions_1_dst)
				
				actions_2_dst = [datapath.ofproto_parser.OFPActionOutput(In_Port_dst)]
				match_2_dst = parser.OFPMatch(in_port=Out_Port_dst, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
				self.add_flow(datapath_dst, 1, match_2_dst, actions_2_dst)
				self.logger.info("Install the flow on switch %s", path[len(path)-1])
				
				if len(path) > 2:
					for i in range(1, len(path)-1):
						self.logger.info("Install the flow on switch %s", path[i])
						In_Port_temp = self.net[path[i]][path[i-1]]['port']
						Out_Port_temp = self.net[path[i]][path[i+1]]['port']
						dp = get_datapath(self, path[i])
						actions_1 = [dp.ofproto_parser.OFPActionOutput(Out_Port_temp)]
						actions_2 = [dp.ofproto_parser.OFPActionOutput(In_Port_temp)]
						match_1 = parser.OFPMatch(in_port=In_Port_temp, eth_type = 0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
						match_2 = parser.OFPMatch(in_port=Out_Port_temp, eth_type = 0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
						self.add_flow(dp, 1, match_1, actions_1)
						self.add_flow(dp, 1, match_2, actions_2)

			# Send the packet to the original switch
				path_port = self.net[path[0]][path[1]]['port']
				actions = [datapath.ofproto_parser.OFPActionOutput(path_port)]
				data = msg.data
				pkt = packet.Packet(data)
				eth = pkt.get_protocols(ethernet.ethernet)[0]
				# change the mac address of packet
				eth.src = self.ip_to_mac[src_ip] 
				eth.dst = self.ip_to_mac[dst_ip] 
				# self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
				pkt.serialize()
				out = datapath.ofproto_parser.OFPPacketOut(
				datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
					actions=actions, data=pkt.data)
				datapath.send_msg(out)

			# actions = [datapath.ofproto_parser.OFPActionOutput(Out_Port)]
			# data = msg.data
			# pkt = packet.Packet(data)
			# eth = pkt.get_protocols(ethernet.ethernet)[0]
			# # self.logger.info(" --- Changing destination mac to %s" % (eth.dst))
			# pkt.serialize()
			# out = datapath.ofproto_parser.OFPPacketOut(
			# 	datapath=datapath, buffer_id=0xffffffff, in_port=datapath.ofproto.OFPP_CONTROLLER,
			# 	actions=actions, data=pkt.data)
			# datapath.send_msg(out)


	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		switch_list = get_switch(self.topology_api_app, None)
		switches=[switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)
		links_list = get_link(self.topology_api_app, None)
		links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)	
		

app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')
app_manager.require_app('ryu.app.gui_topology.gui_topology')	
