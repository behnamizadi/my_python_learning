#!/usr/bin/python

'''
Coursera:
- Software Defined Networking (SDN) course
-- Programming Assignment: Layer-2 Firewall Application

Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr,IPAddr
from collections import namedtuple
import pox.lib.packet as pkt
import os

''' Add your imports here ... '''

import csv

log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewallpolicies.csv" % os.environ[ 'HOME' ]  

''' Add your global variables here ... '''


	
class Firewall (EventMixin):

	def __init__ (self):
		self.listenTo(core.openflow)
		log.debug("Enabling Firewall Module")
		self.policy_table=[]

	def _handle_ConnectionUp (self, event):	
		with open(policyFile, 'rb') as f:
			reader = csv.DictReader(f)
			for row in reader:
				self.policy_table.append((row['id'],row['src_ip'],row['src_port'], row['dst_ip'],row['dst_port'],row['action']))
	
	def _handle_PacketIn (self, event):
		dpid = event.connection.dpid
		inport = event.port
		packet = event.parsed
		packet_in=event.ofp
		if packet.parsed:
			log.warning("switch=%i port=%i ", dpid, inport)
		msg = of.ofp_packet_out()
		msg.data = packet_in
		tcp = packet.find('tcp')
		port=None
		if tcp is not None:
			srcport=tcp.srcport
			dstport=tcp.dstport
			srcip=packet.find('ipv4').srcip
			dstip=packet.find('ipv4').dstip
			if self.get_policy(srcip,srcport,dstip,dstport)=="A":
				msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
				log.warning(" acepted from switch=%i port=%i ", dpid, inport)
		else:
			msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))

		# Send message to switch
		event.connection.send(msg)
	
	def get_policy(self,src_ip,src_port,dst_ip,dst_port):
		policy='D'
		for row in self.policy_table:
			if (row[1]=='*' or src_ip==IPAddr(row[1])) and (src_port==row[2] or row[2]=='*') and (row[3]=='*' or dst_ip==IPAddr(row[3])) and (dst_port==row[4] or row[4]=='*'):
				policy=row[5]
		return policy
		

def launch ():
	'''
	Starting the Firewall module
	'''
	core.registerNew(Firewall)
