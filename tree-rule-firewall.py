from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr,IPAddr
from collections import namedtuple
import pox.lib.packet as pkt
import os
import xml.etree.ElementTree as ET
''' Add your imports here ... '''

import csv

log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewallpolicies.xml" % os.environ[ 'HOME' ]  

''' Add your global variables here ... '''


	
class Firewall (EventMixin):

	def __init__ (self):
		self.listenTo(core.openflow)
		log.debug("Enabling Firewall Module")
		self.policy_table=[]
		tree = ET.parse(policyFile)
		self.root = tree.getroot()
		

	def _handle_ConnectionUp (self, event):	

		pass

	
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
		for srcip in self.root.iter('srcip'):
			if IPAddr(srcip.attrib['val'])==src_ip:
				for srcport in srcip:
					if srcport.attrib['val']==src_port or 1==1:
						for dstip in srcport:
							if IPAddr(dstip.attrib['val'])==dst_ip:
								for dstport in dstip:
									if dstport.attrib['val']==dst_port or 1==1:
										policy = dstport.text
										break
								break
						break		
				break
			
		return policy

def launch ():
	'''
	Starting the Firewall module
	'''
	core.registerNew(Firewall)
