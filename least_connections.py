"""
This component acts as a controller for hash based load-balancing
where the destination server is found by hashing the source ip address
"""


from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import time
import hashlib
import re
import sys

log = core.getLogger()

IDLE_TOUT = 5 #seconds
HARD_TOUT = 1000 #seconds

#Redirect stdout to controller_results.txt
#sys.stdout = open("controller_results.txt", "w")

#HS load balancer
LB_IP = IPAddr('10.1.0.254')
LB_MAC = EthAddr('00:00:00:00:FE:00')

#HS load balancer
class LoadBalancer (EventMixin):
  class Server:
    def __init__ (self, ip, mac, port):
      self.ip = IPAddr(ip)
      self.mac = EthAddr(mac)
      self.port = port
      self.conn = 0

    def __str__ (self):
      return','.join([str(self.ip), str(self.mac), str(self.port), str(self.conn)])

    def short_str(self):
      return ' '.join([str(self.ip), "with", str(self.conn), "connections."])

  def __init__ (self, connection):
    self.connection = connection
    self.listenTo(connection)
    #init servers
    self.servers = [
      self.Server('10.1.0.1', '00:00:00:00:00:01', 1),
      self.Server('10.1.0.2', '00:00:00:00:00:02', 2),
      self.Server('10.1.0.3', '00:00:00:00:00:03', 3),
      self.Server('10.1.0.4', '00:00:00:00:00:04', 4),
      self.Server('10.1.0.5', '00:00:00:00:00:05', 5),
      self.Server('10.1.0.6', '00:00:00:00:00:06', 6),
      self.Server('10.1.0.7', '00:00:00:00:00:07', 7),
      self.Server('10.1.0.8', '00:00:00:00:00:08', 8),
      self.Server('10.1.0.9', '00:00:00:00:00:09', 9)]
    self.climac_to_port = {}
  
  def get_server (self, packet):
    #least connections selection
    best_serv = self.servers[0]
    for curr_serv in self.servers:
      if curr_serv.conn < best_serv.conn:
        best_serv = curr_serv
    best_serv.conn += 1
    #TODO DELETE DEBUG STATEMENT
    print ("Connection added to server: " + best_serv.short_str())
    return best_serv

  def handle_arp (self, packet, in_port):
    #print "ARP packet"
    #get ARP request
    arp_req = packet.next
    
    #create ARP reply
    arp_rep = arp()
    arp_rep.opcode = arp.REPLY
    arp_rep.hwsrc = LB_MAC		#hardware source?
    arp_rep.hwdst = arp_req.hwsrc
    arp_rep.protosrc = LB_IP		#proto? it takes IP
    arp_rep.protodst = arp_req.protosrc

    #create Ethernet packet
    eth = ethernet()
    eth.type = ethernet.ARP_TYPE
    eth.dst = packet.src
    eth.src = LB_MAC
    eth.set_payload(arp_rep)

    #send ARP reply to client
    msg = of.ofp_packet_out()
    msg.data = eth.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.in_port = in_port
    self.connection.send(msg)

  def handle_request (self, packet, event, src_ip, src_mac):
    #add client to climac_to_port map
    self.climac_to_port[str(packet.src)] = event.ofp.in_port
    print str(packet.src), " - ", event.ofp.in_port

    #print "Other packet"
    #get server to handle request
    server = self.get_server(packet)

    #install reverse rule from server to client
    msg = of.ofp_flow_mod()
    msg.idle_timeout = IDLE_TOUT
    msg.hard_timeout = HARD_TOUT
    msg.buffer_id = None

    #set the ofpff_send_flow_rem flag to force the switch to send a flow removed
    #message every time a flow from server to client is removed
    msg.flags = 1

    #set matching
    msg.match.in_port = server.port
    msg.match.dl_src = server.mac
    msg.match.dl_dst = packet.src
    msg.match.dl_type = ethernet.IP_TYPE #no clue about this, read into it
    msg.match.nw_src = server.ip
    msg.match.nw_dst = packet.next.srcip

    #Set src IP and MAC to LB and forward packet to client
    msg.actions.append(of.ofp_action_nw_addr.set_src(src_ip))
    msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
    msg.actions.append(of.ofp_action_output(port = event.port))

    self.connection.send(msg)

    #install forward rule from server to client
    msg = of.ofp_flow_mod()
    msg.idle_timeout = 0
    msg.hard_timeout = HARD_TOUT
    msg.buffer_id = None
    msg.data = event.ofp #forwards packet
    #msg.flags = 1 	#sends flowremoved message 
    #set matching
    msg.match.in_port = event.port
    msg.match.dl_src = packet.src
    print "DATA LINK SOURCE: ", packet.src
    msg.match.dl_dst = src_mac
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_src = packet.next.srcip
    msg.match.nw_dst = src_ip

    #actions
    msg.actions.append(of.ofp_action_nw_addr.set_dst(server.ip))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(server.mac))
    msg.actions.append(of.ofp_action_output(port = server.port))

    self.connection.send(msg)

  def _handle_FlowRemoved(self, event):
    msg =  event.ofp
    servIP = msg.match.nw_src
    #check if servIP is a server IP
    
    for curr_serv in self.servers:
      if curr_serv.ip == servIP:
        curr_serv.conn -= 1
        #TODO DELETE DEBUG STATEMENT
        print ("Connection removed from server: " + curr_serv.short_str())
        break
    print msg.match.dl_dst
    remmsg = of.ofp_flow_mod()
    remmsg.match.dl_src = str(msg.match.dl_dst)
    remmsg.command = of.OFPFC_DELETE_STRICT
    print "sending it"
    self.connection.send(remmsg)
    
    #self.connection.send(of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT,action=of.ofp_action_output(port=3),priority=32,match=of.ofp_match(dl_src="00:00:00:00:00:0c")))  
    return 
     

    

  def resend_packet (self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    #print "Packet in "
    packet = event.parse()
    if packet.type != packet.ARP_TYPE:
      if packet.next.dstip != LB_IP:
        servip = re.compile("00:00:00:00:00:0[0-9]")
        print "dst - ", str(packet.dst)
    	if servip.match(str(packet.dst)):		#check if packet is going to a server
	  print "to server"
	  self.handle_request(packet, event, packet.next.dstip, packet.dst)
	  return
        else:
	  self.resend_packet(event.ofp, self.climac_to_port[str(packet.dst)])
          return
      self.handle_request(packet, event, LB_IP, LB_MAC)
    else:
      if packet.next.protodst != LB_IP:
         print "bad arp"
         return
      self.handle_arp(packet, event.port)


def launch ():
  def start_balance (event):
    log.debug("control %s" % (event.connection,))
    LoadBalancer(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_balance)



