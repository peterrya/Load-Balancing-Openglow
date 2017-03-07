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

log = core.getLogger()

IDLE_TOUT = 60 #seconds
HARD_TOUT = 300 #seconds

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

    def __str__ (self):
      return','.join([str(self.ip), str(self.mac), str(self.port)])

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

  def get_server (self, packet):
    #hash based selection
    newserv = str.encode(str(packet.next.srcip))	#get hash of packet source ip
    servhash = hashlib.md5(newserv).hexdigest()
    hval = int(servhash, 16)		#get last digit of hash
    hval =  hval % 10

    self.last_server = hval % len(self.servers)
    print self.servers[self.last_server]
    return self.servers[self.last_server] #last server is the most recent

  def handle_arp (self, packet, in_port):
    print "ARP packet"
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
    print "Other packet"
    #get server to handle request
    server = self.get_server(packet)

    #install reverse rule from server to client
    msg = of.ofp_flow_mod()
    msg.idle_timeout = IDLE_TOUT
    msg.hard_timeout = HARD_TOUT
    msg.buffer_id = None

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
    msg.idle_timeout = IDLE_TOUT
    msg.hard_timeout = HARD_TOUT
    msg.buffer_id = None
    msg.data = event.ofp #forwards packet
    
    #set matching
    msg.match.in_port = event.port
    msg.match.dl_src = packet.src
    msg.match.dl_dst = src_mac
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_src = packet.next.srcip
    msg.match.nw_dst = src_ip

    #actions
    msg.actions.append(of.ofp_action_nw_addr.set_dst(server.ip))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(server.mac))
    msg.actions.append(of.ofp_action_output(port = server.port))

    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    print "Packet in "
    packet = event.parse()
    if packet.type != packet.ARP_TYPE:
      if packet.next.dstip != LB_IP:
        servip = re.compile("00:00:00:00:00:0[0-9]")
        print "src - ", str(packet.dst)
    	if servip.match(str(packet.dst)):		#check if packet is going to a server
	  print "to server"
	  self.handle_request(packet, event, packet.next.dstip, packet.dst)
	  return
        else:
	  print "bad ip"
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


'''
frivilous changes
class load_balancer (EventMixin):
  def __init__ (self):
    self.listenTo(core.openflow)
    print "init"
    def _handle_ConnectionUp (self, event):
      print "connection up"
      log.debug("Connection %s" % event.connection)
      LoadBalancer(event.connection)

def launch ():
  core.registerNew(load_balancer)


'
class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
 
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.serv_to_port = {}	#table of servers and their ports
    self.cli_to_port = {}	#table of clients and their ports
    


  def resend_packet (self, packet_in, out_port):
   
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)
 
  def act_like_switch (self, packet, packet_in):
    
    Implement switch-like behavior.
   
    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.
    
    # Learn the port for the source MAC 
    print "packet - ", packet
    print "packet_in", packet_in
    dir(arp()) 
    #generate hash for incoming ip
    bprt = str.encode(str(packet.src))
    prt = hashlib.md5(bprt).hexdigest()

    servip = re.compile("00:00:00:00:00:0[0-9]")
    if servip.match(str(packet.src)):		#check if packet is from a server
      self.serv_to_port[str(packet.src)] = packet_in.in_port	#add server to table
      if (str(packet.dst) not in self.serv_to_port) and (str(packet.dst) not in self.cli_to_port):
        # Flood the packet out everything but the input port
        self.resend_packet(packet_in, of.OFPP_ALL)
      else:	#dest is known
	if str(packet.dst) in self.serv_to_port:
       	  prt = self.serv_to_port[str(packet.dst)]
        else:
 	  prt = self.cli_to_port[str(packet.dst)]
        #log.debug("Installing flow ", str(packet.dst), "->", prt)

        msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
        msg.match = of.ofp_match.from_packet(packet)
	msg.data = packet_in
      #
      #< Set other fields of flow_mod (timeouts? buffer_id? >
        msg.idle_timeout = 60
        msg.hard_timeout = 300
      #< Add an output action, and send -- similar to resend_packet() >
        msg.actions.append(of.ofp_action_output(port = prt))
        self.connection.send(msg)
    else:
      
      hval = int(prt, 16)
      hval =  hval % 10
      hmac =  "00:00:00:00:00:0" + str(hval) #hmac is the load balanced dest mac
      hip = "10.1.0." + str(hval) #hip is the load balanced dest ip
      prt = self.serv_to_port[hmac]
      msg = of.ofp_flow_mod()
      #print "hip - ", hip
      packet.dst = EthAddr(hmac) 
      prt = self.serv_to_port[str(packet.dst)]
      
      ## Set fields to match received packet
      msg.match = of.ofp_match.from_packet(packet)
      msg.data = packet_in
      
      #< Set other fields of flow_mod (timeouts? buffer_id? >
      msg.idle_timeout = 60
      msg.hard_timeout = 300
      #< Add an output action, and send -- similar to resend_packet() >
      #print hip, " - ", hmac
      #print packet
      msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(hip)))
      msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(hmac)))
      msg.actions.append(of.ofp_action_output(port = prt))
      #print "packet - ", packet, "\n\n"
      self.connection.send(msg)
      
       	

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)'''
