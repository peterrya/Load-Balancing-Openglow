"""
Creates 1 switch with 1010 hosts, 10 servers and 1000 clients
"""

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.log import output, error

servlist = []
clilist = []

def upserv( self, line ):
    "upserv starts a HTTP server on every server host"
    net = self.mn
    #help(net) 
    for x in range (0, 9):
        net.__getitem__(servlist[x]).cmd('python -m SimpleHTTPServer 80 &')
CLI.do_upserv = upserv

def cliwget( self, num ):
    "cliwget has each client wget 10.0.0.4"
    net = self.mn
    nu = int(num)
    while (nu > 0):
	nu = nu - 1
    	for x in range (0,99):
		print net.__getitem__(clilist[x]).cmd('wget 10.1.0.254')
CLI.do_cliwget = cliwget

class MyTopo( Topo ):
    "Load Balancing topology."

    def __init__( self ):
        "Create Load Balancing topo."

        # Initialize topology
        Topo.__init__( self )

	# Add hosts
	
	for x in range(1,10):
		hostname = 'server'+str(x)
		ipad = '10.1.0.' + str(x)
		servlist.append(self.addHost(hostname, ip=ipad))

	for x in range(1,100):
		hostname = 'zclient'+str(x)
		clilist.append(self.addHost(hostname))
		
	# Add switches
	switchname = 's'+str(1) 
        rightSwitch = self.addSwitch( switchname )

        # Add links
	for x in range(0,9):
        	self.addLink( rightSwitch, servlist[x] )
	
	for x in range(0,99):
		self.addLink( rightSwitch, clilist[x] )

topos = { 'mytopo': ( lambda: MyTopo() ) }

