"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

	# Add hosts
	servlist = []
	clilist = []
	
	for x in range(1,1000):
		hostname = 'client'+str(x)
		clilist.append(self.addHost(hostname))
	
	for x in range(1,10):
		hostname = 'server'+str(x)
		servlist.append(self.addHost(hostname))
	
	# Add switches
	switchname = 's'+str(1) 
        rightSwitch = self.addSwitch( switchname )

        # Add links
	for x in range(0,999):
        	self.addLink( rightSwitch, clilist[x] )
	
	for x in range(0,9):
		self.addLink( rightSwitch, servlist[x] )


topos = { 'mytopo': ( lambda: MyTopo() ) }
