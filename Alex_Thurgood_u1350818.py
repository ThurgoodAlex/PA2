from core import core
from ib.addresses import IPAddr
import openflow.libopenflow_01 as of
log = core.getLogger()

class LoadBalancer(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.h1_ip = IPAddr("10.0.0.1")
        self.h5_ip = IPAddr("10.0.0.5")
        self.h1_port = 1
        self.h5_port = 5
    
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        log.info("Switch %s has connected." % (event.dpid))
        self.setup_rules()
    
    def setup_rules(self):
        h1_to_h5 = of.ofp_flow_mod()
        h1_to_h5.match.in_port = self.h1_port
        h1_to_h5.match.dl_type = 0x0800 
        h1_to_h5.match.nw_dst = self.h5_ip
        h1_to_h5.actions.append(of.ofp_action_output(port=self.h5_port))
        self.connection.send(h1_to_h5)
        log.info("Installed flow rule: h1 -> h5")
        
        h5_to_h1 = of.ofp_flow_mod()
        h5_to_h1.match.in_port = self.h5_port
        h5_to_h1.match.dl_type = 0x0800
        h5_to_h1.match.nw_dst = self.h1_ip 
        h5_to_h1.actions.append(of.ofp_action_output(port=self.h1_port))
        self.connection.send(h5_to_h1)
        log.info("Installed flow rule: h5 -> h1")
        
def launch():
    core.registerNew(LoadBalancer)
    log.info("LoadBalancer application started!")