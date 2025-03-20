from pox.core import core 
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

class LoadBalancer(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.h1_ip = IPAddr("10.0.0.10")
        self.h5_ip = IPAddr("10.0.0.5")
        self.h1_port = 1
        self.h5_port = 5
        log.info("LoadBalancer initialized")
    
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        log.info("Switch %s has connected." % (event.dpid))
        self.setup_rules()
    
    def setup_rules(self):
        """Set up OpenFlow rules to allow ARP packets and direct flows between h1 and h5."""
        
        # ARP packet rule
        arp_rule = of.ofp_flow_mod()
        arp_rule.match.dl_type = 0x0806
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(arp_rule)
        log.info("Created ARP rule")

        # h1 -> h5 rule
        h1_to_h5 = of.ofp_flow_mod()
        h1_to_h5.match.in_port = self.h1_port
        h1_to_h5.match.dl_type = 0x0800 
        h1_to_h5.match.nw_dst = self.h5_ip
        h1_to_h5.actions.append(of.ofp_action_output(port=self.h5_port))
        self.connection.send(h1_to_h5)
        log.info("Created flow rule from h1 -> h5")
        
        # h5 -> h1 rule
        h5_to_h1 = of.ofp_flow_mod()
        h5_to_h1.match.in_port = self.h5_port
        h5_to_h1.match.dl_type = 0x0800
        h5_to_h1.match.nw_dst = self.h1_ip 
        h5_to_h1.actions.append(of.ofp_action_output(port=self.h1_port))
        self.connection.send(h5_to_h1)
        log.info("Created flow rule from h5 -> h1")
        
    def _handle_PacketIn (self, event):
        """This method has been taken and modified from the noxrepo documentation"""
        packet = event.parsed
        if packet.type == packet.ARP_TYPE:
            if packet.payload.opcode == arp.REQUEST:
                log.info("ARP request")
                arp_reply = arp()
                arp_reply.hwsrc = packet.dst
                arp_reply.hwdst = packet.hwsrc
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = packet.protodst
                arp_reply.protodst = packet.protosrc
                
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = packet.src
                ether.src = packet.dst
                ether.payload = arp_reply

                #send this packet to the switch
                #see section below on this topic
                msg = of.ofp_packet_out()
                msg.data = ether.pack() 
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)

                log.info("Sent ARP reply to %s" % arp_reply.protodst)
            
            elif packet.payload.opcode == arp.REPLY:
                log.info("ARP reply")
            else:
                log.info("Unknown ARP")

def launch():
    core.registerNew(LoadBalancer)
