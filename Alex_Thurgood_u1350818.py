from pox.core import core 
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

class LoadBalancer(object):
    def __init__(self):
        self.h1_ip = IPAddr("10.0.0.1")
        self.h5_ip = IPAddr("10.0.0.5")
        self.h1_port = 1
        self.h5_port = 5

        core.openflow.addListeners(self)
        log.info(f"LoadBalancer initialized with {self.h1_ip}:{self.h1_port} and {self.h5_ip}:{self.h5_port}")
    
    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {event.dpid} has connected.")
        self.setup_rules(event)
    
    def setup_rules(self, event):
        """Set up OpenFlow rules to allow direct flows between h1 and h5."""
        
        # h1 -> h5 rule
        h1_to_h5 = of.ofp_flow_mod()
        h1_to_h5.match.in_port = self.h1_port
        h1_to_h5.match.dl_type = 0x0800 
        h1_to_h5.match.nw_dst = self.h5_ip
        h1_to_h5.actions.append(of.ofp_action_output(port=self.h5_port))
        event.connection.send(h1_to_h5)
        log.info("Created flow rule from h1 -> h5")
        
        # h5 -> h1 rule
        h5_to_h1 = of.ofp_flow_mod()
        h5_to_h1.match.in_port = self.h5_port
        h5_to_h1.match.dl_type = 0x0800
        h5_to_h1.match.nw_dst = self.h1_ip 
        h5_to_h1.actions.append(of.ofp_action_output(port=self.h1_port))
        event.connection.send(h5_to_h1)
        log.info("Created flow rule from h5 -> h1")
        
    def _handle_PacketIn(self, event):
        """Handle incoming packets, including ARP requests."""
        packet = event.parsed
        log.info(f"PacketIn: {packet} (type {packet.type})")
        
        if packet.type == ethernet.ARP_TYPE:
            self._handle_ARP(event, packet)
        else:
            log.info("Ignoring non-ARP packet")

    def _handle_ARP(self, event, packet):
        """This method has been taken and modified from the noxrepo documentation"""
        arp_packet = packet.payload

        if arp_packet.opcode == arp.REQUEST:
            requested_ip = arp_packet.protodst
            
            if requested_ip in self.arp_table:
                mac_address = self.arp_table[requested_ip]
                log.info(f"Sending ARP reply for {requested_ip} with MAC {mac_address}")

                # Create ARP reply
                arp_reply = arp()
                arp_reply.hwsrc = mac_address
                arp_reply.hwdst = arp_packet.hwsrc
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = requested_ip
                arp_reply.protodst = arp_packet.protosrc

                # Create Ethernet frame
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.src = mac_address
                ether.dst = packet.src
                ether.payload = arp_reply

                # Send ARP reply
                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)

                log.info(f"Sent ARP reply to {arp_packet.protosrc}")

            else:
                log.info(f"No ARP entry for {requested_ip}, ignoring request.")

        elif arp_packet.opcode == arp.REPLY:
            log.info("Received an ARP reply, ignoring.")
        else:
            log.info("Unknown ARP operation")

def launch():
    core.registerNew(LoadBalancer)
