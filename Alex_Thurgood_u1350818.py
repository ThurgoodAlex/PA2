from pox.core import core 
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

class LoadBalancer(object):
    def __init__(self):
        self.vIP = IPAddr("10.0.0.10")
        #this h1 and h5 stuff is old
        self.h1_ip = IPAddr("10.0.0.1")
        self.h5_ip = IPAddr("10.0.0.5")
        self.h1_port = 1
        self.h5_port = 5
        self.server_port = 0

        self.current_server = 0

        self.clients_arp_table = {
            IPAddr("10.0.0.1"): EthAddr("00:00:00:00:00:01"),
            IPAddr("10.0.0.2"): EthAddr("00:00:00:00:00:02"),
            IPAddr("10.0.0.3"): EthAddr("00:00:00:00:00:03"),
            IPAddr("10.0.0.4"): EthAddr("00:00:00:00:00:04")
        }

        self.client_ip_port_table = {
            IPAddr("10.0.0.1"): 1,
            IPAddr("10.0.0.2"): 2,
            IPAddr("10.0.0.3"): 3,
            IPAddr("10.0.0.4"): 4
        }

        self.severs_arp_table = {
            IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
            IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06"),
        }

        self.server_ip_port_table = {
            IPAddr("10.0.0.5"): 5,
            IPAddr("10.0.0.6"): 6,
        }

        self.client_to_server_mapping = {}

        core.openflow.addListeners(self)
        log.info(f"LoadBalancer initialized with {self.h1_ip}:{self.h1_port} and {self.h5_ip}:{self.h5_port}")
        log.info(f"Client ARP table: {self.clients_arp_table}")
        log.info(f"Server ARP table: {self.severs_arp_table}")

    def round_robin(self, client_ip):
        if self.current_server == 0:
            server_ip = IPAddr("10.0.0.5")
            self.current_server = 1
        else:
            server_ip = IPAddr("10.0.0.6")
            self.current_server = 0

        server_mac = self.severs_arp_table[server_ip]  
        self.server_port = self.server_ip_port_table[server_ip] 

        self.client_to_server_mapping[client_ip] = (server_ip, server_mac, self.server_port)

        log.info(f"Round Robin selected: {server_ip} ({server_mac}) on port {self.server_port}")
        
        return server_ip, server_mac, self.server_port
    
    def _handle_ConnectionUp(self, event):

        log.info(f"Switch {event.dpid} has connected.")
    
    def install_flows(self, event):
        """Set up OpenFlow rules to allow direct flows between the servers and the virtual ip."""
        
        # # h1 -> h5 rule
        # h1_to_h5 = of.ofp_flow_mod()
        # h1_to_h5.match.in_port = self.h1_port
        # h1_to_h5.match.dl_type = 0x0800 
        # h1_to_h5.match.nw_dst = self.h5_ip
        # h1_to_h5.actions.append(of.ofp_action_output(port=self.h5_port))
        # event.connection.send(h1_to_h5)
        # log.info("Created flow rule from h1 -> h5")
        
        # # h5 -> h1 rule
        # h5_to_h1 = of.ofp_flow_mod()
        # h5_to_h1.match.in_port = self.h5_port
        # h5_to_h1.match.dl_type = 0x0800
        # h5_to_h1.match.nw_dst = self.h1_ip 
        # h5_to_h1.actions.append(of.ofp_action_output(port=self.h1_port))
        # event.connection.send(h5_to_h1)
        # log.info("Created flow rule from h5 -> h1")

        # h5 -> virtual ip 
        h5_to_server = of.ofp_flow_mod()
        h5_to_server.match.nw_dst = self.vIP
        h5_to_server.actions.append(of.ofp_action_output(port=self.server_port))
        event.connection.send(h5_to_server)
        log.info(f"Created flow rule to forward traffic to VIP {self.vIP} -> {self.h5_ip} on port {self.server_port}")

        #h6 -> virtual ip 
        h6_to_server = of.ofp_flow_mod()
        h6_to_server.match.nw_dst = self.vIP
        h6_to_server.actions.append(of.ofp_action_output(port=self.server_port)) 
        event.connection.send(h6_to_server)
        log.info(f"Created flow rule to forward traffic to VIP {self.vIP} -> h6 on port {self.server_port}")


    def check_client_mapping(self, client_ip):
        log.info(f"Looking up server for client {client_ip}")
        if client_ip in self.client_to_server_mapping:
            server_info = self.client_to_server_mapping[client_ip]
            log.info(f"Found existing mapping for client {client_ip}: {server_info}")
            return self.client_to_server_mapping[client_ip]
        log.info(f"No existing mapping found for {client_ip}, using round-robin")
        return self.round_robin(client_ip)
        
    def _handle_PacketIn(self, event):
        """This method has been taken and modified from the noxrepo documentation"""
        
        packet = event.parsed
        log.info(f"This is the parsed packet: {packet} and packet type {packet.type}")
        
        if packet.type == packet.ARP_TYPE:
            log.info(f"Processing ARP packet from port {event.port}")
            client_ip = packet.payload.src
            server_ip, server_mac, server_port = self.get_server_for_client(client_ip)
            log.info(f"Server assigned: IP={server_ip}, MAC={server_mac}, port={server_port}")
            self._handle_ARP(event, packet, server_ip, server_mac, server_port)
            #how do i handle IPv4 Packets?
        elif packet.type == packet.IP_TYPE:
            self._handle_IP(event, packet)
        else:
            log.info("Unknown ARP")

    def _handle_ARP(self, event, packet, server_ip, server_mac, server_port):
        arp_packet = packet.payload
        log.info(f"ARP packet opcode: {arp_packet.opcode}")
        if packet.payload.opcode == arp.REQUEST:
            log.info(f"ARP request from {arp_packet.hwsrc} for {arp_packet.protodst}")
            log.info(f"ARP request details - protosrc: {arp_packet.protosrc}, hwdst: {arp_packet.hwdst}")
            arp_reply = arp()
            arp_reply.hwsrc = packet.dst
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = server_mac
            arp_reply.protodst = arp_packet.protosrc

            log.info(f"Created ARP reply with hwsrc={arp_reply.hwsrc}, hwdst={arp_reply.hwdst}")
            log.info(f"ARP reply protosrc={arp_reply.protosrc}, protodst={arp_reply.protodst}")

            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = packet.dst
            ether.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = ether.pack() 
            msg.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(msg)

            log.info(f"Sent ARP reply to {arp_reply.protodst} on port {event.port}")
            
        elif packet.payload.opcode == arp.REPLY:
            log.info("ARP reply")

    def _handle_IP(event, packet):
        pass

def launch():
    core.registerNew(LoadBalancer)
