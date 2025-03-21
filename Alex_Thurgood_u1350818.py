from pox.core import core 
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

class LoadBalancer(object):
    def __init__(self):
        self.vIP = IPAddr("10.0.0.10")
        self.current_server = 0

        self.clients_MAC_table = {
            IPAddr("10.0.0.1"): EthAddr("00:00:00:00:00:01"),
            IPAddr("10.0.0.2"): EthAddr("00:00:00:00:00:02"),
            IPAddr("10.0.0.3"): EthAddr("00:00:00:00:00:03"),
            IPAddr("10.0.0.4"): EthAddr("00:00:00:00:00:04")
        }

        self.client_port_table = {
            IPAddr("10.0.0.1"): 1,
            IPAddr("10.0.0.2"): 2,
            IPAddr("10.0.0.3"): 3,
            IPAddr("10.0.0.4"): 4
        }

        self.servers_MAC_table = {
            IPAddr("10.0.0.5"): EthAddr("00:00:00:00:00:05"),
            IPAddr("10.0.0.6"): EthAddr("00:00:00:00:00:06"),
        }

        self.server_port_table = {
            IPAddr("10.0.0.5"): 5,
            IPAddr("10.0.0.6"): 6,
        }

        self.client_to_server_mapping = {}

        core.openflow.addListeners(self)
        log.info(f"Client ARP table: {self.clients_MAC_table}")
        log.info(f"Server ARP table: {self.servers_MAC_table}")

    def round_robin(self, client_ip):
        if self.current_server == 0:
            server_ip = IPAddr("10.0.0.5")
            self.current_server = 1
        else:
            server_ip = IPAddr("10.0.0.6")
            self.current_server = 0

        server_mac = self.servers_MAC_table[server_ip]  
        server_port = self.server_port_table[server_ip] 

        self.client_to_server_mapping[client_ip] = (server_ip, server_mac, server_port)

        log.info(f"Round Robin selected: {server_ip} ({server_mac}) on port {server_port}")
        
        return server_ip, server_mac, server_port
    
    def _handle_ConnectionUp(self, event):

        log.info(f"Switch {event.dpid} has connected.")
    
    def install_flows(self, event, client_ip,client_mac,client_port, server_ip, server_mac, server_port):
        """Set up OpenFlow rules to allow direct flows between the servers and the virtual ip."""
        
        # client -> server
        client_to_server = of.ofp_flow_mod()
        client_to_server.match.in_port = client_port
        client_to_server.match.dl_type = 0x0800
        client_to_server.match.nw_dst = self.vIP
        client_to_server.match.dl_src = client_mac  
        client_to_server.actions.append(of.ofp_action_dl_addr.set_dst(server_mac)) 
        client_to_server.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        client_to_server.actions.append(of.ofp_action_output(port=server_port))
        event.connection.send(client_to_server)
        log.info(f"client -> server rule created matching on client MAC: {client_mac}, server MAC: {server_mac}, client port: {client_port}")


        # server -> client
        server_to_client = of.ofp_flow_mod()
        server_to_client.match.in_port = server_port
        server_to_client.match.dl_type = 0x0800 
        server_to_client.match.nw_src = server_ip 
        server_to_client.match.nw_dst = client_ip
        server_to_client.match.dl_src = server_mac
        server_to_client.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))
        server_to_client.actions.append(of.ofp_action_nw_addr.set_src(self.vIP))
        server_to_client.actions.append(of.ofp_action_output(port=client_port))
        event.connection.send(server_to_client)
        log.info(f"server -> client rule created matching on server MAC: {server_mac}, client MAC: {client_mac}, server port: {server_port}")


    def check_client_mapping(self, client_ip):
        log.info(f"Looking up server for client {client_ip}")
        if client_ip in self.client_to_server_mapping:
            log.info(f"checking mapping{self.client_to_server_mapping}")
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
            client_ip = packet.payload.protosrc
            server_ip, server_mac, server_port = self.check_client_mapping(client_ip)
            self._handle_ARP(event, packet, client_ip, server_ip, server_mac, server_port)
            #how do i handle IPv4 Packets?
        elif packet.type == packet.IP_TYPE:
            self._handle_IP(event, packet)
        else:
            log.info(f"mystery packet{event.parsed}")

    def _handle_ARP(self, event, packet, client_ip, server_ip, server_mac, server_port):
        arp_packet = packet.payload
        log.info(f"ARP packet opcode: {arp_packet.opcode}")
        client_mac = self.clients_MAC_table[client_ip]
        client_port = self.client_port_table[client_ip]
        log.info(f"Client info: IP={client_ip}, MAC={client_mac}, port={client_port}")
        log.info(f"Server info IP={server_ip}, MAC={server_mac}, port={server_port}")
        if packet.payload.opcode == arp.REQUEST:
            log.info(f"ARP request from {arp_packet.hwsrc} for {arp_packet.protodst}")
            log.info(f"ARP request details - protosrc: {arp_packet.protosrc}, hwdst: {arp_packet.hwdst}")

            self.install_flows(event, client_ip,client_mac,client_port, server_ip, server_mac, server_port)


            arp_reply = arp()
            arp_reply.hwsrc = server_mac
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = server_ip 
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

    def _handle_IP(self, event, packet):
        log.info(f"in the handle ip with packet: {event.parsed}")
        ip_packet = packet.payload

        if ip_packet.dstip == self.vIP:
            client_ip = ip_packet.srcip
            if client_ip in self.client_to_server_mapping:
                server_ip, server_mac, server_port = self.client_to_server_mapping[client_ip]
                msg = of.ofp_packet_out()
                msg.data = event.data
                msg.actions.append(of.ofp_action_output(port=server_port))
                event.connection.send(msg)
                log.info(f"Forwarded IP packet from {client_ip} to server {server_ip} on port {server_port}")
            else:
                log.info("bad IP")

def launch():
    core.registerNew(LoadBalancer)
