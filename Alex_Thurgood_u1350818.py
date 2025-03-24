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
        """Ensure consistent server mapping for each client IP"""
        if client_ip in self.client_to_server_mapping:
            log.info(f"Existing mapping found for {client_ip}. Returning existing mapping.")
            return self.client_to_server_mapping[client_ip]

        server_ips = list(self.servers_MAC_table.keys())
        server_ip = server_ips[len(self.client_to_server_mapping) % len(server_ips)]

        server_mac = self.servers_MAC_table[server_ip]  
        server_port = self.server_port_table[server_ip] 

        self.client_to_server_mapping[client_ip] = (server_ip, server_mac, server_port)

        log.info(f"Round Robin selected: {server_ip} ({server_mac}) on port {server_port}")
        
        return server_ip, server_mac, server_port
    
    def _handle_ConnectionUp(self, event):
        """This is here just to make sure the switch properly connects"""
        log.info(f"Switch {event.dpid} has connected.")
    
    def install_flows(self, event, client_ip,client_mac,client_port, server_ip, server_mac, server_port):
        """Set up OpenFlow rules to allow direct flows between the client and the server"""
        
        # client -> server flow rule
        client_to_server = of.ofp_flow_mod()
        client_to_server.match.in_port = client_port
        client_to_server.match.dl_type = 0x0800
        client_to_server.match.nw_dst = self.vIP
        client_to_server.actions.append(of.ofp_action_dl_addr.set_dst(server_mac)) 
        client_to_server.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        client_to_server.actions.append(of.ofp_action_output(port=server_port))
        event.connection.send(client_to_server)
        log.info(f"client -> server rule created {client_to_server}")


        # server -> client flow rule
        server_to_client = of.ofp_flow_mod()
        server_to_client.match.in_port = server_port
        server_to_client.match.dl_type = 0x0800 
        server_to_client.match.nw_src = server_ip 
        server_to_client.match.nw_dst = client_ip
        server_to_client.actions.append(of.ofp_action_nw_addr.set_src(self.vIP))
        server_to_client.actions.append(of.ofp_action_output(port=client_port))
        event.connection.send(server_to_client)
        log.info(f"server -> client rule created: {server_to_client} ")

        
    def _handle_PacketIn(self, event):
        """This method handles each packet and checks whether or not its an ARP or IP packet """
        
        packet = event.parsed
        log.info(f"This is the parsed packet: {packet} and packet type {packet.type}")
        
        if packet.type == packet.ARP_TYPE:
            log.info(f"Processing ARP packet from port {event.port}")
            client_ip = packet.payload.protosrc
            server_ip, server_mac, server_port = self.round_robin(client_ip)
            log.info(f"sending client{client_ip}, server {server_ip} to handle arp")
            self._handle_ARP(event, packet, client_ip, server_ip, server_mac, server_port)
        else:
            self._handle_IP(event, packet)


    def _handle_ARP(self, event, packet, client_ip, server_ip, server_mac, server_port):
        """This is based off the noxrepo documentation and only handles ARP packets. This creates the flow rules and sets up the ARP reply"""
        arp_packet = packet.payload
        log.info(f"ARP packet: {arp_packet}")
        if client_ip  in self.clients_MAC_table:
            client_mac = self.clients_MAC_table[client_ip]
            client_port = self.client_port_table[client_ip]
        else:
            client_mac = self.servers_MAC_table[server_ip]
            client_port = self.server_port_table[server_ip]

        log.info(f"Client info: IP={client_ip}, MAC={client_mac}, port={client_port}")
        log.info(f"Server info IP={server_ip}, MAC={server_mac}, port={server_port}")
        if packet.payload.opcode == arp.REQUEST:

            arp_reply = arp()
            arp_reply.hwsrc = server_mac
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = self.vIP 
            arp_reply.protodst = arp_packet.protosrc
           

            log.info(f"Created ARP reply with hwsrc={arp_reply.hwsrc}, hwdst={arp_reply.hwdst}")
            log.info(f"ARP reply protosrc={arp_reply.protosrc}, protodst={arp_reply.protodst}")

            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = server_mac
            ether.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = ether.pack() 
            msg.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(msg)

            self.install_flows(event, client_ip,client_mac,client_port, server_ip, server_mac, server_port)

            log.info(f"Sent ARP reply to {arp_reply.protodst} on port {event.port}")
            
        elif packet.payload.opcode == arp.REPLY:
            log.info("ARP reply")

    def _handle_IP(self, event, packet):
        """This handles the case when the packet is an IP packet"""
        log.info(f"handling packet {packet}")
        
        if packet.type == packet.IP_TYPE:
            log.info("ipv4")
            if packet.payload.dstip == self.vIP:
                client_ip = packet.payload.srcip
                server_info = self.round_robin(client_ip)
                if server_info:
                    server_ip, server_mac, server_port = server_info
                    packet.dst = server_mac
                    packet.dstip = server_ip
                    log.info(f"grabbing server info {server_mac, server_ip} and creating message")
                    msg = of.ofp_packet_out()
                    msg.data = packet.pack()
                    msg.actions.append(of.ofp_action_output(port=server_port))
                    event.connection.send(msg)
                    log.info("sent message")
                else:
                    log.warning(f"No server mapping found for client {client_ip}")
            else:
                log.info(f"not bound for our vip: {self.vIP}")
        else:
            log.info(f"unkown packet{packet}")

def launch():
    core.registerNew(LoadBalancer)