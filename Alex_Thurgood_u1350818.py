from pox.core import core 
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

class LoadBalancer(object):
    def __init__(self):
        """Setting the virtual IP, the current server for round-robin and the client and server tables"""
        self.vIP = IPAddr("10.0.0.10")
        self.current_server = 0

        self.clients_MAC_table = {}

        self.client_port_table = {}

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
        """Implements a round robin based system for picking which server to map to """
        if client_ip in self.client_to_server_mapping:
            log.info(f"Existing mapping found for {client_ip}. Returning existing mapping.")
            return self.client_to_server_mapping[client_ip]
        
        log.info(f"current server{self.current_server}")
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



    def _create_client_mapping(self, ip, mac, port):
        """Create the client mapping from ip to MAC to Port"""
        if ip not in self.clients_MAC_table:
            self.clients_MAC_table[ip] = mac
            self.client_port_table[ip] = port
            log.info(f"created new client mapping: IP={ip}, MAC={mac}, Port={port}")
        #do i need to handle the case if the mapping info changes?
        
    def _handle_PacketIn(self, event):
        """This method handles each packet and checks whether or not its an ARP or IP packet """
        
        packet = event.parsed
        log.info(f"This is the parsed packet: {packet} and packet type {packet.type}")
        
        if packet.type == packet.ARP_TYPE:
            log.info(f"Processing ARP packet from port {event.port}")
            log.info(f"ARP Packet details: {packet.payload}")
            log.info(f"ARP Request from IP: {packet.payload.protosrc}")
            log.info(f"ARP Request for IP: {packet.payload.protodst}")
            ip = packet.payload.protosrc

            #Dynamically create the client mappings
            mac, port = packet.src, event.port
            log.info(f"packet info {ip, mac, port}")
            if ip not in self.servers_MAC_table:
                self._create_client_mapping(ip, mac, port)

            #when the packet is coming from client-side
            if ip in self.clients_MAC_table:
                client_ip = ip
                client_port = self.client_port_table[ip]
                client_mac = self.clients_MAC_table[ip]
                if client_ip in self.client_to_server_mapping:
                    server_ip, server_mac, server_port = self.client_to_server_mapping[client_ip]
                else:
                    server_ip, server_mac, server_port = self.round_robin(client_ip)
                    log.info(f"sending client{client_ip}, server {server_ip} to handle arp")
                    self._handle_ARP(event, packet, client_ip, server_ip, server_mac, server_port,client_mac, client_port)
            #when packet is coming from server-side
            elif ip in self.servers_MAC_table:
                client_ip = packet.payload.protodst
                client_port = self.client_port_table[ip]
                client_mac = self.clients_MAC_table[ip]
                server_ip = ip
                server_mac = self.servers_MAC_table[server_ip]
                server_port = self.server_port_table[server_ip]
                log.info(f"ARP request from server {server_ip} for client {client_ip}, passing to _handle_ARP")
                self._handle_ARP(event, packet, client_ip, server_ip, server_mac, server_port, client_mac, client_port)
        #IP packet case        
        else:
            self._handle_IP(event, packet)


    def _handle_ARP(self, event, packet, client_ip, server_ip, server_mac, server_port, client_mac, client_port):
        """This has been taken and modified from the nox repo documentation."""

        log.info(f"Handling ARP for client_ip={client_ip}, server_ip={server_ip}")
        log.info(f"Client MAC table: {self.clients_MAC_table}")
        log.info(f"Server MAC table: {self.servers_MAC_table}")
        arp_packet = packet.payload
        log.info(f"ARP packet: {arp_packet}")
    

        log.info(f"Client info: IP={client_ip}, MAC={client_mac}, port={client_port}")
        log.info(f"Server info IP={server_ip}, MAC={server_mac}, port={server_port}")

        #ARP request case
        if packet.payload.opcode == arp.REQUEST:
            if packet.payload.protodst == self.vIP:
                #creating the arp reply from the client to the server
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

                log.info(f"Sent ARP reply to {arp_reply.protodst} on port {event.port}")
                self.install_flows(event, client_ip, client_mac, client_port, server_ip, server_mac, server_port)
            elif packet.payload.protodst in self.clients_MAC_table:
                #creating an arp reply from the server to the client
                client_ip = packet.payload.protodst
                client_mac = self.clients_MAC_table[client_ip]

                arp_reply = arp()
                arp_reply.hwsrc = client_mac
                arp_reply.hwdst = packet.src
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = client_ip
                arp_reply.protodst = arp_packet.protosrc

                log.info(f"Created ARP reply for client IP {client_ip} with hwsrc={arp_reply.hwsrc}, hwdst={arp_reply.hwdst}")
                log.info(f"ARP reply protosrc={arp_reply.protosrc}, protodst={arp_reply.protodst}")

                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = packet.src
                ether.src = client_mac
                ether.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = ether.pack()
                msg.actions.append(of.ofp_action_output(port=event.port))
                event.connection.send(msg)

                log.info(f"Sent ARP reply to {arp_reply.protodst} on port {event.port}")
            else:
                log.warning(f"ARP request for unknown IP {packet.payload.protodst}. Dropping.")
        elif packet.payload.opcode == arp.REPLY:
            log.info(f"Received ARP reply from {packet.payload.protosrc} with MAC {packet.payload.hwsrc}")

    def _handle_IP(self, event, packet):
        """This handles the case when the packet is an IP packet"""
       
        if packet.type == packet.IP_TYPE:
            log.info(f"ipv4 packet{packet}")
            if packet.payload.dstip == self.vIP:
                client_ip = packet.payload.srcip
                if client_ip in self.clients_MAC_table:
                    client_mac = self.clients_MAC_table[client_ip]
                    client_port = self.client_port_table[client_ip]
                else:
                    log.warning(f"Client IP {client_ip} not in MAC table. Dropping packet.")
                    return
                server_info = self.round_robin(client_ip)
                if server_info:
                    server_ip, server_mac, server_port = server_info
                    packet.dst = server_mac
                    packet.payload.dstip = server_ip
                    log.info(f"grabbing server info {server_mac, server_ip} and creating message")
                    self.install_flows(event, client_ip, client_mac, client_port, server_ip, server_mac, server_port)
                    msg = of.ofp_packet_out()
                    msg.data = packet.pack()
                    msg.actions.append(of.ofp_action_output(port=server_port))
                    event.connection.send(msg)
                    log.info("sent message")
                else:
                    log.warning(f"No server mapping found for client {client_ip}")
            else:
                log.info(f"not bound for our vip: {self.vIP}")

def launch():
    core.registerNew(LoadBalancer)