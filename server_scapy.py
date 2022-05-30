import logging
from scapy.all import *
import socket
import random
import sys
from scapy.layers.inet import IP, TCP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_blocked_ips():
    f = open('Log.txt', 'r')
    t = f.read()
    f.close()
    return t.split('\n')[1:]


class Server:

    def __init__(self):

        # initiating server
        self.__PORT = 51000
        if len(socket.gethostbyname_ex(socket.gethostname())[-1]) > 1:
            self.__HOST = socket.gethostbyname_ex(socket.gethostname())[-1][0]
        else:
            self.__HOST = socket.gethostbyname_ex(socket.gethostname())[-1][-1]
        self.__blocked_ips = get_blocked_ips()
        
        self.interface = get_working_if()
        for iface in get_working_ifaces():
            if iface.ip == self.__HOST:
                self.interface = iface

        data = '\n'.join(self.__blocked_ips)
        print(f"Blocked ips: \n{data}\n")

        self.__server_filter = f'(tcp dst port 51000 || tcp dst port 51001) and tcp[tcpflags] & (tcp-rst) == 0'

        # keeps the last seq and ack numbers with the client
        self.__last_seq, self.__last_ack = 0, 0

        # keeps the client addr as (IP,PORT) after he connects
        self.__client_addr = ()

        # keeps ips that are in the 3-way-handshake with the server
        self.__in_handshake_process = []

        # generating list of sniffers
        sniffers = []

        # looping to sniff every network interface
        for interface in get_working_ifaces():
            sniffers.append(
                AsyncSniffer(count=0, iface=interface, store=False, filter=self.__server_filter,
                             prn=lambda p: self.packet_handler(p)))

        for sniffer in sniffers:
            sniffer.start()

        try:
            while True:
                pass
        except KeyboardInterrupt:

            # stopping all interfaces
            for sniffer in sniffers:
                sniffer.stop()

            print('----Program ended----')
            sys.exit(-1)

    def packet_handler(self, pack):

        # A TCP packet
        if TCP in pack:

            # packet flags, seq, ack, and ports
            self.__packet_flag = pack[TCP].flags
            self.__packet_src_port = pack[TCP].sport
            self.__packet_dst_port = pack[TCP].dport
            self.__packet_ip_src = pack[IP].src
            self.__packet_seq = pack[TCP].seq
            self.__packet_ack = pack[TCP].ack

            # if the sender is blocked, ignoring him by passing on
            if self.__packet_ip_src in self.__blocked_ips:
                pass

            # A first SYN
            elif self.__packet_flag == 'S' and (self.__packet_ip_src not in self.__in_handshake_process):

                print(f'----Communication request from ({self.__packet_ip_src}, {self.__packet_src_port})----')

                # adding ip to handshake process list
                self.__in_handshake_process.append(self.__packet_ip_src)

                ip = IP(dst=self.__packet_ip_src)

                # server's ISN
                starting_seq = random.randint(10000, 1000000)

                sa_packet = TCP(sport=self.__PORT, dport=self.__packet_src_port,
                                flags='SA', seq=self.__packet_ack, ack=self.__packet_seq + 1)

                # sending SYN-ACK packet
                send(ip / sa_packet, verbose=0, iface=self.interface)

            # 2 SYN in a row --> meaning a SYN flood attack
            elif self.__packet_flag == 'S' and (self.__packet_ip_src in self.__in_handshake_process):

                ip = IP(dst=self.__packet_ip_src)

                rst_packet = TCP(sport=self.__PORT, dport=self.__packet_src_port, flags='R',
                                 seq=random.randint(10000, 1000000), ack=self.__packet_seq + 1)

                # sending reset to attacker
                send(ip / rst_packet, verbose=0, iface=self.interface)

                # removing the attacker ip from handshake process list
                del self.__in_handshake_process[self.__in_handshake_process.index(self.__packet_ip_src)]

                # adding attacker to the blocked ips
                self.__blocked_ips.append(self.__packet_ip_src)
                print(f'----Detected attack from ({self.__packet_ip_src}, {self.__packet_src_port})----')
                server_filter = f'(tcp dst port {self.__PORT} || tcp dst port {self.__PORT + 1}]) and tcp[tcpflags] & (' \
                                f'tcp-rst) == 0 '

                f = open('Log.txt', 'a')

                # Adding ip to the black list
                f.write("\n" + self.__packet_ip_src)
                f.close()

                self.__new_port = IP(dst=self.__client_addr[0]) / TCP(sport=self.__PORT, dport=self.__client_addr[1],
                                                                      flags='A', seq=self.__last_ack,
                                                                      ack=self.__last_seq) / f"new port {self.__PORT + 1}"

                # updating the current communication port
                self.__PORT += 1
                send(self.__new_port, verbose=0, iface=self.interface)
                print(f'----Sent a new port for communication to ({self.__client_addr[0]},{self.__client_addr[1]})----')

            # user finished the 3-way-handshake
            elif self.__packet_flag == 'A' and (self.__packet_ip_src in self.__in_handshake_process):

                print(f'----TCP communication established with ({self.__packet_ip_src}, {self.__packet_src_port})----')
                del self.__in_handshake_process[self.__in_handshake_process.index(self.__packet_ip_src)]

                # setting the client address as (IP, PORT)
                self.__client_addr = (self.__packet_ip_src, self.__packet_src_port)
                self.__last_seq = pack[TCP].seq
                self.__last_ack = pack[TCP].ack


            # client sent message with PSH,ACK
            elif pack[TCP].flags == 'PA':

                ip = IP(dst=self.__packet_ip_src)
                message = bytes(pack[TCP].payload).decode()
                print(f"Client [On port {self.__PORT}]: {message}")
                packet_ack = pack[TCP].ack

                ack_packet = TCP(sport=self.__PORT, dport=self.__packet_src_port, flags='A',
                                 seq=packet_ack, ack=self.__packet_seq + len(message)) / message

                # ACK client's message
                send(ip / ack_packet, verbose=0, iface=self.interface)

                self.__last_seq = pack[TCP].seq
                self.__last_ack = pack[TCP].ack


if __name__ == "__main__":
    print("----Starting server----")
    server = Server()
