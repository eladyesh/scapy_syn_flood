import random
from scapy.all import *
import time
import socket
import threading
from scapy.layers.inet import IP, TCP


class Client:

    def __init__(self):

        # initiating client
        if len(socket.gethostbyname_ex(socket.gethostname())[-1]) > 1:
            self.__HOST = socket.gethostbyname_ex(socket.gethostname())[-1][0]
        else:
            self.__HOST = socket.gethostbyname_ex(socket.gethostname())[-1][-1]

        #self.__HOST = "someone else \\ 192.168... 172..."

        # optional
        self.interface = get_working_if()
        for iface in get_working_ifaces():
            if iface.ip == self.__HOST:
                self.interface = iface

        # setting client
        self.__PORT = 51000
        self.__ADDR = (self.__HOST, self.__PORT)
        self.send_to_server_port = RandShort()
        self.run_once = 0

        # syn packet
        self.__syn_packet = TCP(sport=self.send_to_server_port, dport=self.__PORT, flags="S", seq=1000)
        self.__ip_packet = IP(dst=self.__HOST)
        send(self.__ip_packet / self.__syn_packet, verbose=0, iface=self.interface)

        # syn_ack packet
        self.__syn_ack_packet = \
            sniff(iface=self.interface, filter=f'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 and tcp src port {self.__PORT}',
                  count=1)[0]

        # ack_paket
        self.__ack_packet = TCP(sport=self.send_to_server_port, dport=self.__PORT, flags="A",
                              seq=self.__syn_ack_packet[TCP].ack,
                              ack=self.__syn_ack_packet[TCP].seq + 1)

        send(self.__ip_packet / self.__ack_packet, iface=self.interface)

        # starting current_sequence and current_acknowledgment
        self.__current_seq, self.__current_ack = self.__syn_ack_packet[TCP].ack, self.__syn_ack_packet[TCP].seq + 1

    def receive(self):
        """
        Function receives messages from the server
        """

        while 1:

            # the echo packet from the server
            echo_ack = \
                sniff(iface=self.interface,
                      filter=f'tcp[tcpflags] & (tcp-ack) != 0 and (tcp src port {self.__PORT} ||'
                             f'tcp src port {self.__PORT + 1})', count=1)[0]

            # message from server
            message = bytes(echo_ack[TCP].payload).decode()

            if message:
                print(f"\nServer [On port {self.__PORT}]: {message}\nPlease send a message to the server: ")

                if message.find("new port") != -1 and len(message.split(" ")) == 3:
                    self.__PORT = int(message.split(" ")[2])
                    print("----Attack on communication----")
                    print(f"----Communicating with the server now on port {self.__PORT}----")

            # updating current sequence and ack
            self.__current_seq = echo_ack[TCP].ack
            self.__current_ack = echo_ack[TCP].seq + len(message)

    def send(self):

        # starting thread for receiving messages from the server
        communication_thread = Thread(target=self.receive)
        communication_thread.start()

        while True:

            # inputted data from client
            if self.run_once == 0:
                self.data = input("Please send a message to the server: \n")
                self.run_once += 1
            else:
                self.data = input("")

            if not self.data:
                break

            # sending information packet to the server
            self.__packet = TCP(sport=self.send_to_server_port, dport=self.__PORT, seq=self.__current_seq,
                              ack=self.__current_ack,
                              flags="PA") / self.data
            send(self.__ip_packet / self.__packet, verbose=0, iface=self.interface)


if __name__ == "__main__":
    client = Client()
    client.send()
