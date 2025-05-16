import argparse
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import Padding, sendpfast
from socket import gaierror


def generate_packets(iface, eth_src, eth_dst, ip_src, ip_dst, transport_proto, tagged_vlan=0, port_src=[1], port_dst=[1], count=1):
    eth = Ether(src=eth_src, dst=eth_dst)
    ip = IP(src=ip_src, dst=ip_dst)
    if transport_proto == 'tcp':
        transport = TCP(sport=port_src, dport=port_dst)
    if transport_proto == 'udp':
        transport = UDP(sport=port_src, dport=port_dst)
    if transport_proto == 'icmp':
        transport = ICMP()
    packet = eth / Dot1Q(vlan=tagged_vlan) / ip / transport if tagged_vlan else eth / ip / transport
    pad_len = 60 - len(packet)
    pad = Padding()
    pad.load = '\\x00' * pad_len
    packet = packet/pad
    return packet


def send_packets(iface, eth_src, eth_dst, ip_src, ip_dst, transport_proto, tagged_vlan=0, port_src=[1], port_dst=[1], count=1):
    packets = []
    for transport in transport_proto:
        packets += generate_packets(iface, eth_src, eth_dst, ip_src, ip_dst, transport, tagged_vlan, port_src, port_dst, count)
    print(f'Total:{len(packets)}')
    sendpfast(packets, mbps=10, count=count, parse_results=True, iface=iface)


def create_parser():
    parser = argparse.ArgumentParser(
        description="Compare pcap files for lag|ecmp hashing tests"
    )
    parser.add_argument("iface", help="Source interface", type=str)
    parser.add_argument("--mac_src", help="list mac src", nargs="+")
    parser.add_argument("--mac_dst", help="list mac dst", nargs="+")
    parser.add_argument("--vlan", help="tagged vlan", default=0, type=int)
    parser.add_argument("--ip_src", help="list ip src", nargs="+")
    parser.add_argument("--ip_dst", help="list ip src", nargs="+")
    parser.add_argument("--tcp", dest="transport", 
                        action="append_const", const="tcp")
    parser.add_argument("--udp", dest="transport", 
                        action="append_const", const="udp")
    parser.add_argument("--icmp", dest="transport", 
                        action="append_const", const="icmp")
    parser.add_argument("--port_src", help="list port src", 
                        nargs="+", type=int, default=[1])
    parser.add_argument("--port_dst", help="list port src", 
                        nargs="+", type=int, default=[1])
    return parser


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()

    try:
        send_packets(
            args.iface, args.mac_src, args.mac_dst, 
            args.ip_src, args.ip_dst, args.transport, 
            tagged_vlan=args.vlan, 
            port_src=args.port_src, port_dst=args.port_dst, 
            count=1
            )
    except gaierror as e: print(e)
    except ValueError: print("Please check input params")
