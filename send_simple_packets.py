import argparse
import time
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import Padding, sendpfast


def add_padding(packet):
    if len(packet) > 59:
        return packet
    pad_len = 60 - len(packet)
    pad = Padding()
    pad.load = b"\x00" * pad_len
    packet = packet/pad
    return packet


def create_tcp_packets(eth_src, eth_dst, ip_src, ip_dst, tagged_vlan=0, port_src=[1], port_dst=[1]):
    eth = Ether(src=eth_src, dst=eth_dst) / Dot1Q(vlan=tagged_vlan) if tagged_vlan else Ether(src=eth_src, dst=eth_dst)
    packets = add_padding(eth / IP(src=ip_src, dst=ip_dst) / TCP(sport=port_src, dport=port_dst))
    return packets


def create_udp_packets(eth_src, eth_dst, ip_src, ip_dst, tagged_vlan=0, port_src=[1], port_dst=[1]):
    eth = Ether(src=eth_src, dst=eth_dst) / Dot1Q(vlan=tagged_vlan) if tagged_vlan else Ether(src=eth_src, dst=eth_dst) 
    packets = add_padding(eth / IP(src=ip_src, dst=ip_dst) / UDP(sport=port_src, dport=port_dst))
    return packets


def create_icmp_packets(eth_src, eth_dst, ip_src, ip_dst, tagged_vlan=0):
    eth = Ether(src=eth_src, dst=eth_dst) / Dot1Q(vlan=tagged_vlan) if tagged_vlan else Ether(src=eth_src, dst=eth_dst)   
    packets = add_padding(eth / IP(src=ip_src, dst=ip_dst)  / ICMP())
    return packets


def create_parser():
    parser = argparse.ArgumentParser(
        description="Compare pcap files for lag|ecmp hashing tests"
    )
    parser.add_argument("iface", help="Source interface", type=str)
    parser.add_argument("--mac_src", help="list mac src", nargs="+")
    parser.add_argument("--mac_dst", help="list mac dst", nargs="+")
    parser.add_argument("--vlan", help="tagged vlan", default=0, type=int)
    parser.add_argument("--speed", help="Speed in Mbits per second",
                        default=10, type=int)
    parser.add_argument("--ip_src", help="list ip src", nargs="+")
    parser.add_argument("--ip_dst", help="list ip src", nargs="+")
    parser.add_argument("--tcp", action="store_true")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--icmp", action="store_true")
    parser.add_argument("--port_src", help="list port src",
                        nargs="+", type=int, default=[1])
    parser.add_argument("--port_dst", help="list port src",
                        nargs="+", type=int, default=[1])
    parser.add_argument("--count", help="Total repeating", default=1, type=int)
    return parser


if __name__ == "__main__":
    start_time = time.time()
    parser = create_parser()
    args = parser.parse_args()
    packets = []
    if args.tcp:
        packets.append(
            create_tcp_packets(
                args.mac_src,
                args.mac_dst,
                args.ip_src,
                args.ip_dst,
                tagged_vlan=args.vlan,
                port_src=args.port_src,
                port_dst=args.port_dst
            )
        )
    if args.udp:
        packets.append(
            create_udp_packets(
                args.mac_src,
                args.mac_dst,
                args.ip_src,
                args.ip_dst,
                tagged_vlan=args.vlan,
                port_src=args.port_src,
                port_dst=args.port_dst
            )
        )
    if args.icmp:
        packets.append(
            create_tcp_packets(
                args.mac_src,
                args.mac_dst,
                args.ip_src,
                args.ip_dst,
                tagged_vlan=args.vlan,
            )
        )

    sendpfast(
        packets,
        mbps=args.speed,
        count=args.count,
        parse_results=True,
        iface=args.iface
    )
    print("--- %s seconds ---" % (time.time() - start_time))