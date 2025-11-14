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
    parser.add_argument("--ip", action="store_true")
    parser.add_argument("--port_src", help="list port src",
                        nargs="+", type=int, default=[1])
    parser.add_argument("--port_dst", help="list port dst",
                        nargs="+", type=int, default=[1])
    parser.add_argument("--count", help="Total repeating", default=1, type=int)
    return parser


if __name__ == "__main__":
    start_time = time.time()
    parser = create_parser()
    args = parser.parse_args()
    packets = []
    eth = (
        Ether(src=args.mac_src, dst=args.mac_dst) / Dot1Q(vlan=args.vlan) if args.vlan
        else Ether(src=args.mac_src, dst=args.mac_dst)
    )
    ip = IP(src=args.ip_src, dst=args.ip_dst)
    if args.tcp:
        packets.extend(
            add_padding(eth / ip / TCP(sport=args.port_src, dport=args.port_dst))
        )
    if args.udp:
        packets.extend(
            add_padding(eth / ip / UDP(sport=args.port_src, dport=args.port_dst))
        )
    if args.icmp:
        packets.extend(add_padding(eth / ip / ICMP()))
    if args.ip:
        packets.extend(add_padding(eth / ip))

    sendpfast(
        packets,
        mbps=args.speed,
        count=args.count,
        parse_results=True,
        iface=args.iface
    )
    print("--- %s seconds ---" % (time.time() - start_time))
