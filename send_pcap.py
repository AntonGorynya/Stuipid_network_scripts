from scapy.all import sendp, rdpcap
import argparse


def create_parser():
    parser = argparse.ArgumentParser(description="Send Packets from pcap file")
    parser.add_argument("path", help="Path to *.pcap", type=str)
    parser.add_argument("iface", help="Source interface", type=str)
    parser.add_argument('-c', '--count', help="Count", default=None, type=int)
    parser.add_argument('-i', '--inter', help="Interval",
                        default=0.0, type=float)
    parser.add_argument('-l', '--loop', help="Loop", action='store_true')
    return parser


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    pkts = rdpcap(args.path)
    sendp(
        pkts, iface=args.iface, count=args.count,
        inter=args.inter, loop=args.loop
    )
