from scapy.all import sendp, rdpcap
import argparse


def create_parser():
    parser = argparse.ArgumentParser(description="Send Packets from pcap file")
    parser.add_argument("path", help="Path to *.pcap", type=str)
    parser.add_argument("iface", help="Source interface", type=str)
    return parser


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()
    pkts = rdpcap(args.path)
    sendp(pkts, iface=args.iface)
