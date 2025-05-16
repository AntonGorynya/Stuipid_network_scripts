import argparse
from scapy.all import rdpcap


def create_parser():
    parser = argparse.ArgumentParser(
        description="Compare pcap files for lag|ecmp hashing tests"
    )
    parser.add_argument("file1", help="path to pcap file")
    parser.add_argument("file2", help="path to pcap file")
    return parser


def compare_packets(packets1, packets2):
    output = ""
    if not len(packets1):
        output += "File1 is empty.\n"
    else: 
        output += "File1 is not empty.\n"
    if not len(packets2):
        output += "File2 is empty.\n"
    else: 
        output += "File2 is not empty.\n"
    if len(packets1) == len(packets2):
        for packet1, packet2 in zip(packets1, packets2):
            if (packet1.src != packet2.src) or (packet1.dst != packet2.dst) or (packet1["IP"].src != packet2["IP"].src) or (packet1["IP"].dst != packet2["IP"].dst):
                return output + "Different signature"
            if packet1["IP"].haslayer("TCP"):
                if (packet1["IP"]["TCP"].sport != packet2["IP"]["TCP"].sport) or (packet1["IP"]["TCP"].dport != packet2["IP"]["TCP"].dport):
                    return output + "Different signature"
            if packet1["IP"].haslayer("UDP"):
                if (packet1["IP"]["UDP"].sport != packet2["IP"]["UDP"].sport) or (packet1["IP"]["UDP"].dport != packet2["IP"]["UDP"].dport):
                    return output + "Different signature"
        return output + "Same signature"
    else:
        return output + "Different signature"


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()

    packets1 = rdpcap(args.file1)
    packets2 = rdpcap(args.file2)

    print(compare_packets(packets1, packets2))
