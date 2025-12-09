import argparse
import time
from scapy.all import rdpcap


def create_parser():
    parser = argparse.ArgumentParser(
        description="Compare pcap files for lag|ecmp hashing tests"
    )
    parser.add_argument("file1", help="path to pcap file")
    parser.add_argument("file2", help="path to pcap file")
    parser.add_argument("-s", "--symmetric", action="store_true",
                        help="swap src and dst headers before comparing")
    return parser


def compare_l3_packets(packets1, packets2, swap=False):
    file1len = len(packets1)
    file2len = len(packets2)
    signature = "Diff"
    if file1len == file2len:
        signature = "Same"
        packets1.sort()
        packets2.sort()
        for i in range(file1len):
            packet1 = packets1[i]
            packet2 = packets2[i]
            p1_fields = [packet1.src, packet1.dst]
            p2_fields = [packet2.src, packet2.dst]
            if packet1["IP"].haslayer("TCP") or packet1["IP"].haslayer("UDP"):
                p1_fields.extend([packet1.sport, packet1.dport])
            if packet2["IP"].haslayer("TCP") or packet2["IP"].haslayer("UDP"):
                p2_fields.extend([packet2.sport, packet2.dport])
            if swap:
                l = len(p2_fields)
                p2_fields[1:l:2], p2_fields[:l:2] = p2_fields[:l:2], p2_fields[1:l:2]
            p1_fields.append(packet1["IP"].proto)
            p2_fields.append(packet2["IP"].proto)
            if p2_fields != p1_fields:
                signature = "Diff"
                break
    return f"""
        File1 Len: {file1len}
        File2 Len: {file2len}
        Total Len: {file1len+file2len}
        Signature: {signature}
        """


if __name__ == "__main__":
    start_time = time.time()
    parser = create_parser()
    args = parser.parse_args()

    packets1 = rdpcap(args.file1)
    packets2 = rdpcap(args.file2)    
    swap = args.symmetric

    print(compare_l3_packets(packets1, packets2, swap=swap))
    print("--- %s seconds ---" % (time.time() - start_time))
