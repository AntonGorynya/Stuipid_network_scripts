import argparse, time
from scapy.all import rdpcap


def create_parser():
    parser = argparse.ArgumentParser(
        description="Compare pcap files for lag|ecmp hashing tests"
    )
    parser.add_argument("file1", help="path to pcap file")
    parser.add_argument("file2", help="path to pcap file")
    return parser


def gen_pkts_hash(packets):
    hashes = []
    for packet in packets:
        fields = [packet.src, packet.dst]
        if packet.haslayer("IP"):
            fields.extend([packet["IP"].src, packet["IP"].dst])
            if packet["IP"].haslayer("TCP"):
                fields.extend([packet["IP"]["TCP"].sport, packet["IP"]["TCP"].dport])
            if packet["IP"].haslayer("UDP"):
                fields.extend([packet["IP"]["UDP"].sport, packet["IP"]["UDP"].dport])
        hashes.append(hash(tuple(fields)))
    return hashes


def compare_packets(packets1, packets2):
    file1len = len(packets1)
    file2len = len(packets2)
    signature = "Diff"
    packets1_hashes = None
    packets2_hashes = None
    if file1len == file2len:
        packets1_hashes = hash(tuple(sorted(gen_pkts_hash(packets1))))
        packets2_hashes = hash(tuple(sorted(gen_pkts_hash(packets2))))
    if packets1_hashes == packets2_hashes:
        signature = "Same"
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

    print(compare_packets(packets1, packets2))
    print("--- %s seconds ---" % (time.time() - start_time))
