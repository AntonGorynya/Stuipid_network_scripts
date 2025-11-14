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
    output_msg = ""
    if not len(packets1):
        output_msg += "File1 is empty."
    else: 
        output_msg += "File1 is not empty."
    if not len(packets2):
        output_msg += " File2 is empty."
    else: 
        output_msg += " File2 is not empty."
    if len(packets1) != len(packets2):
        return output_msg + " Different signature. Different length."
    packets1_hashes = hash(tuple(sorted(gen_pkts_hash(packets1))))
    packets2_hashes = hash(tuple(sorted(gen_pkts_hash(packets2))))

    if packets1_hashes != packets2_hashes:
        return output_msg + " Different signature."
    return output_msg + " Same signature."


if __name__ == "__main__":
    start_time = time.time()
    parser = create_parser()
    args = parser.parse_args()

    packets1 = rdpcap(args.file1)
    packets2 = rdpcap(args.file2)

    print(compare_packets(packets1, packets2))
    print("--- %s seconds ---" % (time.time() - start_time))
