import argparse
import time
from scapy.all import *
from scapy.contrib.ospf import *


def create_parser():
	parser = argparse.ArgumentParser(
		description="Generate lsa7 with default route."
	)
	parser.add_argument("-i", "--iface", help="iface", default="eth1")
	parser.add_argument("-p", help="set P-bit", action="store_true")
	parser.add_argument("-m", "--metric", help="route metric", default=1, type=int)
	parser.add_argument("-e", "--extype", help="0 - ExType1, 1 - ExType2", default=1, type=int)
	return parser


def sniff_lsu(iface):
	hwaddr = get_if_hwaddr(ifname)
	pkts = sniff(
		filter=f"proto ospf and ether src {hwaddr}",
		iface=iface,
		stop_filter=lambda x: x.haslayer(OSPF_LSUpd)
	)
	return pkts[-1]


if __name__ == "__main__":
	parser = create_parser()
	args = parser.parse_args()
	ifname = args.iface
	metric = args.metric
	extype = args.extype
	p_bit = 0x08 if args.p else 0x00
	e_bit = 0x02
	pkt = sniff_lsu(ifname)
	sequence_number = pkt[OSPF_LSUpd][OSPF_Router_LSA].seq + 1  
	ip_src = pkt[IP].src
	router_id = pkt[OSPF_Hdr].src
	area = pkt[OSPF_Hdr].area
	time.sleep(1)  # KF немного тугой
	eth = Ether(
		src=get_if_hwaddr(ifname),
		dst="01:00:5e:00:00:05"
	)
	ip = IP(
		src=ip_src,
		dst="224.0.0.5",
		proto=89,
		ttl=1,
		tos=0xc0,
	)
	ospf_header = OSPF_Hdr(
		version=2,
		type=4,                 # Тип 4 - Link State Update (LSU)
		src=router_id,
		area=area,
		len=0,
		chksum=0,
		authtype=0,
		authdata=0x0000000000000000
	)
	lsa1 = OSPF_Router_LSA(
		age=1,
		options=0x08,  # Nssa
		type=1,
		id=router_id,
		adrouter=router_id,
		seq=sequence_number,
		flags=0x02,  # AS boundary
		linkcount=2,
		linklist=[
			OSPF_Link(
				id="7.7.7.7",
				data=ip_src,
				type=1,
				metric=1
			),
			OSPF_Link(
				id="10.2.0.0",
				data="255.255.255.252",
				type=3,
				metric=1
			),
		]
	)
	lsa7 = OSPF_NSSA_External_LSA(
		age=1,
		options=e_bit+p_bit,
		type=7,
		id="0.0.0.0",
		adrouter=router_id,
		seq=0x80000001,
		chksum=0,
		mask="0.0.0.0",
		fwdaddr=ip_src,
		tag=0,
		metric=metric,
		ebit=extype,
	)
	# Магия пересбора пакета
	del lsa7.chksum
	del ospf_header.chksum
	del lsa1.chksum
	lsas = [lsa7, lsa1]
	# lsas = [lsa7]
	lsu = OSPF_LSUpd(
		lsacount=len(lsas),
		lsalist=lsas 
	)
	ospf_header.len = len(ospf_header) + len(lsu)
	ospf_packet = eth / ip / ospf_header / lsu
	sendp(ospf_packet, iface=ifname, verbose=True)
