from scapy.layers.l2 import Ether, Dot1Q, LLC, SNAP, STP
from scapy.all import hexdump, Packet, ShortField, ByteField, sniff, sendp
from functools import partial
from time import sleep

# BPDU flags
TCN = 0x01
TCA = 0x80


class STP_OriginatingVLAN(Packet):
    name = "STP Originating VLAN TLV"
    fields_desc = [
        ByteField("pad", 0x00),  # у сisco 3 байта 0х00
        ShortField("type", 0x0000), 
        ShortField("length", 0x0002),
        ShortField("vlan", 1)
    ]


def generate_pvst_bpdu(
        bridge_mac="00:00:00:00:00:01", root_mac="00:00:00:00:00:01",
        bridge_prio=32768, root_prio=32768, vlan_id=10, path_cost=0,
        port_priority=0x8000, port_num=1, flags=0x00):
    payload = (
        LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x010B)
        / STP(
            rootid=root_prio + vlan_id,
            rootmac=root_mac,
            pathcost=path_cost,
            bridgeid=bridge_prio + vlan_id,
            bridgemac=bridge_mac,
            portid=port_priority+port_num,
            bpduflags=flags,
            age=0.0,
        )
        / STP_OriginatingVLAN(vlan=vlan_id)
    )
    return (
        Ether(src=bridge_mac, dst="01:00:0c:cc:cc:cd", type=0x8100)
        / Dot1Q(prio=5, vlan=vlan_id, type=len(payload))
        / payload
    )


def generate_stp_bpdu(
    bridge_mac="00:00:00:00:00:01", root_mac="00:00:00:00:00:01",
    bridge_prio=32768, root_prio=32768, vlan_id=1, path_cost=0,
    port_priority=0x8000, port_num=1, flags=0x00):
    payload = (
        LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(
            rootid=root_prio + vlan_id,
            rootmac=root_mac,
            pathcost=path_cost,
            bridgeid=bridge_prio + vlan_id,
            bridgemac=bridge_mac,
            portid=port_priority+port_num,
            bpduflags=flags,
            age=0.0,
        )
    )
    return (
        Ether(src=bridge_mac, dst="01:80:c2:00:00:00", type=len(payload))
        / payload 
    )


def handle_bpdu(pkt, iface1, iface2, cost1, cost2, bridge_mac1='11:11:11:11:11:11', bridge_mac2='11:11:11:11:11:11', port_prio1=0x8000, port_prio2=0x8000, port_num1=1, port_num2=2):
    print("Захватили пакет")
    if STP in pkt:
        print("Захвачен STP BPDU")
        if pkt[STP].bpdutype == 0x00 and pkt[Ether].src != '11:11:11:11:11:11':
            print("Тип BPDU 0x00")
            # При получении BPDU от dut отправляем BPDU с лучшим root id
            sendp(generate_pvst_bpdu(bridge_mac=bridge_mac1, path_cost=cost1, port_priority=port_prio1, port_num=port_num1), iface=iface1, verbose=True)
            sendp(generate_pvst_bpdu(bridge_mac=bridge_mac2, path_cost=cost2, port_priority=port_prio2, port_num=port_num2), iface=iface2, verbose=True)
        if pkt[STP].bpdutype == 0x80:
            # При получении TCN
            print("Тип BPDU Topology Change 0x80")
            sendp(generate_pvst_bpdu(bridge_mac=bridge_mac1, path_cost=cost1, port_priority=port_prio1, port_num=port_num1, flags=TCN+TCA), iface=iface1, verbose=True)
            sendp(generate_pvst_bpdu(bridge_mac=bridge_mac2, path_cost=cost2, port_priority=port_prio2, port_num=port_num2, flags=TCN), iface=iface2, verbose=True)
            while True:
                sleep(2)
                sendp(generate_pvst_bpdu(bridge_mac=bridge_mac1, path_cost=cost1, port_priority=port_prio1, port_num=port_num1, flags=TCN), iface=iface1, verbose=True)
                sendp(generate_pvst_bpdu(bridge_mac=bridge_mac2, path_cost=cost2, port_priority=port_prio2, port_num=port_num2, flags=TCN), iface=iface2, verbose=True)


def change_root(
        iface1="eth1", iface2="eth2", cost1=100, cost2=200, 
        bridge_mac1='11:11:11:11:11:11', bridge_mac2='11:11:11:11:11:11',
        port_prio1=0x8000, port_prio2=0x8000, port_num1=1, port_num2=2):
    sniff(
        iface=iface1, filter="ether dst 01:00:0c:cc:cc:cd",
        prn=partial(
            handle_bpdu, iface1=iface1, iface2=iface2,
            cost1=cost1, cost2=cost2,
            bridge_mac1=bridge_mac1, bridge_mac2=bridge_mac2,
            port_prio1=port_prio1, port_prio2=port_prio2,
            port_num1=port_num1, port_num2=port_num2
        ), store=False
    )
