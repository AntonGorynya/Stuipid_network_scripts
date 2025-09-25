from scapy.layers.l2 import Ether, Dot1Q, LLC, SNAP, STP
from scapy.all import hexdump, Packet, ShortField, ByteField, sniff, sendp, Padding
from functools import partial
from time import sleep
import hmac
import hashlib
import struct

# BPDU flags
TCN = 0x01
TCA = 0x80

MSTP_KEY = bytes.fromhex('13AC06A62E47FD51F95D2BA243CD0346') # 802.1Q-2022


class STP_OriginatingVLAN(Packet):
    name = "STP Originating VLAN TLV"
    fields_desc = [
        ByteField("pad", 0x00),  # у сisco 3 байта 0х00
        ShortField("type", 0x0000),
        ShortField("length", 0x0002),
        ShortField("vlan", 1)
    ]


class STP_topology_change_bdpu(Packet):
    name = "Spanning Tree Protocol Topology Change"
    fields_desc = [
        ShortField("proto", 0),
        ByteField("version", 0),
        ByteField("bpdutype", 0x80),
    ]


def padding(func):
    def wrapper():
        if len(func()) > 59:
            return func()
        pad_len = 60 - len(func())
        pad = Padding()
        pad.load = b"\x00" * pad_len
        packet = func()/pad
        return packet
    return wrapper


@padding
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


@padding
def generate_stp_tc_bpdu(bridge_mac="00:00:00:00:00:01"):
    payload = LLC(dsap=0x42, ssap=0x42, ctrl=3) / STP_topology_change_bdpu()
    return (
        Ether(src=bridge_mac, dst="01:80:c2:00:00:00", type=len(payload))
        / payload
    )


def generate_mstp_configuration_digest(instance_meta):
    """
    На вход подается словарь вида:
    {
        instance_number: [vla_idn...]
    }
    Пример для всех VLAN в 1ом instance
    {
        1: [i for i in range(1, 4095)]
    }
    Вывод: ac36177f50283cd4b83821d8ab26de62
    """
    mst_configuration_table = [b'\x00\x00']*4096
    for instance, vlan_range in instance_meta.items():
        for vlan_id in vlan_range:
            mst_configuration_table[vlan_id] = struct.pack('>H', instance)

    message = b''.join(mst_configuration_table)
    hmac_object = hmac.new(MSTP_KEY, message, hashlib.md5)
    return hmac_object.hexdigest()


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

print(len(generate_stp_bpdu()))