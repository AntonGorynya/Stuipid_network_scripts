from scapy.layers.l2 import Ether, Dot1Q, LLC, SNAP, STP
from scapy.data import ETHER_ANY
from scapy.all import (
    hexdump,
    Packet,
    ByteField,
    ShortField,
    IntField,
    MACField,
    StrFixedLenField,
    sendp,
    Padding,
    Raw,
)
import argparse
import hmac
import hashlib
import struct

# BPDU flags
TC = 0x01
TCA = 0x80

FWD = 0x20
LRN = 0x10
DSG = 0xC
BKP_ALT = 0x4
ROOT = 0x8,

PROPOSAL = 0x2
AGREEMENT = 0x40

MSTP_KEY = bytes.fromhex('13AC06A62E47FD51F95D2BA243CD0346')  # 802.1Q-2022


class STP_OriginatingVLAN(Packet):
    name = "STP Originating VLAN TLV"
    fields_desc = [ 
        ShortField("type", 0x0000),
        ShortField("length", 0x0002),
        ShortField("vlan", 1)
    ]


class Version1_Length(Packet):
    name = "STP Version 1 length"
    fields_desc = [
        ByteField("version1_length", 0x00),  # Поле не отображается в wireshark для PVST\STP, хотя физически присутствует для всего семейства STP. Не участвует при расчете длины STP
    ]


class STP_TCN(Packet):
    name = "Spanning Tree Protocol Topology Change Notification"
    fields_desc = [
        ShortField("proto", 0),
        ByteField("version", 0),
        ByteField("bpdutype", 0x80),
    ]


class HexDigestField(StrFixedLenField):
    def i2repr(self, pkt, x):
        if isinstance(x, bytes):
            return x.hex()
        return repr(x)


class MST_Header(Packet):
    name = "MST STP Extension"
    fields_desc = [
        ShortField("version3_length", 0x0040),
        ByteField("config_id_format_selector", 0),
        StrFixedLenField("name", b"\x00" * 32, length=32),
        ShortField("revision", 0),
        # StrFixedLenField("digest", b"\x00" * 16, length=16),
        HexDigestField("digest", b"\x00" * 16, length=16),
        IntField("cist_internal_path_cost", 0),
        ShortField("cist_bridgeid", 0),
        MACField("cist_bridge_mac", ETHER_ANY),
        ByteField("cist_remaining_hops", 20),
    ]


class MSTI(Packet):
    name = "MSTID X"
    fields_desc = [
        ByteField("flags", 0),
        ShortField("root_id", 0x8000),
        MACField("root_mac", ETHER_ANY),
        IntField("path_cost", 0),
        ByteField("bridge_prio", 0x80),
        ByteField("port_prio", 0x80),
        ByteField("remaining_hops", 20),
    ]


def padding(func):
    def wrapper(*args, **kwargs):
        pkt = func(*args, **kwargs)
        if len(pkt) > 59:
            return pkt
        pad_len = 60 - len(pkt)
        pad = Padding()
        pad.load = b"\x00" * pad_len
        return pkt/pad
    return wrapper


@padding
def generate_stp_bpdu(
    bridge_mac="00:00:00:00:00:01", root_mac="00:00:00:00:00:01",
    bridge_prio=32768, root_prio=32768, vlan_id=1, path_cost=0,
    port_prio=0x8000, port_num=1, flags=0x00, age=0, max_age=20,
):
    payload = (
        LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(
            rootid=root_prio + vlan_id,
            rootmac=root_mac,
            pathcost=path_cost,
            bridgeid=bridge_prio + vlan_id,
            bridgemac=bridge_mac,
            portid=port_prio+port_num,
            bpduflags=flags,
            age=age,
            maxage=max_age,
        )
    )
    return (
        Ether(src=bridge_mac, dst="01:80:c2:00:00:00", type=len(payload))
        / payload / Version1_Length()
    )


@padding
def generate_stp_tcn(bridge_mac="00:00:00:00:00:01"):
    payload = LLC(dsap=0x42, ssap=0x42, ctrl=3) / STP_TCN()
    return (
        Ether(src=bridge_mac, dst="01:80:c2:00:00:00", type=len(payload))
        / payload
    )


@padding
def generate_rstp_bpdu(
    bridge_mac="00:00:00:00:00:01", root_mac="00:00:00:00:00:01",
    bridge_prio=32768, root_prio=32768, vlan_id=1, path_cost=0,
    port_prio=0x8000, port_num=1, flags=0x00, age=0, max_age=20,
):
    payload = (
        LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(
            version=2,
            bpdutype=0x02,
            rootid=root_prio + vlan_id,
            rootmac=root_mac,
            pathcost=path_cost,
            bridgeid=bridge_prio + vlan_id,
            bridgemac=bridge_mac,
            portid=port_prio+port_num,
            bpduflags=flags,
            age=age,
            maxage=max_age,
        )
        / Version1_Length()
    )
    return (
        Ether(src=bridge_mac, dst="01:80:c2:00:00:00", type=len(payload))
        / payload
    )


def generate_rpvst_bpdu(
    bridge_mac="00:00:00:00:00:01", root_mac="00:00:00:00:00:01",
    bridge_prio=32768, root_prio=32768, vlan_id=10, path_cost=0,
    port_prio=0x8000, port_num=1, flags=0x00, age=0, max_age=20,
):
    payload = (       
        LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x010B)
        / STP(
            version=2,
            bpdutype=0x02,
            rootid=root_prio + vlan_id,
            rootmac=root_mac,
            pathcost=path_cost,
            bridgeid=bridge_prio + vlan_id,
            bridgemac=bridge_mac,
            portid=port_prio+port_num,
            bpduflags=flags,
            age=age,
            maxage=max_age,
        )
        / Version1_Length()
        / STP_OriginatingVLAN(vlan=vlan_id)
    )
    return (
        Ether(src=bridge_mac, dst="01:00:0c:cc:cc:cd", type=0x8100)
        / Dot1Q(prio=5, vlan=vlan_id, type=len(payload))
        / payload
    )


def generate_pvst_bpdu(
    bridge_mac="00:00:00:00:00:01", root_mac="00:00:00:00:00:01",
    bridge_prio=32768, root_prio=32768, vlan_id=10, path_cost=0,
    port_prio=0x8000, port_num=1, flags=0x00, age=0, max_age=20,
):
    payload = (
        LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x010B)
        / STP(
            rootid=root_prio + vlan_id,
            rootmac=root_mac,
            pathcost=path_cost,
            bridgeid=bridge_prio + vlan_id,
            bridgemac=bridge_mac,
            portid=port_prio+port_num,
            bpduflags=flags,
            age=age,
            maxage=max_age,
        )
        / Version1_Length()
        / STP_OriginatingVLAN(vlan=vlan_id)
    )
    return (
        Ether(src=bridge_mac, dst="01:00:0c:cc:cc:cd", type=0x8100)
        / Dot1Q(prio=5, vlan=vlan_id, type=len(payload))
        / payload
    )


@padding
def generate_pvst_tcn(bridge_mac="00:00:00:00:00:01", vlan_id=10):
    payload = (
        LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=0x010B)
        / STP_TCN()
        / STP_OriginatingVLAN(vlan=vlan_id)
    )
    return (
        Ether(src=bridge_mac, dst="01:00:0c:cc:cc:cd", type=0x8100)
        / Dot1Q(prio=5, vlan=vlan_id, type=len(payload))
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
        0: [i for i in range(1, 4095)]
    }
    Вывод: ac36177f50283cd4b83821d8ab26de62
    """
    mst_configuration_table = [b'\x00\x00']*4096
    for instance, vlan_range in instance_meta.items():
        for vlan_id in vlan_range:
            mst_configuration_table[vlan_id] = struct.pack('>H', instance)

    message = b''.join(mst_configuration_table)
    hmac_object = hmac.new(MSTP_KEY, message, hashlib.md5)
    return hmac_object.digest()


def parse_vlan_ranges(vlan_ranges):
    vlan_list = []
    for part in vlan_ranges.split(','):
        if '-' in part:
            min_vlan, max_vlan = part.split('-')
            vlan_list.extend([i for i in range(int(min_vlan), int(max_vlan)+1)])
        else:
            vlan_list.append(int(part))
    return vlan_list


def to_int(value):
    if 'x' in value:
        return int(value, 16)
    return int(value)


def generate_mstp_bpdu(
    src_mac=None,
    bridge_mac="00:00:00:00:00:01", root_mac="00:00:00:00:00:01",
    bridge_prio=32768, root_prio=32768, path_cost=0,
    port_prio=0x8000, port_num=1, flags=0x00, name="",
    revision=1, instances=[],
    cist_internal_path_cost=0, cist_bridgeid=32768,
    cist_remaining_hops=20, age=0, max_age=20,
):
    src_mac = bridge_mac if src_mac is None else src_mac  # Отличается для деревьев MSTI, которые не совпадают с CIST
    instance_to_vlans = {
        0: [i for i in range(1, 4095)]  # по умолчанию все в MSTID=0
    }
    msti_headers = Raw(b''*0)

    for instance in instances:    
        msti_headers /= MSTI(
            flags=instance['flags'],
            root_id=int(instance['prio'])+int(instance['id']),
            root_mac=root_mac if instance['root_mac'] == '' else instance['root_mac'],
            path_cost=int(instance['path_cost']),
            bridge_prio=int(instance['bridge_prio']) >> 8,
            port_prio=int(instance['port_prio']) >> 8,
            remaining_hops=int(instance['remaining_hops']),
        )
        mstid = int(instance['id'])
        instance_to_vlans.update({
            mstid: []
        })        
        vlan_list = parse_vlan_ranges(instance['vlan_ranges']) 
        instance_to_vlans.update({
            0: set(instance_to_vlans[0])-set(vlan_list),
            mstid: vlan_list
        })

    mst_headers = MST_Header(
        name=name,
        revision=revision,
        digest=generate_mstp_configuration_digest(instance_to_vlans),
        cist_internal_path_cost=cist_internal_path_cost,
        cist_bridgeid=cist_bridgeid,  # cist bridge priority + 0(instance ID)
        cist_bridge_mac=src_mac, # до этого был root_mac
        cist_remaining_hops=cist_remaining_hops,
    ) / msti_headers
    mst_headers.version3_length = len(mst_headers)-2  # 2 - длина поля где хранится длина
    payload = (
        LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(
            version=3,
            bpdutype=0x02,
            rootid=root_prio,      # как бы MSTI 0, те +0
            rootmac=root_mac,
            pathcost=path_cost,
            bridgeid=bridge_prio,  # как бы MSTI 0, те +0
            bridgemac=bridge_mac,
            portid=port_prio+port_num,
            bpduflags=flags,
            age=age,
            maxage=max_age,
        )
        / Version1_Length()
        / mst_headers
    )
    return (
        Ether(src=src_mac, dst="01:80:c2:00:00:00", type=len(payload))
        / payload
    )


def create_parser():
    parser = argparse.ArgumentParser(
        description="Send STP family BPDU",
        epilog="""
        Examples:
        send_bpdu.py rstp eth1 --bridge_mac "68:87:c6:cb:7d:0a" --flags 124 --root_mac "68:87:c6:cb:7d:07"
        send_bpdu.py mstp eth1 --bridge_mac "68:87:c6:cb:7d:0a" --flags 124 --root_mac "68:87:c6:cb:7d:07" --name "Popupu" --revision 1 --instances  "id=1 vlan_ranges=1-10,20-30 flags=124 root_mac=00:11:22:33:44:55" "id=2 vlan_ranges=31-40"
        """
    )
    parser.add_argument(
        'protocol',
        choices=['stp', 'stp_tcn', 'pvst', 'pvst_tcn', 'rstp', 'rpvst', 'mstp'],
        help="STP-family protocol"
    )
    parser.add_argument("iface", help="Source interface", type=str)
    parser.add_argument('--src_mac', default=None, 
                        help="only for MSTP", type=str)
    parser.add_argument('--bridge_mac', default="00:00:00:00:00:01", 
                        help="Default value 00:00:00:00:00:01", type=str)
    parser.add_argument('--root_mac', default="00:00:00:00:00:01", type=str,
                        help="Default value 00:00:00:00:00:01. CIST MAC for MSTP")
    parser.add_argument('--bridge_prio', default=32768,
                        help="Default value 32768 = 0x8000", type=int)
    parser.add_argument('--root_prio', default=32768,
                        help="Default value 32768 = 0x8000", type=int)
    parser.add_argument('--age', default=0, type=int, help="BPDU Age")
    parser.add_argument('--max_age', default=20, type=int, help="BPDU Max Age")
    parser.add_argument('--vid', default=1, type=int)
    parser.add_argument('--path_cost', default=0,
                        help="path cost to root. Default = 0", type=int)
    parser.add_argument('--port_prio', type=int, default=0x8000,
                        help="Default value 32768 = 0x8000, 0x80=128")
    parser.add_argument('--port_num', default=1, type=int)
    parser.add_argument('--name', type=str, default="",
                        help="MST Config Name")
    parser.add_argument('--revision', type=int, default=1,
                        help="MST Config Revision")
    parser.add_argument('--instances', nargs='+', default=[],
                        help="""
                        Instance to VLAN mapping in format "key:value"
                        possible_keys:
                        -'id'
                        -'prio'
                        -'root_mac'
                        -'vlan_ranges'
                        -'flags'
                        -'path_cost'
                        -'bridge_prio'
                        -'port_prio'
                        -'remaining_hops'
                        Examples: --instances  "id=1 vlan_ranges=1-10,20-30 flags=124 root_mac=00:11:22:33:44:55" "id=2 vlan_ranges=31-40"
                        """)  # не оч красиво, но лучше не придумал
    parser.add_argument('--cist_internal_path_cost', type=int, default=0,
                        help="Internal Path cost to CIST root. Default = 0")
    parser.add_argument('--cist_remaining_hops', type=int, default=20,
                        help="CIST remaining hops. Default = 20")
    parser.add_argument(
        '--flags',
        default='0x00',
        type=str,
        help="""
            TC = 0x01
            TCA = 0x80
            FWD = 0x20
            LRN = 0x10
            DSG = 0xC
            PROPOSAL = 0x2
            """
    )
    parser.add_argument('-c', '--count', default=None, type=int,
                        help="Total repeating")
    parser.add_argument('-i', '--inter', help="Interval between bpdu",
                        default=2.0, type=float)
    parser.add_argument('-l', '--loop', help="Loop", action='store_true')
    parser.add_argument('--hex', help='Pring BPDU Hex output',
                        action='store_true')
    parser.add_argument('-v', '--verbose', help='human readable',
                        action='store_true')
    return parser


if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()

    flags = to_int(args.flags)
    if args.protocol == 'stp':
        bpdu = generate_stp_bpdu(
            bridge_mac=args.bridge_mac,
            root_mac=args.root_mac,
            bridge_prio=args.bridge_prio,
            root_prio=args.root_prio,
            vlan_id=args.vid,
            path_cost=args.path_cost,
            port_prio=args.port_prio,
            port_num=args.port_num,
            flags=flags,
            age=args.age,
            max_age=args.max_age,

        )
    if args.protocol == 'stp_tcn':
        bpdu = generate_stp_tcn(bridge_mac=args.bridge_mac)
    if args.protocol == 'pvst_tcn':
        bpdu = generate_pvst_tcn(bridge_mac=args.bridge_mac, vlan_id=args.vid)
    if args.protocol == 'pvst':
        bpdu = generate_pvst_bpdu(
            bridge_mac=args.bridge_mac,
            root_mac=args.root_mac,
            bridge_prio=args.bridge_prio,
            root_prio=args.root_prio,
            vlan_id=args.vid,
            path_cost=args.path_cost,
            port_prio=args.port_prio,
            port_num=args.port_num,
            flags=flags,
            age=args.age,
            max_age=args.max_age,
        )
    if args.protocol == 'rstp':
        bpdu = generate_rstp_bpdu(
            bridge_mac=args.bridge_mac,
            root_mac=args.root_mac,
            bridge_prio=args.bridge_prio,
            root_prio=args.root_prio,
            vlan_id=args.vid,
            path_cost=args.path_cost,
            port_prio=args.port_prio,
            port_num=args.port_num,
            flags=flags,
            age=args.age,
            max_age=args.max_age,
        )
    if args.protocol == 'rpvst':
        bpdu = generate_rpvst_bpdu(
            bridge_mac=args.bridge_mac,
            root_mac=args.root_mac,
            bridge_prio=args.bridge_prio,
            root_prio=args.root_prio,
            vlan_id=args.vid,
            path_cost=args.path_cost,
            port_prio=args.port_prio,
            port_num=args.port_num,
            flags=flags,
            age=args.age,
            max_age=args.max_age,
        )
    if args.protocol == 'mstp':
        instance_params = []
        for instance in args.instances:
            instance_param = {
                'id': 0,
                'prio': args.root_prio,
                'root_mac': args.root_mac,
                'vlan_ranges': "",
                'flags': 124,
                'path_cost': args.path_cost,
                'bridge_prio': args.bridge_prio,  # 0x8000 -> 0x80
                'port_prio': args.port_prio,
                'remaining_hops': args.cist_remaining_hops,
            }
            for p in instance.split(' '):
                k, v = p.split('=')
                instance_param[k] = to_int(v) if k == 'flags' else v
            instance_params.append(instance_param)
        bpdu = generate_mstp_bpdu(
            src_mac=args.src_mac,
            bridge_mac=args.bridge_mac,
            root_mac=args.root_mac,
            bridge_prio=args.bridge_prio,
            root_prio=args.root_prio,
            path_cost=args.path_cost,
            port_prio=args.port_prio,
            port_num=args.port_num,
            flags=flags,
            name=args.name,
            revision=args.revision,
            instances=instance_params,
            cist_internal_path_cost=args.cist_internal_path_cost,
            cist_remaining_hops=args.cist_remaining_hops,
            age=args.age,
            max_age=args.max_age,
        )        
    if args.hex:
        print("Generated BPDU Hex:")
        hexdump(bpdu)
    if args.verbose:
        print("Generated BPDU Human Readable:")
        bpdu.show()
    sendp(bpdu, iface=args.iface, count=args.count, inter=args.inter, loop=args.loop)
