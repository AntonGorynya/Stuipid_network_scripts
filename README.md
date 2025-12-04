# Stuipid_network_scripts

- send_simple_packets.py - генерирует tcp\udp\icmp\ip пакеты для тестовых целей.
```sh
sudo python3 ./send_packets.py eth1 --mac_src '00:AA:CC:DD:EE:FF' --mac_dst 'B4:7D:76:10:7C:20' --ip_src '192.168.0.1' --ip_dst '192.168.1.0/24' '--tcp' --port_src 1 --port_dst 1 --vlan 5
```
- compare_pcap.py - сравнение pcap файлов по hash-ам по полям mac, ip, port
```sh
sudo python3 ./compare.py ./1.pcap ./2.pcap
        File1 Len: 63
        File2 Len: 63
        Total Len: 126
        Signature: Same
```
- send_bpdu.py - генерирует  BPDU выбранного проткола.
```sh
sudo python3 ./send_bpdu.py rstp eth1 --flags=124 --path_cost 10 -l -v
Generated BPDU Human Readable:
###[ Ethernet ]###
  dst       = 01:80:c2:00:00:00
  src       = 00:00:00:00:00:01
  type      = 0x27
###[ LLC ]###
     dsap      = 0x42
     ssap      = 0x42
     ctrl      = 3
###[ Spanning Tree Protocol ]###
        proto     = 0
        version   = 2
        bpdutype  = 2
        bpduflags = 124
        rootid    = 32769
        rootmac   = 00:00:00:00:00:01
        pathcost  = 10
        bridgeid  = 32769
        bridgemac = 00:00:00:00:00:01
        portid    = 32769
        age       = 0
        maxage    = 20
        hellotime = 2
        fwddelay  = 15
###[ STP Version 1 length ]###
           version1_length= 0
###[ Padding ]###
              load      = b'\x00\x00\x00\x00\x00\x00\x00'
```
- nssa_lsa7 - снифает lsu после чего отправляет информацию про внешний маршрут
```sh
sudo python3 ./send_lsa7_default_route.py -i eth2 -e 0 -m 20 &
sudo vtysh -c 'conf t' -c 'router ospf' -c 'network 2.2.2.0/30 area 1
```

- send_pcap - отправляем пакеты из pcap файла
```sh
sudo python send_pcap.py pcap eth1
```
## Установка
```sh
pip install -r requirements.txt
```
## Пример запуска

