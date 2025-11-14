# Stuipid_network_scripts
На даннаый момент 2 простых скрипта
- send_simple_packets.py - генерирует tcp\udp\icmp\ip пакеты для тестовых целей.
```sh
sudo python3 ./send_packets.py eth1 --mac_src '00:AA:CC:DD:EE:FF' --mac_dst 'B4:7D:76:10:7C:20' --ip_src '192.168.0.1' --ip_dst '192.168.1.0/24' '--tcp' --port_src 1 --port_dst 1 --vlan 5
```
- compare_pcap.py - сравнение pcap файлов по hash-ам по полям mac, ip, port
```sh
sudo python3 ./compare.py ./1.pcap ./2.pcap
```
- send_bpdu.py - генерирует одно BPDU выбранного протколо.
```sh
sudo python send_bpdu.py stp eth1 --bridge_mac "00:11:22:33:44:55" --port_num 77
```
- nssa_lsa7 - снифает lsu после чего отправляет информацию про внешний маршрут
```sh
sudo python3 ./send_lsa7_default_route.py -i eth2 -e 0 -m 20 &
sudo vtysh -c 'conf t' -c 'router ospf' -c 'network 2.2.2.0/30 area 1
```
## Установка
```sh
pip install -r requirements.txt
```
## Пример запуска

