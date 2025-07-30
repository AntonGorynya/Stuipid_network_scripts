# Stuipid_network_scripts
На даннаый момент 2 простых скрипта
- send_simple_packets.py - генерирует tcp\udp\icmp пакеты для тестовых целей.
- compare_pcap.py - сравнение pcap файлов по hash-ам по полям mac, ip, port
## Установка
```sh
pip install -r requirements.txt
```
## Пример запуска
```sh
udo python3 ./send_packets.py eth1 --mac_src '00:AA:CC:DD:EE:FF' --mac_dst 'B4:7D:76:10:7C:20' --ip_src '192.168.0.1' --ip_dst '192.168.1.0/24' '--tcp' --port_src 1 --port_dst 1 --vlan 5
```
