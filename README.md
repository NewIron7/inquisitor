# inquisitor
ARP poisoning tool for educational purpose

```shell
ettercap -T -S -i eth0 -M arp:remote /192.168.1.2// /192.168.1.3//

lftp ftp://ftpuser@192.168.1.2
put local_file.txt

tcpdump -i eth0

inquisitor 192.168.1.3 02:42:C0:A8:01:03 192.168.1.2 02:42:C0:A8:01:02 eth0
```
