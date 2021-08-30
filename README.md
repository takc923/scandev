scandev scans the current network and shows the devices on the network.

Example:

Show all devices

```
$ scandev
IP 192.168.1.30 (apple.local.) is at b8:27:eb:56:84:7a
IP 192.168.1.9 (orange.local.) is at b8:27:eb:fe:97:99
IP 192.168.1.2 (banana.local.) is at 96:77:97:73:9b:3d
IP 192.168.1.8 (peach.local.) is at 2a:3b:58:96:77:97
IP 192.168.1.28 () is at ef:60:9b:2a:3b:58
IP 192.168.1.10 () is at a7:83:32:ef:60:9b
IP 192.168.1.5 () is at 42:8f:85:a7:83:32
IP 192.168.1.1 () is at ed:25:34:42:8f:85
IP 192.168.1.15 () is at d0:b4:96:ed:25:34
```

Show only Raspberry Pi devices

```
$ scandev -r
IP 192.168.1.30 (apple.local.) is at b8:27:eb:56:84:7a
IP 192.168.1.9 (orange.local.) is at b8:27:eb:fe:97:99
```

The source was copied and pasted from [here](https://github.com/google/gopacket/blob/3eaba08943250fd212520e5cff00ed808b8fc60a/examples/arpscan/arpscan.go) at first and modified.
