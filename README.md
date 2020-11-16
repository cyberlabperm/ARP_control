# ARP_control
Simple programm for monitoring and control ARP traffic in local network as an IDS.
Requirements - scapy https://scapy.net/

Startup configs via config.ini
  Work both for windows and linux system.  
  All path should be valid in OS. 
  Windows: C:\Data\
  Linux: /var/log/
  Network: address/mask
  iface: setup interface to list
  
  run_mode: live - scan $network > create arp table > control ARP traffic
            preload - load arp table from DB > scan $network > control ARP traffic
            config - python shell
 
 How to setup DB?
 Use python shell to create DB with initialize_local_db(). For MYSQL you need to create DB, user and grant him access before this step.
 This will create DB file and TABLE with following format (net_address, MAC address, hostname)
 net_address - IP address if statis, dhcp if host use DHCP-server
 MAC address - in 'FF:FF:FF:FF:FF:FF' format
 hostname - just str format, it can be domain, example cyberlab.local
 
