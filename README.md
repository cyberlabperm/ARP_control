# ARP_control
Simple programm for monitoring and control ARP traffic in local network as an IDS.
Requirements - scapy https://scapy.net/

Startup configs via config.ini
  Work both for windows and linux system.  
  All path should be valid in OS. 
  Windows: C:\Data\
  Linux: /var/log/
  Network: address/mask
  
  run_mode: live - scan $network > create arp table > control ARP traffic
            preload - load arp table from DB > scan $network > control ARP traffic
            config - python shell
 
 
