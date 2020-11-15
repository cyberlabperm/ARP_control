#ARP-control-server © 2020, cyberlabperm
#Released under GNU GPL v3 license 
from scapy.all import srp, Ether, ARP, sniff, wrpcap, PcapReader
import sqlite3, time

#load configuration
config = open('config.ini', 'r')
for line in config:
    if line[0] != '#':
        if 'network' in line:
            network = line[line.index('=')+2:len(line)-1]
        elif 'pcap_folder' in line:
            pcap_folder = line[line.index('=')+2:len(line)-1]
        elif 'log_folder' in line:
            log_folder = line[line.index('=')+2:len(line)-1]
        elif 'db_folder' in line:
            db_folder = line[line.index('=')+2:len(line)-1]
        elif 'db_name' in line:
            db_name = line[line.index('=')+2:len(line)-1]
        elif 'run_mode' in line:
            mode = line[line.index('=')+2:len(line)-1]
config.close()

global arp_table
arp_table = dict()

#method to scan network configuration and create IP-MAC-HOST table
def arp_scan(network):
    assert isinstance(network, str), 'example 192.168.0.0/24'
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),timeout=5)
    for pkt in ans:
        IP = pkt[1].psrc
        MAC = pkt[1].src 
        if IP not in arp_table.keys():
            event_time = time.strftime("%d-%m-%Y %H.%M.%S", time.localtime())
            print(f'{event_time} new host detected {IP} - {MAC} added to arp_table')
            arp_table[IP] =  MAC  

def load_arp_table_from_db():
    print('Waiting for initialize arp_table')
    db = sqlite3.connect(db_folder+db_name)
    cur = db.cursor()
    db_req = f'SELECT * FROM hosts;'    
    cur.execute(db_req)
    hosts = cur.fetchall()
    print('ARP-table loaded from DB. Initilizing.')
    for host in hosts:
        if host[0] != 'dhcp':
           arp_table[host[0]] = host[1] 
    
#method for sniffing network and log arp
def arp_filter():
    sniff(filter='arp', prn=arp_handler)

def arp_handler(pkt):
    IP = pkt.psrc
    MAC = pkt.src
    event_time = time.strftime("%d-%m-%Y %H.%M.%S", time.localtime())
    if IP not in arp_table.keys():
            arp_table[IP] =  MAC
            return f'{event_time} new host detected {IP} - {MAC} added to arp_table'
    if IP in arp_table.keys() and MAC != arp_table.get(IP):
        try:
            host = select_host_from_db(MAC)
            if str(host) == 'None':
               host = IP
        except BaseException:
            host = IP
        if len(pcap_folder) != 0:
            wrpcap(pcap_folder+f'{time.localtime().tm_mday}_arp_alert.pcap',pkt, append = True)
        if len(log_folder) != 0:
            log = open(log_folder+'arp.log', 'a')
            log.write(f'{event_time} {host} alert ARP-spoofing detected from {MAC}')        

        return f'{event_time} {host} alert ARP-spoofing detected from {MAC}'
                
#DB / file methods for preload mode
def initialize_local_db():
    conn = sqlite3.connect(db_folder+db_name) 
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS hosts
                  (basic_net TEXT, mac TEXT,
                   hostname TEXT)
               """)
    conn.commit()

def insert_hosts(hosts:list):
    conn = sqlite3.connect(db_folder+db_name)
    cursor = conn.cursor()
    for host in hosts:
        cmd = f"INSERT INTO hosts (basic_net, MAC, hostname) VALUES ('{str(host[0])}', '{str(host[1])}', '{str(host[2])}');"
        cursor.execute(cmd)
    conn.commit()    

def insert_host_in_db(net,MAC,hostname):
    conn = sqlite3.connect(db_folder+db_name)
    cursor = conn.cursor()
    cmd = f"INSERT INTO hosts (basic_net, MAC, hostname) VALUES ('{str(net)}', '{str(MAC)}', '{str(hostname)}');"
    cursor.execute(cmd)
    conn.commit()

def select_host_from_db(MAC):
    db = sqlite3.connect(db_folder+db_name)
    db.row_factory = lambda cursor, row: row[0]
    cur = db.cursor()
    db_req = f'SELECT hostname FROM hosts WHERE mac="{MAC}";'    
    cur.execute(db_req)
    hostname = cur.fetchone()
    return hostname 
    
#programm example
if mode == 'live':
    print(f'Scaning local {network}')
    arp_scan(network)
    print('ARP-table ready. ARP-filter started')
    arp_filter()
elif mode == 'preload':
    load_arp_table_from_db()
    arp_scan(network)       
    print('ARP-table ready. ARP-filter started')
    arp_filter()


