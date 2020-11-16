#ARP-control-server © 2020, cyberlabperm
#Released under GNU GPL v3 license 
from scapy.all import srp, sniff, wrpcap, Ether, ARP
import time, configparser

#load configuration
config = configparser.ConfigParser()
config.read("config.ini")
network = config.get('MAIN', 'network')
iface = config.get('MAIN', 'iface')
pcap_folder = config.get('MAIN', 'pcap_folder')
log_folder = config.get('MAIN', 'log_folder')
mode = config.get('MAIN', 'mode')
use_db = config.get('DB', 'use_db') 
if use_db == 'mysql':
    import pymysql
    mysql_host = config.get('DB', 'mysql_host')
    mysql_user =  config.get('DB', 'mysql_user')
    mysql_password = config.get('DB', 'mysql_password')
    mysql_db = config.get('DB', 'db_name')  
elif use_db == 'sqlite3':
    import sqlite3
    db_folder = config.get('DB', 'db_folder')
    db_name = config.get('DB', 'db_name')


global arp_table
arp_table = dict()

#method to scan network configuration and create IP-MAC-HOST table
def arp_scan(network, iface):
    assert isinstance(network, str), 'example 192.168.0.0/24'
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), iface = iface, timeout = 5)
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
def arp_filter(iface):
    if len(iface) != 0:
        sniff(iface=iface,filter='arp', prn=arp_handler)
    else:
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
    if use_db == 'mysql':
        conn = pymysql.connect(host=mysql_host, user=mysql_user, password=mysql_password)
    elif use_db == 'sqlite3':
        conn = sqlite3.connect(db_folder+db_name)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS hosts
                  (basic_net TEXT, mac TEXT,
                   hostname TEXT)
               """)
    conn.commit()

def insert_hosts(hosts:list):
    if use_db == 'mysql':
        conn = pymysql.connect(host=mysql_host, user=mysql_user, password=mysql_password, db = mysql_db)
    elif use_db == 'sqlite3':
        conn = sqlite3.connect(db_folder+db_name)
    cursor = conn.cursor()
    for host in hosts:
        cmd = f"INSERT INTO hosts (basic_net, MAC, hostname) VALUES ('{str(host[0])}', '{str(host[1])}', '{str(host[2])}');"
        cursor.execute(cmd)
    conn.commit()    

def insert_host_in_db(net,MAC,hostname):
    if use_db == 'mysql':
        conn = pymysql.connect(host=mysql_host, user=mysql_user, password=mysql_password, db = mysql_db)
    elif use_db == 'sqlite3':
        conn = sqlite3.connect(db_folder+db_name)
    cursor = conn.cursor()
    cmd = f"INSERT INTO hosts (basic_net, MAC, hostname) VALUES ('{str(net)}', '{str(MAC)}', '{str(hostname)}');"
    cursor.execute(cmd)
    conn.commit()

def select_host_from_db(MAC):
    if use_db == 'mysql':
        conn = pymysql.connect(host=mysql_host, user=mysql_user, password=mysql_password, db = mysql_db)
    elif use_db == 'sqlite3':
        conn = sqlite3.connect(db_folder+db_name)
    conn.row_factory = lambda cursor, row: row[0]
    cur = conn.cursor()
    db_req = f'SELECT hostname FROM hosts WHERE mac="{MAC}";'    
    cur.execute(db_req)
    hostname = cur.fetchone()
    return hostname 
    
#programm __init__
if mode == 'live':
    print(f'Scaning local {network}')
    arp_scan(network, iface)
    print('ARP-table ready. ARP-filter started')
    arp_filter(iface)
elif mode == 'preload':
    load_arp_table_from_db()
    arp_scan(network, iface)       
    print('ARP-table ready. ARP-filter started')
    arp_filter(iface)


