#from scape.all import *
from scapy.all import *
import time
#def replace_ip_packet(a, ip_tag):
#def replace_packet(a, tag,objs=IP):
'''
def replace_packet(a, tag,objs='IP'):
    ''
    a is single packet
    tag is like containing tuple (replace_src_tag, replace_dst_tag)
    objs could be 'IP' or 'Ether' ... dependant which layer you want to replace
    ''
    if a.haslayer(objs):
        src=a[objs].src
        dst=a[objs].dst
        #for aa in ip_tag:
        for aa in tag:
            if src==aa[0]:
                a[objs].src=aa[1]
            if dst==aa[0]:
                a[objs].dst=aa[1]
    return a
'''
def replace_ip_and_mac(a, tag):
    '''
    a is single packet
    tag is list_ containing tuple (match_ip, replace_ip, replace_mac)
    '''
    #if a.haslayer(objs):
    if a.haslayer('IP'):
        #src=a[objs].src
        src=a['IP'].src
        #dst=a[objs].dst
        dst=a['IP'].dst
        #for aa in ip_tag:
        for aa in tag:
            if src==aa[0]:
                #a[objs].src=aa[1]
                a['IP'].src=aa[1]
                a['Ether'].src=aa[2]
            if dst==aa[0]:
                #a[objs].dst=aa[1]
                a['IP'].dst=aa[1]
                a['Ether'].dst=aa[2]
    return a

def replace_dns(a,name_tag):
    n=0
    if a.haslayer('DNSQR'):
        name=a['DNSQR'].qname.decode('ascii')[:-1]
        for aa in name_tag:
            if aa[0]==name:
                n+=1
                a['DNSQR'].qname=aa[1].encode('ascii')+b'.'
                #a['DNSQR'].qname=aa[1].encode('ascii')+b'\0'
                if a.haslayer('DNSRR'):
                    #for idx, ab in enumerate(a['DNSRR']):
                    dns_num=a['DNS'].ancount
                    for ab in range(dns_num):
                        a['DNSRR'][ab].rrname=a['DNSQR'].qname
                        a['DNSRR'][ab].rdata='7.7.7.7'
                nscount=a['DNS'].nscount
                if nscount:
                    for ab in range(nscount):
                        a['DNS'].ns[ab].rrname=b'server.com.'
    if a.haslayer('Raw'):
        for aa in name_tag:
            #if aa.encode('ascii') in a['Raw'].load:
            if aa[0].encode('ascii') in a['Raw'].load:
                #a['Raw'].load.replace(aa.encode('ascii'),name_
                a['Raw'].load=a['Raw'].load.replace(aa[0].encode('ascii'),aa[1].encode('ascii'))
                n+=1
    #n=0
    if a.haslayer('IP'):
        del a['IP'].len
        del a['IP'].chksum
        n+=1
    if a.haslayer('UDP'):
        del a['UDP'].len    
        del a['UDP'].chksum
        n+=1
    if n:
        a=Ether(a.build())
    return a
                
#def replace_mac_packet(a,mac_tag):
#def replace_ip_pcap(file_name,ip_tag):
#def replace_ip_pcap(file_name,ip_tag,mac_tag):
'''
#def replace_pcap(file_name,ip_tag,dns_tag,mac_tag=None):
    ''
    ip_tag is a list containing tuple (replace_src_ip, replace_dst_ip)
    dns_tag is a list containing tuple (replace_src_dns_request, replace_dst_dns_request)
    mac_tag is a list containing tuple (replace_src_mac, replace_dst_mac)
    ''
'''
def replace_pcap(file_name,server_ips,server_names):
    '''
    server_ips is lists containing server ip(s) string
    for example:
        ['1.1.1.1','2.2.2.2']
    server_names is lists containing server domain name,
    used for replacing DNS request name,
    example:
        ['server.com','server-plus.com']
    '''
    ip_tag, name_tag=generate_tag_list(server_ips,server_names)
    print('Read file in memory, this may occupy a while...')
    packets=rdpcap(file_name)
    l=[]
    for a in packets:
        #if a.haslayer(IP):
        #l.append(replace_packet(a,ip_tag,'IP'))
        #b=replace_packet(a,ip_tag,'IP')
        b=replace_ip_and_mac(a,ip_tag)
        b=replace_dns(b,name_tag)
        # if dns_tag!=None:
        #    #b=replace_dns(b,dns_tag)
        #if mac_tag!=None:
        #    b=replace_packet(b,mac_tag,'Ether')
        l.append(b)
    c=file_name.split('.')
    #d=c[0]+'_'+str(int(time.time()))+c[1]
    d=c[0]+'_'+str(int(time.time()))+'.'+c[1]
    #wrpcap(c[0]+'_'+str(int(time.time()))+c[1],l)
    wrpcap(d,l)
    print('File export as ',d)

import os
import random
#def replace(ip_list,domain_name):
def generate_tag_list(ip_list,domain_name):
    print('Current version only support ipv4')
    ip_tag=[]
    for a in ip_list:
        #i=os.random(4)
        i=os.urandom(4)
        ip=''
        for aa in i:
            ip+=str(int(aa))+'.'
        ip=ip[:-1]
        mac=''.join([hex(aa)[2:]+':' for aa in os.urandom(6)])[:-1]
        ip_tag.append((a,ip,mac))
    domain_tag=[]
    for a in domain_name:
        #i=os.urandom(16)
        #i=[aa %128 for aa in i]
        #i=[chr(random.randint(48,110)) for aa in range(16)]
        #i=[chr(random.randint(48,110)) for aa in range(16)]
        i=[chr(random.randint(97,122)) for aa in range(16)]
        #name=bytes(i).decode('a
        name=''.join(i)+'.nobody'
        domain_tag.append((a,name))
    return (ip_tag,domain_tag)









