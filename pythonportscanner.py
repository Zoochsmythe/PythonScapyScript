#########################################################################################################################
# Python Port Scanner                                                                                                   #
# By Zachery Smith                                                                                                      #
# Code based off tutorials found on https://www.phillips321.co.uk/2014/08/12/python-port-scanner-nmap-py/               #
# and https://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/                #
# This program will take about 3-5 minutes to finish a TCP scan if you try to scan two ports and a full /24 subnet      #
# Github Repo: https://github.com/Zoochsmythe/PythonScapyScript.git                                                     #
#########################################################################################################################

from logging import getLogger, ERROR
from scapy.all import *
#getLogger("scapy.runtime").setLevel(ERROR)
import sys
from datetime import datetime
from time import strftime
import argparse

SYNACK = 0x12
RSTACK = 0x14

def main():
    #Allows for different arguments to be selected
    parser = argparse.ArgumentParser(description='Python Port Scanner emulates the nmap tool')
    parser.add_argument('-sS','--tcpscan', action='store_true', help='Enables TCP scans')
    parser.add_argument('-sU','--udpscan', action='store_true', help='Enable UDP scans') #did not get UDP to work
    parser.add_argument('-p','--ports', default='1-1024', help='The ports you want to scan: Ex. 22,23,24,25 or 1-30')
    parser.add_argument('-t','--targets', help='The targets you want to scan: Ex. 192.168.0.0/24')
    if len(sys.argv)==1: 
        parser.print_help() #if no flags are selected, send out general information
        sys.exit(0)
    args = parser.parse_args()

    #set targets
    targets=[]
    if args.targets:
        if '/' in args.targets: #if subnet create cidr array
            targets = CIDRarray(args.targets)
        elif '-' in args.targets: #if ip range, create list
            targets = makeiplist(args.targets)
        else:
            targets.append(args.targets)
    else:
        parser.print_help
        errormsg("You need to specify a target")

    #set ports
    if args.ports == '-':
        args.ports = '1-65535'
    ranges = (x.split("-") for x in args.ports.split(","))
    ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]

    start_clock = datetime.now()
    print "[*] Scanning started at " + strftime("%H:%M:%S")

    #go through targets and begin the scan
    for target in targets:
        isup = check_host(target) #check the host with ICMP packets to see if they are up

        #If the host is up, start scanning the designated ports
        if isup == True: 
            print "[*] Started scanning IP " + str(target)  
            for port in ports:
                status = scan_port(port, target)
                if status == True:
                    print "Port " + str(port) + ": Open"

    stop_clock = datetime.now()
    total_time = stop_clock - start_clock
    print "\n[*] Scanning Finished!"
    print"[*] Total Scan Duration: " + str(total_time)

#function that splits the list if the -t flag is with x.x.x.1-x selected
def makeiplist(targetslist):
    list=[]
    first3octets = '.'.join(targetslist.split('-')[0].split('.')[:3]) + '.'
    for i in range(int(targetslist.split('-')[0].split('.')[3]),int(targetslist.split('-')[1])+1):
        list.append(first3octets+str(i))
    return list

#Function that sends ICMP packet with a timeout of 1 to see if the host is up
def check_host(ip):
    conf.verb = 0
    ping = sr1(IP(dst = ip)/ICMP(),timeout = 1)
    if not ping:
        return False
    else:
        return True

#scans port, and checks the response of the scapy packet with what a SYNACK response would be
def scan_port(port, target):
    srcport = RandShort()
    conf.verb = 0
    SYNACKpkt = sr1(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S"),timeout=1)
    if(str(type(SYNACKpkt))=="<type 'NoneType'>"):
        return False
    elif(SYNACKpkt.haslayer(TCP)):
        pktflags = SYNACKpkt.getlayer(TCP).flags
        if pktflags == SYNACK:
            return True
        else:
            return False
        RSTpkt = sr1(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R"),timeout=1)

#function that splits the subnet into the first three octet
def CIDRarray(targetsarg):
    parts = targetsarg.split("/")
    IPbase = ip_to_bin(parts[0])
    subnet = int(parts[1])
    iparray=[]
    if subnet == 32:
        return bin_to_ip(IPbase)
    else:
        ipPrefix = IPbase[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            iparray.append(bin_to_ip(ipPrefix+decimal_to_bin(i, (32-subnet))))
        return iparray

#splits the octet pads with 8 zeros or bits to binary
def ip_to_bin(x):
    b = ""
    inQuads = x.split(".")
    outQuads = 4
    for q in inQuads:
        if q !="":
            b += decimal_to_bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -=1
    return b

#bitwise operation for changing decimal values in ip adress to binary
def decimal_to_bin(z, d=None):
    s=""
    while z > 0:
        if z&1:
            s = "1"+s
        else:
            s = "0"+s
        z >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "":
        s = "0"
    return s

#takes the binary version of IP address and changes it to dec
def bin_to_ip(y):
    ip = ""
    for i in range(0,len(y),8):
        ip += str(int(y[i:i+8],2))+"."
    return ip[:-1]


if __name__ == '__main__':
    main()