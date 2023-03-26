from unicodedata import name
from scapy.all import *
import time

class MyPacket():
    def __init__(self) -> None:
        self.packTimne = None
        self.lens = None
        self.packet = None
        self.tcptrace = None
        # 数据链路层
        self.layer_4 = {'name' : None, 'src': None, 'dst': None,'info':None}
        # 网络层
        self.layer_3 = {'name' : None, 'src': None, 'dst': None,'version': None, 'ihl': None, 'tos': None, \
            'len': None, 'id': None, 'flag': None, 'chksum':None, 'opt':None, 'hwtype':None, 'ptype':None, \
            'hwlen':None,'type':None,'op':None, 'info':None, 'hwsrc':None, 'hwdst':None}
        # 传输层
        self.layer_2 = {'name':None, 'src': None, 'dst': None, 'seq':None, 'ack':None, 'dataofs':None, 'reserved':None, \
            'flag':None, 'len':None, 'chksum':None, 'type':None, 'code':None, 'id':None,'info':None, 'window':None, \
            'tcptrace':None, 'tcpSdTrace': None, 'tcpRcTrace':None}
        # 应用层
        self.layer_1 = {'name':None, 'info':None}
    
    def parse(self, packet, startTime):
        self.packTimne = '{:.7f}'.format(time.time() - startTime)
        self.myParse(packet)

    def myParse(self, packet):
        self.lens = str(len(packet))
        self.packet = packet
        self.parseLayer_4(packet)
    
    # 数据链路层协议: Ethernet、令牌环、FDDI、PPP、loopback
    def parseLayer_4(self, packet):
        # Ethernet
        if packet.type == 0x800 or packet.type == 0x86dd or packet.type == 0x806:
            self.layer_4['name'] = 'Ethernet'
            self.layer_4['src'] = packet.src
            self.layer_4['dst'] = packet.dst
            self.layer_4['info'] = ('Ethernet; ' + 'Source MAC Address: '+ packet.src + ' ' + 'Destination MAC Address: ' + packet.dst)
        # loopback
        elif packet.type == 0x2 or packet.type == 0x18:
            self.layer_4['name'] = 'Loopback'
            self.layer_4['info'] = 'Loopback; '
        self.parseLayer_3(packet)
        

    # Ethernet --> IP / ARP
    def parseLayer_3(self, packet):
        # IPv4
        if packet.type == 0x800 or packet.type == 0x2: 
            self.layer_3['name'] = 'IPv4'
            self.layer_3['src'] = packet[IP].src
            self.layer_3['dst'] = packet[IP].dst
            self.layer_3['version'] = packet[IP].version
            self.layer_3['ihl'] = packet[IP].ihl
            self.layer_3['tos'] = packet[IP].tos
            self.layer_3['len'] = packet[IP].len
            self.layer_3['id'] = packet[IP].id
            self.layer_3['flag'] = packet[IP].flags
            self.layer_3['chksum'] = packet[IP].chksum
            self.layer_3['opt'] = packet[IP].options
            self.layer_3['info'] = ('IPv4; ' + 'Source IP Address: ' + packet[IP].src + ' ' + 'Destination IP Address: ' + packet[IP].dst)
            self.parseLayer_2(packet, 4)
        # IPv6
        elif packet.type == 0x86dd or packet.type == 0x18: 
            self.layer_3['name'] = 'IPv6'
            self.layer_3['src'] = packet[IPv6].src
            self.layer_3['dst'] = packet[IPv6].dst
            self.layer_3['version'] = packet[IPv6].version
            self.layer_3['info'] = ('IPv6; ' + 'Source IP Address: ' + packet[IPv6].src + ' ' + 'Destination IP Address: ' + packet[IPv6].dst)
            self.parseLayer_2(packet, 6)
        # ARP
        elif packet.type == 0x806 : 
            self.layer_3['name'] = 'ARP'
            self.layer_3['src'] = packet[ARP].psrc
            self.layer_3['dst'] = packet[ARP].pdst
            self.layer_3['op'] = packet[ARP].op 
            self.layer_3['hwtype'] = packet[ARP].hwtype
            self.layer_3['ptype'] = packet[ARP].ptype
            self.layer_3['hwlen'] = packet[ARP].hwlen
            self.layer_3['len'] = packet[ARP].plen
            self.layer_3['hwsrc'] = packet[ARP].hwsrc
            self.layer_3['hwdst'] = packet[ARP].hwdst
            if packet[ARP].op == 1:
                self.layer_3['info'] = ('Request: Who has %s? Tell %s' % (packet[ARP].pdst, packet[ARP].psrc))
            elif packet[ARP].op == 2:
                self.layer_3['info'] = ('Reply: %s is at %s' % (packet[ARP].psrc, packet[ARP].hwsrc))
            else:
                self.layer_3['info'] = ('OP: '+ packet[ARP].op)

    # IPv4 / IPv6 --> TCP / UDP / TLS/ ICMP / IGMP / ...
    def parseLayer_2(self, packet, num):
        if num == 4:
            # TCP
            if packet[IP].proto == 6:
                self.layer_2['tcptrace'] = ('%s %s %s %s' % (packet[IP].src, packet[IP].dst,packet[TCP].sport, packet[TCP].dport))
                self.layer_2['tcpSdTrace'] = ('%s %s' % (packet[IP].src, packet[TCP].sport))
                self.layer_2['tcpRcTrace'] = ('%s %s' % (packet[IP].dst, packet[TCP].dport))
                self.layer_2['name'] = 'TCP'
                self.layer_2['src'] = packet[TCP].sport
                self.layer_2['dst'] = packet[TCP].dport
                self.layer_2['seq'] = packet[TCP].seq
                self.layer_2['ack'] = packet[TCP].ack
                self.layer_2['window'] = packet[TCP].window
                self.layer_2['dataofs'] = packet[TCP].dataofs
                self.layer_2['reserved'] = packet[TCP].reserved
                self.layer_2['flag'] = packet[TCP].flags
                self.layer_2['info'] = ('Source Port: %s -> Destination Port: %s Seq: %s Ack: %s Win: %s' % (packet[TCP].sport, packet[TCP].dport, packet[TCP].seq, packet[TCP].ack, packet[TCP].window))
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.parseLayer_1(packet, 4)
                elif  packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    self.parseLayer_1(packet, 6)
            # UDP
            elif packet[IP].proto == 17:
                self.layer_2['name'] = 'UDP'
                self.layer_2['src'] = packet[UDP].sport
                self.layer_2['dst'] = packet[UDP].dport
                self.layer_2['len'] = packet[UDP].len
                self.layer_2['chksum'] = packet[UDP].chksum
                self.layer_2['info'] =  ('Source Port: %s -> Destination Port: %s' % (packet[UDP].sport, packet[UDP].dport))
                if packet.haslayer('DNS'):
                    self.parseLayer_1(packet, 7)
            # TLS
            elif packet[IP].proto == 56: 
                self.layer_2['name'] = 'TLS'
                self.layer_2['src'] = packet[TLS].sport
                self.layer_2['dst'] = packet[TLS].dport
                self.layer_2['len'] = packet[TLS].len
                self.layer_2['chksum'] = packet[TLS].chksum
                self.layer_2['info'] = 'Source: %s --> Destination: %s' % (packet[TLS].sport, packet[TLS].dport)
            # ICMP
            elif packet[IP].proto == 1: 
                self.layer_2['name'] = 'ICMP'
                self.layer_2['type'] = packet[ICMP].type
                self.layer_2['code'] = packet[ICMP].code
                self.layer_2['id'] = packet[ICMP].id
                self.layer_2['chksum'] = packet[ICMP].chksum
                self.layer_2['seq'] = packet[ICMP].seq
                if packet[ICMP].type == 8:
                    self.layer_2['info'] = ('Echo (ping) request id: %s seq: %s' % (packet[ICMP].id,packet[ICMP].seq))
                elif packet[ICMP].type == 0:
                    self.layer_2['info'] = ('Echo (ping) reply id: %s seq: %s' % (packet[ICMP].id,packet[ICMP].seq))
                else:
                    self.layer_2['info'] = ('type: %s id: %s seq: %s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq))      
            # IGMP
            elif packet[IP].proto == 2: 
                self.layer_2['name'] = 'IGMP'
                self.layer_2['len'] = packet[IPOption_Router_Alert].length
                self.layer_2['info'] = 'This tool not yet supported for IGMP. '
            else:
                self.layer_2['name'] = ' '
                self.layer_2['info'] = ('This tool not yet supported for this protocol. IPv4 & packet[IP].proto = %s' % str(packet[IP].proto))
        elif num == 6:
            # TCP
            if packet[IPv6].nh == 6: 
                self.layer_2['tcptrace'] = ('%s %s %s %s' % (packet[IPv6].src, packet[IPv6].dst, packet[TCP].sport, packet[TCP].dport))
                self.layer_2['tcpSdTrace'] = ('%s %s' % (packet[IPv6].src,packet[TCP].sport))
                self.layer_2['tcpRcTrace'] = ('%s %s' % (packet[IPv6].dst, packet[TCP].dport))
                self.layer_2['name'] = 'TCP'
                self.layer_2['src'] = packet[TCP].sport
                self.layer_2['dst'] = packet[TCP].dport
                self.layer_2['seq'] = packet[TCP].seq
                self.layer_2['ack'] = packet[TCP].ack
                self.layer_2['window'] = packet[TCP].window
                self.layer_2['dataofs'] = packet[TCP].dataofs
                self.layer_2['reserved'] = packet[TCP].reserved
                self.layer_2['flag'] = packet[TCP].flags
                self.layer_2['info'] = ('Source Port: %s -> Destination Port: %s Seq: %s Ack: %s Win: %s' % (packet[TCP].sport, packet[TCP].dport, packet[TCP].seq, packet[TCP].ack, packet[TCP].window))
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.parseLayer_1(packet, 4)
                elif  packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    self.parseLayer_1(packet, 6)
            # UDP
            elif packet[IPv6].nh == 17:
                self.layer_2['name'] = 'UDP'
                self.layer_2['src'] = packet[UDP].sport
                self.layer_2['dst'] = packet[UDP].dport
                self.layer_2['len'] = packet[UDP].len
                self.layer_2['chksum'] = packet[UDP].chksum
                self.layer_2['info'] =  ('Source Port: %s -> Destination Port: %s' % (packet[UDP].sport, packet[UDP].dport))
                if packet.haslayer('DNS'):
                    self.parseLayer_1(packet, 7)
            # TLS
            elif packet[IPv6].nh == 56: 
                self.layer_2['name'] = 'TLS'
                self.layer_2['src'] = packet[TLS].sport
                self.layer_2['dst'] = packet[TLS].dport
                self.layer_2['len'] = packet[TLS].len
                self.layer_2['chksum'] = packet[TLS].chksum
                self.layer_2['info'] = 'Source: %s --> Destination: %s' % (packet[TLS].sport, packet[TLS].dport)
            # ICMP
            elif packet[IPv6].nh == 1:
                self.layer_2['name'] = 'ICMP'
                self.layer_2['type'] = packet[ICMP].type
                self.layer_2['code'] = packet[ICMP].code
                self.layer_2['id'] = packet[ICMP].id
                self.layer_2['chksum'] = packet[ICMP].chksum
                self.layer_2['seq'] = packet[ICMP].seq
                if packet[ICMP].type == 8:
                    self.layer_2['info'] = ('Echo (ping) request id: %s seq: %s' % (packet[ICMP].id, packet[ICMP].seq))
                elif packet[ICMP].type == 0:
                    self.layer_2['info'] = ('Echo (ping) reply id: %s seq: %s' % (packet[ICMP].id, packet[ICMP].seq))
                else:
                    self.layer_2['info'] = ('type: %s ID: %s seq: %s' % (packet[ICMP].type, packet[ICMP].id, packet[ICMP].seq))    
            # IGMP
            elif packet[IPv6].nh == 2: 
                self.layer_2['name'] = 'IGMP'
                self.layer_2['len'] = packet[IPOption_Router_Alert].length
                self.layer_2['info'] = 'This tool not yet supported for IGMP. '
            # ICMP in IPv6
            elif packet[IPv6].nh == 58: 
                if packet.haslayer('ICMPv6ND_NS') == True:
                    self.layer_2['name'] = 'ICMPv6'
                    self.layer_2['type'] = packet[ICMPv6ND_NS].type
                    self.layer_2['code'] = packet[ICMPv6ND_NS].code
                    self.layer_2['info'] = ('type: %s details: %s ' % (packet[ICMPv6ND_NS].type, str(packet[ICMPv6ND_NS])))
                elif packet.haslayer('ICMPv6ND_NA') == True:
                    self.layer_2['name'] = 'ICMPv6'
                    self.layer_2['type'] = packet[ICMPv6ND_NA].type
                    self.layer_2['code'] = packet[ICMPv6ND_NA].code
                    self.layer_2['info'] = ('type: %s details: %s ' % (packet[ICMPv6ND_NA].type, str(packet[ICMPv6ND_NA])))
                elif packet.haslayer('ICMPv6ND_RA') == True:
                    self.layer_2['name'] = 'ICMPv6'
                    self.layer_2['type'] = packet[ICMPv6ND_RA].type
                    self.layer_2['code'] = packet[ICMPv6ND_RA].code
                    self.layer_2['info'] = ('type: %s details: %s ' % (packet[ICMPv6ND_RA].type, str(packet[ICMPv6ND_RA])))
                else:
                    self.layer_2['name'] = 'ICMPv6'
            else:
                self.layer_2['name'] = ' '
                self.layer_2['info'] = ('This tool not yet supported for this protocol. IPv6 & packet[IPv6].nh = %s' % str(packet[IPv6].nh))
    
    # HTTP / HTTPS / DNS
    def parseLayer_1(self, packet, num):
        # HTTP
        if num == 4:
            self.layer_1['name'] = 'HTTP'
            if packet.haslayer('HTTPRequest'):
                self.layer_1['info'] = ('%s %s %s' % (packet.sprintf("{HTTPRequest:%HTTPRequest.Method%}").strip("'"), packet.sprintf("{HTTPRequest:%HTTPRequest.Path%}").strip("'"), packet.sprintf("{HTTPRequest:%HTTPRequest.Http-Version%}").strip("'")))
            elif packet.haslayer('HTTPResponse'):
                self.layer_1['info'] = ('%s' % packet.sprintf("{HTTPResponse:%HTTPResponse.Status-Line%}").strip("'"))
        # HTTPS   
        elif num == 6:
            self.layer_1['name'] = 'HTTPS'
            self.layer_1['info'] = ('%s -> %s Seq: %s Ack: %s Win: %s' % (packet[TCP].sport, packet[TCP].dport, packet[TCP].seq, packet[TCP].ack, packet[TCP].window))
        # DNS
        elif num == 7:
            self.layer_1['name'] = 'DNS'
            if packet[DNS].opcode == 0: 
                tmp = ' '
                if packet[DNS].qd :
                    tmp = bytes.decode(packet[DNS].qd.qname)
                self.layer_1['info'] = ('DNS request:  %s ' % tmp)
            else:
                self.layer_1['info'] = 'DNS reply'


