from __future__ import division
from scapy.all import *
import time, sys
from collections import defaultdict, Counter
from pprint import pprint


class PktFeaturizer:

    def __init__(self, pkt):
        self.arrival_time = pkt.time
        self.len_bytes = len(pkt)
        self.pkt_type, self.features = "other", {}
        if pkt.haslayer(ICMP):
            self.pkt_type, self.features = ICMP, self.ICMPfeatures(pkt)
        elif pkt.haslayer(DNS):
            self.pkt_type, self.features = DNS, self.DNSfeatures(pkt)
        elif pkt.haslayer(STP):
            self.pkt_type, self.features = STP, self.STPfeatures(pkt)
        elif pkt.haslayer(DHCP):
            self.pkt_type, self.features = DHCP, self.DHCPfeatures(pkt)
        elif pkt.haslayer(TCP):
            self.pkt_type, self.features = TCP, self.TCPfeatures(pkt)
        elif pkt.haslayer(UDP):
            self.pkt_type, self.features = UDP, self.UDPfeatures(pkt)
        elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
            self.pkt_type, self.features = IP, self.IPfeatures(pkt)
        elif pkt.haslayer(ARP):
            self.pkt_type, self.features = ARP, self.ARPfeatures(pkt)
        elif pkt.haslayer(Ether):
            self.pkt_type, self.features = Ether, self.Etherfeatures(pkt)
        elif pkt.haslayer(Dot11):
            self.pkt_type, self.features = Dot11, self.Dot11features(pkt)
        elif pkt.haslayer(Dot3):
            self.pkt_type, self.features = Dot3, self.Dot3features(pkt)

    def ICMPfeatures(self, pkt):
        icmp_features = {
            "ICMP type": pkt[ICMP].type,
            "ICMP code": pkt[ICMP].code,
            }
        if pkt.haslayer(IP) or pkt.haslayer(IPv6):
            icmp_features.update(self.IPfeatures(pkt))
        return icmp_features

    def DNSfeatures(self, pkt):
        dns_features = {
            "DNS recursion-desired": pkt[DNS].rd,
            "DNS question-count": pkt[DNS].qdcount,
            "DNS question-name": pkt[DNS].qd.qname,
            "DNS question-type": pkt[DNS].qd.qtype,
            "DNS question-class": pkt[DNS].qd.qclass
            }
        if pkt.haslayer(UDP):
            dns_features.update(self.UDPfeatures(pkt))
        return dns_features

    def STPfeatures(self, pkt):
        stp_features = {
            "STP proto":   pkt[STP].proto,
            "STP version": pkt[STP].version,
            }
        if pkt.haslayer(Dot3):
            stp_features.update(self.Dot3features(pkt))
        return stp_features

    def DHCPfeatures(self, pkt):
        dhcp_features = {}
        for option in pkt[DHCP].options:
            if len(option)==2:
                dhcp_features.update({"DHCP "+option[0] : option[1]})

        if pkt.haslayer(UDP):
            dhcp_features.update(self.UDPfeatures(pkt))
        return dhcp_features

    def TCPfeatures(self, pkt):
        tcp_features = {
            "TCP sport": pkt[TCP].sport,
            "TCP dport": pkt[TCP].dport,
            }
        if (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            tcp_features.update(self.IPfeatures(pkt))
        return tcp_features

    def UDPfeatures(self, pkt):
        udp_features = {
            "UDP sport": pkt[UDP].sport,
            "UDP dport": pkt[UDP].dport,
            "UDP len":   pkt[UDP].len,
            }
        if (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            udp_features.update(self.IPfeatures(pkt))
        return udp_features

    def IPfeatures(self, pkt):
        if pkt.haslayer(IP):
            ip_features = {
                "IP src": pkt[IP].src,
                "IP dst": pkt[IP].dst,
                "IP len": pkt[IP].len,
                }
        else:
            ip_features = {
                "IP src": pkt[IPv6].src,
                "IP dst": pkt[IPv6].dst,
                "IP plen": pkt[IPv6].plen
                }

        if pkt.haslayer(Ether):
            ip_features.update(self.Etherfeatures(pkt))
        if pkt.haslayer(Dot3):
            ip_features.update(self.Dot3features(pkt))
        if pkt.haslayer(Dot11):
            ip_features.update(self.Dot11features(pkt))
        return ip_features

    def ARPfeatures(self, pkt):
        arp_features = {
            "ARP hwtype": pkt[ARP].hwtype,
            "ARP ptype":  pkt[ARP].ptype,
            "ARP hwsrc":  pkt[ARP].hwsrc,
            "ARP psrc":   pkt[ARP].psrc,
            "ARP hwdst":  pkt[ARP].hwdst,
            "ARP pdst":   pkt[ARP].pdst,
            }
        if pkt.haslayer(Ether):
            arp_features.update(self.Etherfeatures(pkt))
        if pkt.haslayer(Dot3):
            arp_features.update(self.Dot3features(pkt))
        if pkt.haslayer(Dot11):
            arp_features.update(self.Dot11features(pkt))
        return arp_features

    def Etherfeatures(self, pkt):
        ether_features = {
            "Ether src":  pkt[Ether].src,
            "Ether dst":  pkt[Ether].dst,
            "Ether type": pkt[Ether].type,
            }
        return ether_features

    def Dot3features(self, pkt):
        dot3_features = {
            "802.3 src":  pkt[Dot3].src,
            "802.3 dst":  pkt[Dot3].dst,
            }
        return dot3_features

    def Dot11features(self, pkt):
        dot11_features = {
            }
        return dot11_features


def test_pktfeaturizer(pkt):
    features = PktFeaturizer(pkt)
    print features.pkt_type
    print features.features


#---------------------------------------------------------------------------------#

class pcapSummary:

    def __init__(self):
        self.pkt_type_features = defaultdict(int)
        self.pcap_summary = defaultdict(int)
        pass

    def identify_device(self, pkt):
        return pkt.src

    def pkt_feature(self, pkt):
        """for each packet type: save each feature name and append feature value to that feature name list"""
        device_id = self.identify_device(pkt)
        features = PktFeaturizer(pkt)
        #print features.pkt_type, features.features

        if features.pkt_type not in self.pkt_type_features:
            self.pkt_type_features[features.pkt_type] = defaultdict(list)

        for feature_name, feature_value in features.features.iteritems():
            self.pkt_type_features[features.pkt_type][feature_name].append(feature_value)
        return

    def summarize(self):
        """print pcap summary by counting all features per packet type"""
        for pkt_type, feature in self.pkt_type_features.iteritems():

            self.pcap_summary[pkt_type] = defaultdict(list)
            print pkt_type

            for feature_name, feature_list in sorted(feature.iteritems()):
                try:
                    feature_summary = Counter(feature_list)
                except TypeError:
                    print "unhashable list"
                    print feature_list
                    feature_summary = feature_list
                self.pcap_summary[pkt_type][feature_name] = feature_summary
                print feature_name, ": ", feature_summary

            print "\n"

        return

    def run(self, pcap_file):
        sniff(offline=pcap_file, store=0, prn=self.pkt_feature)
        print "--Summary--"
        print "[Pkt Type]"
        print "Feature: Counter { feature_value: packet_count, ... }"
        print "------\n"

        self.summarize()

if __name__ == "__main__":
    #sniff(prn=test_pktfeaturizer)

    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            print "Usage: python {} -r pcapFile".format(sys.argv[0])
        elif sys.argv[1] == "-r":
            try:
                pcap = sys.argv[2]
                pcapSummary().run(pcap)
            except:
                print "Usage: python {} -r pcapFile".format(sys.argv[0])
        else:
            print "Usage: python {} -r pcapFile".format(sys.argv[0])
    else:
        print "Usage: python {} -r pcapFile".format(sys.argv[0])
