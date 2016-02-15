from __future__ import division
from scapy.all import *
import numpy as np
import time, sys
from collections import defaultdict, Counter
from pprint import pprint
from pktFeaturizer import PktFeaturizer


class CounterLog:

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


def test_counterlog(pcap=None):
    if pcap is None:
        pcap = '../data/nest_bg_short.pcap'

    if os.path.isfile(pcap):
        CounterLog().run(pcap)
    else:
        print "File path "+pcap+" does not exist."
    return

if __name__ == "__main__":
    test_counterlog()
