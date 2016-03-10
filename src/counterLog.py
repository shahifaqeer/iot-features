from __future__ import division
import numpy as np
import time, sys, os
import json
from collections import defaultdict, Counter
from pprint import pprint
from pktFeaturizer import PktFeaturizer
import utils

DECIMAL_PLACES = 1  #for calculating gap between packets (s) from arrival time


class CounterLog:

    def __init__(self):
        self.pkt_type_features = defaultdict(int)
        self.pcap_summary = defaultdict(int)
        pass

    def sort_pkt_features_by_type(self, pkt_list):
        """for each packet type: save each feature name and append feature value to that feature name list"""
        #print features.pkt_type, features.features

        for pkt_features in pkt_list:

            if pkt_features.pkt_type not in self.pkt_type_features:
                self.pkt_type_features[pkt_features.pkt_type] = defaultdict(list)

            #self.pkt_type_features[pkt_features.pkt_type]['arrival_time'].append(pkt_features.arrival_time)
            #self.pkt_type_features[pkt_features.pkt_type]['direction'].append(pkt_features.direction)
            #self.pkt_type_features[pkt_features.pkt_type]['len_bytes'].append(pkt_features.len_bytes)
            for feature_name, feature_value in pkt_features.features.iteritems():
                self.pkt_type_features[pkt_features.pkt_type][feature_name].append(feature_value)
        return

    def summarize(self):
        """print pcap summary by counting all features per packet type"""
        for pkt_type, feature in self.pkt_type_features.iteritems():

            #pkt_type is non serializable scapy object. use pkt_type.name instead.
            self.pcap_summary[pkt_type.name] = defaultdict(list)
            #print pkt_type, pkt_type.name

            for feature_name, feature_list in sorted(feature.iteritems()):
                if feature_name == 'arrival_time':  # calculate time diff
                    rounded_diff = [round(diff, DECIMAL_PLACES) for diff in np.diff(feature_list)]
                    feature_summary = Counter(rounded_diff)
                    feature_name = 'diff_arrival_time'
                else:
                    try:
                        feature_summary = Counter(feature_list)
                    except TypeError:
                        #print "unhashable list"
                        #print feature_list
                        feature_summary = {feature_list: 1}
                self.pcap_summary[pkt_type.name][feature_name] = feature_summary
                #print feature_name, ": ", feature_summary
            #print "\n"
        return

    def to_JSON(self, outputFolder, outputfile):
        if outputFolder[-1]!='/':
            outputFolder += '/'
        if not os.path.exists(outputFolder):
            os.makedirs(outputFolder)

        with open(outputFolder + outputfile, 'w') as outfile:
            json.dump(self.pcap_summary, outfile)
            #print self.pcap_summary

    def run(self, pkt_list, outputFolder, outputfile):
        self.sort_pkt_features_by_type(pkt_list)
        #print "--Summary--"
        #print "[Pkt Type]"
        #print "Feature: Counter { feature_value: packet_count, ... }"
        #print "------\n"
        self.summarize()
        self.to_JSON(outputFolder, outputfile)


def test_counterlog(pkt_list=None):
    if pkt_list is None:
        pcapFile = '../data/smartthings_bg_short.pcap'
        macAddress = 'd0:52:a8:00:81:b6'
        pkt_list = utils.get_pkt_list(pcapFile, macAddress)
    outputFolder = 'output_test'
    outputfile = 'counter.log'
    CounterLog().run(pkt_list, outputFolder, outputfile)
    return

if __name__ == "__main__":
    test_counterlog()
