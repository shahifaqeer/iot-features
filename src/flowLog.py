from __future__ import division
import numpy as np
import pandas as pd
import json, os
from collections import defaultdict, Counter
from pktFeaturizer import PktFeaturizer
import utils

DECIMAL_PLACES = 1  #for calculating gap between packets (s) from arrival time


class FlowLog:
    '''
    input: list of pkt_info
    create matrix (# flows x # time_periods) for PCA
    flow_count.log: {(ip.src, sport, ip.dst, dport, proto, direction, pktlen) : COUNT / time_period}
    flow_byte.log: {(ip.src, sport, ip.dst, dport, proto, direction) : BYTES / time_period}
    '''

    def __init__(self, time_period=1.0):
        if (time_period is None) or (time_period <= 0.0):   # recheck just in case
            time_period = 1.0
        self.time_period = time_period
        self.time_init = 0.0
        self.pkt_counter = defaultdict(list)
        self.byte_counter = defaultdict(list)

    def _set_time_init(self, time_init):
        self.time_init = time_init

    def extract_flowtuple_per_pkt(self, pkt_info):
        '''flow tuple is a dict containing extracted flow info from a pkt used to get the matrix'''
        flow_tuple = {}
        if pkt_info.features['pkt_type'] in ['TCP', 'UDP', 'ICMP', 'DHCP']:     # concentrate on these 4 pkt types only
            proto = pkt_info.features['pkt_type']
            flow_tuple['proto'] = proto
            flow_tuple['srcip'] = pkt_info.features['IP src']
            flow_tuple['dstip'] = pkt_info.features['IP dst']
            if proto == 'UDP' or proto == 'DHCP':   # dhcp uses udp ports
                flow_tuple['sport'] = int(pkt_info.features['UDP sport'])
                flow_tuple['dport'] = int(pkt_info.features['UDP dport'])
            elif proto == 'TCP':
                flow_tuple['sport'] = int(pkt_info.features['TCP sport'])
                flow_tuple['dport'] = int(pkt_info.features['TCP dport'])
            else:   # icmp has no port nums
                flow_tuple['sport'] = -1
                flow_tuple['dport'] = -1

            try:
                flow_tuple['pkt_time'] = float(pkt_info.features['arrival_time'])
                flow_tuple['pkt_rel_time'] = float(pkt_info.features['arrival_time']) - self.time_init  # take relative time instead of absolute time
                flow_tuple['direction'] = int(pkt_info.features['direction'])
                flow_tuple['pkt_len'] = int(pkt_info.features['len_bytes'])
            except:
                print "Error extracting flow_tuple", flow_tuple
                print pkt_info.to_JSON()
            #print flow_tuple
        return flow_tuple

    def count_flowtuple_per_timeperiod(self, pkt_list):
        """convert pkt_list --> {flow: byte/count per time_period}
        flow_len = ('IP src', 'TCP/UDP sport', 'IP dst', 'TCP/UDP dport', 'TCP/UDP', 'direction', 'len_bytes')"""

        self._set_time_init( float( pkt_list[0].features['arrival_time'] ) )    # Assuming pkts are in increasing time order

        tstart = 0.0
        tstop = tstart + self.time_period
        pkt_counter = defaultdict(int)
        byte_counter = defaultdict(int)

        for pkt_info in pkt_list:
            flow_tuple = self.extract_flowtuple_per_pkt(pkt_info)
            if flow_tuple:  # check if dict is not empty
                flow_tuple1 = (flow_tuple['srcip'], flow_tuple['sport'], flow_tuple['dstip'], flow_tuple['dport'], flow_tuple['proto'], flow_tuple['direction'], flow_tuple['pkt_len'])
                flow_tuple2 = (flow_tuple['srcip'], flow_tuple['sport'], flow_tuple['dstip'], flow_tuple['dport'], flow_tuple['proto'], flow_tuple['direction'])
                #print flow_tuple

                #TODO ERROR HERE - why does one flow keep getting repeated???
                while (flow_tuple['pkt_rel_time'] >= tstop):
                    if pkt_counter:
                        self.update_flowtuple1_counts(pkt_counter, time_index)
                        print "time_index:", time_index, "pkt_counter:", pkt_counter
                        pkt_counter = defaultdict(int)
                    if byte_counter:
                        self.update_flowtuple2_bytes(byte_counter, time_index)
                        #print "time_index:", time_index, "byte_counter:", byte_counter
                        byte_counter = defaultdict(int)
                    tstart = tstop
                    tstop = tstart + self.time_period

                if (flow_tuple['pkt_rel_time'] >= tstart) and (flow_tuple['pkt_rel_time'] < tstop):     # assumes that pkt_time >= tstart implicitly
                    pkt_counter[flow_tuple1] += 1
                    byte_counter[flow_tuple2] += flow_tuple['pkt_len']
                    time_index = tstart


    def update_flowtuple1_counts(self, pkt_counter, time_index):
        """convert (pkt_counter{ [flow]: count }, time_index) --> self.pkt_counter
        such that matrix1 = pd.DataFrame(pkt_counter).pivot(index=time_index, columns=flow, values=count)"""

        for flow, count in pkt_counter.iteritems():
            self.pkt_counter['flow'].append(flow)
            self.pkt_counter['time'].append(time_index)
            self.pkt_counter['count'].append(count)

    def update_flowtuple2_bytes(self, byte_counter, time_index):
        """convert (byte_counter{ [flow]: bytes }, time_index) --> self.byte_counter
        such that matrix2 = pd.DataFrame(byte_counter).pivot(index=time_index, columns=flow, values=bytes)"""

        for flow, sum_bytes in byte_counter.iteritems():
            self.byte_counter['flow'].append(flow)
            self.byte_counter['time'].append(time_index)
            self.byte_counter['bytes'].append(sum_bytes)

    def to_JSON(self, outputFolder, outputfile):
        if outputFolder[-1]!='/':
            outputFolder += '/'
        if not os.path.exists(outputFolder):
            os.makedirs(outputFolder)

        with open(outputFolder + outputfile, 'w') as outfile:
            json.dump({'pkt_counter':self.pkt_counter, 'byte_counter':self.byte_counter}, outfile)

    def to_DataFrame(self, outputFolder):
        '''convert to pivoted dataframe ready for PCA analysis'''
        if outputFolder[-1]!='/':
            outputFolder += '/'
        if not os.path.exists(outputFolder):
            os.makedirs(outputFolder)

        df_pkt_counter = pd.DataFrame(self.pkt_counter).pivot(index='time', columns='flow', values='count')
        df_byte_counter = pd.DataFrame(self.byte_counter).pivot(index='time', columns='flow', values='bytes')
        print "df_pkt_counter", df_pkt_counter.head()
        print "df_byte_counter", df_byte_counter.head()

        df_pkt_counter.to_pickle(outputFolder + 'df_pkt_counter.pkl')
        df_byte_counter.to_pickle(outputFolder + 'df_byte_counter.pkl')

    def run(self, pkt_list, outputFolder, outputfile):
        self.count_flowtuple_per_timeperiod(pkt_list)
        self.to_JSON(outputFolder, outputfile)
        self.to_DataFrame(outputFolder)


def test_flowlog(pkt_list=None):
    if pkt_list is None:
        pcapFile = '../data/smartthings_bg_short.pcap'
        macAddress = 'd0:52:a8:00:81:b6'
        pkt_list = utils.get_pkt_list(pcapFile, macAddress)
    outputFolder = 'output_test'
    outputfile = 'flow.log'
    FlowLog().run(pkt_list, outputFolder, outputfile)
    return

if __name__ == "__main__":
    test_flowlog()
