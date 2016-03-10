import os, sys
import optparse
import json
#from scapy.all import sniff
#from pktFeaturizer import PktFeaturizer
from counterLog import CounterLog
from flowLog import FlowLog
import utils


def main():

    parser = optparse.OptionParser(usage='python %prog -r pcapFile -m macAddress [-o outputFolder -t timeStart -d deltaTime -s all|none|count|flow|dns -p period]')
    #parser.add_option('-h', '--help')
    parser.add_option('-r', '--pcapFile', dest='pcapFile', help="(required) input pcap file path" )
    parser.add_option('-m', '--macAddress', dest='macAddress', help="(required) MAC address of IoT device to decide direction. Please input address in format xx:xx:xx:xx:xx:xx." )
    parser.add_option('-o', '--outputFolder', dest='outputFolder', default="output", help="(optional) output folder to store generated logs. default=output/" )
    parser.add_option('-t', '--timeStart', dest='timeStart', type="float", default=0.0, help="(optional) relative time stamp (s) to start logging. default=0.0" )
    parser.add_option('-d', '--deltaTime', dest='deltaTime', type="float", default=172800.0, help="(optional) relative delta time (s) from time start to stop logging. default=2 days" )
    parser.add_option('-s', '--summary', dest='summary', type="choice", choices = ["none", "counter", "flow", "dns", "all"], default="all", help="(optional) output logs to save in outputFolder (-o). {none, counter, flow, dns, all}. default=all" )
    parser.add_option('-p', '--period', dest='period', type="float", default=1.0, help="time period (s) to get measure flow counts. default=1.0" )

    (options, args) = parser.parse_args()

    if options.pcapFile is None:
        options.pcapFile = raw_input("Enter pcap file name:")
    if not os.path.isfile(options.pcapFile):
        print "File "+options.pcapFile+" does not exist."
        sys.exit()

    if options.macAddress is None:
        utils.mac_addresses()
        options.macAddress = raw_input("Enter MAC address of device:")
    options.macAddress = options.macAddress.lower()
    if (not ":" in options.macAddress) or (len(options.macAddress) != 17):
        print "Please input valid mac address in format xx:xx:xx:xx:xx:xx"
        utils.mac_addresses()
        sys.exit()

    if options.outputFolder is None:
        options.outputFolder = "output/"
    if options.outputFolder[-1] != '/':
        options.outputFolder+'/'    #make sure it ends in a /
    if not os.path.exists(options.outputFolder):
        try:
            os.makedirs(options.outputFolder)
        except:
            err = sys.exc_info()[0]
            print "Cant create output folder " + options.outputFolder
            print str(err)
            sys.exit()

    if (options.timeStart is None) or (options.timeStart < 0):
        options.timeStart = 0.0
        print "Set timeStart to " + options.timeStart

    if (options.deltaTime is None) or (options.deltaTime < 0):
        options.deltaTime = 172800.0
        print "Set deltaTime to " + options.deltaTime

    if (options.period is None) or (options.period <= 0):
        options.period = 1.0
        print "Set period to " + options.period

    if (options.summary is None):
        options.summary = 'all'
        print "Output all logs"

    # MAIN pkt feature extraction
    tstart, tstop = utils._set_relative_time(options.pcapFile, options.timeStart, options.deltaTime)
    pkt_list = utils.get_pkt_list(options.pcapFile, options.macAddress, tstart, tstop)

    # Summary on top of device pkts extracted
    if options.summary=='counter' or options.summary=='all':
        print "Run CounterLog(). Save to "+options.outputFolder+"counter.log"
        CounterLog().run(pkt_list, options.outputFolder, 'counter.log')
    if options.summary=='dns' or options.summary=='all':
        print "Run DNSLog(). Save to "+options.outputFolder+"dns.log"
        #DNSLog().run(pkt_list)
    if options.summary=='flow' or options.summary=='all':
        print "Run FlowLog(time_period). Save to "+options.outputFolder+"flow.log"
        FlowLog(options.period).run(pkt_list, options.outputFolder, 'flow.log')
    if options.summary=='none':
        print "Save pkt_list to "+options.outputFolder+"pkt_list.log"
        # TODO doesn't work due to serialization problem / dict of dict -> json
        with open(options.outputFolder + 'pkt_list.log', 'w') as outfile:
            for pkt_features in pkt_list:
                json.dump(pkt_features.to_JSON(), outfile)
    return

if __name__ == "__main__":
    #pkt_list = utils.test_pkt_list('../data/smartthings_bg_short.pcap', 'd0:52:a8:00:81:b6')
    #pkt_list = utils.get_pkt_list('../data/smartthings_bg_short.pcap', 'd0:52:a8:00:81:b6')
    main()
