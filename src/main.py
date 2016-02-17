import os, sys
import optparse
import json
from scapy.all import sniff
from pktFeaturizer import PktFeaturizer
#from counterLog import CounterLog

pkt_list = []    # global pkt list to save extracted packet

def mac_addresses():
    mac = {}
    mac['Amazon Echo'] = '74:75:48:9b:70:25'
    mac['SmartThings'] = 'd0:52:a8:00:81:b6'
    mac['Nest Thermostat'] = '18:b4:30:14:52:1d'
    mac['Pixstar Photoframe'] = 'b4:ab:2c:08:3c:f8'
    mac['Ubi'] = '6c:fa:a7:15:dd:ab'
    mac['Sharx IPCam'] = '00:e0:4c:b7:3c:d2'

    print "Known MAC addresses"
    for dev, addr in mac.iteritems():
        print dev, " - ", addr

    return

def extract_pkt_features(macAddress):
    global pkt_list

    def pkt_featurize(pkt):
        '''extract features from each pkt; add direction feature based on macAddress; append to global pkt_list'''
        UP = 1
        DW = 0
        pkt_info = PktFeaturizer(pkt)
        if pkt.src == macAddress:
            pkt_info._set_direction(UP)
            pkt_list.append(pkt_info)
        elif pkt.dst == macAddress:
            pkt_info._set_direction(DW)
            pkt_list.append(pkt_info)
    return pkt_featurize

def test_pkt_features(macAddress):
    global pkt_list
    print "Test pkt features"
    print "macAddress", macAddress
    print "pkt_list", pkt_list

    def pkt_print(pkt):
        if pkt.src == macAddress:
            print "UP"
            print pkt.show()
        elif pkt.dst == macAddress:
            print "DW"
            print pkt.show()
        else:
            print "Not a device pkt"
        #print pkt.show()
    return pkt_print

def main():

    parser = optparse.OptionParser(usage='python %prog -r pcapFile -m macAddress [-o outputFolder -t timeStart -d deltaTime -s summary]')
    #parser.add_option('-h', '--help')
    parser.add_option('-r', '--pcapFile', dest='pcapFile', help="(required) input pcap file path" )
    parser.add_option('-m', '--macAddress', dest='macAddress', help="(required) MAC address of IoT device to decide direction. Please input address in format xx:xx:xx:xx:xx:xx" )
    parser.add_option('-o', '--outputFolder', dest='outputFolder', default="output", help="(optional) output folder to store generated logs. default=output/" )
    parser.add_option('-t', '--timeStart', dest='timeStart', type="float", default=0.0, help="(optional) relative time stamp (s) to start logging. default=0.0" )
    parser.add_option('-d', '--deltaTime', dest='deltaTime', type="float", default=172800.0, help="(optional) relative delta time (s) from time start to stop logging. default=2 days" )
    parser.add_option('-s', '--summary', dest='summary', type="choice", choices = ["none", "counter", "flow", "dns", "all"], default="all", help="(optional) output logs to save in outputFolder (-o)" )

    (options, args) = parser.parse_args()

    if options.pcapFile is None:
        options.pcapFile = raw_input("Enter pcap file name:")
    if not os.path.isfile(options.pcapFile):
        print "File "+options.pcapFile+" does not exist."
        sys.exit()

    if options.macAddress is None:
        mac_addresses()
        options.macAddress = raw_input("Enter MAC address of device:")
    options.macAddress = options.macAddress.lower()
    if (not ":" in options.macAddress) or (len(options.macAddress) != 17):
        print "Please input valid mac address in format xx:xx:xx:xx:xx:xx"
        mac_addresses()
        sys.exit()

    if options.outputFolder is None:
        options.outputFolder = "output"
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

    if (options.summary is None):
        options.summary = 'all'
        print "Output all logs"

    # MAIN pkt feature extraction
    sniff(offline=options.pcapFile, store=0, prn=extract_pkt_features(options.macAddress))
    #sniff(offline=options.pcapFile, store=0, prn=test_pkt_features(options.macAddress))

    # Summary on top of device pkts extracted
    if options.summary=='counter' or options.summary=='all':
        print "Run CounterLog(). Save to "+options.outputFolder+"/counter.log"
        #CounterLog().run(pkt_list)
    if options.summary=='dns' or options.summary=='all':
        print "Run DNSLog(). Save to "+options.outputFolder+"/dns.log"
        #DNSLog().run(pkt_list)
    if options.summary=='flow' or options.summary=='all':
        print "Run FlowLog(). Save to "+options.outputFolder+"/flow.log"
        #FlowLog().run(pkt_list)
    if options.summary=='none':
        print "Save pkt_list to "+options.outputFolder+"/pkt_list.log"
        # TODO doesn't work due to serialization problem / dict of dict -> json
        with open('pkt_list.json', 'w') as outfile:
            for pkt_features in pkt_list:
                json.dump(pkt_features.to_JSON(), outfile)

    return

if __name__ == "__main__":
    main()
