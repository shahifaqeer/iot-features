from scapy.all import sniff
from pktFeaturizer import PktFeaturizer


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

def extract_pkt_features(macAddress, pkt_list):
    def pkt_featurize(pkt):
        '''extract features from each pkt; add direction feature based on macAddress; append to global pkt_list'''
        UP = 1
        DW = 0
        pkt_info = PktFeaturizer(pkt)
        if pkt.src == macAddress:
            pkt_info._set_direction(UP)
            #print "pkt.src", pkt.src, pkt_info.direction
            pkt_list.append(pkt_info)
        elif pkt.dst == macAddress:
            pkt_info._set_direction(DW)
            #print "pkt.dst", pkt.dst, pkt_info.direction
            pkt_list.append(pkt_info)
    return pkt_featurize

def test_pkt_features(macAddress, pkt_list):
    #global pkt_list
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

def get_pkt_list(pcapFile, macAddress):
    pkt_list = []    # global pkt list to save extracted packet
    sniff(offline=pcapFile, store=0, prn=extract_pkt_features(macAddress, pkt_list))
    return pkt_list

def test_pkt_list(pcapFile, macAddress):
    if (pcapFile is None) or (macAddress is None):
        pcapFile = '../data/smartthings_bg_short.pcap'
        macAddress = 'd0:52:a8:00:81:b6'
    pkt_list = []
    sniff(offline=pcapFile, store=0, prn=test_pkt_features(macAddress, pkt_list))
    return pkt_list

if __name__ == "__main__":
    #pkt_list = test_pkt_list('../data/smartthings_bg_short.pcap', 'd0:52:a8:00:81:b6')
    pkt_list = get_pkt_list('../data/smartthings_bg_short.pcap', 'd0:52:a8:00:81:b6')
