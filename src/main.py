import sys, getopt
from counterLog import CounterLog

def usage():
    print "Usage: python {} -r pcapFile -o outputFolder -m macAddress(device)".format(sys.argv[0])
    sys.exit(2)
    return

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

def main(argv):
    pcapFile = ''
    outputFolder = ''
    macAddress = ''

    try:
        opts, args = getopt.getopt(argv, "hr:o:m:", ["pcapFile=", "outputFolder=", "macAddress="])
    except getopt.GetoptError as err:
        print str(err)
        usage()
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-r", "--pcapFile"):
            pcapFile = a
            if not os.path.isfile(pcapFile)
                print "File "+pcapFile+" does not exist."
                sys.exit()
        elif o in ("-o", "--outputFolder"):
            outputFolder = a
            if not os.path.exists(outputFolder):
                os.makedirs(outputFolder)
        elif o in ("-m", "--macAddress"):
            macAddress = a.lower()
            if (not ":" in macAddress) or (len(macAddress) != 17):
                print "Please input valid mac address in format xx:xx:xx:xx:xx:xx"
                mac_addresses()
                usage()
        else:
            assert False, "unhandled option"
            usage()

    # TODO fix to run pktFeaturizer with -r, -o, -m and then to others
    CounterLog().run(pcapFile)

    return


if __name__ == "__main__":
    main()
