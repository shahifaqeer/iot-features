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
