from scapy.all import *
import json
import sys

CNAME = 5

class DnsLogger:

	def __init__(self, pcap_filename, mac_address):
		self.MAC = mac_address
		self.pcap = pcap_filename
		self.entries = {}

	def pkt_filter(self):
		return lambda pkt: pkt.haslayer(DNS) and (pkt[Ether].src == self.MAC or pkt[Ether].dst == self.MAC)

	def create_entry(self, entry_name):
		self.entries[entry_name] = {"ips": []}

	def get_entry(self, entry_name):
		if(entry_name not in self.entries.keys()):
			self.create_entry(entry_name)
		return self.entries[entry_name]

	def process(self, pkt):
		entry = self.get_entry(pkt[DNS].qd.qname)
		answers = pkt[DNS].ancount  # only dealing with ancount, not nscount
		if(pkt[DNS].ancount > 0):
			for i in range(answers - 1, -1, -1):
				if(pkt[DNS].an[i].type == CNAME):
					entry["CNAME"] = pkt[DNS].an[i].rdata
				else:
					ip = pkt[DNS].an[i].rdata
					if(ip not in entry["ips"]):
						entry["ips"].append(ip)
				if(i > 0):
					del pkt[DNS].an[i]

	# Writes to json file by default
	def run(self, write=True):
		print("Sniffing packets from:\n\t%s" % (self.pcap))
		sniff(offline=self.pcap, store=0, lfilter=self.pkt_filter(), prn=self.process)
		if(write):
			filename = os.path.basename(self.pcap)[:-5] + ".json"
			print("Writing to file: %s" % (filename))
			with open(filename, "w") as fjson:
				fjson.write(json.dumps(self.entries, sort_keys=True, indent=2))
		else:
			print(json.dumps(self.entries, sort_keys=True, indent=2))

def usage():
	print("python dnsLogger.py [-h] path_to_pcap MAC_address")
	print("Description:")
	print("Finds all the DNS queries names and the IPs associated with them.")
	print("If a canonical name (CNAME) is found, it is also added to the entry.")

def main():
	if(len(sys.argv) != 3 or sys.argv[2] == "-h"):
		usage()
		return
	
	filename = sys.argv[1]
	MAC = sys.argv[2]

	dns = DnsLogger(filename, MAC)
	dns.run()

if __name__ == "__main__":
	main()