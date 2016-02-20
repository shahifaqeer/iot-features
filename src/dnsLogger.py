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
		'''
		Returns a lambda function to filter the packets parsed from the pcap file.
		Checks to see if the packet contains the DNS layer and if the source or destination
		of the Ethernet layer contains the mac address
		'''
		return lambda pkt: pkt.haslayer(DNS) and (pkt[Ether].src == self.MAC or pkt[Ether].dst == self.MAC)

	def create_entry(self, entry_name):
		'''
		Creates an entry in the entries dictionary with the entry_name as the key

		Keyword Arguments:
		entry_name = string -- Name of entry to create in dictionary
		'''

		self.entries[entry_name] = {"ips": []}

	def get_entry(self, entry_name):
		'''
		Retrieves an entry with the given entry_name from the dictionary of entries.
		If an entry can not be found, a new one will be created with the entry_name as the key.

		Keyword Arguments:
		entry_name = string -- Name of entry to get from or create in self.entries 

		Returns:
		dictionary -- entry found or created from self.entries
		'''

		if(entry_name not in self.entries.keys()):
			self.create_entry(entry_name)
		return self.entries[entry_name]

	def process(self, pkt):
		'''
		Processes a packet by finding all of the IP addresses associated with a DNS query.

		Keyword Arguments:
		pkt = scapy packet -- Packet returned by sniffing a pcap file with the scapy module
		'''

		entry = self.get_entry(pkt[DNS].qd.qname)
		# Find the number of answers in this packet
		# Get the IP address of each answer stored in an
		# If the answer is a CNAME, then the data will be the cname
		# Only dealing with ancount, not nscount
		answers = pkt[DNS].ancount  
		for i in range(answers):
			if(pkt[DNS].an[i].type == CNAME):
				entry["CNAME"] = pkt[DNS].an[i].rdata
			else:
				ip = pkt[DNS].an[i].rdata
				if(ip not in entry["ips"]):
					entry["ips"].append(ip)

	def run(self, write=True):
		'''
		Parses the pcap file, self.pcap, by looking at all the DNS packets that come from or go to 
		the mac address, self.MAC.
		'''

		print("Sniffing packets from:\n\t%s" % (self.pcap))
		sniff(offline=self.pcap, store=0, lfilter=self.pkt_filter(), prn=self.process)
		if(write):
			filename = os.path.basename(self.pcap)[:-5] + ".json"
			print("Writing to file: %s" % (filename))
			with open(filename, "w") as fjson:
				fjson.write(json.dumps(self.entries, sort_keys=True, indent=2))
		else:
			print(json.dumps(self.entries, sort_keys=True, indent=2))


# Function to print the usage of this program
def usage():
	print("python dnsLogger.py [-h] path_to_pcap MAC_address")
	print("Description:")
	print("Finds all the DNS queries names and the IPs associated with them.")
	print("If a canonical name (CNAME) is found, it is also added to the entry.")


def main():
	# If not enough or too much command line arguments or the user asked to print the usage
	if(len(sys.argv) != 3 or sys.argv[1] == "-h"):
		usage()
		return
	
	# Retrieve the pcap filename or path and the mac address to sniff onto from the command line
	filename = sys.argv[1]
	MAC = sys.argv[2]

	# Create a DnsLogger with the provided filename and mac address
	# Run will write the results to the json file with the same basename as the provided filename
	dns = DnsLogger(filename, MAC)
	dns.run()

if __name__ == "__main__":
	main()