# Device Identification

Identify IoT device by extracting packet features at each layer

Create packet summaries of pcap files by packet type

Use summaries across different homes/locations to figure out which packet features (layer by layer) are best for identifying devices

Usage: python main.py -r ../data/smartthings_bg_short.pcap -m d0:52:a8:00:81:b6 -o ../processed/smartthings_bg_d1800_p1/ -t 100.0 -d 1800.0 -s all -p 1.0

Output contains counter.log, flow.log, df_pkt_counters.pkl, df_byte_counters.pkl.
