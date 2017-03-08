import dpkt
import sys

if len(sys.argv) < 4 or len(sys.argv) > 4:
	print "Usage:", sys.argv[0], "server.pcap client.pcap rtpport"
	sys.exit()



def rtprtsp(pcap):
	rtp_packet=0
	rtsp_packet=0
	other=0
	total_packet=0

	for ts,buf in pcap:
		try:eth=dkpt.ethernet.Ethernet(buf)
	        except:continue
	#counts total number of packets
		total_packet+=1
	#picks up IPv4 packets
		if eth.type==2048:
			ip=eth.data
		if ip.p==17:         #picking only udp packets # In accordance to RFC5237
			try:udp=ip.data
			except:continue
			if udp.sport == sys.argv[3] or udp.dport == sys.argv[3]: #picking only the rtp packets
				rtp_packet+=1
		else:
			other+=1
	return(rtp_packet)



f=open(sys.argv[1])
pcap=dpkt.pcap.Reader(f)
server_rtp=rtprtsp(pcap)

f=open(sys.argv[2])
pcap=dpkt.pcap.Reader(f)
client_rtp=rtprtsp(pcap)

try:packetdrop=((server_rtp-client_rtp)/server_rtp)*100
except:packetdrop=0

print "rtp packets sent from server: "+str(server_rtp)
print "rtp packets received by the client: "+str(client_rtp)
print 'percentage of packet drop: '+str(packetdrop)





