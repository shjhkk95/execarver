#!/usr/bin/python

from scapy.all import *
import sys
import os
import socket
import struct

numFiles = 0;

def endianChange(string):
	#print(string)
	newEndianList = []
	for i in range(0,len(string),2):
		newEndianList.insert(0,string[i:i+2])
	a = ''.join(newEndianList)
	#print(a)
	return a

def sniffing(interface, BPFfilters):
	#print("BPFfilters" + BPFfilters)
	print("SNIFFING PACKETS.....")
	pckts = []
	if len(BPFfilters) == 0:
		try:
			print("INTERFACE : " + interface)
			pckts = sniff(iface = interface, count = 3000)
		except:
			print("NO SUCH INTERFACE DEVICE")
			sys.exit()
	else :
		filters = ' and '.join(BPFfilters)
		print("BPF FILTERS : " + filters + " INTERFACE : " + interface)
		try:
			pckts = sniff(iface = interface, count = 3000, filter = filters)
		except:
			print("BPF FILTER FORMAT IS WRONG.. EXTING PROGRAM...")
			sys.exit()
			
		
	#print(pckts + "eeeffe")
	return pckts
	



def packets_into_session(packets):
	print("MERGING PACKETS INTO SESSIONS...")
	return packets.sessions()

def merge_packets_in_session(sessions, ip):
	print("CONCANATING PAYLOAD IN EACH SESSION INTO ONE STREAM...")
	DataList = []
	for session in sessions:
		data = ''
		
		for packet in sessions[session]:
			if packet.haslayer(IP):
				if packet[IP].dst ==  ip and packet.haslayer(TCP):
					data = data + packet[TCP].load
		DataList.append(data)
		
	return DataList

def find_and_extract_PE(List):
	print("EXTRACTING PE FILE OUT OF STREAM...")
	
	for DataStream in List:
		if 'MZ' in DataStream:
			MZindex = DataStream.index('MZ')
			extractPE(DataStream[MZindex:])
	return

def extractPE(DataStream):
	
	#print(len(DataStream))
	#print((DataStream[60:64].encode("hex")))
	try:
		COFFoffset = int(endianChange(DataStream[60:64].encode("hex")),16)
	
	except:
		return
	
	#print(COFFoffset)
	#print(DataStream[COFFoffset:COFFoffset+4].encode("hex"))
	if DataStream[COFFoffset:COFFoffset+2] != 'PE':
		return
	'''
	OptionalHeaderIndex = COFFoffset + 24
	
	print(str(OptionalHeaderIndex) + " Optional Header Index")
	print(DataStream[OptionalHeaderIndex:OptionalHeaderIndex+2].encode("hex"))
	print(DataStream[OptionalHeaderIndex+60:OptionalHeaderIndex+64].encode("hex"))
	HeaderSize = DataStream[OptionalHeaderIndex+60:OptionalHeaderIndex+64].encode("hex")
	
	HeaderSize = int(endianChange(HeaderSize), 16)
	print((HeaderSize))
	
	sections = {'.bss':-1,'.cormeta':-1,'.data':-1,'.debug':-1,'.drective':-1,
	'.edata':-1, '.idata':-1, '.idlesym': -1, '.pdata' : -1,'.rdata':-1,
	'.reloc' : -1, '.rsrc' : -1, '.sbss' : -1, '.sdata' : -1, '.srdata' : -1,
	'.sxdata' : -1, '.text' : -1, '.tls' : -1, '.tls$' : -1, '.vsdata' : -1,
	'.xdata' : -1}

	for key in sections.keys():
		sections[key] = DataStream.index(key) if key in DataStream else -1
	print(sections)
	sectionSize = 0
	for i in sections:
		if (sections[i] != -1):
			print("sectionIndex" +str(sections[i]))
			sSize = DataStream[sections[i]+16:sections[i]+20]
			sSize = (sSize.encode("hex"))
			print(sSize)
			print(endianChange(sSize))
			sSize = int(endianChange(sSize), 16)
			#sSize = struct.unpack("<L", sSize)[0]
			print(sSize)
			sectionSize = sectionSize + sSize
	totalSize = HeaderSize + sectionSize
	print(totalSize)
	'''
	
	
	count = 0
	for i in range(len(DataStream)):
		
		if DataStream[::-1][i].encode('hex') == '00':
			count = count + 1
		else :
			break
	DataStream = DataStream[:len(DataStream)-count]
	global numFiles
	numFiles = numFiles + 1
	PEfile= open("FILE"+str(numFiles)+'.exe',"w+")
	PEfile.write(DataStream)
	f1 = open("FILE"+str(numFiles)+'.exe',"r")
	a = f1.read()
	print("FILE"+str(numFiles)+'.exe with ' + str(len(a)) + ' byte(s) is created')
	return
	
		

			
def main():
        packet = []

	if len(sys.argv   ) < 2:
		print("TOO FEW ARGUMENTS")
		sys.exit()
	if sys.argv[1] == '-i':
		if len(sys.argv) == 2:
			#print('ee')
			packet = sniffing("eth0",[])

		elif sys.argv[2] == '-r':
			try:
				print("READING PCAP FILE...")
				packet = rdpcap(sys.argv[3])
			except :
				print("WE NEED TRACEFILE")
				sys.exit()
		elif   len(sys.argv) == 3:
			if sys.argv[2] == '-r':
				print("WE NEED TRACEFILE")
			else :
				packet = sniffing(sys.argv[2], [])

		else :
			if sys.argv[3] == '-r':
				try:
					print("READING PCAP FILE...")
					packet = rdpcap(sys.argv[4])
				except:
					print("WE NEED TRACEFILE")
					sys.exit()
			else :
				bpfFilter = []
				for i in range(3,len(sys.argv)):
					bpfFilter.append(sys.argv[i])
				#print bpfFilter
				packet = sniffing(sys.argv[2], bpfFilter)
					

	elif sys.argv[1] == '-r':
		try :
			print("READING PCAP FILE...")
			packet = rdpcap(sys.argv[2])
		except:
			print("WE NEED TRACEFILE")
			sys.exit()


	else:
		print("Specify one of the option -i or -r")
		sys.exit()

        
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	ip = (s.getsockname()[0])
	s.close()

	session = packets_into_session(packet)
	data = merge_packets_in_session(session, ip)
	find_and_extract_PE(data)

if __name__ == "__main__":
        main()
