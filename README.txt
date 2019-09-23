Program "execarver.py" is packet analyze program that extract PE(Protable Executable) program from network traffic or "pcap" file. Program used scapy API to sniff packets or to read pcap file in memory. As it reads the packets, if program identifies PE file in the stream, it extracts PE file out of stream and save in the local disk. 

Usage : execarver.py [-i interface] [-r tracefile] expressions

The program has 2 choices mode to run. First, -i flag runs program with sniffing mode. The  program starts to sniff the packets (3000 packets). With the packets sniffed, it merges packets with same stream into sessions, and look if PE file is there. If program finds and portable executable in the stream, it extract it and save it in the local disk. If interface argument is not specified, program uses "eht0" as interface. Expressions arguments are any number of arguments that are used to filter specific traffic to be monitored. The program prints processes as it reads or sniff packet, merge into stream, concatenate the raw bytes, and generating new PE file. All PE files that are generated in these programs are runnable on Windows. 

The -r flag runs program with reading pcap mode. It reads tracefile(pcap file) from command line argument and use rdpcap(traceFile) function to convert file to packets. With packets, the program basically do samething as in -i flag. It merges packets into correct stream and look if PE file is there. If there is PE file, it saves PE file into local memory. 

** If both -i and -r flags are used, -i flag is ignored.
** If program runs with -r (reading pcap) mode, it ignores all the expression.
** If none of -i and -r flags are used, program prints error message and exit.
** If -r flag is used and there is no traceFile argument, program prints error message and exit.
** If BPF filter is not well formatted, the program prints error message and exit
** If there is syntax error in bpf filter, the sniff function won't return, but print(tcpdump: syntax error in filter expression: syntax error) YOU HAVE TO EXIT PROGRAM MANUALLY.

					
****					
VERY IMPORTANT NOTES ABOUT USING -i FLAG : If you are using -i flag, big files not be downloaded fully. Please try with 3000 packets for reducing time purpose. 30,000 packets are still enough to sniff packet smaller than 1 megabytes. If scapy sniff function doesn't capture the whole PE file stream, PE file won't be runnable on any operating systems. So be sure that scapy captures whole stream of PE file. 

Trial Runs:
Sample Input 1 : 
./execarver.py -r pc2.pcap  ##(pc2.pcap file has 2 PE file with 1.6MB and 4.2MB each)
Sample Output 1 : 
READING PCAP FILE...
MERGING PACKETS INTO SESSIONS...
CONCANATING PAYLOAD IN EACH SESSION INTO ONE STREAM...
EXTRACTING PE FILE OUT OF STREAM...
FILE1.exe with 1626112 byte(s) is created
FILE2.exe with 4239360 byte(s) is created

Sample Input 2 : 
./execarver.py -i -r ##(-r has priority to -i flag but there is no trace file.. Program will print error and exit)
Sample Output 2:
READING PCAP FILE...
WE NEED TRACE FILE

Sample Input 3:
./execarver.py  ##(at least on flag should be set as command line argument)
Sample Output 3:
TOO FEW ARGUMENTS

Sample Input 4:
./execarver.py -i eth0 (Sniff packet with interface = eth0)
Sample Output 4:
SNIFFING PACKETS.....
INTERFACE : eth0
MERGING PACKETS INTO SESSIONS...
CONCANATING PAYLOAD IN EACH SESSION INTO ONE STREAM...
EXTRACTING PE FILE OUT OF STREAM...
FILE1.exe with 1032192 byte(s) is created

Sample Input 5:
./execarver.py -i eth0 "tcp" (Sniff packet with interface = eth0 and filter = tcp)
Sample Output 5:
SNIFFING PACKETS.....
BPF FILTERS : tcp INTERFACE : eth0
MERGING PACKETS INTO SESSIONS...
CONCANATING PAYLOAD IN EACH SESSION INTO ONE STREAM...
EXTRACTING PE FILE OUT OF STREAM...
FILE1.exe with 1032192 bytes(s) created

Sample Input 6:
./execarver.py -i eth0 -r pc2.pcap "eijfiew" (if both flags are specified, -r flag has priority)
Sample Output 6:
READING PCAP FILE...
MERGING PACKETS INTO SESSIONS...
CANCANATING PAYLOAD IN EACH SESSION INTO ONE STREAM...
EXTRACTING PE FILE OUT OF STREAM....
FILE1.exe with 1626112 byte(s) is created
FILE2.exe with 4239360 byte(s) is created










