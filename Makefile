all: remove build

remove:
	rm tcp.txt

build:
	gcc main.c sniff.c lfunc.c -o sniffer -lpcap 
