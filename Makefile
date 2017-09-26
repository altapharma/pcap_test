all : pcap_test

pcap_test: main.o
	gcc -o pcap_test main.o -lpcap

main.o: sub26_hw1.c my_pcap.h
	gcc -c -o main.o sub26_hw1.c

clean:
	rm -f pcap_test
	rm -f *.o

