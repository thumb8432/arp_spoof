all: arp_spoof
arp_spoof: main.cpp MyARP.o
	g++ -o arp_spoof main.cpp MyARP.o -lpcap -lglog -lpthread -W -Wall
MyARP.o: MyARP.h MyARP.cpp
	g++ -o MyARP.o -c MyARP.cpp -lpcap -lglog -W -Wall
clean:
	rm MyARP.o
	rm arp_spoof