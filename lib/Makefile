CPP = g++
LIB = libxpkt.a
OBJS = agent.o arp_spoof.o arp.o ether.o filter.o utils.o xpkt.o ip.o

$(LIB): $(OBJS)
	$(AR) rv $@ $(OBJS)

%.o: %.cpp
	$(CPP) -c -I../include $< -o $@

clean:
	rm -f $(OBJS) $(LIB)