OBJS	= estpd.o session.o cipher.o inet.o registry.o

CC 		= gcc
CFLAGS	= -g --std=gnu99 -Wall -Werror
LD 		= gcc
LDFLAGS = -lssl -lcrypto -lpthread

estpd: $(OBJS)
	$(LD) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(OBJS)
