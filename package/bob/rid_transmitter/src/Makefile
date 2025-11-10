TARGETS = rid_transmitter
OBJS    = rid_transmitter.o opendroneid.o

CFLAGS  += -Werror -fno-strict-aliasing -w
LDFLAGS += -L.  -lpthread -lcjson -lm -ldl -lrt -lcscommon

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -o $@ $^
	
$(TARGETS): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	
clean:
	rm -f  *.o $(TARGETS) *.d


