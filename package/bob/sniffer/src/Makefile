TARGETS = sniffer 

CFLAGS  += -Werror -fno-strict-aliasing -w
LDFLAGS += -L. -lpthread -lm -ldl -lrt #-lcjson 

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -o $@ $^
		
sniffer: sniffer.o 
	$(CC) $(CFLAGS) -s -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

clean:
	rm -f  *.o $(TARGETS) *.d


