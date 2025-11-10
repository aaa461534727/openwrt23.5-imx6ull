TARGETS = uart uart_loopback

CFLAGS  += -Werror -fno-strict-aliasing -w
LDFLAGS += -L. -lpthread -lm -ldl -lrt #-lcjson 

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -o $@ $^
		
uart: uart.o 
	$(CC) $(CFLAGS) -s -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

uart_loopback: uart_loopback.o 
	$(CC) $(CFLAGS) -s -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

clean:
	rm -f  *.o $(TARGETS) *.d


