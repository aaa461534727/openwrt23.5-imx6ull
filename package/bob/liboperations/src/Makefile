TARGETS = liboperations.so
OBJS    = operations_network.o operations_wireless.o operations_system.o

CFLAGS  += -Wall -fno-strict-aliasing
LDFLAGS += -L. -lpthread -lm -lz -lcscommon

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -fpic -o $@ $^
	
$(TARGETS): $(OBJS)
	$(CC) -shared -lc -o  $@ $^ $(LDFLAGS)
	
clean:
	rm -f *.o $(TARGETS) *.d 