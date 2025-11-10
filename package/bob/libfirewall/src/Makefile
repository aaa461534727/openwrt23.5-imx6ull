
TARGETS = libfirewall.so libfirewall.a cs_firewall
OBJS = firewall.o

CFLAGS  += -Werror -fno-strict-aliasing
LDFLAGS += -L. -lpthread -lm -lcscommon

all: $(TARGETS)

%.o : %.c
	echo "CONFIG_IPV6="$(CFLAGS)
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -fpic -o $@ $^

libfirewall.so: $(OBJS)
	$(CC) -shared -lc -o  $@ $^ $(LDFLAGS)

libfirewall.a: $(OBJS)
	$(AR) -r libfirewall.a $(OBJS)
	ranlib libfirewall.a

cs_firewall: firewall_main.o libfirewall.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o $(TARGETS) *.d 