
CFLAGS += -I./ -Wall -fno-strict-aliasing
LDFLAGS += -L. -lpthread -lcjson -ljson-c -lcommon -lz -lmosquitto -lcrypto -lssl -luci

SRCS := $(wildcard ./*.c)
OBJS := $(subst .c,.o,$(SRCS))

TARGETS	 += iotm

all:$(TARGETS)

$(TARGETS): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	
%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -fpic -o $@ $^

clean:
	@rm -rf $(TARGETS) *.o *.o.d

romfs:
	$(ROMFSINST) $(TARGETS) /usr/sbin/$(TARGETS)
	
