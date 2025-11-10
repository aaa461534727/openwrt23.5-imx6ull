
TARGETS = libcsconfig.so
OBJS = cs_config.o

CFLAGS  += -Werror -fno-strict-aliasing
LDFLAGS += -L. -lconfig

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -fpic -o $@ $^

libcsconfig.so: $(OBJS)
	$(CC) -shared -lc -o  $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(TARGETS) *.d 
