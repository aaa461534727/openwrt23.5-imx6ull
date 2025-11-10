TARGETS = custom_app

CFLAGS  += -Werror -fno-strict-aliasing -w
LDFLAGS += -L. -lpthread -lm -ldl -lrt -lcjson -lcscommon

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -o $@ $^
		
custom_app: custom_app.o 
	$(CC) $(CFLAGS) -s -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

clean:
	rm -f  *.o $(TARGETS) *.d


