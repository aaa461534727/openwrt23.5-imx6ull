TARGETS   = debug_cmd
OBJS      = debug_cmd.o 

TARGETS_1 = rid_check
OBJS_1    = rid_check.o

CFLAGS  += -Wall 
LDFLAGS += -L. -lpthread

all: $(TARGETS) $(TARGETS_1)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -o $@ $^
	
$(TARGETS): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TARGETS_1): $(OBJS_1)
	$(CC) -o $@ $^ $(LDFLAGS)
	
clean:
	rm -f *.o *.d $(TARGETS) $(TARGETS_1)



