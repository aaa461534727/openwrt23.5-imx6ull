TARGETS   = lcd_test
OBJS      = lcd_test.o

TARGETS_1 = lcd_info
OBJS_1    = lcd_info.o

TARGETS_2 = v4l2_camera
OBJS_2    = v4l2_camera.o

CFLAGS  += -Wall 
LDFLAGS += -L. -lpthread  -lcscommon

all: $(TARGETS) $(TARGETS_1) $(TARGETS_2)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -o $@ $^
	
$(TARGETS): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TARGETS_1): $(OBJS_1)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TARGETS_2): $(OBJS_2)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o *.d $(TARGETS) $(TARGETS_1) $(TARGETS_2)

