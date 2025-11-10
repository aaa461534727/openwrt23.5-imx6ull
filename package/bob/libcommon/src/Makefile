include $(TOPDIR)/.config

TARGETS = libcscommon.so

CFLAGS  += -Wall -fno-strict-aliasing
LDFLAGS += -L. -lpthread -luci -lm -lz -lubus -lblobmsg_json -lubox -lssl -lcrypto -ldatconf -lkvcutil 
LDFLAGS += -L../libcjson -lcjson  
ifeq ($(CONFIG_PACKAGE_ssl-proxy),y)
LDFLAGS += -lSGSKF -lscspi -lsslvpn
endif

OBJS := cs_common.o cs_common2.o cs_uci.o cs_uci_fun.o cs_file.o cs_firmware.o cs_led.o cs_param_check.o cs_ubus_cli.o md5.o cs_board.o

ifeq ($(CONFIG_CS_COMMON_BASE64), y)
OBJS += cs_base64.o
endif

ifeq ($(CONFIG_CS_COMMON_AES), y)
OBJS += cs_aes.o
endif

ifeq ($(CONFIG_CS_COMMON_SSL), y)
OBJS += cs_ssl.o
endif

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -fpic -o $@ $^
	
$(TARGETS): $(OBJS)
	$(CC) -shared -lc -o  $@ $^ $(LDFLAGS)
	
clean:
	rm -f *.o $(TARGETS) *.d 
