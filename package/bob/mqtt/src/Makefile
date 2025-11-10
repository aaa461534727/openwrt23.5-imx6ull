TARGETS = mqtt 

# 定义OpenWRT的STAGING_DIR路径（根据实际路径调整）
STAGING_DIR = $(PWD)/staging_dir/target-mipsel_24kc_musl-1.1.16

# 头文件路径：优先使用SDK路径
CFLAGS += -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/usr/include/modbus
CFLAGS += -Wall -O2 -Werror -fno-strict-aliasing -w

# 链接库路径：指定SDK的库目录和库名
LDFLAGS += -L$(STAGING_DIR)/usr/lib -lmodbus
LDFLAGS += -lpthread -lm -ldl -lrt -lnl-3 -lnl-genl-3 -lcrypto -lcares -lssl -lmosquitto

all: $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -Wp,-MD,$@.d -c -o $@ $^

mqtt: mqtt.o 
	$(CC) $(CFLAGS) -s -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

clean:
	rm -f *.o $(TARGETS) *.d