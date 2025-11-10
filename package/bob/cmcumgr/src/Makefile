# =====================
# 项目配置选项
# =====================
ENABLE_SERIAL ?= 1       # 串行传输支持 (1=启用, 0=禁用)
ENABLE_CLI ?= 1          # 命令行工具支持 (1=启用, 0=禁用)
VERSION := 0.2.1         # 项目版本

# =====================
# 编译器配置
# =====================
CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar
CFLAGS := -std=gnu99 -Wendif-labels -Werror=format=2 \
          -Werror=implicit-function-declaration \
          -Werror=undef -Werror=unused-function \
          -Wfloat-equal -Winit-self -Wmissing-include-dirs -Wnested-externs \
          -Wold-style-definition -Wpointer-arith -Wredundant-decls -Wshadow \
          -Wstrict-aliasing=2 -Wstrict-prototypes -Wwrite-strings \
          -include config.h

CFLAGS += -L$(STAGING_DIR)/lib

# =====================
# 编译器特定标志
# =====================
ifeq ($(CC),gcc)
CFLAGS += -Werror=shift-overflow=2 -Wimplicit-fallthrough=5 -Wsuggest-attribute=noreturn -Wlogical-op
else ifeq ($(CC),clang)
CFLAGS += -Werror=shift-overflow -Wimplicit-fallthrough -Wmissing-noreturn
endif

# =====================
# 安装路径配置
# =====================
prefix ?= /usr
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
libdir ?= $(exec_prefix)/lib
includedir ?= $(prefix)/include

# =====================
# 源文件定义
# =====================
# 工具库
UTILS_SRCS := src/mcumgr-client/lib/base64.c \
              src/mcumgr-client/lib/crc16.c \
              src/mcumgr-client/lib/hexlify.c \
              src/mcumgr-client/lib/utils.c
UTILS_OBJS := $(UTILS_SRCS:.c=.o)

# CBOR 库
CBOR_SRCS := src/mcumgr-client/mgmt/tinycbor/src/cborparser.c \
             src/mcumgr-client/mgmt/tinycbor/src/cborencoder.c
CBOR_OBJS := $(CBOR_SRCS:.c=.o)
CBOR_CFLAGS := -Wno-implicit-fallthrough  # 禁用特定警告

# 主库
MCUMGR_SRCS := src/mcumgr-client/mgmt/mgmt_common.c \
               src/mcumgr-client/mgmt/mgmt_utils.c \
               src/mcumgr-client/mgmt/mgmt_hdr.c \
               src/mcumgr-client/mgmt/mgmt_img.c \
               src/mcumgr-client/mgmt/mgmt_os.c \
               src/mcumgr-client/image/mcuboot_img.c \
               src/mcumgr-client/image/file_reader.c \
               src/mcumgr-client/image/file_reader_unix.c \
               src/mcumgr-client/commands/cmd_common.c \
               src/mcumgr-client/commands/cmd_os.c \
               src/mcumgr-client/commands/cmd_img.c

# 条件包含串行传输
# ifeq ($(ENABLE_SERIAL),1)
MCUMGR_SRCS += src/mcumgr-client/transport/serial/smp_serial.c \
               src/mcumgr-client/transport/serial/serial_port_unix.c
# endif
MCUMGR_OBJS := $(MCUMGR_SRCS:.c=.o)
LIB_NAME := libcmcumgr-client.a

# 命令行工具
CLI_SRCS := src/cli/main.c \
            src/cli/cli_opts.c
            
# ifeq ($(ENABLE_SERIAL),1)
CLI_SRCS += src/mcumgr-client/transport/serial/serial_opts.c
# endif
CLI_OBJS := $(CLI_SRCS:.c=.o)
CLI_TARGET := cmcumgr

# =====================
# 源文件定义 (添加部分)
# =====================
# ble_ota 应用
BLE_OTA_SRC := ble_ota.c
BLE_OTA_OBJ := $(BLE_OTA_SRC:.c=.o)
BLE_OTA_TARGET := ble_ota

# =====================
# 包含路径
# =====================
INCLUDES := -I. \
            -Isrc/mcumgr-client/lib/include \
            -Isrc/mcumgr-client/include/mcumgr-client \
            -Isrc/mcumgr-client/transport \
            -Isrc/mcumgr-client/mgmt/tinycbor/src\
            -Isrc/mcumgr-client/include

# =====================
# 构建目标
# =====================
.PHONY: all clean install

all: config.h $(LIB_NAME) $(CLI_TARGET) $(BLE_OTA_TARGET)

# 生成配置文件
config.h:
	@echo "#define VERSION \"$(VERSION)\"" > $@

# 构建工具库
src/mcumgr-client/lib/%.o: src/mcumgr-client/lib/%.c config.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 构建CBOR库 (使用特殊警告标志)
src/mcumgr-client/mgmt/tinycbor/src/%.o: src/mcumgr-client/mgmt/tinycbor/src/%.c config.h
	$(CC) $(CFLAGS) $(CBOR_CFLAGS) $(INCLUDES) -c $< -o $@

# 构建主库对象
src/mcumgr-client/%.o: src/mcumgr-client/%.c config.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 构建CLI对象
src/cli/%.o: src/cli/%.c config.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 构建主静态库
$(LIB_NAME): $(MCUMGR_OBJS) $(UTILS_OBJS) $(CBOR_OBJS)
	$(AR) rcs $@ $^

# 构建命令行工具
$(CLI_TARGET): $(CLI_OBJS) $(LIB_NAME)
	$(CC) -o $@ $^ $(CFLAGS)

# =====================
# 构建规则 (添加部分)
# =====================
# 构建 ble_ota 对象
$(BLE_OTA_OBJ): $(BLE_OTA_SRC) config.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ -fno-builtin -nostartfiles

# 构建 ble_ota 应用
$(BLE_OTA_TARGET): $(BLE_OTA_OBJ) $(LIB_NAME)
	$(CC) -static $(CFLAGS) -s -o $@ $^ $(LDFLAGS) -nostdlib -fno-builtin -Wl,--gc-sections
	$(STRIP) $@  

# =====================
# 清理
# =====================
clean:
	rm -f $(UTILS_OBJS) $(CBOR_OBJS) $(MCUMGR_OBJS) $(CLI_OBJS) \
	      $(LIB_NAME) $(CLI_TARGET) $(BLE_OTA_OBJ) $(BLE_OTA_TARGET) config.h

# =====================
# 安装
# =====================

romfs:
	$(ROMFSINST) cmcumgr /usr/sbin/cmcumgr
	$(ROMFSINST) $(BLE_OTA_TARGET) /usr/sbin/$(BLE_OTA_TARGET)