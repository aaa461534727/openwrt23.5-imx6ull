include $(TOPDIR)/rules.mk

# 包名设为modbus,,这个是menuconfig显示的名字 避免与系统已有libmodbus冲突
PKG_NAME:=modbus
PKG_VERSION:=3.1.6
PKG_RELEASE:=1

# 源码路径指向你的src/libmodbus-3.1.6目录
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

# 菜单配置位置定义
define Package/$(PKG_NAME)
  SECTION:=bob Properties
  CATEGORY:=bob Properties

  TITLE:=Modbus Protocol Stack
  DEPENDS:=+libpthread
  URL:=https://libmodbus.org/
endef

define Package/$(PKG_NAME)/description
This package provides Modbus protocol stack implementation 
using libmodbus v3.1.6 source code.
endef

# 源码准备阶段
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
  # 关键路径:复制src/libmodbus-3.1.6下的所有内容
	$(CP) ./src/libmodbus-3.1.6/* $(PKG_BUILD_DIR)/
endef

# 配置阶段
define Build/Configure
	(cd $(PKG_BUILD_DIR) && \
		test -f configure || ./autogen.sh && \
		./configure \
			--host=$(GNU_TARGET_NAME) \
			--prefix=/usr \
			--disable-static \
			CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include" \
			LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib -lpthread" \
	)
endef

# 编译阶段
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		RANLIB="$(TARGET_RANLIB)"
endef

# 开发文件安装
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/modbus
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/modbus*.h $(1)/usr/include/modbus/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/.libs/libmodbus.so* $(1)/usr/lib/
endef

# 目标设备安装
define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/.libs/libmodbus.so.* $(1)/usr/lib/
	# 创建版本号软链接（关键步骤）
	$(LN) libmodbus.so.5 $(1)/usr/lib/libmodbus.so
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
