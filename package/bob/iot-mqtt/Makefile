#
# Copyright (C) 2015 CaryStudio
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=iot-mqtt
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
#PKG_KCONFIG:=
#PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk
#include $(INCLUDE_DIR)/kernel.mk
#include $(INCLUDE_DIR)/carystudio_flags.mk

define Package/$(PKG_NAME)
	SECTION:=bob Properties
	CATEGORY:=bob Properties
	TITLE:= iot-mqtt
	DEPENDS:=+libpthread +libcjson +libjson-c +libuci +libcommon +libmosquitto-ssl
endef

TARGET_CFLAGS += \
	-I$(LINUX_DIR)/include \
	$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),-DCONFIG_$(c)))
	
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
#	$(CP) ./files $(PKG_BUILD_DIR)/ -r
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	@echo 'STRIP='$(STRIP)
#	@$(STRIP) $(PKG_BUILD_DIR)/$(PKG_NAME)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iotm $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/iot-mqtt.init $(1)/etc/init.d/iot-mqtt
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/iot.config $(1)/etc/config/iot
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
