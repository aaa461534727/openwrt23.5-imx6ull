#
# Copyright (C) 2015 CaryStudio
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=rid_transmitter
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk

define Package/rid_transmitter
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= remote id transmitter
  DEPENDS:=+libpthread +libcjson
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/rid_transmitter/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rid_transmitter $(1)/usr/sbin/rid_transmitter

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/rid_transmitter.init $(1)/etc/init.d/rid_transmitter
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/etc/config/rid_transmitter $(1)/etc/config/rid_transmitter
endef

$(eval $(call BuildPackage,rid_transmitter))
