#
# Copyright (C) 2015 CaryStudio
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=libfirewall
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
#PKG_KCONFIG:=
#PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/flags.mk

define Package/libfirewall
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  SUBMENU:=libs
  TITLE:= libfirewall
  DEPENDS:=+libpthread +libcommon
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libfirewall.so $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libfirewall.a $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/*.h $(1)/usr/include
endef


define Package/libfirewall/install
	#$(INSTALL_DIR) $(1)/usr/lib/
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/libfirewall.so $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cs_firewall $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,libfirewall))
