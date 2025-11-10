#
# Copyright (C) 2015 CaryStudio
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/carystudio_flags.mk

PKG_NAME:=libcommon
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/libcommon/Default
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  SUBMENU:=libs
  TITLE:=lib cs common module
endef	

define Package/libcommon
	$(call Package/libcommon/Default)
	MENU:=1
  TITLE:= cs common library
  DEPENDS:=+libpthread +libcjson +libuci +zlib +libblobmsg-json +libubus +libubox +libopenssl +libkvcutil +PACKAGE_ssl-proxy:libscskf
endef

define Package/libcommon/config
	config CS_COMMON_BASE64
		bool "support base64"
		depends on PACKAGE_libcommon
		default n
		help
		  Support base64 in cscommon

	config CS_COMMON_AES
		bool "support aes"
		depends on PACKAGE_libcommon
		default n
		help
		  Support AES in cscommon

	config CS_COMMON_SSL
		bool "support ssl encode and decode"
		depends on PACKAGE_libcommon
		default n
		help
		  Support SSL in cscommon

endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libcscommon.so $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/*.h $(1)/usr/include
endef


define Package/libcommon/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libcscommon.so $(1)/usr/lib/
endef

	
$(eval $(call BuildPackage,libcommon))
