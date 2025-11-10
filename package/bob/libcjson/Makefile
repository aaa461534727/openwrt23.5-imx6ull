
include $(TOPDIR)/rules.mk

PKG_NAME:=libcjson
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
#PKG_KCONFIG:=
#PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk


define Package/libcjson
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  SUBMENU:=libs
  TITLE:= cjson library

endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libcjson.{a,so*} $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/cJSON.h $(1)/usr/include
endef


define Package/libcjson/install
	$(INSTALL_DIR) $(1)/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libcjson.{a,so*} $(1)/lib/
endef

	
$(eval $(call BuildPackage,libcjson))




