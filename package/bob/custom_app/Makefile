include $(TOPDIR)/rules.mk

PKG_NAME:=custom_app
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk

define Package/custom_app
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= test app
  DEPENDS:=+libpthread +libnl-core +libnl-genl +libnl-route +libcjson +libcommon
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/custom_app/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/custom_app $(1)/usr/sbin/custom_app
endef

$(eval $(call BuildPackage,custom_app))
