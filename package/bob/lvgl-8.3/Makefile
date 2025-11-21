include $(TOPDIR)/rules.mk

PKG_NAME:=lvgl-8.3
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk

define Package/lvgl-8.3
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= lvgl graphics library test application
  DEPENDS:=+libpthread +libnl-core +libnl-genl +libnl-route +libcjson +libcommon
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/lvgl-8.3/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lvgl_test $(1)/usr/sbin/lvgl_test
endef

$(eval $(call BuildPackage,lvgl-8.3))
