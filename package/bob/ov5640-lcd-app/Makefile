include $(TOPDIR)/rules.mk

PKG_NAME:=ov5640-lcd-app
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk

define Package/ov5640-lcd-app
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= ov5640 lcd test app
  DEPENDS:=+libpthread +libnl-core +libnl-genl  +libcjson +libcommon
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/ov5640-lcd-app/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lcd_test $(1)/usr/sbin/lcd_test
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lcd_info $(1)/usr/sbin/lcd_info
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/v4l2_camera $(1)/usr/sbin/v4l2_camera
	
endef

$(eval $(call BuildPackage,ov5640-lcd-app))
