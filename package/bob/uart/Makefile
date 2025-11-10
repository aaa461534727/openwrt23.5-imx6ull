include $(TOPDIR)/rules.mk

PKG_NAME:=uart
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk

define Package/uart
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= uart client
  DEPENDS:=+libpthread +libnl-core +libnl-genl +libnl-route
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/uart/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uart $(1)/usr/sbin/uart
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/uart.init $(1)/etc/init.d/uart
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/etc/config/uart $(1)/etc/config/uart
endef

$(eval $(call BuildPackage,uart))
