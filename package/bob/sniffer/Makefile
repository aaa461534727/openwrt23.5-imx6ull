include $(TOPDIR)/rules.mk

PKG_NAME:=sniffer
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk

define Package/sniffer
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= sniffer client
  DEPENDS:=+libpthread +libnl-core +libnl-genl +libnl-route
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/sniffer/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sniffer $(1)/usr/sbin/sniffer
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/sniffer.init $(1)/etc/init.d/sniffer
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/etc/config/sniffer $(1)/etc/config/sniffer
endef

$(eval $(call BuildPackage,sniffer))
