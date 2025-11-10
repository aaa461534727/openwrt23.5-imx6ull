include $(TOPDIR)/rules.mk

PKG_NAME:=mqtt
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

include $(INCLUDE_DIR)/package.mk

define Package/mqtt
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= mqtt client
  DEPENDS:=+libcares +libopenssl +libmodbus +libmosquitto-ssl +libnl-core +libnl-genl
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/mqtt/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mqtt $(1)/usr/sbin/mqtt
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/mqtt.init $(1)/etc/init.d/mqtt
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/etc/config/mqtt $(1)/etc/config/mqtt
endef

$(eval $(call BuildPackage,mqtt))
