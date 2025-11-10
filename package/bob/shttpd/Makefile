include $(TOPDIR)/rules.mk

PKG_NAME:=shttpd
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/flags.mk

define Package/$(PKG_NAME)
	SECTION:=bob
	CATEGORY:=bob Properties
	TITLE:=shttpd for web management
	DEPENDS:=+libpthread +libuci +libjson-c +libcjson +libcommon +liboperations +libopenssl  +PACKAGE_ssl-proxy:libscskf +libcsconfig
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
#	$(CP) ./files $(PKG_BUILD_DIR)/ -r
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	@echo 'STRIP='$(STRIP)
#	@$(STRIP) $(PKG_BUILD_DIR)/$(PKG_NAME)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/shttpd.init $(1)/etc/init.d/shttpd
	$(INSTALL_DIR) $(1)/etc/ssl/certs
	$(INSTALL_DATA) ./files/server.pem $(1)/etc/ssl/certs/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

