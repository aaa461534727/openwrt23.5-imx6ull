include $(TOPDIR)/rules.mk

PKG_NAME:=web
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/web
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= web server
  DEPENDS:=+libopenssl +libpthread +libuci
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/shttpd-1.42/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
  $(MAKE) -C $(PKG_BUILD_DIR)/examples \
    CC="$(TARGET_CC)" \
    CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -I$(PKG_BUILD_DIR)/src" \
    LDFLAGS="$(TARGET_LDFLAGS) -L$(PKG_BUILD_DIR)/src" \
    LIBS="-lssl -lcrypto -lpthread -ldl -luci -lshttpd" \
    unix
  
  $(MAKE) -C $(PKG_BUILD_DIR)/src\
    CC="$(TARGET_CC)" \
    STRIP="$(STRIP)" \
    CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include" \
    LDFLAGS="$(TARGET_LDFLAGS)" \
    LIBS="-lssl -lcrypto -lpthread -ldl -luci" \
    unix

endef

define Package/web/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/shttpd $(1)/usr/sbin/shttpd
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/examples/example $(1)/usr/sbin/example  
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/init.d/shttpd.init $(1)/etc/init.d/shttpd
  
endef

$(eval $(call BuildPackage,web))
