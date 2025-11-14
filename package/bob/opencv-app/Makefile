# package/utils/opencv-simple-test/Makefile
include $(TOPDIR)/rules.mk

PKG_NAME:=opencv-app
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define Package/opencv-app
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:=Simple OpenCV Test
  DEPENDS:= +opencv +libopencv-core +libopencv-imgproc +libopencv-imgcodecs
endef

define Package/opencv-app/description
  Very simple OpenCV test application
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CXX="$(TARGET_CXX)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		CXXFLAGS="$(TARGET_CXXFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		STAGING_DIR="$(STAGING_DIR)"
endef

define Package/opencv-app/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/opencv-simple-test $(1)/usr/bin/
endef

$(eval $(call BuildPackage,opencv-app))
