
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/version.mk

PKG_NAME:=cs-base-files
PKG_RELEASE:=1
PKG_BUILD_DEPENDS:=base-files
PKG_FILE_DEPENDS:=
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/cs-base-files
  	SECTION:=bob Properties
  	CATEGORY:=bob Properties
	SUBMENU:=cs-base-files
  	TITLE:=Base Properties
  	VERSION:=$(PKG_RELEASE)-$(REVISION)
endef

define Package/cs-base-files/config
	source "$(SOURCE)/cs-config.in"
endef

define Package/cs-base-files/description
 	packages for carystudio.
endef

define Package/cs-base-files/config
	source "$(SOURCE)/cs-config.in"
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile/Default
endef

Build/Compile = $(Build/Compile/Default)

define Package/cs-base-files/install
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,cs-base-files))
