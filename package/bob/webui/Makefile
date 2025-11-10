include $(TOPDIR)/rules.mk

PKG_NAME:=webui
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

NPM_BIN=$(if $(shell which cnpm),cnpm,npm)
include $(INCLUDE_DIR)/package.mk

define Package/webui
  SECTION:=bob Properties
  CATEGORY:=bob Properties
  TITLE:= webui for ui
  DEPENDS:=+libpthread +libnl-core +libnl-genl +libnl-route
endef

define Package/webui/config
	config KL_WEBUI_DEBUG
		bool "support webui debug"
		depends on PACKAGE_webui
		default n
		help
		  not compressing web UI code with debug message		
	choice
	    prompt "web ui style"
		config KL_UI_ROUTER
			bool "router web ui"
			depends on PACKAGE_webui
			default n
			help
			  router web ui
		config KL_UI_REPEATER
			bool "repeater web ui"
			depends on PACKAGE_webui
			default n
			help
			  repeater web ui
		config KL_UI_AP
			bool "ap web ui"
			depends on PACKAGE_webui
			default n
			help
			  ap web ui
		config KL_OPNSENSE_UI
			bool "4G/5G modem web ui"
			depends on PACKAGE_webui
			default n
			help
			  4G/5G modem web ui
		config KL_OPNSENSE_MIFI
			bool "mifi web ui"
			depends on PACKAGE_webui
			default n
			help
			  mifi web ui
		config KL_OPNSENSE_DTU
			bool "dtu web ui"
			depends on PACKAGE_webui
			help
			  DTU web ui
	endchoice
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	cd $(PKG_BUILD_DIR); \
		rm -rf node_modules/ package-lock.json; \
		$(NPM_BIN) install; \
		$(NPM_BIN) run run
endef

define Package/webui/install
	$(INSTALL_DIR) $(1)/web
	$(CP) $(PKG_BUILD_DIR)/dist/* $(1)/web/
ifeq ($(CONFIG_KL_OPNSENSE_MIFI),y)
	$(RM) $(1)/web/nat/*
	$(RM) $(1)/web/data/*
	$(RM) $(1)/web/firewall/*
	$(RM) $(1)/web/language/uk.json; \
	$(RM) $(1)/web/language/ct.json; \
	$(RM) $(1)/web/language/ru.json; \
	$(RM) $(1)/web/language/vn.json; \
	$(RM) $(1)/web/wan_ie.html; \
	$(RM) $(1)/web/login_ie.html;
endif
endef

$(eval $(call BuildPackage,webui))
