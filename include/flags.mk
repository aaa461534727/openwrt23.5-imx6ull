#=================================================================
# cs_flags.mk:
# - included by package.mk / kernel-defaults.mk
#
# 1. This file defines product specific C compile flags based on 
# product selection specified in <PRODUCT>.conf (CONFIG_AWRT_PRODUCT_XXX). 
# 
# 2. The added compile flags are visible to kernel/kernel modules/user programs
# compilation. 
# - For kernel: passed as CFLAGS_KERNEL (kernel-defaults.mk)
# - For kernel modules / user program: passed as EXTRA_FLAGS 
# 
#=================================================================

  #TARGET_CFLAGS += -DWIFI_SUPPORT
  #TARGET_CFLAGS += -DBOARD_HAS_5G_RADIO
  #TARGET_CFLAGS += -DBOARD_HAS_11AX
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib -lpthread -lcrypto -lssl -lcscommon
ifeq ($(CONFIG_KL_CUSTOM),y)
ifneq ($(wildcard $(TOPDIR)/Release/def_config/$(subst ",,$(CONFIG_KL_CSID))/board.mk),)
include $(TOPDIR)/Release/def_config/$(subst ",,$(CONFIG_KL_CSID))/board.mk
endif
	TARGET_CFLAGS += -DCONFIG_KL_CUSTOM $(BOARD_CFLAGS)
endif

ifeq ($(CONFIG_MTK_CHIP_MT7986),y)
	TARGET_CFLAGS += -DCONFIG_MTK_CHIP_MT7986
endif

ifeq ($(CONFIG_PACKAGE_libcslog),y)
	TARGET_CFLAGS += -DSUPPORT_CSLOG
endif

ifeq ($(CONFIG_ETH_PORT_MAP),y)
	TARGET_CFLAGS += -DETH_PORT_MAP
	TARGET_CFLAGS += -DETH_PORT_WAN=$(CONFIG_ETH_PORT_WAN)
	TARGET_CFLAGS += -DETH_PORT_LAN1=$(CONFIG_ETH_PORT_LAN1)
	TARGET_CFLAGS += -DETH_PORT_LAN2=$(CONFIG_ETH_PORT_LAN2)
	TARGET_CFLAGS += -DETH_PORT_LAN3=$(CONFIG_ETH_PORT_LAN3)
	TARGET_CFLAGS += -DETH_PORT_LAN4=$(CONFIG_ETH_PORT_LAN4)
	TARGET_CFLAGS += -DETH_PORT_LAN5=$(CONFIG_ETH_PORT_LAN5)
	TARGET_CFLAGS += -DETH_PORT_LAYOUT=\\\"$(CONFIG_ETH_PORT_LAYOUT)\\\"
endif

ifeq ($(CONFIG_PACKAGE_swconfig), y)
	TARGET_CFLAGS += -DSUPPORT_SWITCH_SWCONFIG
endif

ifeq ($(CONFIG_CS_COMMON_SSL),y)
	TARGET_CFLAGS += -DCONFIG_CS_COMMON_SSL
endif

ifeq ($(CONFIG_PACKAGE_modem_mcm),y)
	TARGET_CFLAGS += -DUSE_MCM_USB_MODEM
endif

ifeq ($(CONFIG_IPV6),y)
	TARGET_CFLAGS += -DUSE_IPV6
endif

ifeq ($(CONFIG_PACKAGE_cloudupdate_check),y)
	TARGET_CFLAGS += -DCONFIG_CLOUDUPDATE_SUPPORT
endif

ifeq ($(CONFIG_PACKAGE_crpc),y)
  TARGET_CFLAGS += -DCONFIG_CRPC_SUPPORT
endif

ifeq ($(CONFIG_PACKAGE_netcwmp),y)
  TARGET_CFLAGS += -DCONFIG_TR069_SUPPORT
endif

ifeq ($(CONFIG_PACKAGE_netcwmp_dtu),y)
  TARGET_CFLAGS += -DCONFIG_TR069_SUPPORT
endif

ifeq ($(CONFIG_PACKAGE_snmpd),y)
  TARGET_CFLAGS += -DCONFIG_SNMP_SUPPORT
endif

ifeq ($(CONFIG_PACKAGE_ddns),y)
  TARGET_CFLAGS += -DCONFIG_DDNS_SUPPORT
endif

ifeq ($(CONFIG_PACKAGE_cste_thinap),y)
  TARGET_CFLAGS += -DCONFIG_THINAP_SUPPORT
endif

ifeq ($(CONFIG_MULTI_GUEST_SSID_SUPPORT),y)
  TARGET_CFLAGS += -DCONFIG_MULTI_GUEST_SSID_SUPPORT
endif

ifeq ($(CONFIG_USB_STORAGE_SUPPORT),y)
  TARGET_CFLAGS += -DCONFIG_USB_STORAGE_SUPPORT
endif

ifeq ($(CONFIG_AUTO_SERIALNUMBER),y)
  TARGET_CFLAGS += -DCONFIG_AUTO_SERIALNUMBER
endif

ifeq ($(CONFIG_TIME_ZONE_CUSTOM),y)
  TARGET_CFLAGS += -DCONFIG_TIME_ZONE_CUSTOM
endif

ifeq ($(CONFIG_KL_OPNSENSE_UI),y)
  TARGET_CFLAGS += -DCONFIG_KL_OPNSENSE_UI
endif

ifeq ($(CONFIG_KL_OPNSENSE_DTU), y)
  TARGET_CFLAGS += -DCONFIG_KL_OPNSENSE_DTU
endif

ifeq ($(CONFIG_PACKAGE_dtu),y)
  TARGET_CFLAGS += -DCONFIG_DTU_SUPPORT
endif

ifeq ($(CONFIG_PACKAGE_iot-mqtt),y)
  TARGET_CFLAGS += -DAPP_IOT_MQTT
endif

ifeq ($(CONFIG_PACKAGE_ailing-mqtt),y)
  TARGET_CFLAGS += -DAPP_IOT_MQTT
endif

ifeq ($(CONFIG_PACKAGE_mtkhnat_util),y)
  TARGET_CFLAGS += -DCONFIG_USER_FAST_NAT
endif

ifeq ($(CONFIG_PACKAGE_quagga), y)
  TARGET_CFLAGS += -DAPP_QUAGGA
endif

