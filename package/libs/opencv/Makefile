# Copyright (C) 2024 Fusion CCTV, Inc.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=opencv
PKG_VERSION:=4.5.4
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/opencv/opencv
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_MIRROR_HASH:=67ccecf88715ef063c4205ce3767946065ede057a77eb4c2cfe30c81b6822c9e

PKG_BUILD_DIR = $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE

PKG_INSTALL:=1
CMAKE_INSTALL:=1
CMAKE_BINARY_SUBDIR:=build
PKG_BUILD_PARALLEL:=0
PKG_USE_MIPS16:=0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/opencv/Default/description
 OpenCV (Open Source Computer Vision Library) is an open source computer
 vision and machine learning software library. OpenCV was built to provide
 a common infrastructure for computer vision applications and to accelerate
 the use of machine perception in the commercial products. Being a
 BSD-licensed product, OpenCV makes it easy for businesses to utilize
 and modify the code.
endef

define Package/opencv
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=OpenCV-$(PKG_VERSION)
  URL:=https://opencv.org/
  DEPENDS:=+libatomic +librt +libtiff +libjpeg +libpng +libpthread +libstdcpp +libwebp +zlib 	#+libhighgui
endef

CMAKE_OPTIONS += \
	-DBUILD_opencv_gpu:BOOL=OFF \
	-DWITH_1394:BOOL=OFF -DBUILD_opencv_stitching:BOOL=OFF \
	-DBUILD_opencv_superres:BOOL=OFF -DBUILD_opencv_ts:BOOL=OFF \
	-DBUILD_opencv_highgui:BOOL=ON \
	-DBUILD_opencv_videostab:BOOL=OFF \
	-DWITH_FFMPEG:BOOL=OFF \
	-DWITH_GSTREAMER:BOOL=OFF \
	-DWITH_LIBV4L:BOOL=OFF \
	-DWITH_PNG:BOOL=OFF \
	-DWITH_GTK:BOOL=OFF \
	-DWITH_TIFF:BOOL=OFF \
	-DCMAKE_VERBOSE:BOOL=OFF \
	-DENABLE_PRECOMPILED_HEADERS=OFF

TARGET_LDFLAGS += -latomic


define Package/opencv/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libopencv* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,opencv))
