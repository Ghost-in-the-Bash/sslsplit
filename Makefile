# This Makefile is for compiling SSLsplit as a package for OpenWRT 18.06.0.
# It based off of the Makefile in https://github.com/adde88/sslsplit-openwrt

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME := sslsplit
PKG_VERSION := 0.5.3
PKG_RELEASE := 1
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
PKG_SOURCE_PROTO := git
PKG_SOURCE_URL := git://github.com/ghost-in-the-bash/sslsplit-netgrok

define Package/sslsplit
	SECTION := net
	CATEGORY := Network
	TITLE := sslsplit -- transparent SSL/TLS interception
	DEPENDS := \
		+libevent2 \
		+libevent2-openssl +libopenssl +openssl \
		+libevent2-pthreads +libpthread \
		+musl-fts
endef

define Package/sslsplit/description
	SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted
	network connections. It is intended to be useful for network forensics,
	application security analysis and penetration testing.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -rf ./src/ $(PKG_BUILD_DIR)/
endef

CONFIGURE_PATH := src/
MAKE_PATH := src/
TARGET_CFLAGS += $(TARGET_CPPFLAGS)

define Package/sslsplit/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/sslsplit $(1)/usr/bin/
endef

$(eval $(call BuildPackage, sslsplit, +musl-fts))
