# OpenWrt package for the partizan client (OpenWrt 24.10 SDK, e.g. mediatek/filogic).
#
# Two ways to build, chosen by PARTIZAN_BINARY:
#   - empty: compile this checkout with the SDK's Rust (packages feed, rust-package.mk);
#     the workspace needs Rust 1.99, so this works once the feed ships it;
#   - path to a binary built with
#       cargo zigbuild --profile release-client -p client-openwrt --target aarch64-unknown-linux-musl
#     packaged as is (the fallback from the spec).
#
#   make package/partizan/compile PARTIZAN_BINARY=/path/to/partizan

include $(TOPDIR)/rules.mk

PKG_NAME:=partizan
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PARTIZAN_SRC ?= $(CURDIR)/../../..
PARTIZAN_BINARY ?=

ifeq ($(PARTIZAN_BINARY),)
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1
endif

include $(INCLUDE_DIR)/package.mk
ifeq ($(PARTIZAN_BINARY),)
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk
endif

define Package/partizan
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=partizan VPN client (SOCKS5 over QUIC/TLS)
  DEPENDS:=$(if $(PARTIZAN_BINARY),,$(RUST_ARCH_DEPENDS))
endef

define Package/partizan/description
  Client for a partizan server. Keeps one session over QUIC (TCP+TLS as a
  fallback) and exposes it as a local SOCKS5 proxy for podkop.
endef

# Survives sysupgrade; holds the connection URI with the device token.
define Package/partizan/conffiles
/etc/config/partizan
endef

ifeq ($(PARTIZAN_BINARY),)
define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) $(PARTIZAN_SRC)/Cargo.toml $(PARTIZAN_SRC)/Cargo.lock $(PARTIZAN_SRC)/crates $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call Build/Compile/Cargo,crates/client-openwrt)
endef
else
define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/bin
	$(INSTALL_BIN) $(PARTIZAN_BINARY) $(PKG_INSTALL_DIR)/bin/partizan
endef
endif

define Package/partizan/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/partizan $(1)/usr/bin/partizan
	$(INSTALL_BIN) ./files/partizan.init $(1)/etc/init.d/partizan
	# INSTALL_CONF installs with mode 0600: the config holds the token.
	$(INSTALL_CONF) ./files/partizan.config $(1)/etc/config/partizan
endef

$(eval $(call BuildPackage,partizan))
