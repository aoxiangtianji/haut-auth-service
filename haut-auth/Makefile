include $(TOPDIR)/rules.mk

PKG_NAME:=haut-auth
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

# Build the in-tree Cargo project. Sources (Cargo.toml, Cargo.lock, src/) live
# alongside this Makefile and are copied into the build dir before compiling.
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/haut-auth
  SECTION:=net
  CATEGORY:=Network
  TITLE:=HAUT Campus Network Auth Service
  URL:=https://github.com/
  DEPENDS:=$(RUST_ARCH_DEPENDS)
endef

define Package/haut-auth/description
  Srun campus-network auto-authentication daemon for Henan University of
  Technology, rewritten in Rust for a small memory footprint. No Python or
  TLS stack required (the portal is plaintext HTTP).
endef

# Copy the in-tree crate into the build directory.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./Cargo.toml ./Cargo.lock ./src $(PKG_BUILD_DIR)/
endef

define Package/haut-auth/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/haut-auth $(1)/usr/bin/haut-auth
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./etc/config/haut-auth $(1)/etc/config/haut-auth
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./etc/init.d/haut-auth $(1)/etc/init.d/haut-auth
endef

$(eval $(call RustBinPackage,haut-auth))
$(eval $(call BuildPackage,haut-auth))
