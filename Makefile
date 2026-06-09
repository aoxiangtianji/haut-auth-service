include $(TOPDIR)/rules.mk

PKG_NAME:=haut-auth
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/haut-auth
  SECTION:=net
  CATEGORY:=Network
  TITLE:=HAUT Campus Network Auth Service
  DEPENDS:=+python3-light +python3-urllib +python3-openssl +python3-codecs
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/haut-auth/install
	$(INSTALL_DIR) $(1)/usr/lib/python3/haut-auth
	$(CP) ./haut-auth/usr/lib/python3/haut-auth/*.py $(1)/usr/lib/python3/haut-auth/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./haut-auth/etc/config/haut-auth $(1)/etc/config/haut-auth
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./haut-auth/etc/init.d/haut-auth $(1)/etc/init.d/haut-auth
endef

$(eval $(call BuildPackage,haut-auth))
