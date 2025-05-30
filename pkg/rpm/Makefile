# Build Aerospike Server RPM Distribution.

DEPTH = ../..
include $(DEPTH)/make_in/Makefile.vars

PKG = $(realpath $(DEPTH)/pkg)
SOURCE_ROOT = $(PKG)/dist
BUILD_ROOT = $(SOURCE_ROOT)/BUILD
OPT_AS = $(BUILD_ROOT)/opt/aerospike

REV = $(shell $(DEPTH)/build/version | sed 's/-/_/g')
OS = $(shell $(DEPTH)/build/os_version)

CONF_VERSION = _systemd

ifeq ($(USE_EE),1)
all:	dist-ee package clean
else
all:	dist package clean
endif

.PHONY:dist
dist:
	install -d $(BUILD_ROOT)/etc/aerospike
	install -d $(BUILD_ROOT)/etc/aerospike/sample
	install -d $(BUILD_ROOT)/usr/lib/systemd/system
	install -d $(BUILD_ROOT)/etc/systemd/system/aerospike.service.d
	install -d $(BUILD_ROOT)/usr/bin

	install -pm 755 $(BIN_DIR)/asd $(BUILD_ROOT)/usr/bin/asd
	install -pm 755 $(DEPTH)/tools/bin/asd-coldstart $(BUILD_ROOT)/usr/bin/asd-coldstart
	install -pm 755 $(DEPTH)/as/etc/irqbalance-ban.sh $(BUILD_ROOT)/etc/aerospike/irqbalance-ban.sh
	install -pm 644 $(DEPTH)/as/etc/aerospike$(CONF_VERSION).conf $(BUILD_ROOT)/etc/aerospike/aerospike.conf
	install -pm 644 $(DEPTH)/as/etc/README.sample.conf.md $(BUILD_ROOT)/etc/aerospike/sample/README.md
	install -pm 644 $(DEPTH)/as/etc/aerospike_ssd$(CONF_VERSION).conf $(BUILD_ROOT)/etc/aerospike/sample/aerospike_ssd.conf
	install -pm 644 $(DEPTH)/as/etc/aerospike_mesh$(CONF_VERSION).conf $(BUILD_ROOT)/etc/aerospike/sample/aerospike_mesh.conf

	install -p -D -m 644 $(DEPTH)/as/etc/aerospike.service $(BUILD_ROOT)/usr/lib/systemd/system/aerospike.service
	install -p -D -m 644 $(DEPTH)/as/etc/aerospike-server.tmpfiles $(BUILD_ROOT)/etc/tmpfiles.d/aerospike.conf
	install -p -D -m 644 $(DEPTH)/as/etc/aerospike-server.sysconfig $(BUILD_ROOT)/etc/sysconfig/aerospike
	install -p -D -m 644 $(DEPTH)/as/etc/aerospike.service.d/* $(BUILD_ROOT)/etc/systemd/system/aerospike.service.d

	install -d $(OPT_AS)/doc
ifeq ($(EDITION),community)
	install -pm 644 $(DEPTH)/LICENSE $(OPT_AS)/doc/LICENSE
	install -pm 644 $(DEPTH)/LICENSE-AGPL $(OPT_AS)/doc
	install -pm 644 $(DEPTH)/LICENSE-APACHE $(OPT_AS)/doc
else
	install -pm 644 $(EEREPO)/LICENSE $(OPT_AS)/doc/LICENSE
endif

	install -d $(OPT_AS)/data
	install -d $(OPT_AS)/smd
	install -d $(OPT_AS)/usr/udf/lua

	install -d $(OPT_AS)/bin
	install -pm 755 $(DEPTH)/tools/memacct/asparsemem $(OPT_AS)/bin

package:
	install -pm 644 $(OPT_AS)/doc/LICENSE $(PKG)/packages
	install -d $(SOURCE_ROOT)/RPMS/$(ARCH)

	sed 's/@VERSION@/'$(REV)'/g' < $(PKG)/rpm/server-spec-base > $(PKG)/rpm/aerospike.spec
ifeq ($(EDITION),federal)
	cat $(EEREPO)/pkg/rpm/server-spec-fips >> $(PKG)/rpm/aerospike.spec
endif
	cat $(PKG)/rpm/server-spec-files >> $(PKG)/rpm/aerospike.spec
	cat $(PKG)/rpm/server-spec-systemd >> $(PKG)/rpm/aerospike.spec

ifeq ($(USE_EE),1)
	cat $(EEREPO)/pkg/rpm/as-files >> $(PKG)/rpm/aerospike.spec
	cat $(EEREPO)/pkg/rpm/xdr-files >> $(PKG)/rpm/aerospike.spec
endif
	cat $(PKG)/rpm/server-spec-config >> $(PKG)/rpm/aerospike.spec

ifeq ($(USE_EE),1)
	echo "%config(noreplace) /etc/aerospike/features.conf" >> $(PKG)/rpm/aerospike.spec
	install -pm 644 $(EEREPO)/etc/eval_features.conf $(BUILD_ROOT)/etc/aerospike/features.conf
endif
ifeq ($(EDITION),federal)
	cat $(EEREPO)/pkg/rpm/fips-files >> $(PKG)/rpm/aerospike.spec
endif

	cat $(PKG)/rpm/server-spec-scripts >> $(PKG)/rpm/aerospike.spec

	sed -i 's/@RELEASE@/'$(OS)'/g' $(PKG)/rpm/aerospike.spec
	sed -i 's/@EDITION@/'$(EDITION)'/g' $(PKG)/rpm/aerospike.spec
	sed -i 's/@ARCH@/'$(ARCH)'/g' $(PKG)/rpm/aerospike.spec

	sed -i '1i Requires(pre): /usr/sbin/useradd' $(PKG)/rpm/aerospike.spec
	cd $(DEPTH); rpmbuild -bb -vv --define "dist .$(OS)" --buildroot $(BUILD_ROOT) $(PKG)/rpm/aerospike.spec

	find $(SOURCE_ROOT)/RPMS -type f -exec mv {} $(PKG)/packages \;

clean:
	rm -rf $(PKG)/rpm/aerospike.spec
	rm -rf $(SOURCE_ROOT)/*

ifeq ($(USE_EE),1)
  include $(AS_EE)/make_in/Makefile.rpm.in
endif
