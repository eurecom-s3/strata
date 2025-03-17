obj-m := lime.o
lime-objs := tcp.o disk.o main.o hash.o deflate.o capture_write.o

KVER ?= $(shell uname -r)

KDIR ?= /lib/modules/$(KVER)/build

PWD := $(shell pwd)

.PHONY: modules modules_install clean distclean debug

default:
	$(MAKE) -C $(KDIR) M="$(PWD)" modules
	strip --strip-unneeded lime.ko

debug:
	KCFLAGS="-DLIME_DEBUG" $(MAKE) CONFIG_DEBUG_SG=y -C $(KDIR) M="$(PWD)" modules
	strip --strip-unneeded lime.ko

symbols:
	$(MAKE) -C $(KDIR) M="$(PWD)" modules

modules:    main.c disk.c tcp.c hash.c lime.h
	$(MAKE) -C /lib/modules/$(KVER)/build M="$(PWD)" $@
	strip --strip-unneeded lime.ko

modules_install:    modules
	$(MAKE) -C $(KDIR) M="$(PWD)" $@

clean:
	rm -f *.o *.mod.c Module.symvers Module.markers modules.order \.*.o.cmd \.*.ko.cmd \.*.o.d *.ko
	rm -rf \.tmp_versions

distclean: mrproper
mrproper:    clean
	rm -f *.ko
