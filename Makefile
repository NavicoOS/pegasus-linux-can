KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

test:
	rmmod pegasus_usb || :
	insmod pegasus_usb.ko

