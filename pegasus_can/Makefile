KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

test:
	rmmod -f pegasus_can || :
	insmod pegasus_can.ko

