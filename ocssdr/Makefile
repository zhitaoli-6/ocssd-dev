# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y



KERNELDIR = /lib/modules/$(shell uname -r)/build
#KERNELDIR = /home/sirius/repos/linux-4.15
PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install



clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions .cache.mk *.order *vers

depend .depend dep:
	$(CC) $(EXTRA_CFLAGS) -M *.c > .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif
