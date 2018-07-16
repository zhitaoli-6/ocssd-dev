DEBFLAGS = -O2

EXTRA_CFLAGS += $(DEBFLAGS)
#EXTRA_CFLAGS += -I..

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m	:= ram-disk.o

else

KERNELDIR = /lib/modules/$(shell uname -r)/build
#KERNELDIR = /home/sirius/repos/linux-4.15
PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif



clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

depend .depend dep:
	$(CC) $(EXTRA_CFLAGS) -M *.c > .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif
