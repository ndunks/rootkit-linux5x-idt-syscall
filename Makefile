CFLAGS = -Wall -Wnounused-result

SOURCE_FILE = get_syscall.c
OBJECT_FILE = $(SOURCE_FILE:.c=.o)
TARGET_FILE = $(SOURCE_FILE:.c=.ko)

#KERNEL_PATH = /lib/modules/$(shell uname -r)/build
KERNEL_PATH = /rifin/app/linux-5.6.3
CFLAGS_get_syscall.o := -fstack-protector
#LDFLAGS_get_syscall.o := -isystem
obj-m := $(OBJECT_FILE)

TEST_KERNEL := /rifin/app/linux-5.6.3/arch/x86/boot/bzImage
KERNEL := linux.x86_64

QEMU = qemu-system-x86_64 \
		-m 128 \
		-smp 1 \
		-serial mon:stdio \
		-nographic \
		-drive file=fat:rw:./root \
		-drive format=raw,file=rootfs.img \
		-initrd initrd.cpio \
		-nic user,model=virtio,hostfwd=tcp::1233-:1233 \
		-append "nokaslr debug earlyprintk=ttyS0 console=ttyS0" \
		-s

all:
	$(MAKE) CROSS_COMPILE=$(CROSS) -C $(KERNEL_PATH) M=$(PWD) modules
	cp -f get_syscall.ko root/

clean:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) clean
	rm -rf Module.symvers *.mod.c *.ko *.o *~

initrd:
	cd initrd; \
	find . | cpio -o -R root:root -H newc > ../initrd.cpio

qemulate:
	$(QEMU) -kernel $(KERNEL) $(X)

test:
	$(QEMU) -kernel $(TEST_KERNEL) $(X)

konsole:
	konsole --qwindowtitle qemulate -e $(QEMU) -kernel $(KERNEL) $(X)

watch: all
	while true; do \
		make konsole & \
		inotifywait -e close_write -q Makefile *.c ;\
		(make all && kill -9 $$(pidof qemu-system-x86_64)) || echo "**FAILED**" ;\
		sleep 0.5 ;\
	done
.PHONY: qemulate initrd test watch clean all konsole