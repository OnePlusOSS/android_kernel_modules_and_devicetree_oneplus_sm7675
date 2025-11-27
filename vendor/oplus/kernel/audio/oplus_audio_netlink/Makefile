oplus_audio_netlink-objs := oplus_audio_netlink_kernel.o
obj-$(CONFIG_AUDIO_NETLINK_KERNEL) += oplus_audio_netlink.o

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) modules $(KBUILD_OPTIONS) VERBOSE=1
modules_install:
	$(MAKE) M=$(M) -C $(KERNEL_SRC) modules_install
clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) clean
