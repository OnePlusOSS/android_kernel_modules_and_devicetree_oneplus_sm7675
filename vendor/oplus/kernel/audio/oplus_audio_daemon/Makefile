oplus_audio_daemon-objs := oplus_audio_daemon_kernel.o
obj-$(CONFIG_AUDIO_DAEMON_KERNEL_MTK_HIFI) += oplus_audio_daemon.o

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) modules $(KBUILD_OPTIONS) VERBOSE=1
modules_install:
	$(MAKE) M=$(M) -C $(KERNEL_SRC) modules_install
clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) clean
