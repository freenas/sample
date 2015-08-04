KMOD=sample_driver

SRCS= sample_driver.c

SRCS+= sample_support_${MACHINE_CPUARCH}.c

beforeinstall:
	$(INSTALL) -d -m 755 -o root -g wheel $(DESTDIR)/$(KMODDIR)

.include <bsd.kmod.mk>
