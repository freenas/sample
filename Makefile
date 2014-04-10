KMOD=sample_driver

SRCS= sample_driver.c

SRCS+= sample_support_${MACHINE_CPUARCH}.c

.include <bsd.kmod.mk>
