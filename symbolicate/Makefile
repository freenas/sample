CC=	clang
PROG=	symbolicate
SRCS=	symbolicate.pyx
MAN=

CLEANFILES+=	symbolicate.c

LOCALLIB=	/usr/local/lib

PVERS!=python -c 'import sys; print "%d.%d" % (sys.version_info.major, sys.version_info.minor)'

CFLAGS+=	-O0 -g
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-I/usr/local/include/python${PVERS}
LDFLAGS+=	-L/usr/local/lib -lpython${PVERS} -lbfd -liberty

symbolicate.c:	symbolicate.pyx
	cython --embed symbolicate.pyx

symbolicate:  symbolicate.o

.include <bsd.prog.mk>
