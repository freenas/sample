CC=	clang	# for blocks
PROG=	sample
SRCS=	Hash.c Proc.c Thread.c main.c Tree.c \
	Stack.c Symbol.c SymbolGroup.c
MAN8=	sample.8

LOCALLIB=	/usr/local/lib

.if !defined(USE_BFD)
USE_BFD=YES
.endif

CFLAGS+=	-I${.CURDIR}/../driver
CFLAGS+=	-fblocks -g -O0 -I/usr/local/include
.if defined(USE_BFD) && ${USE_BFD} == "YES"
CFLAGS+=	-DBFD=1
.endif
LDFLAGS+=	-L${LOCALLIB}

LDADD=	-static -lBlocksRuntime -lkvm -lutil

.if defined(USE_BFD) && ${USE_BFD} == "YES"
LDADD+=	-lbfd -liberty -lz
.endif

.include <bsd.prog.mk>

