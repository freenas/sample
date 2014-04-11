CC=	clang	# for blocks
PROG=	sample
SRCS=	Hash.c Proc.c Thread.c main.c Tree.c \
	Stack.c Symbol.c SymbolGroup.c
MAN=
LOCALLIB=	/usr/local/lib

CFLAGS+=	-I${.CURDIR}/../driver
CFLAGS+=	-fblocks -g -O0 -I/usr/local/include
LDFLAGS+=	-L${LOCALLIB}

LDADD=	-lBlocksRuntime -lkvm -lutil -lbfd -liberty -lz -llzma

.include <bsd.prog.mk>

