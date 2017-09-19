# Example makefile for CPE 464
#

CC = gcc
CFLAGS = -g -Wall -Werror
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  trace-$(EXEC_SUFFIX)

trace-$(EXEC_SUFFIX): trace.c
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ trace.c checksum.c smartalloc.c physicalLayer.c linkLayer.c transportLayer.c -lpcap

handin: README
	handin bellardo 464_p1 README smartalloc.c smartalloc.h checksum.c checksum.h trace.c physicalLayer.c physicalLayer.h linkLayer.c linkLayer.h transportLayer.c transportLayer.h Makefile

clean:
	-rm -rf trace-* trace-*.dSYM

remake:
	make clean; make
