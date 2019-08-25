all: libminipcsc.so

SOURCES=	ccid-driver.c	\
		errf.c		\
		pcsc.c

OBJS=		$(SOURCES:%.c=%.o)

CFLAGS+=	-O2 -g -m64 -D_GNU_SOURCE
CFLAGS+=	-fstack-protector-all -fwrapv -fPIC \
		-D_FORTIFY_SOURCE=2 -Wall
CFLAGS+=	-DHAVE_LIBUSB

CFLAGS+=	$(shell pkg-config --cflags libbsd-overlay)
LIBS+=		$(shell pkg-config --libs libbsd-overlay)

CFLAGS+=	$(shell pkg-config --cflags libusb-1.0)
LIBS+=		$(shell pkg-config --libs libusb-1.0)

libminipcsc.so: $(OBJS) libpcsc.version
	$(CC) -shared -o $@ $(LIBS) $(LDFLAGS) \
	    -Wl,--version-script=libpcsc.version $(OBJS)

.PHONY: clean
clean:
	rm -f $(OBJS) libminipcsc.so
