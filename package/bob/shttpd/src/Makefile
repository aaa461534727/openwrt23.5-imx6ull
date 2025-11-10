include $(TOPDIR)/.config

CGI_SRC := dtu-cgi/dtu-cgi.c dtu-cgi/dtu-cgi-firewall.c dtu-cgi/dtu-cgi-get.c \
		dtu-cgi/dtu-cgi.h dtu-cgi/dtu-cgi-modem.c dtu-cgi/dtu-cgi-network.c \
		dtu-cgi/dtu-cgi-other.c dtu-cgi/dtu-cgi-set.c dtu-cgi/dtu-cgi-wireless.c \
		dtu-cgi/dtu-cgi-vpn.c

SRCS=		string.c shttpd.c log.c cgi.c io_ssi.c \
		io_file.c io_socket.c io_ssl.c io_emb.c io_dir.c io_cgi.c \
		web_ex.c web_query.c io_post.c io_upload.c session_auth.c \
		$(CGI_SRC) discover.c 

HDRS=		defs.h llist.h shttpd.h std_includes.h io.h md5.h ssl.h \
		compat_unix.h compat_win32.h compat_rtems.h config.h \
		web_ex.h discover.h
OBJS=		$(SRCS:%.c=%.o) compat_unix.c
PROG=		shttpd
CL_FLAGS=	/MD /TC /nologo /DNDEBUG /Os 	# MSVC compiler flags

# Possible flags: (in brackets are rough numbers for 'gcc -O2' on i386)
# -DHAVE_MD5		- use system md5 library (-2kb)
# -DNDEBUG		- strip off all debug code (-5kb)
# -D_DEBUG		- build debug version (very noisy) (+6kb)
# -DNO_CGI		- disable CGI support (-5kb)
# -DNO_SSL		- disable SSL functionality (-2kb)
# -DNO_AUTH		- disable authorization support (-4kb)
# -DCONFIG=\"file\"	- use `file' as the default config file
# -DNO_SSI		- disable SSI support (-4kb)
# -DNO_THREADS		- disable threads support (?)

# -DNO_ALIAS		- disable alias support
# -DNO_DIR			- disable dir support
# -DSESSION_AUTH	- session auth support

# XXX Note for the windows users. In order to build shttpd, MSVS6 is needed.
# Follow these steps:
# 1. Add c:\path_to_msvs6\bin to the system Path environment variable.
# 2. Add two new system environment variables:
#    LIB=c:\path_to_msvs6\lib
#    INCLUDE=c:\path_to_msvs6\include
# 3. start console, go to shttpd-VERSION\src\ directory
# 4. type "nmake msvc"
# 5. go to shttpd-VERSION\examples , type "nmake msvc"

CFLAGS += -Os -ffunction-sections -fdata-sections
CFLAGS += -Wall -DNO_AUTH -DNO_SSI -DNO_CGI -D_DEBUG -DNO_ALIAS -DNO_DIR -DSESSION_AUTH
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -luci -ljson-c -lcscommon -L. -l$(PROG) -loperations -lssl -lcsconfig
LDFLAGS += -L../libcjson -lcjson

ifeq ($(CONFIG_PACKAGE_ssl-proxy),y)
LDFLAGS += -lSGSKF -lscspi -lsslvpn
endif
#LIBS = $(LDFLAGS) -luci

all: unix
	@echo "make (unix|msvc|mingw|rtems)"
	@echo 'Linux: "LIBS=-ldl make unix"'
	@echo 'BSD: "LIBS=-lpthread make unix"'
	@echo 'Solaris: "LIBS="-lpthread -lnsl -lsocket" make unix"'
	@echo ' '
	@echo 'STRIP='$(STRIP)
	@echo 'CFLAGS='$(CFLAGS)
	@echo 'LDFLAGS='$(LDFLAGS)
	@echo ' '

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

lib$(PROG).a: $(OBJS) compat_unix.o
	$(AR) -r lib$(PROG).a $(OBJS) compat_unix.o 2>&1
	ranlib lib$(PROG).a 2>&1

unix: lib$(PROG).a
	$(CC) $(CFLAGS) standalone.c -o $(PROG) $(LDFLAGS)
	$(STRIP) $(PROG)
#	$(CC) $(CFLAGS) standalone.c -o $(PROG) $(LIBS) -L. -l$(PROG)
#$(CC) $(CFLAGS) -fpic $(SRCS) compat_unix.c -shared -o lib$(PROG).so

rtems:
	$(CC) -c $(CFLAGS) $(SRCS) compat_rtems.c
	$(AR) -r lib$(PROG).a *.o && ranlib lib$(PROG).a 

$(PROG).lib: $(SRCS) $(HDRS) compat_win32.c
	del *.obj
	cl /c $(CL_FLAGS) compat_win32.c $(SRCS)
	lib /nologo *.obj /out:$@

msvc:	$(PROG).lib
	cl $(CL_FLAGS) standalone.c /link /out:$(PROG).exe \
	ws2_32.lib user32.lib advapi32.lib shell32.lib $(PROG).lib

mingw:
	$(CC) -c $(CFLAGS) $(SRCS) compat_win32.c
	$(AR) -r lib$(PROG).a *.o && ranlib lib$(PROG).a 
	$(CC) $(CFLAGS) $(SRCS) compat_win32.c standalone.c \
		-o $(PROG) $(LIBS) -lws2_32 -lcomdlg32 -lcomctl32

man:
	cat shttpd.1 | tbl | groff -man -Tascii | col -b > shttpd.1.txt
	cat shttpd.1 | tbl | groff -man -Tascii | less

clean:
	rm -rf *.o *.core $(PROG) lib$(PROG).a *.lib *.obj
