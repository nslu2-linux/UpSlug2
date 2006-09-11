#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(upslug2, 12, http://sourceforge.net/projects/nslu/)
AM_INIT_AUTOMAKE(1.9)
AC_CONFIG_SRCDIR([config.h.in])
AM_CONFIG_HEADER([config.h])

# Checks system specific stuff
AC_CANONICAL_HOST
case "$host" in
  *-linux*)
    AC_DEFINE(BROKEN_PCAP_TIMEOUT, 1, [Define if pcap_open_live timeout does not work])
    AC_DEFINE(DEFAULT_ETHERNET_IF, "eth0", [Define default ethernet interface])
    ;;
  *-darwin*)
    AC_DEFINE(DEFAULT_ETHERNET_IF, "en0", [Define default ethernet interface])
    ;;
esac

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
dnl Check whether libpcap is already available
have_libpcap=no
test "${with_libpcap+set}" != "set" && with_libpcap=no

AC_ARG_WITH(libpcap,
[  --with-libpcap          use libpcap if available],
[case "$with_libpcap" in
  yes)
    AC_CHECK_HEADER(pcap.h,[
      AC_CHECK_LIB(pcap, pcap_open_live, [
      have_libpcap=yes
      AC_CHECK_LIB(pcap, pcap_inject, [
      	AC_DEFINE(HAVE_PCAP_INJECT, 1, [pcap_inject function is in libpcap])
	])
      ])])
    ;;
 esac])

LIBPCAP_LIBS=""
if test $have_libpcap = yes; then
  AC_DEFINE(HAVE_LIBPCAP, 1, [Define to use libpcap])
  LIBPCAP_LIBS="-lpcap"
fi

AC_SUBST(LIBPCAP_LIBS)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_TYPE_UID_T

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([memset select socket strerror strtoul getifaddrs])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
