dnl    dlz-ldap-enum: bind9 DLZ module for using an LDAP database to answer
dnl                   ENUM queries over DNS
dnl    Copyright (C) 2012-2014 Daniel Pocock
dnl
dnl    Please see the COPYING file for license terms

AC_INIT(dlz-ldap-enum,1.0.4)
AC_CONFIG_SRCDIR(dlz_ldap_enum_driver.c)
AM_INIT_AUTOMAKE

AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST
AM_CONFIG_HEADER(config.h)

AC_PROG_CC

AC_PROG_INSTALL

AC_PROG_LIBTOOL

AC_ARG_ENABLE(bind99,
[  --enable-bind99         Enable building for bind9 9.9.x and later],
   [AC_DEFINE([BIND_9_9], , [Indicates we are compiling for bind9 9.9 or later])],
   [])

AC_OUTPUT(Makefile)


