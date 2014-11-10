
#DIST_SUBDIRS = 

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES    = dlz_ldap_enum.la

dlz_ldap_enum_la_SOURCES = dlz_ldap_enum_driver.c
dlz_ldap_enum_la_SOURCES += sdlz_helper.c
dlz_ldap_enum_la_LDFLAGS = -module -avoid-version
dlz_ldap_enum_la_LIBADD = -lldap

noinst_HEADERS = dlz_ldap_enum_driver.h
noinst_HEADERS += bind98_dlz_dlopen.h
noinst_HEADERS += sdlz_helper.h

EXTRA_DIST = dlz_ldap_enum.conf

#pkglibdir = $(libdir)/bind9

#EXTRA_DIST = COPYING gpl-3.0.txt


