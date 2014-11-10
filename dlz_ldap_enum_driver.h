/*
 * Copyright (C) 2002 Stichting NLnet, Netherlands, stichting@nlnet.nl.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND STICHTING NLNET
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * STICHTING NLNET BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 * USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * The development of Dynamically Loadable Zones (DLZ) for Bind 9 was
 * conceived and contributed by Rob Butler.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ROB BUTLER
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * ROB BUTLER BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 * USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef DLZ_LDAP_ENUM_DRIVER_H
#define DLZ_LDAP_ENUM_DRIVER_H

#ifndef USE_COPIED_DLZ_DLOPEN_H
#include <dns/dlz_dlopen.h>
#else

#ifdef BIND_9_9
#error The bundled copy of dlz_dlopen.h only works with bind9 9.8.x, bind9 up to 9.9.5 does not install dlz_dlopen.h under /usr/include but 9.9.6 or later does.
#endif
// These things are borrowed from the main bind sources,
// this is meant to be installed as part of the public API,
// but may not be available on all systems.
#include "bind98_dlz_dlopen.h"
// ---from named/globals.h---
// this is used from the traditional dlz_ldap code, now
// that we have dlz_dlopen, maybe the memory management
// needs to be changed to use a memory pool local to the module
extern isc_mem_t *              ns_g_mctx                ;

#endif

dlz_dlopen_version_t dlz_version;
dlz_dlopen_allowzonexfr_t dlz_allowzonexfr;
dlz_dlopen_allnodes_t dlz_allnodes;
dlz_dlopen_authority_t dlz_authority;
dlz_dlopen_findzonedb_t dlz_findzonedb;
dlz_dlopen_lookup_t dlz_lookup;
dlz_dlopen_create_t dlz_create;
dlz_dlopen_destroy_t dlz_destroy;

#define ARG_MODULE_NAME 0
#define ARG_CONNECTION_POOL_SIZE ARG_MODULE_NAME+1
#define ARG_LDAP_VERSION ARG_CONNECTION_POOL_SIZE+1
#define ARG_LDAP_BIND_METHOD ARG_LDAP_VERSION+1
#define ARG_LDAP_USER_DN ARG_LDAP_BIND_METHOD+1
#define ARG_LDAP_CREDENTIAL ARG_LDAP_USER_DN+1
#define ARG_LDAP_HOSTS ARG_LDAP_CREDENTIAL+1

#define ARG_ENUM_SUFFIX ARG_LDAP_HOSTS+1

#define ARG_SOA ARG_ENUM_SUFFIX+1
#define ARG_NS ARG_SOA+1
#define ARG_DEFAULT_TTL ARG_NS+1

#define ARG_FIND_ZONE ARG_DEFAULT_TTL+1
#define ARG_LOOKUP ARG_FIND_ZONE+1
#define ARG_AUTHORITY ARG_LOOKUP+1
#define ARG_ALL_NODES ARG_AUTHORITY+1
#define ARG_ALLOW_XFR ARG_ALL_NODES+1

#define TYPE_SOA "SOA"
#define TYPE_NS "NS"
#define TYPE_NAPTR "NAPTR"

#define NAPTR_BUFSIZE 2048
#define NAPTR_TEMPLATE "100 10 \"u\" \"E2U+%s\" \"!^\\\\%s$!%s:%s!\" ."

// ITU E.164 standard specifies 3 to 15 digits permitted
// and we allow one spot for the leading +
#define MIN_NUM_LENGTH 3
#define MAX_NUM_LENGTH 15

#endif
