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
 * The development of Dynamically Loadable Zones (DLZ) for BIND 9 was
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

/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <dns/log.h>
#include <dns/sdlz.h>
#include <dns/result.h>

#include <isc/mem.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <named/globals.h>

#include <dlz/sdlz_helper.h>
#include "dlz_ldap_enum_driver.h"

/*
 * Need older API functions from ldap.h.
 */
#define LDAP_DEPRECATED 1

#include <ldap.h>

#define SIMPLE "simple"
#define KRB41 "krb41"
#define KRB42 "krb42"
#define V2 "v2"
#define V3 "v3"

//static dns_sdlzimplementation_t *dlz_ldap = NULL;

#define dbc_search_limit 30
#define ALLNODES 1
#define ALLOWXFR 2
#define AUTHORITY 3
#define FINDZONE 4
#define LOOKUP 5

/*%
 * Structure to hold everthing needed by this "instance" of the LDAP
 * driver remember, the driver code is only loaded once, but may have
 * many separate instances.
 */

typedef struct {
#ifdef ISC_PLATFORM_USETHREADS
	db_list_t    *db; /*%< handle to a list of DB */
#else
	dbinstance_t *db; /*%< handle to db */
#endif
	int method;	/*%< security authentication method */
	char *user;	/*%< who is authenticating */
	char *cred;	/*%< password for simple authentication method */
	int protocol;	/*%< LDAP communication protocol version */
	char *hosts;	/*%< LDAP server hosts */
	char *enum_suffix;
	char *soa;
	char *ns;
	int default_ttl;
} ldap_instance_t;

/*
 * Private methods
 */

/*% checks that the LDAP URL parameters make sense */
static isc_result_t
dlz_ldap_checkURL(char *URL, int attrCnt, const char *msg) {
	isc_result_t result = ISC_R_SUCCESS;
	int ldap_result;
	LDAPURLDesc *ldap_url = NULL;

	if (!ldap_is_ldap_url(URL)) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "%s query is not a valid LDAP URL", msg);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	ldap_result = ldap_url_parse(URL, &ldap_url);
	if (ldap_result != LDAP_SUCCESS || ldap_url == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "parsing %s query failed", msg);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	if (ldap_count_values(ldap_url->lud_attrs) < attrCnt) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "%s query must specify at least "
			      "%d attributes to return",
			      msg, attrCnt);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	if (ldap_url->lud_host != NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "%s query must not specify a host", msg);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	if (ldap_url->lud_port != 389) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "%s query must not specify a port", msg);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	if (ldap_url->lud_dn == NULL || strlen (ldap_url->lud_dn) < 1) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "%s query must specify a search base", msg);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	if (ldap_url->lud_exts != NULL || ldap_url->lud_crit_exts != 0) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "%s uses extensions. "
			      "The driver does not support LDAP extensions.",
			      msg);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

 cleanup:
	if (ldap_url != NULL)
		ldap_free_urldesc(ldap_url);

	return (result);
}

/*% Connects / reconnects to LDAP server */
static isc_result_t
dlz_ldap_connect(ldap_instance_t *dbi, dbinstance_t *dbc) {
	isc_result_t result;
	int ldap_result;

	/* if we have a connection, get ride of it. */
	if (dbc->dbconn != NULL) {
		ldap_unbind_s((LDAP *) dbc->dbconn);
		dbc->dbconn = NULL;
	}

	/* now connect / reconnect. */

	/* initialize. */
	dbc->dbconn = ldap_init(dbi->hosts, LDAP_PORT);
	if (dbc->dbconn == NULL)
		return (ISC_R_NOMEMORY);

	/* set protocol version. */
	ldap_result = ldap_set_option((LDAP *) dbc->dbconn,
				      LDAP_OPT_PROTOCOL_VERSION,
				      &(dbi->protocol));
	if (ldap_result != LDAP_SUCCESS) {
		result = ISC_R_NOPERM;
		goto cleanup;
	}

	/* "bind" to server.  i.e. send username / pass */
	ldap_result = ldap_bind_s((LDAP *) dbc->dbconn, dbi->user,
				  dbi->cred, dbi->method);
	if (ldap_result != LDAP_SUCCESS) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	return (ISC_R_SUCCESS);

 cleanup:

	/* cleanup if failure. */
	if (dbc->dbconn != NULL) {
		ldap_unbind_s((LDAP *) dbc->dbconn);
		dbc->dbconn = NULL;
	}

	return (result);
}

#ifdef ISC_PLATFORM_USETHREADS


/*%
 * Properly cleans up a list of database instances.
 * This function is only used when the driver is compiled for
 * multithreaded operation.
 */
static void
ldap_destroy_dblist(db_list_t *dblist) {
	dbinstance_t *ndbi = NULL;
	dbinstance_t *dbi = NULL;

	/* get the first DBI in the list */
	ndbi = ISC_LIST_HEAD(*dblist);

	/* loop through the list */
	while (ndbi != NULL) {
		dbi = ndbi;
		/* get the next DBI in the list */
		ndbi = ISC_LIST_NEXT(dbi, link);
		/* release DB connection */
		if (dbi->dbconn != NULL)
			ldap_unbind_s((LDAP *) dbi->dbconn);
		/* release all memory that comprised a DBI */
		destroy_sqldbinstance(dbi);
	}
	/* release memory for the list structure */
	isc_mem_put(ns_g_mctx, dblist, sizeof(db_list_t));
}

/*%
 * Loops through the list of DB instances, attempting to lock
 * on the mutex.  If successful, the DBI is reserved for use
 * and the thread can perform queries against the database.
 * If the lock fails, the next one in the list is tried.
 * looping continues until a lock is obtained, or until
 * the list has been searched dbc_search_limit times.
 * This function is only used when the driver is compiled for
 * multithreaded operation.
 */
static dbinstance_t *
ldap_find_avail_conn(db_list_t *dblist) {
	dbinstance_t *dbi = NULL;
	dbinstance_t *head;
	int count = 0;

	/* get top of list */
	head = dbi = ISC_LIST_HEAD(*dblist);

	/* loop through list */
	while (count < dbc_search_limit) {
		/* try to lock on the mutex */
		if (isc_mutex_trylock(&dbi->instance_lock) == ISC_R_SUCCESS)
			return (dbi); /* success, return the DBI for use. */

		/* not successful, keep trying */
		dbi = ISC_LIST_NEXT(dbi, link);

		/* check to see if we have gone to the top of the list. */
		if (dbi == NULL) {
			count++;
			dbi = head;
		}
	}
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
		      DNS_LOGMODULE_DLZ, ISC_LOG_INFO,
		      "LDAP driver unable to find available connection "
		      "after searching %d times",
		      count);
	return (NULL);
}
#endif /* ISC_PLATFORM_USETHREADS */

static isc_result_t
mail_to_naptr(const char *tel, const char *mail, int ttl,
	const char *scheme, char **naptr)
{
	int len;
	char naptr_buf[NAPTR_BUFSIZE + 1];
	char *_naptr;

	*naptr = NULL;

	len = snprintf(naptr_buf, NAPTR_BUFSIZE, NAPTR_TEMPLATE, 
		scheme, tel, scheme, mail);
	if(len >= NAPTR_BUFSIZE)
		return ISC_R_FAILURE;

	_naptr = isc_mem_strdup(ns_g_mctx, naptr_buf);
	if (_naptr == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			"LDAP driver unable to allocate memory "
			"while processing results");
		return ISC_R_FAILURE;	
	}
	*naptr = _naptr;

	return ISC_R_SUCCESS;
}

static isc_result_t
ldap_process_results(LDAP *dbc, LDAPMessage *msg, char ** attrs,
		     void *ptr, isc_boolean_t allnodes, char *tel,
			void *dbdata)
{
	isc_result_t result = ISC_R_SUCCESS;
	int i = 0;
	int j;
	int len;
	char *attribute = NULL;
	LDAPMessage *entry;
	char *endp = NULL;
	char *host = NULL;
	char *type = TYPE_NAPTR;
	char *data = NULL;
	char **vals = NULL;
	char *schemes[] = { "sip", "xmpp", NULL };
	int ttl = ((ldap_instance_t *)dbdata)->default_ttl;

	/* make sure there are at least some attributes to process. */
	REQUIRE(attrs != NULL || attrs[0] != NULL);

	/* get the first entry to process */
	entry = ldap_first_entry(dbc, msg);
	if (entry == NULL) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_INFO,
			      "LDAP no entries to process.");
		return (ISC_R_FAILURE);
	}

	/* loop through all entries returned */
	while (entry != NULL) {

		/* get the list of values for this attribute. */
		vals = ldap_get_values(dbc, entry, attrs[0]);
		/* skip empty attributes. */
		if (vals == NULL || ldap_count_values(vals) < 1)
			continue;
		/*
		 * we only use the first value.  this driver
		 * does not support multi-valued attributes.
		 */

		for(j = 0; schemes[j] != NULL; j++)
		{
			mail_to_naptr(tel, vals[0], ttl, schemes[j], &data);
			// now store the naptr:
			if (data == NULL) {
	                        isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
                                      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
                                      "LDAP driver unable to allocate memory "
                                      "while processing results");
        	                result = ISC_R_FAILURE;
               	         	goto cleanup;
               		 }

			result = dns_sdlz_putrr((dns_sdlzlookup_t *) ptr,
						type, ttl, data);
			if (result != ISC_R_SUCCESS)
			{
				isc_log_write(dns_lctx,
					DNS_LOGCATEGORY_DATABASE,
					DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
					"dlz-ldap: putrr failed "
					"for \"%s %u %s\", %s",
					type, ttl, data,
					isc_result_totext(result));
				goto cleanup;
			}
			isc_mem_free(ns_g_mctx, data);
			data = NULL;
		}

		/* free vals for next loop */
                ldap_value_free(vals);
		vals = NULL;

		/* get the next entry to process */
		entry = ldap_next_entry(dbc, entry);
	} /* end while (entry != NULL) */

 cleanup:
	/* de-allocate memory */
	if (vals != NULL)
		ldap_value_free(vals);
	if (data != NULL)
		isc_mem_free(ns_g_mctx, data);

	return (result);
}

static isc_result_t
dnsname_strip_suffix(void *dbdata, char *name)
{
	char *_suffix = ((ldap_instance_t *)dbdata)->enum_suffix;
	int d;

	d = strlen(name) - strlen(_suffix);
        if(d > 1)
        {
                if(name[d-1] != '.')
                        return ISC_R_FAILURE;
                name[d-1] = 0;
        }
        else if(d == 1)
        {
                return ISC_R_FAILURE;
        }
	else
		name[0] = 0;
	
	return ISC_R_SUCCESS;
}

static isc_result_t
dnsname_e164(void *dbdata, const char *name, char **e164num)
{
	char *_e164num = NULL;
	int d, i, x;

	*e164num = NULL;

	isc_log_write(dns_lctx,
		DNS_LOGCATEGORY_DATABASE,
		DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(1),
		"dlz-ldap: trying to convert to E.164: %s", name);

	d = strlen(name);
	if(d % 2 != 1)
	{
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			"Unexpected length of string");
		return ISC_R_FAILURE;
	}
	d = (d / 2) + 1;
	if(d < MIN_NUM_LENGTH || d > MAX_NUM_LENGTH)
	{
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			"Number too short or too long for E.164");
		return ISC_R_FAILURE;
	}
	// Allocate memory, add space for leading + and trailing 0
	_e164num = isc_mem_allocate(ns_g_mctx, d + 2);
	if(_e164num == NULL)
	{
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			"LDAP driver unable to allocate memory "
			"while converting to E.164");
		return ISC_R_FAILURE;
	}
	_e164num[0] = '+';
	for(i = 1; i <= d; i++)
	{
		x = (d-i) * 2;
		if(!isdigit(name[x]) || (i > 1 && name[x + 1] != '.'))
		{
			isc_mem_free(ns_g_mctx, _e164num);
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				"unexpected character in ENUM query string");
			return ISC_R_FAILURE;
		}
		_e164num[i] = name[x];
	}
	_e164num[d + 1] = 0;

	*e164num = _e164num;
	return ISC_R_SUCCESS;
}

static isc_result_t
handle_authority_static(void *dbdata, void *ptr, int withNS)
{
	char *type;
	char *data;
	char *host;
	int ttl;
	isc_result_t result;

	type = isc_mem_strdup(ns_g_mctx, TYPE_SOA);
	data = isc_mem_strdup(ns_g_mctx, ((ldap_instance_t *)dbdata)->soa);
	host = isc_mem_strdup(ns_g_mctx, ((ldap_instance_t *)dbdata)->enum_suffix);
	ttl = ((ldap_instance_t *)dbdata)->default_ttl;

	result = dns_sdlz_putrr((dns_sdlzlookup_t *) ptr,
				type, ttl, data);
	if (result != ISC_R_SUCCESS)
		isc_log_write(dns_lctx,
			DNS_LOGCATEGORY_DATABASE,
			DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			"dlz-ldap: putrr failed "
			"for \"%s %u %s\", %s",
			type, ttl, data,
			isc_result_totext(result));

	isc_mem_free(ns_g_mctx, type);
	isc_mem_free(ns_g_mctx, data);

	if(withNS > 0)
	{
		type = isc_mem_strdup(ns_g_mctx, TYPE_NS);
		data = isc_mem_strdup(ns_g_mctx, ((ldap_instance_t *)dbdata)->ns);

		result = dns_sdlz_putrr((dns_sdlzlookup_t *) ptr,
					type, ttl, data);
		if (result != ISC_R_SUCCESS)
			isc_log_write(dns_lctx,
			DNS_LOGCATEGORY_DATABASE,
			DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			"dlz-ldap: putrr failed "
			"for \"%s %u %s\", %s",
			type, ttl, data,
			isc_result_totext(result));

		isc_mem_free(ns_g_mctx, type);
		isc_mem_free(ns_g_mctx, data);
	}

	isc_mem_free(ns_g_mctx, host);

	return result;
}

/*%
 * This function is the real core of the driver.   Zone, record
 * and client strings are passed in (or NULL is passed if the
 * string is not available).  The type of query we want to run
 * is indicated by the query flag, and the dbdata object is passed
 * passed in to.  dbdata really holds either:
 *		1) a list of database instances (in multithreaded mode) OR
 *		2) a single database instance (in single threaded mode)
 * The function will construct the query and obtain an available
 * database instance (DBI).  It will then run the query and hopefully
 * obtain a result set.
 */
static isc_result_t
ldap_get_results(const char *zone, const char *record,
		 const char *client, unsigned int query,
		 void *dbdata, void *ptr)
{
	isc_result_t result;
	dbinstance_t *dbi = NULL;
	char *querystring = NULL;
	LDAPURLDesc *ldap_url = NULL;
	int ldap_result = 0;
	LDAPMessage *ldap_msg = NULL;
	int i;
	int entries;
	char *_record;
	char *tel = NULL;

	/* get db instance / connection */
#ifdef ISC_PLATFORM_USETHREADS

	/* find an available DBI from the list */
	dbi = ldap_find_avail_conn((db_list_t *)
				   ((ldap_instance_t *)dbdata)->db);

#else /* ISC_PLATFORM_USETHREADS */

	/*
	 * only 1 DBI - no need to lock instance lock either
	 * only 1 thread in the whole process, no possible contention.
	 */
	dbi =  (dbinstance_t *) ((ldap_instance_t *)dbdata)->db;

#endif /* ISC_PLATFORM_USETHREADS */

	/* if DBI is null, can't do anything else */
	if (dbi == NULL)
		return (ISC_R_FAILURE);

	/* set fields */
	if (zone != NULL) {
		dbi->zone = isc_mem_strdup(ns_g_mctx, zone);
		if (dbi->zone == NULL) {
			result = ISC_R_NOMEMORY;
			goto cleanup;
		}
	} else {
		dbi->zone = NULL;
	}
	if (record != NULL) {
		if(strlen(record) != 1)
		{
			result = dnsname_e164(dbdata, record, &(dbi->record));
			if(result != ISC_R_SUCCESS)
				goto cleanup;
			tel = dbi->record;
		} else {
			if(record[0] == '@')
			{
				if(zone == NULL)
				{
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				_record = isc_mem_strdup(ns_g_mctx, zone);
				result = dnsname_strip_suffix(dbdata, _record);
				if(result != ISC_R_SUCCESS)
				{
					isc_mem_free(ns_g_mctx, _record);
					goto cleanup;
				}
				result = dnsname_e164(dbdata, _record, &(dbi->record));
				isc_mem_free(ns_g_mctx, _record);
				if(result != ISC_R_SUCCESS)
					goto cleanup;
				tel = dbi->record;
			} else {
				dbi->record = isc_mem_strdup(ns_g_mctx, record);
				if (dbi->record == NULL)
				{
					result = ISC_R_NOMEMORY;
					goto cleanup;
				}
			}
		}
	} else {
		dbi->record = NULL;
	}
	if (client != NULL) {
		dbi->client = isc_mem_strdup(ns_g_mctx, client);
		if (dbi->client == NULL) {
			result = ISC_R_NOMEMORY;
			goto cleanup;
		}
	} else {
		dbi->client = NULL;
	}

	/* what type of query are we going to run? */
	switch(query) {
	case ALLNODES:
		/*
		 * if the query was not passed in from the config file
		 * then we can't run it.  return not_implemented, so
		 * it's like the code for that operation was never
		 * built into the driver.... AHHH flexibility!!!
		 */
		if (dbi->allnodes_q == NULL) {
			result = ISC_R_NOTIMPLEMENTED;
			goto cleanup;
		} else {
			querystring = build_querystring(ns_g_mctx,
			dbi->allnodes_q);
		}
		break;
	case ALLOWXFR:
		/* same as comments as ALLNODES */
		if (dbi->allowxfr_q == NULL) {
			result = ISC_R_NOTIMPLEMENTED;
			goto cleanup;
		} else {
			querystring = build_querystring(ns_g_mctx,
			dbi->allowxfr_q);
		}
		break;
	case AUTHORITY:
		result = handle_authority_static(dbdata, ptr, 0);
		goto cleanup;
		/* same as comments as ALLNODES */
		if (dbi->authority_q == NULL) {
			result = ISC_R_NOTIMPLEMENTED;
			goto cleanup;
		} else {
			querystring = build_querystring(ns_g_mctx,
			dbi->authority_q);
		}
		break;
	case FINDZONE:
		/* this is required.  It's the whole point of DLZ! */
		if (dbi->findzone_q == NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(2),
				      "No query specified for findzone.  "
				      "Findzone requires a query");
			result = ISC_R_FAILURE;
			goto cleanup;
		} else {
			querystring = build_querystring(ns_g_mctx,
			dbi->findzone_q);
		}
		break;
	case LOOKUP:
		/* this is required.  It's also a major point of DLZ! */
		if (dbi->lookup_q == NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(2),
				      "No query specified for lookup.  "
				      "Lookup requires a query");
			result = ISC_R_FAILURE;
			goto cleanup;
		} else {
			querystring = build_querystring(ns_g_mctx,
							dbi->lookup_q);
		}
		break;
	default:
		/*
		 * this should never happen.  If it does, the code is
		 * screwed up!
		 */
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "Incorrect query flag passed to "
				 "ldap_get_results");
		result = ISC_R_UNEXPECTED;
		goto cleanup;
	}

	/* if the querystring is null, Bummer, outta RAM.  UPGRADE TIME!!!   */
	if (querystring  == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	/*
	 * output the full query string during debug so we can see
	 * what lame error the query has.
	 */
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
		      DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(1),
		      "\nQuery String: %s\n", querystring);

        /* break URL down into it's component parts, if error cleanup */
	ldap_result = ldap_url_parse(querystring, &ldap_url);
	if (ldap_result != LDAP_SUCCESS || ldap_url == NULL) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	for (i = 0; i < 3; i++) {

		/*
		 * dbi->dbconn may be null if trying to reconnect on a
		 * previous query failed.
		 */
		if (dbi->dbconn == NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_INFO,
				      "LDAP driver attempting to re-connect");

			result = dlz_ldap_connect((ldap_instance_t *) dbdata,
						  dbi);
			if (result != ISC_R_SUCCESS) {
				result = ISC_R_FAILURE;
				continue;
			}
		}

		/* perform ldap search syncronously */
		ldap_result = ldap_search_s((LDAP *) dbi->dbconn,
					    ldap_url->lud_dn,
					    ldap_url->lud_scope,
					    ldap_url->lud_filter,
					    ldap_url->lud_attrs, 0, &ldap_msg);

		/*
		 * check return code.  No such object is ok, just
		 * didn't find what we wanted
		 */
		switch(ldap_result) {
		case LDAP_NO_SUCH_OBJECT:
    			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(1),
				      "No object found matching "
				      "query requirements");
			result = ISC_R_NOTFOUND;
			goto cleanup;
			break;
		case LDAP_SUCCESS:	/* on success do nothing */
			result = ISC_R_SUCCESS;
			i = 3;
			break;
		case LDAP_SERVER_DOWN:
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_INFO,
				      "LDAP driver attempting to re-connect");
			result = dlz_ldap_connect((ldap_instance_t *) dbdata,
						  dbi);
			if (result != ISC_R_SUCCESS)
				result = ISC_R_FAILURE;
			break;
		default:
			/*
			 * other errors not ok.  Log error message and
			 * get out
			 */
    			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "LDAP error: %s",
				      ldap_err2string(ldap_result));
			result = ISC_R_FAILURE;
			goto cleanup;
			break;
		} /* close switch(ldap_result) */
	} /* end for (int i = 0 i < 3; i++) */

	if (result != ISC_R_SUCCESS)
		goto cleanup;

	switch(query) {
	case ALLNODES:
		result = ldap_process_results((LDAP *) dbi->dbconn, ldap_msg,
					      ldap_url->lud_attrs,
					      ptr, isc_boolean_true, NULL,
						dbdata);
		break;
	case AUTHORITY:
	case LOOKUP:
		result = ldap_process_results((LDAP *) dbi->dbconn, ldap_msg,
					      ldap_url->lud_attrs,
					      ptr, isc_boolean_false, tel,
						dbdata);
		break;
	case ALLOWXFR:
		entries = ldap_count_entries((LDAP *) dbi->dbconn, ldap_msg);
		if (entries == 0)
			result = ISC_R_NOPERM;
		else if (entries > 0)
			result = ISC_R_SUCCESS;
		else
			result = ISC_R_FAILURE;
		break;
	case FINDZONE:
		entries = ldap_count_entries((LDAP *) dbi->dbconn, ldap_msg);
		if (entries == 0)
			result = ISC_R_NOTFOUND;
		else if (entries > 0)
			result = ISC_R_SUCCESS;
		else
			result = ISC_R_FAILURE;
		break;
	default:
		/*
		 * this should never happen.  If it does, the code is
		 * screwed up!
		 */
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "Incorrect query flag passed to "
				 "ldap_get_results");
		result = ISC_R_UNEXPECTED;
	}

 cleanup:
	/* it's always good to cleanup after yourself */

        /* if we retrieved results, free them */
	if (ldap_msg != NULL)
		ldap_msgfree(ldap_msg);

	if (ldap_url != NULL)
		ldap_free_urldesc(ldap_url);

	/* cleanup */
	if (dbi->zone != NULL)
		isc_mem_free(ns_g_mctx, dbi->zone);
	if (dbi->record != NULL)
		isc_mem_free(ns_g_mctx, dbi->record);
	if (dbi->client != NULL)
		isc_mem_free(ns_g_mctx, dbi->client);

#ifdef ISC_PLATFORM_USETHREADS

	/* release the lock so another thread can use this dbi */
	isc_mutex_unlock(&dbi->instance_lock);

#endif /* ISC_PLATFORM_USETHREADS */

        /* release query string */
	if (querystring  != NULL)
		isc_mem_free(ns_g_mctx, querystring );

	/* return result */
	return (result);
}

/*
 * dlz_dlopen methods
 */

int
dlz_version(unsigned int *flags)
{
	return DLZ_DLOPEN_VERSION;
}

isc_result_t
dlz_allowzonexfr(void *dbdata, const char *name,
		      const char *client)
{
	isc_result_t result;

	/* check to see if we are authoritative for the zone first */
	result = dlz_findzonedb(dbdata, name);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

        /* get all the zone data */
	result = ldap_get_results(name, NULL, client, ALLOWXFR, dbdata, NULL);
	return (result);
}

isc_result_t
dlz_allnodes(const char *zone, void *dbdata,
		  dns_sdlzallnodes_t *allnodes)
{
	return (ldap_get_results(zone, NULL, NULL, ALLNODES, dbdata, allnodes));
}

isc_result_t
dlz_authority(const char *zone, void *dbdata,
		   dns_sdlzlookup_t *lookup)
{
	return (ldap_get_results(zone, NULL, NULL, AUTHORITY, dbdata, lookup));
}

isc_result_t
dlz_findzonedb(void *dbdata, const char *name) {
	char *_suffix = ((ldap_instance_t *)dbdata)->enum_suffix;
	const char *_name = name;
	int d;

	isc_log_write(dns_lctx,
                        DNS_LOGCATEGORY_DATABASE,
                        DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(1),
                        "findzonedb: %s", name);

	d = strlen(name) - strlen(_suffix);
	if(d > 1)
	{
		if(name[d-1] != '.')
			return ISC_R_FAILURE;
		_name += d;
	}
	else if(d == 1 || d < 0)
	{
		return ISC_R_FAILURE;
	}

	if(strcasecmp(_suffix, _name) == 0)
		return ISC_R_SUCCESS;
	return ISC_R_FAILURE;
}

isc_result_t
dlz_lookup(const char *zone, const char *name,
		void *dbdata, dns_sdlzlookup_t *lookup)
{
	isc_result_t result;

	if (strcmp(name, "*") == 0)
		result = ldap_get_results(zone, "~", NULL, LOOKUP,
					  dbdata, lookup);
	else
		result = ldap_get_results(zone, name, NULL, LOOKUP,
					  dbdata, lookup);
	return (result);
}


isc_result_t
dlz_create(const char *dlzname, unsigned int argc, char *argv[],
		void **dbdata, ...)
{
	isc_result_t result;
	ldap_instance_t *ldap_inst = NULL;
	dbinstance_t *dbi = NULL;
	int protocol;
	int method;

#ifdef ISC_PLATFORM_USETHREADS
	/* if multi-threaded, we need a few extra variables. */
	int dbcount;
	char *endp;
/* db_list_t *dblist = NULL; */
	int i;

#endif /* ISC_PLATFORM_USETHREADS */

	UNUSED(dlzname);

#ifdef ISC_PLATFORM_USETHREADS
	/* if debugging, let user know we are multithreaded. */
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
		      DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(1),
		      "LDAP driver running multithreaded");
#else /* ISC_PLATFORM_USETHREADS */
	/* if debugging, let user know we are single threaded. */
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
		      DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(1),
		      "LDAP driver running single threaded");
#endif /* ISC_PLATFORM_USETHREADS */

	if (argc < (ARG_LOOKUP+1)) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "LDAP driver requires at least "
			      "8 command line args.");
		return (ISC_R_FAILURE);
	}

	/* no more than 13 arg's should be passed to the driver */
	if (argc > (ARG_ALLOW_XFR+1)) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "LDAP driver cannot accept more than "
			      "11 command line args.");
		return (ISC_R_FAILURE);
	}

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(1),
			"argv[0] = %s", argv[ARG_MODULE_NAME]);

	/* determine protocol version. */
	if (strncasecmp(argv[ARG_LDAP_VERSION], V2, strlen(V2)) == 0) {
		protocol = 2;
	} else if (strncasecmp(argv[ARG_LDAP_VERSION], V3, strlen(V3)) == 0) {
		protocol = 3;
	} else {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "LDAP driver protocol must be either %s or %s",
			      V2, V3);
		return (ISC_R_FAILURE);
	}

	/* determine connection method. */
	if (strncasecmp(argv[ARG_LDAP_BIND_METHOD], SIMPLE, strlen(SIMPLE)) == 0) {
		method = LDAP_AUTH_SIMPLE;
	} else if (strncasecmp(argv[ARG_LDAP_BIND_METHOD], KRB41, strlen(KRB41)) == 0) {
		method = LDAP_AUTH_KRBV41;
	} else if (strncasecmp(argv[ARG_LDAP_BIND_METHOD], KRB42, strlen(KRB42)) == 0) {
		method = LDAP_AUTH_KRBV42;
	} else {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "LDAP driver authentication method must be "
			      "one of %s, %s or %s",
			      SIMPLE, KRB41, KRB42);
		return (ISC_R_FAILURE);
	}

	/* multithreaded build can have multiple DB connections */
#ifdef ISC_PLATFORM_USETHREADS

	/* check how many db connections we should create */
	dbcount = strtol(argv[ARG_CONNECTION_POOL_SIZE], &endp, 10);
	if (*endp != '\0' || dbcount < 0) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "LDAP driver database connection count "
			      "must be positive.");
		return (ISC_R_FAILURE);
	}
#endif

	/* check that LDAP URL parameters make sense */
	switch(argc) {
	case ARG_ALLOW_XFR+1:
		result = dlz_ldap_checkURL(argv[ARG_ALLOW_XFR], 0, "allow zone transfer");
		if (result != ISC_R_SUCCESS)
			return (result);
	case ARG_ALL_NODES+1:
		result = dlz_ldap_checkURL(argv[ARG_ALL_NODES], 3, "all nodes");
		if (result != ISC_R_SUCCESS)
			return (result);
	case ARG_AUTHORITY+1:
		if (strlen(argv[ARG_AUTHORITY]) > 0) {
			result = dlz_ldap_checkURL(argv[ARG_AUTHORITY], 3, "authority");
			if (result != ISC_R_SUCCESS)
				return (result);
		}
	case ARG_LOOKUP+1:
		result = dlz_ldap_checkURL(argv[ARG_LOOKUP], 1, "lookup");
		if (result != ISC_R_SUCCESS)
			return (result);
		/* result = dlz_ldap_checkURL(argv[ARG_FIND_ZONE], 0, "find zone");
		if (result != ISC_R_SUCCESS)
			return (result); */
		break;
	default:
		/* not really needed, should shut up compiler. */
		result = ISC_R_FAILURE;
	}

	/* allocate memory for LDAP instance */
	ldap_inst = isc_mem_get(ns_g_mctx, sizeof(ldap_instance_t));
	if (ldap_inst == NULL)
		return (ISC_R_NOMEMORY);
	memset(ldap_inst, 0, sizeof(ldap_instance_t));

	/* store info needed to automatically re-connect. */
	ldap_inst->protocol = protocol;
	ldap_inst->method = method;
	ldap_inst->default_ttl = atoi(argv[ARG_DEFAULT_TTL]);
	ldap_inst->ns = isc_mem_strdup(ns_g_mctx, argv[ARG_NS]);
	if (ldap_inst->ns == NULL) {
                result = ISC_R_NOMEMORY;
                goto cleanup;
        }
	ldap_inst->soa = isc_mem_strdup(ns_g_mctx, argv[ARG_SOA]);
        if (ldap_inst->soa == NULL) {
                result = ISC_R_NOMEMORY;
                goto cleanup;
        }
	ldap_inst->enum_suffix = isc_mem_strdup(ns_g_mctx, argv[ARG_ENUM_SUFFIX]);
	if (ldap_inst->enum_suffix == NULL) {
                result = ISC_R_NOMEMORY;
                goto cleanup;
        }
	ldap_inst->hosts = isc_mem_strdup(ns_g_mctx, argv[ARG_LDAP_HOSTS]);
	if (ldap_inst->hosts == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}
	ldap_inst->user = isc_mem_strdup(ns_g_mctx, argv[ARG_LDAP_USER_DN]);
	if (ldap_inst->user == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}
	ldap_inst->cred = isc_mem_strdup(ns_g_mctx, argv[ARG_LDAP_CREDENTIAL]);
	if (ldap_inst->cred == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

#ifdef ISC_PLATFORM_USETHREADS
	/* allocate memory for database connection list */
	ldap_inst->db = isc_mem_get(ns_g_mctx, sizeof(db_list_t));
	if (ldap_inst->db == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	/* initialize DB connection list */
	ISC_LIST_INIT(*(ldap_inst->db));

	/*
	 * create the appropriate number of database instances (DBI)
	 * append each new DBI to the end of the list
	 */
	for (i = 0; i < dbcount; i++) {

#endif /* ISC_PLATFORM_USETHREADS */

		/* how many queries were passed in from config file? */
		switch(argc) {
		case ARG_LOOKUP+1:
			result = build_sqldbinstance(ns_g_mctx, NULL, NULL,
						     NULL, argv[ARG_FIND_ZONE], argv[ARG_LOOKUP],
						     NULL, &dbi);
			break;
		case ARG_AUTHORITY+1:
			result = build_sqldbinstance(ns_g_mctx, NULL, NULL,
						     argv[ARG_AUTHORITY], argv[ARG_FIND_ZONE], argv[ARG_LOOKUP],
						     NULL, &dbi);
			break;
		case ARG_ALL_NODES+1:
			result = build_sqldbinstance(ns_g_mctx, argv[ARG_ALL_NODES], NULL,
						     argv[ARG_AUTHORITY], argv[ARG_FIND_ZONE], argv[ARG_LOOKUP],
						     NULL, &dbi);
			break;
		case ARG_ALLOW_XFR+1:
			result = build_sqldbinstance(ns_g_mctx, argv[ARG_ALL_NODES],
						     argv[ARG_ALLOW_XFR], argv[ARG_AUTHORITY],
						     argv[ARG_FIND_ZONE], argv[ARG_LOOKUP],
						     NULL, &dbi);
			break;
		default:
			/* not really needed, should shut up compiler. */
			result = ISC_R_FAILURE;
		}

		if (result == ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(2),
				      "LDAP driver created "
				      "database instance object.");
		} else { /* unsuccessful?, log err msg and cleanup. */
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "LDAP driver could not create "
				      "database instance object.");
			goto cleanup;
		}

#ifdef ISC_PLATFORM_USETHREADS
		/* when multithreaded, build a list of DBI's */
		ISC_LINK_INIT(dbi, link);
		ISC_LIST_APPEND(*(ldap_inst->db), dbi, link);
#else
		/*
		 * when single threaded, hold onto the one connection
		 * instance.
		 */
		ldap_inst->db = dbi;

#endif
		/* attempt to connect */
		result = dlz_ldap_connect(ldap_inst, dbi);

		/*
		 * if db connection cannot be created, log err msg and
		 * cleanup.
		 */
		switch(result) {
			/* success, do nothing */
		case ISC_R_SUCCESS:
			break;
			/*
			 * no memory means ldap_init could not
			 * allocate memory
			 */
		case ISC_R_NOMEMORY:
#ifdef ISC_PLATFORM_USETHREADS
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "LDAP driver could not allocate memory "
				      "for connection number %u",
				      i+1);
#else
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "LDAP driver could not allocate memory "
				      "for connection");
#endif
			goto cleanup;
			break;
			/*
			 * no perm means ldap_set_option could not set
			 * protocol version
			 */
		case ISC_R_NOPERM:
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "LDAP driver could not "
				      "set protocol version.");
			result = ISC_R_FAILURE;
			goto cleanup;
			break;
			/* failure means couldn't connect to ldap server */
		case ISC_R_FAILURE:
#ifdef ISC_PLATFORM_USETHREADS
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "LDAP driver could not "
				      "bind connection number %u to server.",
				      i+1);
#else
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "LDAP driver could not "
				      "bind connection to server.");
#endif
			goto cleanup;
			break;
			/*
			 * default should never happen.  If it does,
			 * major errors.
			 */
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "dlz_ldap_create() failed: %s",
					 isc_result_totext(result));
			result = ISC_R_UNEXPECTED;
			goto cleanup;
			break;
		} /* end switch(result) */


#ifdef ISC_PLATFORM_USETHREADS

		/* set DBI = null for next loop through. */
		dbi = NULL;
	}	/* end for loop */

#endif /* ISC_PLATFORM_USETHREADS */


	/* set dbdata to the ldap_instance we created. */
	*dbdata = ldap_inst;

	/* hey, we got through all of that ok, return success. */
	return(ISC_R_SUCCESS);

 cleanup:
	dlz_destroy(ldap_inst);

	return(ISC_R_FAILURE);
}

void
dlz_destroy(void *dbdata) {

	if (dbdata != NULL) {
#ifdef ISC_PLATFORM_USETHREADS
		/* cleanup the list of DBI's */
		ldap_destroy_dblist((db_list_t *)
				    ((ldap_instance_t *)dbdata)->db);

#else /* ISC_PLATFORM_USETHREADS */
		if (((ldap_instance_t *)dbdata)->db->dbconn != NULL)
			ldap_unbind_s((LDAP *)
				      ((ldap_instance_t *)dbdata)->db->dbconn);

		/* destroy single DB instance */
		destroy_sqldbinstance(((ldap_instance_t *)dbdata)->db);
#endif /* ISC_PLATFORM_USETHREADS */

		if (((ldap_instance_t *)dbdata)->hosts != NULL)
			isc_mem_free(ns_g_mctx,
				     ((ldap_instance_t *)dbdata)->hosts);

		if (((ldap_instance_t *)dbdata)->user != NULL)
			isc_mem_free(ns_g_mctx,
				     ((ldap_instance_t *)dbdata)->user);

		if (((ldap_instance_t *)dbdata)->cred != NULL)
			isc_mem_free(ns_g_mctx,
				     ((ldap_instance_t *)dbdata)->cred);

		isc_mem_put(ns_g_mctx, dbdata, sizeof(ldap_instance_t));
	}
}

/* static dns_sdlzmethods_t dlz_ldap_enum_methods = {
	dlz_create,
	dlz_destroy,
	dlz_findzonedb,
	dlz_lookup,
	dlz_authority,
	dlz_allnodes,
	dlz_allowzonexfr,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
}; */



