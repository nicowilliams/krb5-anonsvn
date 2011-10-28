/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/sn2princ.c */
/*
 * Copyright 1991,2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/* Convert a hostname and service name to a principal in the "standard"
 * form. */

#include "k5-int.h"
#include "os-proto.h"
#include "fake-addrinfo.h"
#include <ctype.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if !defined(DEFAULT_RDNS_LOOKUP)
#define DEFAULT_RDNS_LOOKUP 1
#endif

#ifdef WSHELPER
#include <wshelper.h>
#else /* WSHELPER */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#endif /* WSHELPER */

static int
maybe_use_reverse_dns (krb5_context context, int defalt)
{
    krb5_error_code code;
    char * value = NULL;
    int use_rdns = 0;

    code = profile_get_string(context->profile, KRB5_CONF_LIBDEFAULTS,
                              KRB5_CONF_RDNS, 0, 0, &value);
    if (code)
        return defalt;

    if (value == 0)
        return defalt;

    use_rdns = _krb5_conf_boolean(value);
    profile_release_string(value);
    return use_rdns;
}

/*
 * This is the original krb5_sname_to_principal(), renamed to be a
 * helper of the new one.
 */
static
krb5_error_code
krb5_sname_to_principal_old(krb5_context context, const char *realm,
			    const char *hostname, const char *sname,
			    krb5_int32 type, krb5_boolean revlookup_ok,
			    krb5_principal *ret_princ)
{
    char **hrealms = NULL;
    char *remote_host;
    krb5_error_code retval;
    register char *cp;
    char localname[MAXHOSTNAMELEN];

#ifdef DEBUG_REFERRALS
    printf("krb5_sname_to_principal(host=%s, sname=%s, type=%d)\n",hostname,sname,type);
    printf("      name types: 0=unknown, 3=srv_host\n");
#endif

    if ((type == KRB5_NT_UNKNOWN) ||
        (type == KRB5_NT_SRV_HST)) {

        /* if hostname is NULL, use local hostname */
        if (! hostname) {
            if (gethostname(localname, MAXHOSTNAMELEN))
                return SOCKET_ERRNO;
            hostname = localname;
        }

        /* if sname is NULL, use "host" */
        if (! sname)
            sname = "host";

        /* copy the hostname into non-volatile storage */

        if (type == KRB5_NT_SRV_HST) {
            struct addrinfo *ai, hints;
            int err;
            char hnamebuf[NI_MAXHOST];

            /* Note that the old code would accept numeric addresses,
               and if the gethostbyaddr step could convert them to
               real hostnames, you could actually get reasonable
               results.  If the mapping failed, you'd get dotted
               triples as realm names.  *sigh*

               The latter has been fixed in hst_realm.c, but we should
               keep supporting numeric addresses if they do have
               hostnames associated.  */

            memset(&hints, 0, sizeof(hints));
            hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
            err = getaddrinfo(hostname, 0, &hints, &ai);
            if (err) {
#ifdef DEBUG_REFERRALS
                printf("sname_to_princ: failed to canonicalize %s; using as-is", hostname);
#endif
            }
            remote_host = strdup((ai && ai->ai_canonname) ? ai->ai_canonname : hostname);
            if (!remote_host) {
                freeaddrinfo(ai);
                return ENOMEM;
            }

            if ((!err) && revlookup_ok &&
		maybe_use_reverse_dns(context, DEFAULT_RDNS_LOOKUP)) {
                /*
                 * Do a reverse resolution to get the full name, just in
                 * case there's some funny business going on.  If there
                 * isn't an in-addr record, give up.
                 */
                /* XXX: This is *so* bogus.  There are several cases where
                   this won't get us the canonical name of the host, but
                   this is what we've trained people to expect.  We'll
                   probably fix it at some point, but let's try to
                   preserve the current behavior and only shake things up
                   once when it comes time to fix this lossage.  */
                err = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                                  hnamebuf, sizeof(hnamebuf), 0, 0, NI_NAMEREQD);
                freeaddrinfo(ai);
                if (err == 0) {
                    free(remote_host);
                    remote_host = strdup(hnamebuf);
                    if (!remote_host)
                        return ENOMEM;
                }
            } else
                freeaddrinfo(ai);
        } else /* type == KRB5_NT_UNKNOWN */ {
            remote_host = strdup(hostname);
        }
        if (!remote_host)
            return ENOMEM;
#ifdef DEBUG_REFERRALS
        printf("sname_to_princ: hostname <%s> after rdns processing\n",remote_host);
#endif

        if (type == KRB5_NT_SRV_HST)
            for (cp = remote_host; *cp; cp++)
                if (isupper((unsigned char) (*cp)))
                    *cp = tolower((unsigned char) (*cp));

        /*
         * Windows NT5's broken resolver gratuitously tacks on a
         * trailing period to the hostname (at least it does in
         * Beta2).  Find and remove it.
         */
        if (remote_host[0]) {
            cp = remote_host + strlen(remote_host)-1;
            if (*cp == '.')
                *cp = 0;
        }

	if (!realm) {
	    if ((retval = krb5_get_host_realm(context, remote_host,
					      &hrealms))) {
		free(remote_host);
		return retval;
	    }
	    if (!hrealms[0]) {
		free(remote_host);
		krb5_xfree(hrealms);
		return KRB5_ERR_HOST_REALM_UNKNOWN;
	    }
	    realm = hrealms[0];
#ifdef DEBUG_REFERRALS
	    printf("sname_to_princ:  realm <%s> after krb5_get_host_realm\n", realm);
#endif
	}

        retval = krb5_build_principal(context, ret_princ, strlen(realm),
                                      realm, sname, remote_host,
                                      (char *)0);
        if (retval == 0)
            (*ret_princ)->type = type;

#ifdef DEBUG_REFERRALS
        printf("krb5_sname_to_principal returning\n");
        printf("realm: <%s>, sname: <%s>, remote_host: <%s>\n",
               realm,sname,remote_host);
        krb5int_dbgref_dump_principal("krb5_sname_to_principal",*ret_princ);
#endif

        free(remote_host);

        krb5_free_host_realm(context, hrealms);
        return retval;
    } else {
        return KRB5_SNAME_UNSUPP_NAMETYPE;
    }
}

/* XXX NEW, merge */

typedef enum krb5_name_canon_rule_type {
	KRB5_NCRT_BOGUS = 0,
	KRB5_NCRT_AS_IS,
	KRB5_NCRT_QUALIFY,
	KRB5_NCRT_RES_SEARCHLIST,
	KRB5_NCRT_NSS
} krb5_name_canon_rule_type;

struct krb5_name_canon_rule {
	krb5_name_canon_rule next;
	krb5_name_canon_rule_type type;
	krb5_name_canon_rule_options options;
	char *domain;
	char *realm;
	unsigned int mindots;
};

static krb5_error_code get_name_canon_rules(krb5_context context, krb5_name_canon_rule *rules);
static void free_name_canon_rules(krb5_context context, krb5_name_canon_rule rules);

/**
 * Create a principal for the given service running on the given
 * hostname. If KRB5_NT_SRV_HST is used, the hostname is canonicalized
 * according the configured name canonicalization rules, with
 * canonicalization delayed in some cases.  One rule involves DNS, which
 * is insecure unless DNSSEC is used, but we don't use DNSSEC-capable
 * resolver APIs here, so that if DNSSEC is used we wouldn't know it.
 *
 * Canonicalization is immediate (not delayed) only when there is only
 * one canonicalization rule and that rule indicates that we should do a
 * host lookup by name (i.e., DNS).
 *
 * @param context A Kerberos context.
 * @param hostname hostname to use
 * @param sname Service name to use
 * @param type name type of pricipal, use KRB5_NT_SRV_HST or KRB5_NT_UNKNOWN.
 * @param ret_princ return principal, free with krb5_free_principal().
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

krb5_error_code KRB5_CALLCONV
krb5_sname_to_principal(krb5_context context,
			const char *hostname,
			const char *sname,
			int32_t type,
			krb5_principal *ret_princ)
{
    char *realm, *remote_host;
    krb5_error_code retval;
    register char *cp;
    char localname[MAXHOSTNAMELEN];

    if ((type != KRB5_NT_UNKNOWN) &&
	(type != KRB5_NT_SRV_HST))
	return KRB5_SNAME_UNSUPP_NAMETYPE;

    /* if hostname is NULL, use local hostname */
    if (!hostname) {
	if (gethostname(localname, MAXHOSTNAMELEN))
	    return errno;
	hostname = localname;
    }

    /* if sname is NULL, use "host" */
    if (!sname)
	sname = "host";

    remote_host = strdup(hostname);
    if (!remote_host)
	return krb5_enomem(context);

    if (type == KRB5_NT_SRV_HST) {
	krb5_name_canon_rule rules;

	/* Lower-case the hostname, because that's the convention */
	for (cp = remote_host; *cp; cp++)
	    if (isupper((int) (*cp)))
		*cp = tolower((int) (*cp));

	retval = get_name_canon_rules(context, &rules);
	if (retval) {
	    TRACE_NAME_CANON_RULE_ERROR(context, retval);
	    return retval;
	}
	if (rules->type == KRB5_NCRT_NSS && rules->next == NULL) {
	    TRACE_NAME_CANON_RULE_WILL_USE_NSS(context);
	    /* For the default rule we'll just canonicalize here */
	    retval = krb5_sname_to_principal_old(context, NULL,
						 remote_host, sname,
						 KRB5_NT_SRV_HST,
						 0, /* XXX */
						 ret_princ);
	    free(remote_host);
	    free_name_canon_rules(context, rules);
	    return retval;
	}
	free_name_canon_rules(context, rules);
    }

    /* Trailing dot(s) would be bad */
    if (remote_host[0]) {
	cp = remote_host + strlen(remote_host)-1;
	if (*cp == '.')
		*cp = '\0';
    }

    realm = ""; /* "Referral realm" -- borrowed from newer MIT */

    retval = krb5_build_principal(context, ret_princ, strlen(realm),
				  realm, sname, remote_host,
				  (char *)0);

    if (type == KRB5_NT_SRV_HST) {
	/*
	 * Hostname canonicalization is done elsewhere (in
	 * krb5_get_credentials() and krb5_kt_get_entry()).
	 *
	 * We use special magic to indicate to those functions that
	 * this principal name requires canonicalization.
	 */
	(*ret_princ)->type = KRB5_NT_SRV_HST_NEEDS_CANON;

	TRACE_SN2P_DELAYED_CANON(context, sname, remote_host);
    }

    free(remote_host);
    return retval;
}

/*
 * Helper function to parse name canonicalization rule tokens.
 */
static
krb5_error_code
rule_parse_token(krb5_context context, krb5_name_canon_rule rule,
		 const char *tok)
{
    long int n;

    /*
     * Rules consist of a sequence of tokens, some of which indicate
     * what type of rule the rule is, and some of which set rule options
     * or ancilliary data.  First rule type token wins.
     */
    /* Rule type tokens: */
    if (strcmp(tok, "as-is") == 0) {
	if (rule->type == KRB5_NCRT_BOGUS)
	    rule->type = KRB5_NCRT_AS_IS;
    } else if (strcmp(tok, "qualify") == 0) {
	if (rule->type == KRB5_NCRT_BOGUS)
	    rule->type = KRB5_NCRT_QUALIFY;
    } else if (strcmp(tok, "use-resolver-searchlist") == 0) {
	if (rule->type == KRB5_NCRT_BOGUS)
	    rule->type = KRB5_NCRT_RES_SEARCHLIST;
    } else if (strcmp(tok, "nss") == 0) {
	if (rule->type == KRB5_NCRT_BOGUS)
	    rule->type = KRB5_NCRT_NSS;
    /* Rule options: */
    } else if (strcmp(tok, "secure") == 0) {
	rule->options |= KRB5_NCRO_SECURE;
    } else if (strcmp(tok, "ccache_only") == 0) {
	rule->options |= KRB5_NCRO_GC_ONLY;
    } else if (strcmp(tok, "no_referrals") == 0) {
	rule->options |= KRB5_NCRO_NO_REFERRALS;
	rule->options &= ~KRB5_NCRO_USE_REFERRALS;
    } else if (strcmp(tok, "use_referrals") == 0) {
	rule->options |= KRB5_NCRO_USE_REFERRALS;
	rule->options &= ~KRB5_NCRO_NO_REFERRALS;
    /* Rule ancilliary data: */
    } else if (strncmp(tok, "domain=", strlen("domain=")) == 0) {
	free(rule->domain);
	rule->domain = strdup(tok + strlen("domain="));
	if (!rule->domain)
	    return krb5_enomem(context);
    } else if (strncmp(tok, "realm=", strlen("realm=")) == 0) {
	free(rule->realm);
	rule->realm = strdup(tok + strlen("realm="));
	if (!rule->realm)
	    return krb5_enomem(context);
    } else if (strncmp(tok, "mindots=", strlen("mindots=")) == 0) {
	errno = 0;
	n = strtol(tok + strlen("mindots="), NULL, 10);
	if (errno == 0 && n > 0 && n < 8)
	    rule->mindots = n;
    }
    /* ignore bogus tokens; it's not like we can print to stderr */
    /* XXX Trace bogus tokens! */
    return 0;
}

/*
 * This helper function expands the DNS search list rule into qualify
 * rules, one for each domain in the resolver search list.
 */
static
krb5_error_code
expand_search_list(krb5_context context, krb5_name_canon_rule *r, size_t *n,
		   size_t insert_point)
{
#if defined(HAVE_RES_NINIT) || defined(HAVE_RES_SEARCH)
#ifdef USE_RES_NINIT
    struct __res_state statbuf;
#endif /* USE_RES_NINIT */
    krb5_name_canon_rule_options opts;
    krb5_name_canon_rule new_r;
    char **dnsrch;
    char **domains = NULL;
    size_t srch_list_len;
    size_t i;
    int retval;

    /* Sanitize */
    assert((*n) > insert_point);
    free((*r)[insert_point].domain);
    free((*r)[insert_point].realm);
    (*r)[insert_point].domain = NULL;
    (*r)[insert_point].realm = NULL;
    opts = (*r)[insert_point].options;

    /*
     * Would it be worthwhile to move this into context->os_context and
     * krb5_os_init_context()?
     */
#ifdef USE_RES_NINIT
    retval = res_ninit(&statbuf);
    if (retval)
	return ENOENT; /* XXX Create a better error */
    dnsrch = statbuf.dnsrch;
    srch_list_len = sizeof (statbuf.dnsrch) / sizeof (*statbuf.dnsrch);
#else
    retval = res_init();
    if (retval)
	return ENOENT; /* XXX Create a better error */
    dnsrch = _res.dnsrch;
    srch_list_len = sizeof (_res.dnsrch) / sizeof (*_res.dnsrch);
#endif /* USE_RES_NINIT */

    for (i = 0; i < srch_list_len; i++) {
	if (!dnsrch || dnsrch[i] == NULL) {
	    srch_list_len = i;
	    break;
	}
    }

    if (srch_list_len == 0) {
	/* Invalidate this entry and return */
	(*r)[insert_point].type = KRB5_NCRT_BOGUS;
	return 0;
    }

    /*
     * Pre-strdup() the search list so the realloc() below is the last
     * point at which we can fail with ENOMEM.
     */
    domains = calloc(srch_list_len, sizeof (*domains));
    if (domains == NULL)
	return krb5_enomem(context);
    for (i = 0; i < srch_list_len; i++) {
	if ((domains[i] = strdup(dnsrch[i])) == NULL) {
	    for (i--; i >= 0; i--)
		free(domains[i]);
	    return krb5_enomem(context);
	}
    }

    if (srch_list_len > 1) {
	/* The -1 here is because we re-use this rule as one of the new rules */
	new_r = realloc(*r, sizeof (**r) * ((*n) + srch_list_len - 1));
	if (new_r == NULL) {
	    for (i = 0; i < srch_list_len; i++)
		free(domains[i]);
	    free(domains);
	    return krb5_enomem(context);
	}
    } else {
	new_r = *r; /* srch_list_len == 1 */
    }

    /* Make room for the new rules */
    if (insert_point < (*n) - 1) {
	/*
	 * Move the rules that follow the search list rule down by
	 * srch_list_len - 1 rules.
	 */
	memmove(&new_r[insert_point + srch_list_len],
		&new_r[insert_point + 1],
		sizeof (new_r[0]) * ((*n) - (insert_point + 1)));
    }

    /*
     * Clear in case the search-list rule is at the end of the rules;
     * realloc() won't have done this for us.
     */
    memset(&new_r[insert_point], 0, sizeof (new_r[0]) * srch_list_len);

    /* Setup the new rules */
    for (i = 0; i < srch_list_len; i++) {
	TRACE_NAME_CANON_RULE_SEARCHLIST_INS(context, dnsrch[i]);
	new_r[insert_point + i].type = KRB5_NCRT_QUALIFY;
	new_r[insert_point + i].domain = domains[i];
	new_r[insert_point + i].options = new_r[insert_point].options;
    }
    free(domains);

    *r = new_r;
    *n += srch_list_len - 1; /* -1 because we're replacing one rule */

#ifdef USE_RES_NINIT
    res_ndestroy(&statbuf);
#endif /* USE_RES_NINIT */

#else
    /* No resolver API by which to get search list -> use name service */
    if ((*r)[insert_point].options & KRB5_NCRO_SECURE)
	return ENOTSUP;
    (*r)[insert_point].type = KRB5_NCRT_NSS;
#endif /* HAVE_RES_NINIT || HAVE_RES_SEARCH */

    return 0;
}

/*
 * Helper function to parse name canonicalization rules.
 */
static
krb5_error_code
parse_name_canon_rules(krb5_context context, char **rulestrs,
		       krb5_name_canon_rule *rules)
{
    krb5_error_code retval;
    char *tok;
    char *cp;
    char **cpp;
    size_t n = 0;
    size_t i, k;
    krb5_name_canon_rule r;

    for (cpp = rulestrs; *cpp; cpp++)
	n++;

    if ((r = calloc(n, sizeof (*r))) == NULL)
	return krb5_enomem(context);

    /* This code is written without use of strtok_r() :( */
    for (i = 0, k = 0; i < n; i++) {
	cp = rulestrs[i];
	do {
	    tok = cp;
	    cp = strpbrk(cp, ":");
	    if (cp)
		*cp++ = '\0'; /* delimit token */
	    retval = rule_parse_token(context, &r[k], tok);
	} while (cp && *cp);
	/* Loosely validate parsed rule */
	if (r[k].type == KRB5_NCRT_BOGUS ||
	    (r[k].type == KRB5_NCRT_QUALIFY && !r[k].domain) ||
	    (r[k].type == KRB5_NCRT_NSS && (r[k].domain || r[k].realm))) {
	    /* Invalid rule; mark it so and clean up */
	    r[k].type = KRB5_NCRT_BOGUS;
	    free(r[k].realm);
	    free(r[k].domain);
	    r[k].realm = NULL;
	    r[k].domain = NULL;
	    /* XXX Trace this! */
	    continue; /* bogus rule */
	}
	k++; /* good rule */
    }

    /* Expand search list rules */
    for (i = 0; i < n; i++) {
	if (r[i].type != KRB5_NCRT_RES_SEARCHLIST)
	    continue;
	retval = expand_search_list(context, &r, &n, i);
	if (retval)
	    return retval;
    }

    /* The first rule has to be valid */
    k = n;
    for (i = 0; i < n; i++) {
	if (r[i].type != KRB5_NCRT_BOGUS) {
	    k = i;
	    break;
	}
    }
    if (k > 0 && k < n) {
	r[0] = r[k];
	memset(&r[k], 0, sizeof (r[k])); /* KRB5_NCRT_BOGUS is 0 */
    }

    /* Setup next pointers */
    for (i = 1, k = 0; i < n; i++) {
	if (r[i].type == KRB5_NCRT_BOGUS)
	    continue;
	r[k].next = &r[i];
	k++;
    }

    *rules = r;
    return 0; /* We don't communicate bad rule errors here */
}

static const char *rule_type_strs[] = {
    "invalid",
    "as-is",
    "qualify",
    "use-resolver-searchlist",
    "nss"
};

/**
 * This function returns an array of host-based service name
 * canonicalization rules.  The array of rules is organized as a list.
 * See the definition of krb5_name_canon_rule.
 *
 * @param context A Kerberos context.
 * @param rules   Output location for array of rules.
 */
static krb5_error_code
get_name_canon_rules(krb5_context context, krb5_name_canon_rule *rules)
{
    krb5_error_code retval;
    profile_t profile;
    const char *names[5];
    char **values = NULL;
    char *realm = NULL;

    *rules = NULL;
    retval = krb5_get_default_realm(context, &realm);
    if (retval == KRB5_CONFIG_NODEFREALM || retval == KRB5_CONFIG_CANTOPEN)
	realm = NULL;
    else if (retval)
	return retval;

    profile = context->profile;
    names[0] = "libdefaults";

again:
    if (realm) {
	names[1] = realm;
	names[2] = "name_canon_rules";
	names[3] = 0;
    } else {
	names[1] = "name_canon_rules";
	names[2] = 0;
    }

    retval = profile_get_values(profile, names, &values);
    if (realm && (retval || !values || !values[0])) {
	free(realm);
	realm = NULL;
	goto again;
    }

    if (!values || !values[0]) {
	/* Default rule: do the dreaded getaddrinfo()/getnameinfo() dance */
	if ((*rules = calloc(1, sizeof (**rules))) == NULL)
	    return krb5_enomem(context);
	(*rules)->type = KRB5_NCRT_NSS;
	return 0;
    }

    retval = parse_name_canon_rules(context, values, rules);
    profile_free_list(values);
    if (retval)
	return retval;

    {
	size_t k;
	krb5_name_canon_rule r;
	for (k = 0, r = *rules; r; r = r->next, k++) {
	    TRACE_NAME_CANON_RULE(context, k, rule_type_strs[r->type],
				  r->options, r->mindots,
				  r->domain ? r->domain : "<none>",
				  r->realm ? r->realm : "<none>");
	}
    }

    if ((*rules)[0].type != KRB5_NCRT_BOGUS)
	return 0; /* success! */
    free(*rules);
    *rules = NULL;
    /* fall through to return default rule */
    TRACE_NAME_CANON_RULE_ALL_INVALID(context);
    return 0;
}

static
krb5_error_code
get_host_realm(krb5_context context, const char *hostname, char **realm)
{
    krb5_error_code retval;
    char **hrealms = NULL;

    *realm = NULL;
    if ((retval = krb5_get_host_realm(context, hostname, &hrealms)))
	return retval;
    if (!hrealms)
	return KRB5_ERR_HOST_REALM_UNKNOWN; /* krb5_set_error() already done */
    if (!hrealms[0]) {
	krb5_free_host_realm(context, hrealms);
	return KRB5_ERR_HOST_REALM_UNKNOWN; /* krb5_set_error() already done */
    }
    *realm = strdup(hrealms[0]);
    krb5_free_host_realm(context, hrealms);
    return 0;
}

/**
 * Apply a name canonicalization rule to a principal.
 *
 * @param context   Kerberos context
 * @param rule	    name canon rule
 * @param in_princ  principal name
 * @param out_print resulting principal name
 * @param rule_opts options for this rule
 */
static
krb5_error_code
apply_name_canon_rule(krb5_context context, krb5_name_canon_rule rule,
	krb5_const_principal in_princ, krb5_principal *out_princ,
	krb5_name_canon_rule_options *rule_opts)
{
    krb5_error_code retval;
    unsigned int ndots = 0;
    char *realm = NULL;
    char *sname = NULL;
    char *hostname = NULL;
    char *new_hostname;
    const char *cp;
    krb5_data *data;


    assert(in_princ->type == KRB5_NT_SRV_HST_NEEDS_CANON);
    *out_princ = NULL;
    if (rule_opts)
	*rule_opts = 0;
    if (rule->type == KRB5_NCRT_BOGUS)
	return 0; /* rule doesn't apply */
    /*
     * XXX We should really copy Heimdal's krb5_principal_get_comp_string()
     * or else ensure that we have a strndup(), because this is really
     * painful.
     */
    data = krb5_princ_component(context, in_princ, 0);
    sname = malloc(data->length + 1);
    if (sname == NULL)
	return ENOMEM;
    memcpy(sname, data->data, data->length);
    sname[data->length] = '\0';
    data = krb5_princ_component(context, in_princ, 1);
    hostname = malloc(data->length + 1);
    if (hostname == NULL) {
	free(sname);
	return ENOMEM;
    }
    TRACE_NAME_CANON_RULE_APPLY(context, rule_type_strs[rule->type], hostname);
    if (rule_opts)
	*rule_opts = rule->options;
    retval = 0;
    switch (rule->type) {
    case KRB5_NCRT_AS_IS:
	if (rule->mindots > 0) {
	    for (cp = strchr(hostname, '.'); cp && *cp; cp = strchr(cp, '.'))
		ndots++;
	    if (ndots < rule->mindots)
		goto out; /* *out_princ == NULL; rule doesn't apply */
	}
	if (rule->domain) {
	    cp = strstr(hostname, rule->domain);
	    if (cp == NULL)
		goto out; /* *out_princ == NULL; rule doesn't apply */
	    if (cp != hostname && cp[-1] != '.')
		goto out;
	}
	/* Rule matches, copy princ with hostname as-is, with normal magic */
	realm = rule->realm;
	if (!realm) {
	    retval = get_host_realm(context, hostname, &realm);
	    if (retval)
		goto out;
	}
	retval = krb5_build_principal(context, out_princ,
				      strlen(rule->realm),
				      rule->realm, sname, hostname,
				      (char *)0);
	goto out;
	break;
    case KRB5_NCRT_QUALIFY:
	/*
	 * Note that we should never get these rules even if specified
	 * in krb5.conf.  See rule parser.
	 */
	assert(rule->domain != NULL);
	cp = strchr(hostname, '.');
	if (cp && (cp = strstr(cp, rule->domain))) {
	    new_hostname = strdup(hostname);
	    if (new_hostname == NULL) {
		retval = krb5_enomem(context);
		goto out;
	    }

	} else {
	    size_t len;

	    len = strlen(hostname) + strlen(rule->domain) + 2;
	    if ((new_hostname = malloc(len)) == NULL) {
		retval = krb5_enomem(context);
		goto out;
	    }
	    /* We use strcpy() and strcat() for portability for now */
	    strcpy(new_hostname, hostname);
	    if (rule->domain[0] != '.')
		strcat(new_hostname, ".");
	    strcat(new_hostname, rule->domain);
	}
	realm = rule->realm;
	if (!realm) {
	    retval = get_host_realm(context, new_hostname, &realm);
	    if (retval)
		goto out;
	}
	retval = krb5_build_principal(context, out_princ,
				      strlen(realm), realm,
				      sname, new_hostname, (char *)0);
	free(new_hostname);
	goto out;
	break;
    case KRB5_NCRT_NSS:
	retval = krb5_sname_to_principal_old(context, rule->realm,
					     hostname, sname,
					     KRB5_NT_SRV_HST,
					     0, /* XXX */
					     out_princ);
	if (rule->next != NULL &&
	    (retval == KRB5_ERR_BAD_HOSTNAME ||
	     retval == KRB5_ERR_HOST_REALM_UNKNOWN))
	    /*
	     * Bad hostname / realm unknown -> rule inapplicable if
	     * there's more rules.  If it's the last rule then we want
	     * to return all errors from krb5_sname_to_principal_old()
	     * here.
	     */
	    retval = 0;
	goto out;
	break;
    default:
	/* Can't happen, but we need this to shut up gcc */
	break;
    }

out:
    if (!retval && *out_princ)
	TRACE_NAME_CANON_RULE_APPLY_RESULT(context, *out_princ);
    else if (!retval)
	TRACE_NAME_CANON_RULE_NOT_APPLICABLE(context);
    else
	TRACE_NAME_CANON_RULE_APPLY_ERROR(context, retval);
    if (realm != rule->realm)
	free(realm);
    if (*out_princ)
	(*out_princ)->type = KRB5_NT_SRV_HST;
    if (retval)
	krb5_set_error_message(context, retval,
			       _("Name canon rule application failed"));
    return retval;
}

/**
 * Free name canonicalization rules
 */
static void
free_name_canon_rules(krb5_context context, krb5_name_canon_rule rules)
{
    krb5_name_canon_rule r;

    for (r = rules; r; r = r->next) {
	free(r->realm);
	free(r->domain);
    }

    free(rules);
    rules = NULL;
}

struct krb5_name_canon_iterator {
    krb5_name_canon_rule	rules;
    krb5_name_canon_rule	rule;
    krb5_const_principal	in_princ;
    krb5_principal		tmp_princ;
    krb5_creds			*creds;
    int				is_trivial;
    int				done;
};

/**
 * Initialize name canonicalization iterator.
 *
 * @param context   Kerberos context
 * @param in_princ  principal name to be canonicalized OR
 * @param in_creds  credentials whose server is to be canonicalized
 * @param iter	    output iterator object
 */
krb5_error_code KRB5_CALLCONV
krb5_name_canon_iterator_start(krb5_context context,
			       krb5_const_principal in_princ,
			       krb5_creds *in_creds,
			       krb5_name_canon_iterator *iter)
{
    krb5_error_code retval;
    krb5_name_canon_iterator state;
    krb5_const_principal princ;

    *iter = NULL;

    state = calloc(1, sizeof (*state));
    if (state == NULL)
	return krb5_enomem(context);
    princ = in_princ ? in_princ : in_creds->server;

    if (princ->type != KRB5_NT_SRV_HST_NEEDS_CANON) {
	/*
	 * Name needs no canon -> trivial iterator; we still want an
	 * iterator just so as to keep callers simple.
	 */
	state->is_trivial = 1;
	state->creds = in_creds;
    } else {
	retval = get_name_canon_rules(context, &state->rules);
	if (retval) goto err;
	state->rule = state->rules;
    }

    state->in_princ = princ;
    if (in_creds) {
	retval = krb5_copy_creds(context, in_creds, &state->creds);
	if (retval) goto err;
	state->tmp_princ = state->creds->server; /* so we don't leak */
    }

    *iter = state;
    return 0;

err:
    krb5_free_name_canon_iterator(context, state);
    return krb5_enomem(context);
}

/*
 * Helper for name canon iteration.
 */
static krb5_error_code
krb5_name_canon_iterate(krb5_context context,
			krb5_name_canon_iterator *iter,
			krb5_name_canon_rule_options *rule_opts)
{
    krb5_error_code retval;
    krb5_name_canon_iterator state = *iter;

    if (!state)
	return 0;
    if (state->done) {
	krb5_free_name_canon_iterator(context, state);
	*iter = NULL;
	return 0;
    }

    if (state->is_trivial && !state->done) {
	state->done = 1;
	return 0;
    }

    krb5_free_principal(context, state->tmp_princ);
    do {
	retval = apply_name_canon_rule(context, state->rule,
	    state->in_princ, &state->tmp_princ, rule_opts);
	if (retval)
	    return retval;
	state->rule = state->rule->next;
    } while (state->rule != NULL && state->tmp_princ == NULL);

    if (state->tmp_princ == NULL) {
	krb5_free_name_canon_iterator(context, state);
	*iter = NULL;
	return 0;
    }
    if (state->creds)
	state->creds->server = state->tmp_princ;
    if (state->rule == NULL)
	state->done = 1;
    return 0;
}

/**
 * Iteratively apply name canon rules, outputing a principal and rule
 * options each time.  Iteration completes when the @iter is NULL on
 * return or when an error is returned.  Callers must free the iterator
 * if they abandon it mid-way.
 *
 * @param context   Kerberos context
 * @param iter	    name canon rule iterator (input/output)
 * @param try_princ output principal name
 * @param rule_opts output rule options
 */
krb5_error_code KRB5_CALLCONV
krb5_name_canon_iterate_princ(krb5_context context,
			      krb5_name_canon_iterator *iter,
			      krb5_principal *try_princ,
			      krb5_name_canon_rule_options *rule_opts)
{
    krb5_error_code retval;

    *try_princ = NULL;
    retval = krb5_name_canon_iterate(context, iter, rule_opts);
    if (*iter)
	*try_princ = (*iter)->tmp_princ;
    return retval;
}

/**
 * Iteratively apply name canon rules, outputing a krb5_creds and rule
 * options each time.  Iteration completes when the @iter is NULL on
 * return or when an error is returned.  Callers must free the iterator
 * if they abandon it mid-way.
 *
 * @param context   Kerberos context
 * @param iter	    name canon rule iterator
 * @param try_creds output krb5_creds
 * @param rule_opts output rule options
 */
krb5_error_code KRB5_CALLCONV
krb5_name_canon_iterate_creds(krb5_context context,
			      krb5_name_canon_iterator *iter,
			      krb5_creds **try_creds,
			      krb5_name_canon_rule_options *rule_opts)
{
    krb5_error_code retval;

    *try_creds = NULL;
    retval = krb5_name_canon_iterate(context, iter, rule_opts);
    if (*iter)
	*try_creds = (*iter)->creds;
    return retval;
}

/**
 * Free a name canonicalization rule iterator.
 */
void KRB5_CALLCONV
krb5_free_name_canon_iterator(krb5_context context,
			      krb5_name_canon_iterator iter)
{
    if (iter == NULL)
	return;
    if (!iter->is_trivial) {
	if (iter->creds) {
	    krb5_free_creds(context, iter->creds);
	    iter->tmp_princ = NULL;
	}
	if (iter->tmp_princ)
	    krb5_free_principal(context, iter->tmp_princ);
	free_name_canon_rules(context, iter->rules);
    }
    free(iter);
}

