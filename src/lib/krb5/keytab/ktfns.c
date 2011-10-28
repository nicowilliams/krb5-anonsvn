/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/keytab/ktfns.c */
/*
 * Copyright 2001,2008 by the Massachusetts Institute of Technology.
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

/*
 * Dispatch methods for keytab code.
 */

#ifndef LEAN_CLIENT

#include "k5-int.h"

const char * KRB5_CALLCONV
krb5_kt_get_type (krb5_context context, krb5_keytab keytab)
{
    return keytab->ops->prefix;
}

krb5_error_code KRB5_CALLCONV
krb5_kt_get_name(krb5_context context, krb5_keytab keytab, char *name,
                 unsigned int namelen)
{
    return krb5_x((keytab)->ops->get_name,(context, keytab,name,namelen));
}

krb5_error_code KRB5_CALLCONV
krb5_kt_close(krb5_context context, krb5_keytab keytab)
{
    return krb5_x((keytab)->ops->close,(context, keytab));
}

krb5_error_code KRB5_CALLCONV
krb5_kt_get_entry(krb5_context context, krb5_keytab keytab,
                  krb5_const_principal principal, krb5_kvno vno,
                  krb5_enctype enctype, krb5_keytab_entry *entry)
{
    krb5_error_code err;
    krb5_principal try_princ;
    krb5_name_canon_iterator name_canon_iter;

    if (!principal ||
	krb5_princ_type(context, principal) != KRB5_NT_SRV_HST_NEEDS_CANON) {
	err = krb5_x((keytab)->ops->get,(context, keytab, principal, vno,
					 enctype, entry));
	TRACE_KT_GET_ENTRY(context, keytab, principal, vno, enctype, err);
	return err;
    }

    err = krb5_name_canon_iterator_start(context, principal, NULL,
                                         &name_canon_iter);
    if (err)
        return err;

    do {
        err = krb5_name_canon_iterate_princ(context, &name_canon_iter,
                                            &try_princ, NULL);
        if (err)
            break;
	err = krb5_x((keytab)->ops->get,(context, keytab, principal, vno,
					 enctype, entry));
    } while (err == KRB5_KT_NOTFOUND && name_canon_iter);

    if (err != KRB5_KT_NOTFOUND)
        krb5_set_error_message(context, err,
                               _("Name canon failed while searching keytab"));
    krb5_free_name_canon_iterator(context, name_canon_iter);
    TRACE_KT_GET_ENTRY(context, keytab, principal, vno, enctype, err);
    return err;
}

krb5_error_code KRB5_CALLCONV
krb5_kt_start_seq_get(krb5_context context, krb5_keytab keytab,
                      krb5_kt_cursor *cursor)
{
    return krb5_x((keytab)->ops->start_seq_get,(context, keytab, cursor));
}

krb5_error_code KRB5_CALLCONV
krb5_kt_next_entry(krb5_context context, krb5_keytab keytab,
                   krb5_keytab_entry *entry, krb5_kt_cursor *cursor)
{
    return krb5_x((keytab)->ops->get_next,(context, keytab, entry, cursor));
}

krb5_error_code KRB5_CALLCONV
krb5_kt_end_seq_get(krb5_context context, krb5_keytab keytab,
                    krb5_kt_cursor *cursor)
{
    return krb5_x((keytab)->ops->end_get,(context, keytab, cursor));
}

/*
 * In a couple of places we need to get a principal name from a keytab: when
 * verifying credentials against a keytab, and when querying the name of a
 * default GSS acceptor cred.  Keytabs do not have the concept of a default
 * principal like ccaches do, so for now we just return the first principal
 * listed in the keytab, or an error if it's not iterable.  In the future we
 * could consider elevating this to a public API and giving keytab types an
 * operation to return a default principal, and maybe extending the file format
 * and tools to support it.  Returns KRB5_KT_NOTFOUND if the keytab is empty
 * or non-iterable.
 */
krb5_error_code
k5_kt_get_principal(krb5_context context, krb5_keytab keytab,
                    krb5_principal *princ_out)
{
    krb5_error_code ret;
    krb5_kt_cursor cursor;
    krb5_keytab_entry kte;

    *princ_out = NULL;
    if (keytab->ops->start_seq_get == NULL)
        return KRB5_KT_NOTFOUND;
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret)
        return ret;
    ret = krb5_kt_next_entry(context, keytab, &kte, &cursor);
    (void)krb5_kt_end_seq_get(context, keytab, &cursor);
    if (ret)
        return (ret == KRB5_KT_END) ? KRB5_KT_NOTFOUND : ret;
    ret = krb5_copy_principal(context, kte.principal, princ_out);
    krb5_kt_free_entry(context, &kte);
    return ret;
}
#endif /* LEAN_CLIENT */
