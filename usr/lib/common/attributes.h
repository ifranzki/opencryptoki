/*
 * COPYRIGHT (c) International Business Machines Corp. 2012-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * OpenCryptoki ICSF token - LDAP functions
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *
 */

#ifndef _ATTRIBUTES_H_
#define _ATTRIBUTES_H_

#include "pkcs11types.h"

void free_attribute_array(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len);

void cleanse_and_free_attribute_array(CK_ATTRIBUTE_PTR attrs,
                                      CK_ULONG attrs_len);
void cleanse_and_free_attribute_array2(CK_ATTRIBUTE_PTR attrs,
                                       CK_ULONG attrs_len,
                                       CK_BBOOL free_array);

CK_RV dup_attribute_array(const CK_ATTRIBUTE *orig, CK_ULONG orig_len,
                          CK_ATTRIBUTE_PTR *p_dest, CK_ULONG *p_dest_len);

CK_RV dup_attribute_array_no_alloc(const CK_ATTRIBUTE *orig, CK_ULONG num_attrs,
                                   CK_ATTRIBUTE_PTR dest);

const CK_ATTRIBUTE *get_attribute_by_type(const CK_ATTRIBUTE *attrs,
                                          CK_ULONG attrs_len, CK_ULONG type);

CK_RV get_ulong_attribute_by_type(const CK_ATTRIBUTE *attrs,
                                  CK_ULONG attrs_len, CK_ULONG type,
                                  CK_ULONG *value);

CK_RV get_bool_attribute_by_type(const CK_ATTRIBUTE *attrs,
                                 CK_ULONG attrs_len, CK_ULONG type,
                                 CK_BBOOL *value);

CK_RV add_to_attribute_array(CK_ATTRIBUTE_PTR *p_attrs,
                             CK_ULONG_PTR p_attrs_len, CK_ULONG type,
                             const CK_BYTE *value, CK_ULONG value_len);

CK_BBOOL compare_attribute(const CK_ATTRIBUTE *a1, const CK_ATTRIBUTE *a2);

CK_BBOOL compare_attribute_array(const CK_ATTRIBUTE *a1, CK_ULONG a1_len,
                                 const CK_ATTRIBUTE *a2, CK_ULONG a2_len);

CK_RV validate_attribute_array(const CK_ATTRIBUTE *attrs, CK_ULONG num_attrs);

#ifdef DEBUG
/* Debug function: dump one attribute */
void dump_attr(const CK_ATTRIBUTE *a);
#define TRACE_DEBUG_DUMPATTR(x) dump_attr(x)
#else
#define TRACE_DEBUG_DUMPATTR(...)
#endif

#endif
