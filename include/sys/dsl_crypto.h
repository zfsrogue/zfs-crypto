/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2010, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_DSL_CRYPTO_H
#define	_SYS_DSL_CRYPTO_H

#include <sys/dmu.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/zcrypt.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dsl_crypto_ctx {
	uint64_t	dcc_crypt;
	zcrypt_key_t	*dcc_wrap_key;
	boolean_t	dcc_clone_newkey;
	dsl_dataset_t	*dcc_origin_ds;
	uint64_t	dcc_salt;
} dsl_crypto_ctx_t;

int dsl_crypto_key_create(dsl_dir_t *dd, dsl_dataset_phys_t *dsphys,
    uint64_t dsobj, dsl_crypto_ctx_t *ctx, dmu_tx_t *tx);
int dsl_crypto_key_clone(dsl_dir_t *dd, dsl_dataset_phys_t *dsphys,
    uint64_t dsobj, dsl_dataset_t *clone_origin,
    dsl_crypto_ctx_t *ctx, dmu_tx_t *tx);

zfs_crypt_key_status_t dsl_dataset_keystatus(dsl_dataset_t *ds,
    boolean_t dp_config_rwlock_held);
int dsl_dataset_keystatus_byname(const char *dsname,
    zfs_crypt_key_status_t *keystatus);

int dsl_crypto_key_load(const char *dsname, zcrypt_key_t *wrappingkey);
int dsl_crypto_key_unload(const char *dsname);
int dsl_crypto_key_inherit(const char *dsname);
int dsl_crypto_key_new(const char *dsname);
int dsl_crypto_key_change(char *dsname, zcrypt_key_t *newkey, nvlist_t *props);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DSL_CRYPTO_H */
