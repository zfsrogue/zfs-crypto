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
 * Copyright (c) 2007, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_ZIO_CRYPT_H
#define	_SYS_ZIO_CRYPT_H

#include <sys/zcrypt.h>
#include <sys/zio.h>
#include <sys/crypto/api.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Table of supported crypto algorithms, modes and keylengths.
 */
typedef struct zio_crypt_info {
	crypto_mech_name_t	ci_mechname;
	size_t			ci_keylen;
	size_t			ci_maclen;
	size_t			ci_zil_maclen;
	boolean_t		ci_dedupsafe;
	char			*ci_name;
} zio_crypt_info_t;

extern zio_crypt_info_t zio_crypt_table[ZIO_CRYPT_FUNCTIONS];

/*
 * Key wrapping functions.  This may get exposed as a per dataset
 * property in the future if other key wrapping algorithms are added,
 * such as using an RSA key or the NIST AES key wrap function.
 */
enum zfs_crypt_wrap {
	ZIO_CRYPT_WRAP_AES_CCM = 0,
	ZIO_CRYPT_WRAP_AES_GCM,
	ZIO_CRYPT_WRAP_FUNCTIONS,
};

typedef struct zio_crypt_wrap_info {
	crypto_mech_name_t	cwi_mechname;
	size_t			cwi_ivlen;
	size_t			cwi_maclen;
	char			*cwi_name;
} zio_crypt_wrap_info_t;

extern zio_crypt_wrap_info_t zio_crypt_wrap_table[ZIO_CRYPT_WRAP_FUNCTIONS];

#define	ZIO_CRYPT_DATA_IVLEN	12
#define	ZIO_CRYPT_MAX_CCM_DATA	16777215 /* Based on CCM noncesize of 12 */

#define	SET_CRYPTO_DATA(cd, buf, len)			\
	(cd).cd_format = CRYPTO_DATA_RAW;		\
	(cd).cd_offset = 0;				\
	(cd).cd_length = (len);				\
	(cd).cd_miscdata = NULL;			\
	(cd).cd_raw.iov_base = (buf);			\
	(cd).cd_raw.iov_len = (len)

enum zio_crypt zio_crypt_select(enum zio_crypt child, enum zio_crypt parent);
uint64_t zio_crypt_select_wrap(enum zio_crypt);

extern int zio_encrypt_data(int crypt, zcrypt_key_t *key, zbookmark_t *bookmark,
    uint64_t txg, int type, boolean_t dedup, void *src, uint64_t srcsize,
    void **destp, char *mac, char *iv);

extern int zio_decrypt_data(zcrypt_key_t *key, zbookmark_t *bookmark,
    uint64_t txg, int type, void *src, uint64_t srcsize, char *iv, char *mac,
    void *dest, uint64_t destsize);

extern boolean_t l2arc_encrypt_buf(spa_t *spa, dva_t *dva,
    const void* ibuf, size_t ibufsz, void *obuf);
extern boolean_t l2arc_decrypt_buf(spa_t *spa, dva_t *dva,
    void* buf, size_t bufsz);

extern int zvol_dump_encrypt(spa_t *, uint64_t, dva_t *,
    const void *buf, size_t);
extern int zvol_dump_decrypt(spa_t *, uint64_t, dva_t *,
    const void *buf, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZIO_CRYPT_H */
