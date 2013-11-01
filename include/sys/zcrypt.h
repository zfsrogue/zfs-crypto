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

#ifndef _SYS_ZCRYPT_H
#define	_SYS_ZCRYPT_H

#include <sys/zio.h>
#include <sys/crypto/api.h>
#include <sys/refcount.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * zcrypt_key_t
 *
 * We use ref counting on the key to ensure it doesn't disappear after
 * it is handed out but while it is still in use by and encrypt/decrypt.
 *
 * The refcounting is done in zcrypt_key_use/zcrypt_key_release
 * and checked in zcrypt_keystore_remove.
 */
typedef struct zcrypt_key {
	crypto_key_t		zk_key;
	crypto_ctx_template_t	zk_ctx_tmpl;
	boolean_t		zk_ctx_tmpl_valid;
	crypto_key_t		zk_mackey;
	crypto_ctx_template_t	zk_mac_ctx_tmpl;
	uint64_t		zk_crypt;
	boolean_t		zk_mac_ctx_tmpl_valid;
	refcount_t		zk_refcnt;
	uint64_t		zk_ctr;
} zcrypt_key_t;

typedef struct zcrypt_key_phys {
	uint64_t		zkp_crypt;
	uint64_t		zkp_kiv[2];
	uint64_t		zkp_key[6];	/* 256 bit key + MAC of key */
	uint64_t		zkp_miv[2];
	uint64_t		zkp_mackey[6];	/* 256 bit key + MAC of key */
} zcrypt_key_phys_t;

/*
 * ===========================================================================
 * zcrypt_keystore_t
 * ===========================================================================
 *
 * The per SPA keystore contains the following:
 * 	* L2ARC ephemeral key (zcrypt_key_t)
 * 	* AVL tree of dsl keychains and the wrapping key indexed by objset id,
 *        the wrapping key is stored in each zcrypt_keystore_node.  We need to
 *        keep the wrapping key around so that we can add new dsl keychain
 *        nodes since clones inherit the wrapping key by default.
 *
 * The dsl keychain is itself an AVL tree. Each zcrypt_keychain_node_t contains
 * the unwrapped encryption keys indexed by the txg in which it became valid.
 *
 * All of the zcrypt_keystore_t entries are protected by sk_lock including
 * insert/delete from the zcrypt_keystore level AVL tree.
 *
 * Each key (encryption & wrapping) is also reference counted.
 *
 * The zcrypt_keystore_t entries should not be modified outside of the routines
 * in this file.
 *
 * The recommended interface to the keystore outside of this file is via
 * zcrypt_key_lookup() not the zcrypt_keystore routines.
 */

typedef struct keychain_node {
	avl_node_t	dkn_link;
	uint64_t	dkn_txg;
	zcrypt_key_t	*dkn_key;
} zcrypt_keychain_node_t;

typedef struct zcrypt_keystore_node {
	avl_node_t	skn_link;
	uint64_t	skn_os;
	kmutex_t	skn_lock;
	avl_tree_t	skn_keychain;	/* of zcrypt_keychain_node_t */
	zcrypt_key_t	*skn_wrapkey;
} zcrypt_keystore_node_t;

typedef struct zcrypt_keystore {
	krwlock_t	sk_lock;
	avl_tree_t	sk_dslkeys;		/* of zcrypt_keystore_node_t */
} zcrypt_keystore_t;


/*
 * ZFS_IOC_CRYPTO key management interface.
 *
 * The size of the keydata struct element is hardcoded as the size of
 * the largest wrapping key in bytes.
 *
 * The zfs_ioc_crypto_t is only supported when embedded in a
 * zfs_cmd_t since the latter contains the information on the dataset
 * the key operation relates to.
 *
 * The current implementation only covers:
 *
 * 1. Raw key
 * 	The userland passphrase was converted to a key using PKCS#5 PBE
 * 	before being passed over the ioctl.
 * 	Or it was a raw key read from a file (or somewhere else) in userland.
 * 		zic_keydatalen is the length in *BYTES*
 * 		zic_keydata is the raw key value
 *
 * Longer term this needs to cover the following key types:
 *
 * 2. Key description + PIN (Phase 2)
 * 	The PIN to be used to login to the token described in the
 * 	kek property.
 * 		zic_keydatalen is the PIN length
 * 		zic_keydata is the PIN value
 * 	The token object locator info is stored in keysource property.
 *
 * To support all of the above 4k is the maximum we would need likely need
 * since the largest key we need to deal with is a 4096 bit RSA key.
 *
 * Key management commands cover the following cases:
 *
 * 1. Load of wrapping key - including inherit from parent
 * 2. Unload of wrapping key
 * 3. Change of wrapping key
 * 4. New data encryption key
 *
 * zfs_ioc_crypto_t must be same size in 32 & 64 compilation environments
 * since it is passed over the /dev/zfs ioctl, it must also be 64 bit
 * aligned.
 *
 */

#define	ZFS_IOC_MAXKEYLEN	256

typedef struct zfs_ioc_crypt {
	uint64_t 		zic_cmd;	/* zfs_ioc_crypto_cmd_t */
	uint64_t		zic_crypt;
	uint64_t		zic_clone_newkey;
	uint64_t		zic_keydatalen;
	unsigned char	zic_keydata[ZFS_IOC_MAXKEYLEN];
	unsigned char	zic_inherit_dsname[MAXNAMELEN];
	uint64_t		zic_salt;
} zfs_ioc_crypto_t;

/*
 * keystatus is partially persistent and partially temporary.
 * The are two states that persist on disk none and defined.
 * If the on disk state is defined we return the appropriate "in memory"
 * state of available or unavailable depending on wither or not the
 * key is in the keystore.
 *
 * Old pool versions and datasets with encryption=off always have
 * a keystatus of undefined.
 */
typedef enum zfs_crypt_key_status {
	ZFS_CRYPT_KEY_NONE = 0,		/* Wrapping key N/A(DISK) */
	ZFS_CRYPT_KEY_DEFINED,		/* Wrapping key defined (DISK) */
	ZFS_CRYPT_KEY_UNAVAILABLE,	/* Key defined, but not loaded (MEM) */
	ZFS_CRYPT_KEY_AVAILABLE		/* Key defined and loaded (MEM) */
} zfs_crypt_key_status_t;

zcrypt_key_t *zcrypt_key_allocate(void);
void zcrypt_key_free(zcrypt_key_t *key);
zcrypt_key_t *zcrypt_key_gen(int crypt);
zcrypt_key_t *zcrypt_key_copy(zcrypt_key_t *src);
void zcrypt_key_compare(zcrypt_key_t *l, zcrypt_key_t *r);

void zcrypt_key_hold(zcrypt_key_t *key, void *tag);
void zcrypt_key_release(zcrypt_key_t *key, void *tag);

int zcrypt_wrap_key(zcrypt_key_t *wrappingkey, zcrypt_key_t *ptkey,
	caddr_t *wkeybuf, size_t *wkeylen, uint64_t wcrypt);
int zcrypt_unwrap_key(zcrypt_key_t *wk, uint64_t crypt,
    caddr_t wkeybuf, size_t wkeylen, zcrypt_key_t **zck);

void zcrypt_keystore_init(spa_t *spa);
void zcrypt_keystore_fini(spa_t *spa);

zcrypt_key_t *zcrypt_keystore_find_wrappingkey(spa_t *spa, uint64_t os);
zcrypt_keystore_node_t *zcrypt_keystore_find_node(spa_t *spa, uint64_t os,
    boolean_t dp_config_rwlock_held);
zcrypt_key_t *zcrypt_key_lookup(spa_t *spa, uint64_t objset, uint64_t txg);
zcrypt_keystore_node_t *zcrypt_keystore_insert(spa_t *spa,
    uint64_t os, zcrypt_key_t *wrapkey);
int zcrypt_keystore_remove(spa_t *spa, uint64_t os);

void zcrypt_keychain_insert(avl_tree_t *keychain, uint64_t txg,
    zcrypt_key_t *key);

boolean_t zcrypt_mech_available(enum zio_crypt crypt);

int zcrypt_key_from_ioc(zfs_ioc_crypto_t *, zcrypt_key_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZCRYPT_H */
