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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/zcrypt.h>
#include <sys/zio_crypt.h>
#include <sys/zio.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/crypto/api.h>
#include <sys/avl.h>
// FIXME
//#include <sys/ksynch.h>
#include <sys/refcount.h>
// FIXME
//#include <sys/sha2.h>

#ifndef _KERNEL
#include <strings.h>
#endif

zcrypt_key_t *
zcrypt_key_allocate(void)
{
	zcrypt_key_t *key;

	key = kmem_zalloc(sizeof (zcrypt_key_t), KM_PUSHPAGE); // Sleep
	refcount_create(&key->zk_refcnt);

	return (key);
}

void
zcrypt_key_free(zcrypt_key_t *key)
{
	if (key == NULL)
		return;

	refcount_destroy(&key->zk_refcnt);
	if (key->zk_key.ck_length != 0) {
		/*
		 * This will need updating for key
		 * types other than CRYPTO_KEY_RAW.
		 */
		bzero(key->zk_key.ck_data, key->zk_key.ck_length / 8);
		kmem_free(key->zk_key.ck_data, key->zk_key.ck_length / 8);
	}
	crypto_destroy_ctx_template(key->zk_ctx_tmpl);
	if (key->zk_mackey.ck_length != 0) {
		/*
		 * This will need updating for key
		 * types other than CRYPTO_KEY_RAW.
		 */
		bzero(key->zk_mackey.ck_data, key->zk_mackey.ck_length / 8);
		kmem_free(key->zk_mackey.ck_data, key->zk_mackey.ck_length / 8);
	}
	crypto_destroy_ctx_template(key->zk_mac_ctx_tmpl);
	bzero(key, sizeof (zcrypt_key_t));
	kmem_free(key, sizeof (zcrypt_key_t));
	key = NULL;
}

zcrypt_key_t *
zcrypt_key_copy(zcrypt_key_t *src)
{
	zcrypt_key_t *dst;
	size_t rklen;
	if (src == NULL)
		return (NULL);

	zcrypt_key_hold(src, FTAG);
	ASSERT(src->zk_key.ck_format == CRYPTO_KEY_RAW);
	dst = zcrypt_key_allocate();
	dst->zk_crypt = src->zk_crypt;

	rklen = src->zk_key.ck_length / 8;
	if (rklen != 0) {
		dst->zk_key.ck_data = kmem_alloc(rklen, KM_SLEEP);
		bcopy(src->zk_key.ck_data, dst->zk_key.ck_data, rklen);
		dst->zk_key.ck_format = src->zk_key.ck_format;
		dst->zk_key.ck_length = src->zk_key.ck_length;
	}

	rklen = src->zk_mackey.ck_length / 8;
	if (rklen != 0) {
		dst->zk_mackey.ck_data = kmem_alloc(rklen, KM_SLEEP);
		bcopy(src->zk_mackey.ck_data, dst->zk_mackey.ck_data, rklen);
		dst->zk_mackey.ck_format = src->zk_mackey.ck_format;
		dst->zk_mackey.ck_length = src->zk_mackey.ck_length;
	}

	zcrypt_key_release(src, FTAG);

	return (dst);
}

#ifdef DEBUG
void
zcrypt_key_compare(zcrypt_key_t *l, zcrypt_key_t *r)
{
	ASSERT(l->zk_key.ck_format == r->zk_key.ck_format);
	ASSERT(l->zk_key.ck_length == r->zk_key.ck_length);
	ASSERT(bcmp(l->zk_key.ck_data, r->zk_key.ck_data,
	    l->zk_key.ck_length / 8) == 0);
	ASSERT(l->zk_mackey.ck_length == r->zk_mackey.ck_length);
	ASSERT(bcmp(l->zk_mackey.ck_data, r->zk_mackey.ck_data,
	    l->zk_mackey.ck_length / 8) == 0);
}
#endif /* DEBUG */

void
zcrypt_key_hold(zcrypt_key_t *key, void *tag)
{
	(void) refcount_add(&key->zk_refcnt, tag);
}

void
zcrypt_key_release(zcrypt_key_t *key, void *tag)
{
	(void) refcount_remove(&key->zk_refcnt, tag);
}

/*
 * ===========================================================================
 * Key wrap/unwrap support
 * ===========================================================================
 *
 * The wrapping mechanism is hardcoded as AES_CCM/AES_GCM for now,
 * The wrapped key output has a uint64_t index into the
 * zio_crypt_wrap_info_t table.
 *
 * Expected future wrapping algorithms include (but are not limited to):
 * 	AES NIST Keywrap
 * 	RSA keypair and X.509 certificate.
 */

/*
 * zcrypt_wrap_key
 *
 * Using the provided wrapping key wrap the in memory representation of the
 * key into a form suitable for storage in a zap object.
 *
 * Uses kmem_alloc to create space for the wrapped key, the caller
 * should free with kmem_free when it is finished with the wrapped key.
 *
 * returns 0 on success
 */
int
zcrypt_wrap_key(zcrypt_key_t *wrappingkey, zcrypt_key_t *ptkey,
	caddr_t *wkeybuf, size_t *wkeylen, uint64_t wcrypt)
{
	crypto_mechanism_t wmech;
	crypto_data_t wkey_cdt, ptkey_cdt;
	size_t ptkeylen;
	size_t ivlen;
	int ret;
	zcrypt_key_phys_t *wkeyphys;

	/*
	 * Currently we only support wrapping keys of CRYPTO_KEY_RAW
	 */
	ASSERT(ptkey->zk_key.ck_format == CRYPTO_KEY_RAW);
	ASSERT(wcrypt < ZIO_CRYPT_WRAP_FUNCTIONS);

	wmech.cm_type = crypto_mech2id(
	    zio_crypt_wrap_table[wcrypt].cwi_mechname);
	if (wmech.cm_type == CRYPTO_MECH_INVALID)
		return (EINVAL);
	wkeyphys = kmem_zalloc(sizeof (zcrypt_key_phys_t), KM_PUSHPAGE); //Sleep
	wkeyphys->zkp_crypt = wcrypt;

	/*
	 * The data encryption and MAC keys are wrapped separately
	 * since in the future we may support one or both of them
	 * being in a FIPS 140-2 token as sensitive objects and we
	 * won't be able to treat them as "data" and wrap them together
	 * in one operation.
	 */

	/* Data encryption key is first */
	ptkeylen = CRYPTO_BITS2BYTES(ptkey->zk_key.ck_length);
	ivlen = zio_crypt_wrap_table[wcrypt].cwi_ivlen;
	VERIFY(random_get_bytes((uchar_t *)wkeyphys->zkp_kiv, ivlen) == 0);
	if (wcrypt == ZIO_CRYPT_WRAP_AES_CCM) {
		CK_AES_CCM_PARAMS *ccmp;
		ccmp = kmem_zalloc(sizeof (CK_AES_CCM_PARAMS), KM_PUSHPAGE); //Sleep
		ccmp->ulNonceSize = ivlen;
		ccmp->nonce = (uchar_t *)wkeyphys->zkp_kiv;
		ccmp->ulDataSize = ptkeylen;
		ccmp->ulMACSize = zio_crypt_wrap_table[wcrypt].cwi_maclen;
		wmech.cm_param = (char *)ccmp;
		wmech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else if (wcrypt == ZIO_CRYPT_WRAP_AES_GCM) {
		CK_AES_GCM_PARAMS *gcmp;
		gcmp = kmem_zalloc(sizeof (CK_AES_GCM_PARAMS), KM_PUSHPAGE); //Sleep
		gcmp->ulIvLen = ivlen;
		gcmp->pIv = (uchar_t *)wkeyphys->zkp_kiv;
		gcmp->ulTagBits = zio_crypt_wrap_table[wcrypt].cwi_maclen * 8;
		wmech.cm_param = (char *)gcmp;
		wmech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	} else {
		ASSERT(0);
	}

	SET_CRYPTO_DATA(wkey_cdt, (char *)wkeyphys->zkp_key,
	    ptkeylen + zio_crypt_wrap_table[wcrypt].cwi_maclen);
	SET_CRYPTO_DATA(ptkey_cdt, ptkey->zk_key.ck_data, ptkeylen);

#if _KERNEL
    printk("zcrypt 1\n");
#endif
	ret = crypto_encrypt(&wmech, &ptkey_cdt, &wrappingkey->zk_key,
	    NULL, &wkey_cdt, NULL);
	bzero(wmech.cm_param, wmech.cm_param_len);
	kmem_free(wmech.cm_param, wmech.cm_param_len);

	if (ret != CRYPTO_SUCCESS)
		goto out;

	/* Now the HMAC-SHA256 key for use with dedup IV generation */
	ptkeylen = CRYPTO_BITS2BYTES(ptkey->zk_mackey.ck_length);
	VERIFY(random_get_bytes((uchar_t *)wkeyphys->zkp_miv, ivlen) == 0);
	if (wcrypt == ZIO_CRYPT_WRAP_AES_CCM) {
		CK_AES_CCM_PARAMS *ccmp;
		ccmp = kmem_zalloc(sizeof (CK_AES_CCM_PARAMS), KM_PUSHPAGE); //Sleep
		ccmp->ulNonceSize = ivlen;
		ccmp->nonce = (uchar_t *)wkeyphys->zkp_miv;
		ccmp->ulDataSize = ptkeylen;
		ccmp->ulMACSize = zio_crypt_wrap_table[wcrypt].cwi_maclen;
		wmech.cm_param = (char *)ccmp;
		wmech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else if (wcrypt == ZIO_CRYPT_WRAP_AES_GCM) {
		CK_AES_GCM_PARAMS *gcmp;
		gcmp = kmem_zalloc(sizeof (CK_AES_GCM_PARAMS), KM_PUSHPAGE); //Sleep
		gcmp->ulIvLen = ivlen;
		gcmp->pIv = (uchar_t *)wkeyphys->zkp_miv;
		gcmp->ulTagBits = zio_crypt_wrap_table[wcrypt].cwi_maclen * 8;
		wmech.cm_param = (char *)gcmp;
		wmech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	} else {
		ASSERT(0);
	}

	SET_CRYPTO_DATA(wkey_cdt, (char *)wkeyphys->zkp_mackey,
	    ptkeylen + zio_crypt_wrap_table[wcrypt].cwi_maclen);
	SET_CRYPTO_DATA(ptkey_cdt, ptkey->zk_mackey.ck_data, ptkeylen);

#if _KERNEL
    printk("zcrypt 2\n");
#endif
	ret = crypto_encrypt(&wmech, &ptkey_cdt, &wrappingkey->zk_key,
	    NULL, &wkey_cdt, NULL);

	bzero(wmech.cm_param, wmech.cm_param_len);
	kmem_free(wmech.cm_param, wmech.cm_param_len);
out:
	if (ret != CRYPTO_SUCCESS) {
		kmem_free(wkeyphys, sizeof (zcrypt_key_phys_t));
		*wkeylen = 0;
		return (ret);
	}

	*wkeylen = sizeof (zcrypt_key_phys_t);
	*wkeybuf = (caddr_t)wkeyphys;

	return (0);
}

/*
 * zcrypt_unwrap_key
 *
 * Using the provided wrapping key unwrap the key into a zcrypt_key_t.
 *
 * Allocates a zcrypt_key_t using kmem_alloc(), caller should free
 * using zcrypt_key_free().
 *
 * returns 0 on success
 */
int
zcrypt_unwrap_key(zcrypt_key_t *wk, uint64_t crypt,
    caddr_t wkeybuf, size_t wkeylen, zcrypt_key_t **zck)
{
	crypto_mechanism_t wmech;
	crypto_data_t wkey_cdt, ptkey_cdt;
	zcrypt_key_t *tmpzck;
	caddr_t uwrapkey, uwrapmac;
	size_t uwrapkeylen, uwrapmaclen;
	size_t keylen;
	int ret;
	zcrypt_key_phys_t *wkeyphys = (zcrypt_key_phys_t *)wkeybuf;
	uint64_t wcrypt;

	ASSERT(wkeybuf != NULL);
	ASSERT(wkeylen != 0);

	/*
	 * We maybe unwrapping a key of a smaller length than the wrapping
	 * key so unwrapbuflen and keylen need to take that into account.
	 *
	 * The incoming wkey also has the iv stored at the start.
	 */
	wcrypt = wkeyphys->zkp_crypt;
	ASSERT3U(wcrypt, <, ZIO_CRYPT_WRAP_FUNCTIONS);

	wmech.cm_type = crypto_mech2id(
	    zio_crypt_wrap_table[wcrypt].cwi_mechname);
	if (wmech.cm_type == CRYPTO_MECH_INVALID) {
		return (EINVAL);
	}
	keylen = zio_crypt_table[crypt].ci_keylen;

	if (wcrypt == ZIO_CRYPT_WRAP_AES_CCM) {
		CK_AES_CCM_PARAMS *ccmp;
		ccmp = kmem_zalloc(sizeof (CK_AES_CCM_PARAMS), KM_SLEEP);
		ccmp->ulNonceSize = zio_crypt_wrap_table[wcrypt].cwi_ivlen;
		ccmp->nonce = (uchar_t *)wkeyphys->zkp_kiv;
		ccmp->ulMACSize = zio_crypt_wrap_table[wcrypt].cwi_maclen;
		ccmp->ulDataSize = keylen + ccmp->ulMACSize;
		wmech.cm_param = (char *)ccmp;
		wmech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else if (wcrypt == ZIO_CRYPT_WRAP_AES_GCM) {
		CK_AES_GCM_PARAMS *gcmp;
		gcmp = kmem_zalloc(sizeof (CK_AES_GCM_PARAMS), KM_SLEEP);
		gcmp->ulIvLen = zio_crypt_wrap_table[wcrypt].cwi_ivlen;
		gcmp->pIv = (uchar_t *)wkeyphys->zkp_kiv;
		gcmp->ulTagBits = zio_crypt_wrap_table[wcrypt].cwi_maclen * 8;
		wmech.cm_param = (char *)gcmp;
		wmech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	} else {
		ASSERT(0);
	}

	uwrapkeylen = keylen + zio_crypt_wrap_table[wcrypt].cwi_maclen;
	uwrapkey = kmem_zalloc(uwrapkeylen, KM_SLEEP);

	SET_CRYPTO_DATA(ptkey_cdt, uwrapkey, uwrapkeylen);
	SET_CRYPTO_DATA(wkey_cdt, (char *)wkeyphys->zkp_key,
	    keylen + zio_crypt_wrap_table[wcrypt].cwi_maclen);

	ret = crypto_decrypt(&wmech, &wkey_cdt, &wk->zk_key,
	    NULL, &ptkey_cdt, NULL);
	kmem_free(wmech.cm_param, wmech.cm_param_len);
	if (ret != CRYPTO_SUCCESS) {
		kmem_free(uwrapkey, uwrapkeylen);
		zck = NULL;
		return (ret);
	}

	tmpzck = zcrypt_key_allocate();
	tmpzck->zk_key.ck_format = CRYPTO_KEY_RAW;
	tmpzck->zk_key.ck_data = kmem_alloc(keylen, KM_SLEEP);
	tmpzck->zk_key.ck_length = keylen * 8;
	tmpzck->zk_crypt = crypt;
	bcopy(uwrapkey, tmpzck->zk_key.ck_data, keylen);
	kmem_free(uwrapkey, uwrapkeylen);

	/* Now the HMAC-SHA256 key which we know is 32 bytes */
	keylen = 32;
	if (wcrypt == ZIO_CRYPT_WRAP_AES_CCM) {
		CK_AES_CCM_PARAMS *ccmp;
		ccmp = kmem_zalloc(sizeof (CK_AES_CCM_PARAMS), KM_SLEEP);
		ccmp->ulNonceSize = zio_crypt_wrap_table[wcrypt].cwi_ivlen;
		ccmp->nonce = (uchar_t *)wkeyphys->zkp_miv;
		ccmp->ulMACSize = zio_crypt_wrap_table[wcrypt].cwi_maclen;
		ccmp->ulDataSize = keylen + ccmp->ulMACSize;
		wmech.cm_param = (char *)ccmp;
		wmech.cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else if (wcrypt == ZIO_CRYPT_WRAP_AES_GCM) {
		CK_AES_GCM_PARAMS *gcmp;
		gcmp = kmem_zalloc(sizeof (CK_AES_GCM_PARAMS), KM_SLEEP);
		gcmp->ulIvLen = zio_crypt_wrap_table[wcrypt].cwi_ivlen;
		gcmp->pIv = (uchar_t *)wkeyphys->zkp_miv;
		gcmp->ulTagBits = zio_crypt_wrap_table[wcrypt].cwi_maclen * 8;
		wmech.cm_param = (char *)gcmp;
		wmech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	} else {
		ASSERT(0);
	}

	uwrapmaclen = keylen + zio_crypt_wrap_table[wcrypt].cwi_maclen;
	uwrapmac = kmem_zalloc(uwrapmaclen, KM_SLEEP);

	SET_CRYPTO_DATA(ptkey_cdt, uwrapmac, uwrapmaclen);
	SET_CRYPTO_DATA(wkey_cdt, (char *)wkeyphys->zkp_mackey,
	    keylen + zio_crypt_wrap_table[wcrypt].cwi_maclen);

	ret = crypto_decrypt(&wmech, &wkey_cdt, &wk->zk_key,
	    NULL, &ptkey_cdt, NULL);
	kmem_free(wmech.cm_param, wmech.cm_param_len);
	if (ret != CRYPTO_SUCCESS) {
		zcrypt_key_free(tmpzck);
		kmem_free(uwrapmac, uwrapmaclen);
		zck = NULL;
		return (ret);
	}

	tmpzck->zk_mackey.ck_format = CRYPTO_KEY_RAW;
	tmpzck->zk_mackey.ck_data = kmem_alloc(keylen, KM_SLEEP);
	tmpzck->zk_mackey.ck_length = keylen * 8;
	bcopy(uwrapmac, tmpzck->zk_mackey.ck_data, keylen);
	kmem_free(uwrapmac, uwrapmaclen);

	*zck = tmpzck;
	return (0);
}


/*
 * zcrypt_key_from_ioc
 *
 * Turn the ioctl variant of the key into a zcrypt_key_t
 *
 * For now this only supports key by value (RAW) keys but will
 * be extended to support token keys later.
 *
 * This function allocates memory with kmem_alloc the resulting zcrypt_key_t
 * should be freed by zcrypt_key_free()
 */
int
zcrypt_key_from_ioc(zfs_ioc_crypto_t *ioc_key, zcrypt_key_t **zck)
{
	uint64_t keydatalen = ioc_key->zic_keydatalen;
	void *keydata = (void *)(uintptr_t)ioc_key->zic_keydata;
	zcrypt_key_t *zktmp;

	/*
	 * Sanity check the data in the ioctl call based on the value
	 * of crypt.
	 */
	if (ioc_key->zic_crypt == 0 ||
	    keydatalen < zio_crypt_table[ioc_key->zic_crypt].ci_keylen) {
		return (EINVAL);
	}

	zktmp = zcrypt_key_allocate();
	zktmp->zk_key.ck_format = CRYPTO_KEY_RAW;

	zktmp->zk_key.ck_data = kmem_alloc(keydatalen, KM_SLEEP);
	zktmp->zk_key.ck_length = keydatalen * 8;
	bcopy(keydata, zktmp->zk_key.ck_data, keydatalen);
	zktmp->zk_crypt = ioc_key->zic_crypt;

	*zck = zktmp;
	return (0);
}

/*
 * In memory keystore:
 *
 * Each SPA (pool) has its own in memory keystore.  The keystore
 * hangs off the spa_t.  It is an AVL tree indexed by dataset object
 * number (ds->ds_object).  This is the most efficient index for
 * the cases when we need to use the keys for encryption/decryption
 * of data, ie in the ZIO pipeline, since at that time all we have
 * available is a zbookmark_t not a dsl_dataset_t.
 *
 * Each node in the AVL tree indexed by ds_object holds the wrapping key
 * (even if it was inherited) and an AVL tree indexed by txg.  This
 * is the per dataset keychain.
 *
 * The keystore is setup and torndown using zcrypt_keystore_init()
 * and zcrypt_keystore_fini() in the spa setup/teardown functions.
 *
 * Outside of this file there must be no use of avl_find/insert
 * to search or manipulate the AVL trees for the keystore or per
 * entry keychains.
 *
 * Locking:
 *	sk_lock is a RW lock that needs to be taken out
 *	for all operations on the keystore - insert, remove, lookup
 *
 *	skn_lock is a per node mutex to be taken out on updates to
 *	the per node keychains and when expanding the key schedules
 *	of keys in the keychain.
 *
 *	Each zcrypt_key_t is also reference counted and the key returned
 *	from zcrypt_keystore_lookup() must be held while being used.
 */

static avl_tree_t zcrypt_keychain_init(void);
static int zcrypt_keychain_fini(avl_tree_t keychain);

static int
zcrypt_keystore_compare(const void *a, const void *b)
{
	const zcrypt_keystore_node_t *zka = a;
	const zcrypt_keystore_node_t *zkb = b;

	if (zka->skn_os < zkb->skn_os)
		return (-1);
	if (zka->skn_os > zkb->skn_os)
		return (+1);
	return (0);
}

void
zcrypt_keystore_init(spa_t *spa)
{
	spa->spa_keystore =
	    kmem_zalloc(sizeof (zcrypt_keystore_t), KM_SLEEP);
	rw_init(&spa->spa_keystore->sk_lock, NULL, RW_DEFAULT, NULL);
	avl_create(&spa->spa_keystore->sk_dslkeys, zcrypt_keystore_compare,
	    sizeof (zcrypt_keystore_node_t),
	    offsetof(zcrypt_keystore_node_t, skn_link));
}

void
zcrypt_keystore_fini(spa_t *spa)
{
	void *cookie;
	avl_tree_t *tree;
	zcrypt_keystore_node_t *node;

	if (spa->spa_keystore == NULL)
		return;

	rw_enter(&spa->spa_keystore->sk_lock, RW_WRITER);
	/*
	 * Note we don't bother with the refcnt of the keys in here
	 * because this function can't return failure so we just need to
	 * destroy everything.
	 */
	cookie = NULL;
	tree = &spa->spa_keystore->sk_dslkeys;
	while ((node = avl_destroy_nodes(tree, &cookie)) != NULL) {
		mutex_enter(&node->skn_lock);
		(void) zcrypt_keychain_fini(node->skn_keychain);
		zcrypt_key_free(node->skn_wrapkey);
		mutex_exit(&node->skn_lock);
		bzero(node, sizeof (zcrypt_keystore_node_t));
		kmem_free(node, sizeof (zcrypt_keystore_node_t));
	}
	avl_destroy(tree);

	rw_exit(&spa->spa_keystore->sk_lock);
	rw_destroy(&spa->spa_keystore->sk_lock);
	kmem_free(spa->spa_keystore, sizeof (zcrypt_keystore_t));
	spa->spa_keystore = NULL;
}


zcrypt_keystore_node_t *
zcrypt_keystore_insert(spa_t *spa, uint64_t dsobj,
    zcrypt_key_t *wrapkey)
{
	avl_index_t where;
	zcrypt_keystore_node_t *zk;
	zcrypt_keystore_node_t *found_zk;
	avl_tree_t *tree;

	ASSERT(spa->spa_keystore != NULL);
	tree = &spa->spa_keystore->sk_dslkeys;
	zk = kmem_zalloc(sizeof (zcrypt_keystore_node_t), KM_PUSHPAGE); // Sleep

	//mutex_init(&zk->skn_lock, NULL, NULL, NULL);
	mutex_init(&zk->skn_lock, NULL, MUTEX_DEFAULT, NULL);
	zk->skn_os = dsobj;
	zk->skn_wrapkey = wrapkey;

	rw_enter(&spa->spa_keystore->sk_lock, RW_WRITER);
	if ((found_zk = avl_find(tree, zk, &where)) != NULL) {
		zk = found_zk;
	} else {
		avl_insert(tree, zk, where);
		zk->skn_keychain = zcrypt_keychain_init();
	}

	rw_exit(&spa->spa_keystore->sk_lock);

	return (zk);
}

int
zcrypt_keystore_remove(spa_t *spa, uint64_t dsobj)
{
	zcrypt_keystore_node_t zk_tofind;
	zcrypt_keystore_node_t *zk;
	avl_tree_t *tree;
	int err = 0;

	ASSERT(spa->spa_keystore != NULL);

	zk_tofind.skn_os = dsobj;
	tree = &spa->spa_keystore->sk_dslkeys;

	rw_enter(&spa->spa_keystore->sk_lock, RW_WRITER);
	zk = avl_find(tree, &zk_tofind, NULL);
	if (zk == NULL) {
		goto out;
	}
	mutex_enter(&zk->skn_lock);

	err = zcrypt_keychain_fini(zk->skn_keychain);
	if (err != 0) {
		mutex_exit(&zk->skn_lock);
		goto out;
	}
	zcrypt_key_free(zk->skn_wrapkey);
	zk->skn_wrapkey = NULL;
	mutex_exit(&zk->skn_lock);
	mutex_destroy(&zk->skn_lock);

	avl_remove(tree, zk);
	kmem_free(zk, sizeof (zcrypt_keystore_node_t));
out:
	rw_exit(&spa->spa_keystore->sk_lock);

	return (err);
}

zcrypt_keystore_node_t *
zcrypt_keystore_find_node(spa_t *spa, uint64_t dsobj,
    boolean_t config_rwlock_held)
{
	zcrypt_keystore_node_t search;
	zcrypt_keystore_node_t *found = NULL;

	rw_enter(&spa->spa_keystore->sk_lock, RW_READER);
	if (avl_is_empty(&spa->spa_keystore->sk_dslkeys))
		goto out;

	search.skn_os = dsobj;
	found = avl_find(&spa->spa_keystore->sk_dslkeys, &search, NULL);
	if (found == NULL) {
		int error;
		dsl_pool_t *dp = spa_get_dsl(spa);
		dsl_dataset_t *ds;
		boolean_t need_lock;

		rw_exit(&spa->spa_keystore->sk_lock);
		need_lock = !dsl_pool_sync_context(dp) && !config_rwlock_held;
		if (need_lock)
			rw_enter(&dp->dp_config_rwlock, RW_READER);
		error = dsl_dataset_hold_obj(dp, dsobj, FTAG, &ds);
		if (need_lock)
			rw_exit(&dp->dp_config_rwlock);
		rw_enter(&spa->spa_keystore->sk_lock, RW_READER);

		if (!error) {
			if (dsl_dataset_is_snapshot(ds)) {
				search.skn_os =
				    ds->ds_dir->dd_phys->dd_head_dataset_obj;
				found = avl_find(&spa->spa_keystore->sk_dslkeys,
				    &search, NULL);
			}
			dsl_dataset_rele(ds, FTAG);
		}
	}
out:
	rw_exit(&spa->spa_keystore->sk_lock);

	return (found);
}

zcrypt_key_t *
zcrypt_keystore_find_wrappingkey(spa_t *spa, uint64_t dsobj)
{
	zcrypt_keystore_node_t *zk;

	zk = zcrypt_keystore_find_node(spa, dsobj, B_FALSE);
	if (zk == NULL)
		return (NULL);

	return (zk->skn_wrapkey);
}

static int
zcrypt_keychain_compare(const void *a, const void *b)
{
	const zcrypt_keychain_node_t *dka = a;
	const zcrypt_keychain_node_t *dkb = b;

	if (dka->dkn_txg < dkb->dkn_txg)
		return (-1);
	if (dka->dkn_txg > dkb->dkn_txg)
		return (+1);
	return (0);
}

static avl_tree_t
zcrypt_keychain_init(void)
{
	avl_tree_t tree;
	avl_create(&tree, zcrypt_keychain_compare,
	    sizeof (zcrypt_keychain_node_t),
	    offsetof(zcrypt_keychain_node_t, dkn_link));
	return (tree);
}

static zcrypt_keychain_node_t *
zcrypt_keychain_find(avl_tree_t keychain, uint64_t txg)
{
	zcrypt_keychain_node_t search_dkn;
	zcrypt_keychain_node_t *found_dkn;
	avl_index_t where;

	search_dkn.dkn_txg = txg;
	found_dkn = avl_find(&keychain, &search_dkn, &where);
	if (found_dkn == NULL) {
		found_dkn = avl_nearest(&keychain, where, AVL_BEFORE);
	}

	return (found_dkn);
}

void
zcrypt_keychain_insert(avl_tree_t *keychain, uint64_t txg,
    zcrypt_key_t *key)
{
	zcrypt_keychain_node_t *dkn;

	dkn = kmem_alloc(sizeof (zcrypt_keychain_node_t), KM_PUSHPAGE); //Sleep

	dkn->dkn_txg = txg;
	dkn->dkn_key = key;

	avl_add(keychain, dkn);
}

static int
zcrypt_keychain_fini(avl_tree_t keychain)
{
	void *cookie = NULL;
	zcrypt_keychain_node_t *node = NULL;

#if 0
	while (AVL_NEXT(&keychain, node) != NULL) {
		if (!refcount_is_zero(&node->dkn_key->zk_refcnt))
			return (EBUSY);
	}
#endif

	while ((node = avl_destroy_nodes(&keychain, &cookie)) != NULL) {
		zcrypt_key_free(node->dkn_key);
		kmem_free(node, sizeof (zcrypt_keychain_node_t));
	}
	avl_destroy(&keychain);

	return (0);
}

/*
 * zcrypt_key_lookup
 *
 * This function looks up the key we need based on the bookmark.
 * It returns a reference to the key that the caller should NOT free.
 * The caller should use zcrypt_key_hold/release()
 * On failure it returns NULL;
 */
zcrypt_key_t *
zcrypt_key_lookup(spa_t *spa, uint64_t objset, uint64_t txg)
{
	zcrypt_keystore_node_t *skn;
	zcrypt_keychain_node_t *dkn;
	crypto_mechanism_t mech = { 0 };
	zcrypt_key_t *key;

#if _KERNEL
    printk("zcrypt_key_lookup enter\n");
#endif

	skn = zcrypt_keystore_find_node(spa, objset, B_FALSE);
	if (skn == NULL)
		return (NULL);

	/* ZIL writes use txg 0 but we want the latest key */
	if (txg == 0)
		txg = -1UL;
	mutex_enter(&skn->skn_lock);
	dkn = zcrypt_keychain_find(skn->skn_keychain, txg);
	if (dkn == NULL) {
		mutex_exit(&skn->skn_lock);
		return (NULL);
	}
	key = dkn->dkn_key;
	if (key != NULL && !key->zk_ctx_tmpl_valid) {
		mech.cm_type = crypto_mech2id(
		    zio_crypt_table[key->zk_crypt].ci_mechname);
		if (crypto_create_ctx_template(&mech, &key->zk_key,
		    &key->zk_ctx_tmpl, KM_SLEEP) == CRYPTO_SUCCESS)
			key->zk_ctx_tmpl_valid = B_TRUE;
	}
	if (key != NULL && !key->zk_mac_ctx_tmpl_valid) {
		mech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC_GENERAL);
		if (crypto_create_ctx_template(&mech, &key->zk_mackey,
		    &key->zk_mac_ctx_tmpl, KM_SLEEP) == CRYPTO_SUCCESS)
			key->zk_mac_ctx_tmpl_valid = B_TRUE;
	}
	mutex_exit(&skn->skn_lock);

#if _KERNEL
    printk("zcrypt_key_lookup exit: key %p\n", key);
#endif
	return (key);
}

zcrypt_key_t *
zcrypt_key_gen(int crypt)
{
	caddr_t genkeybuf;
	size_t genkeylen;
	zcrypt_key_t *key;

	/*
	 * crypt tells us which algorithm is being used and
	 * thus the type and size of key we need generated.
	 *
	 * For now we are using random_get_bytes() to generate the
	 * raw key.  Ideally use crypto_key_generate()  however that needs
	 * a crypto_provider_t so only works with hardware providers.
	 *
	 * This may need to change for FIPS 140-2 at levels > 2,
	 * the key really should be generated on the hardware crypto
	 * device as a sensitive key object and extracted in wrapped form.
	 */
	genkeylen = zio_crypt_table[crypt].ci_keylen;
	genkeybuf = kmem_alloc(genkeylen, KM_PUSHPAGE); // Sleep
	VERIFY(random_get_bytes((uchar_t *)genkeybuf, genkeylen) == 0);

	key = zcrypt_key_allocate();
	key->zk_key.ck_format = CRYPTO_KEY_RAW;
	key->zk_key.ck_data = genkeybuf;
	key->zk_key.ck_length = (genkeylen * 8);
	key->zk_crypt = crypt;

	/* Generate an HMAC-SHA256 key for dedup IV generation as well */
	genkeylen = 32;
	genkeybuf = kmem_alloc(genkeylen, KM_PUSHPAGE); // Sleep
	VERIFY(random_get_bytes((uchar_t *)genkeybuf, genkeylen)
	    == CRYPTO_SUCCESS);
	key->zk_mackey.ck_format = CRYPTO_KEY_RAW;
	key->zk_mackey.ck_data = genkeybuf;
	key->zk_mackey.ck_length = (genkeylen * 8);

	return (key);
}

boolean_t
zcrypt_mech_available(enum zio_crypt crypt)
{
	crypto_mech_type_t mech;

	if (crypt == ZIO_CRYPT_INHERIT || crypt == ZIO_CRYPT_OFF)
		return (TRUE);

	mech = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);

	if (mech == CRYPTO_MECH_INVALID) {
		return (FALSE);
	}
	return (TRUE);
}
