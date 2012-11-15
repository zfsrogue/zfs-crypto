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

#include <sys/zfs_context.h>
#include <sys/sunddi.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/zcrypt.h>
#include <sys/zfs_ioctl.h>
#include <sys/zio_crypt.h>
#include <sys/zio.h>
#include <sys/dmu.h>
#include <sys/dbuf.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dmu_objset.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/zvol.h>
#include <sys/crypto/api.h>
#include <sys/avl.h>
//#include <sys/ksynch.h>
//#include <sys/sha2.h>

#ifndef _KERNEL
#include <strings.h>
#endif


enum zio_crypt
zio_crypt_select(enum zio_crypt child, enum zio_crypt parent)
{
	ASSERT(child < ZIO_CRYPT_FUNCTIONS);
	ASSERT(parent < ZIO_CRYPT_FUNCTIONS);

	if (child == ZIO_CRYPT_INHERIT)
		return (parent);

	if (child == ZIO_CRYPT_ON)
		return (ZIO_CRYPT_ON_VALUE);

	return (child);
}

/*
 * While we only support symmetric keys for wrapping we match
 * the algorithm and mode of that used for dataset encryption.
 * To to anything else really requires a per dataset property.
 *
 * To make this quick we base this on intimate (but committed)
 * knowlege of the zio_crypt_table[] and zio_crypt_wrap_table[].
 */
uint64_t
zio_crypt_select_wrap(enum zio_crypt wcrypt)
{
	ASSERT(wcrypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT(wcrypt != ZIO_CRYPT_OFF);

	if (wcrypt <= ZIO_CRYPT_AES_256_CCM)
		return (ZIO_CRYPT_WRAP_AES_CCM);
	return (ZIO_CRYPT_WRAP_AES_GCM);
}

/*
 * zio_crypt_gen_data_iv
 *
 * For CCM the max NonceSize is 13, however we actually
 * only have 12 bytes of iv because a 13 byte iv with CCM
 * doesn't give us enough plaintext size 65536 vs 16777215 for a
 * 12 byte iv.
 *
 * For GCM the nonce can be greater than 96 bits but due to issues
 * with the GHASH function that is used if more than 96 bits are passed in
 * we must not exceed 96 bits.
 *
 * We need more than just the txg for the iv because there could
 * be a lot of data getting encrypted with a given key in this
 * txg. IV values need to be unique under a given key for CCM/GCM to be safe.
 *
 * In the default case the 96 bits of IV is generated from the txg and a
 * counter, 1 bit is used to distinguish an IV for use by the ZIL
 * and one for the "normal" case, since they must not ever clash because that
 * would be IV re-use.
 *
 * Take 47 bits of the txg, that is enough to keep that unique for 8
 * million years assuming 1 txg per/sec.
 * Then we can have a 48 bit counter to make up our 96 bits.
 *
 * Each key has a monatonically increasing counter so that the combination
 * of txg and the counter provides a unique IV. We store the counter as a
 * 64 bit int because we can atomically increment that.
 * The counter state is not stored persistently because we don't need
 * to since the txg is and we don't re-use transaction ids.
 * We also don't need to reset the counter back to zero when the txg changes,
 * letting it wrap around is fine - it won't wrap around in a single
 * transaction until we have hardware available that can push > 2^48 blocks
 * in a single transaction.
 *
 * For the ZIL the txg will be 0 on a write but !0 on a replay, so we can't
 * use the txg.  However the zb_blkid is safe to use since it is the ZIL
 * sequence number, and it never repeats.  So for the ZIL the IV is 47 bits of
 * the zb_objset and 48 bits of the zb_blkid (counter).  This ensures that on
 * clones where we have a copy of the origin's keychain we will still generate
 * a different IV for ZIL blocks.
 *
 * If dedup is enabled we want to be able to dedup blocks
 * encrypted with the same key.  This means an IV generation method
 * is needed that is based not on block location or on when the block is
 * written but on the plaintext since that is the only constant that will
 * give us an IV+key+plaintext combination that will dedup.
 * For this case we use an MAC of the plaintext, it has to be a keyed hash
 * rather than a plain hash because otherwise attackers could mount collision
 * attacks.
 *
 * We also must use a different key for the MAC than for the actual
 * data encryption.  The MAC used here is HMAC-SHA256 and is currently
 * hardcoded.  Once SHA-3 comes out we probably need a way to migrate
 * to using that - but dedup will be making that transition too.
 *
 * For GCM IV re-use can result in revealing information about the key so
 * it isn't safe to use the dedup IV method with GCM.  For CCM IV re-use
 * can result in revealing information about the plaintext, however in this
 * case it won't reveal anything more than the dedup already does and it
 * doesn't allow the attacker to recover plaintext.  If this isn't acceptable
 * a risk then dedup should be set to off on those encrypted datasets.
 *
 */
static void
zio_crypt_gen_data_iv(int crypt, int type, boolean_t dedup, void *data,
    uint64_t datalen, zcrypt_key_t *key, uint64_t txg, zbookmark_t *bookmark,
    char *iv)
{
	size_t ivlen = ZIO_CRYPT_DATA_IVLEN;
	uint16_t _iv[6];
	uint64_t ctr;
#if _KERNEL
	ASSERT3U(sizeof (_iv), ==, ZIO_CRYPT_DATA_IVLEN);
	bzero(iv, ivlen);

	if (type == DMU_OT_INTENT_LOG) {
		uint16_t _iv[6];
		_iv[0] = BE_16(BF64_GET(bookmark->zb_objset, 32, 15));
		_iv[0] |= 0x8000;
		_iv[1] = BE_16(BF64_GET(bookmark->zb_objset, 16, 16));
		_iv[2] = BE_16(BF64_GET(bookmark->zb_objset,  0, 16));
		_iv[3] = BE_16(BF64_GET(bookmark->zb_blkid, 32, 16));
		_iv[4] = BE_16(BF64_GET(bookmark->zb_blkid, 16, 16));
		_iv[5] = BE_16(BF64_GET(bookmark->zb_blkid,  0, 16));
		bcopy(&_iv, iv, sizeof (_iv));
		return;
	}

	if (dedup && zio_crypt_table[crypt].ci_dedupsafe) {
		crypto_data_t mac;
		crypto_data_t cd_data;
		crypto_mechanism_t mmech;
		int error;

		mmech.cm_type = crypto_mech2id(SUN_CKM_SHA256_HMAC_GENERAL);
		mmech.cm_param = (char *)&ivlen;
		mmech.cm_param_len = sizeof (ivlen);
		mac.cd_format = CRYPTO_DATA_RAW;
		mac.cd_offset = 0;
		mac.cd_raw.iov_base = iv;
		mac.cd_length = mac.cd_raw.iov_len = ivlen;
		SET_CRYPTO_DATA(cd_data, data, datalen);
		error = crypto_mac(&mmech, &cd_data, &key->zk_mackey,
		    key->zk_mac_ctx_tmpl, &mac, NULL);
		if (error == CRYPTO_OLD_CTX_TEMPLATE) {
			key->zk_mac_ctx_tmpl_valid = B_FALSE;
			crypto_destroy_ctx_template(key->zk_mac_ctx_tmpl);
			key->zk_mac_ctx_tmpl = NULL;
			error = crypto_mac(&mmech, &cd_data, &key->zk_mackey,
			    NULL, &mac, NULL);
		}
		if (error == CRYPTO_SUCCESS)
			return;
	}

	ctr = atomic_inc_64_nv(&key->zk_ctr);
	_iv[0] = BE_16(BF64_GET(txg, 32, 15));
	_iv[1] = BE_16(BF64_GET(txg, 16, 16));
	_iv[2] = BE_16(BF64_GET(txg,  0, 16));
	_iv[3] = BE_16(BF64_GET(ctr, 32, 16));
	_iv[4] = BE_16(BF64_GET(ctr, 16, 16));
	_iv[5] = BE_16(BF64_GET(ctr,  0, 16));
	bcopy(&_iv, iv, sizeof (_iv));
#endif
}

static crypto_mechanism_t *
zio_crypt_setup_mech_common(int crypt, int type, size_t datalen)
{
	crypto_mechanism_t *mech = NULL;

	mech = kmem_zalloc(sizeof (crypto_mechanism_t), KM_SLEEP);
	mech->cm_type = crypto_mech2id(zio_crypt_table[crypt].ci_mechname);
	ASSERT(mech->cm_type != CRYPTO_MECH_INVALID);

	if (mech->cm_type == crypto_mech2id(SUN_CKM_AES_CCM)) {
		CK_AES_CCM_PARAMS *ccmp;
		ccmp = kmem_alloc(sizeof (CK_AES_CCM_PARAMS), KM_SLEEP);
		ccmp->ulNonceSize = ZIO_CRYPT_DATA_IVLEN;
		ccmp->ulAuthDataSize = 0;
		ccmp->authData = NULL;
		ccmp->ulDataSize = datalen;
		if (type == DMU_OT_INTENT_LOG) {
			ccmp->ulMACSize = zio_crypt_table[crypt].ci_zil_maclen;
		} else {
			ccmp->ulMACSize = zio_crypt_table[crypt].ci_maclen;
		}

		mech->cm_param = (char *)ccmp;
		mech->cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	} else if (mech->cm_type == crypto_mech2id(SUN_CKM_AES_GCM)) {
		CK_AES_GCM_PARAMS *gcmp;
		gcmp = kmem_alloc(sizeof (CK_AES_GCM_PARAMS), KM_SLEEP);
		gcmp->ulIvLen = ZIO_CRYPT_DATA_IVLEN;
		gcmp->ulAADLen = 0;
		gcmp->pAAD = NULL;
		if (type == DMU_OT_INTENT_LOG) {
			gcmp->ulTagBits =
			    zio_crypt_table[crypt].ci_zil_maclen * 8;
		} else {
			gcmp->ulTagBits = zio_crypt_table[crypt].ci_maclen * 8;
		}

		mech->cm_param = (char *)gcmp;
		mech->cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	} else {
		ASSERT(0);
	}

	return (mech);
}

static crypto_mechanism_t *
zio_crypt_setup_mech_with_iv(int crypt, int type, size_t datalen, void *iv)
{
	crypto_mechanism_t *mech;

	mech = zio_crypt_setup_mech_common(crypt, type, datalen);
	if (mech == NULL)
		return (NULL);
	if (mech->cm_type == crypto_mech2id(SUN_CKM_AES_CCM)) {
		CK_AES_CCM_PARAMS *ccmp = (CK_AES_CCM_PARAMS *)mech->cm_param;
		ccmp->nonce = iv;
	} else if (mech->cm_type == crypto_mech2id(SUN_CKM_AES_GCM)) {
		CK_AES_GCM_PARAMS *gcmp = (CK_AES_GCM_PARAMS *)mech->cm_param;
		gcmp->pIv = iv;
	} else {
		ASSERT(0);
	}
	return (mech);
}

static crypto_mechanism_t *
zio_crypt_setup_mech_gen_iv(int crypt, int type, boolean_t dedup,
    zcrypt_key_t *key, uint64_t txg, zbookmark_t *bookmark,
    void *data, size_t datalen, char *iv)
{
	crypto_mechanism_t *mech;

	mech = zio_crypt_setup_mech_common(crypt, type, datalen);
	if (mech == NULL)
		return (NULL);

	zio_crypt_gen_data_iv(crypt, type, dedup, data, datalen,
	    key, txg, bookmark, iv);
	if (mech->cm_type == crypto_mech2id(SUN_CKM_AES_CCM)) {
		CK_AES_CCM_PARAMS *ccmp = (CK_AES_CCM_PARAMS *)mech->cm_param;
		ccmp->nonce = (uchar_t *)iv;
	} else if (mech->cm_type == crypto_mech2id(SUN_CKM_AES_GCM)) {
		CK_AES_GCM_PARAMS *gcmp = (CK_AES_GCM_PARAMS *)mech->cm_param;
		gcmp->pIv = (uchar_t *)iv;
	} else {
		ASSERT(0);
	}

	return (mech);

}

static void
zio_crypt_free_mech(crypto_mechanism_t *mech)
{
	/*
	 * Note we must not attempt to bzero or free the nonce/or pIV
	 * fields of the params structs because they are passed in
	 * by reference to us from zio_decrypt() and zio_write_bp_init()
	 */
	if (mech->cm_param_len != 0) {
		bzero(mech->cm_param, mech->cm_param_len);
		kmem_free(mech->cm_param, mech->cm_param_len);
	}
	bzero(mech, sizeof (crypto_mechanism_t));
	kmem_free(mech, sizeof (crypto_mechanism_t));
}


/*
 * zio_encrypt_data
 *
 * To be called only from the zio pipeline.
 *
 * The mac and iv are filled in and returned along with the ciphertext.
 */
int
zio_encrypt_data(int crypt, zcrypt_key_t *key, zbookmark_t *bookmark,
    uint64_t txg, int type, boolean_t dedup, void *src, uint64_t size,
    void **destp, char *mac, char *iv)
{
	int err = EIO;
#if _KERNEL
	crypto_data_t plaintext, ciphertext;
	crypto_mechanism_t *mech;
	iovec_t *srciov = NULL, *dstiov = NULL;
	uio_t srcuio = { 0 }, dstuio = { 0 };
	caddr_t dest;
	uint_t iovcnt;
	size_t maclen;
	boolean_t lsrc = B_FALSE;
#if defined (ZFS_DEBUG) && defined (_KERNEL)
	void *srccopy;
#endif

	ASSERT(crypt < ZIO_CRYPT_FUNCTIONS);
	ASSERT3U(crypt, !=, ZIO_CRYPT_OFF);
	ASSERT3U(size, <=, ZIO_CRYPT_MAX_CCM_DATA);
	ASSERT(key != NULL);
	ASSERT(mac != NULL);
	ASSERT(iv != NULL);

	/*
	 * A zvol_prealloc or some other case where DB_NOFILL is set
	 * on the dbuf can cause us to get here with src == NULL but
	 * srcsize > 0
	 */
	if (src == NULL) {
		lsrc = B_TRUE;
		src = kmem_zalloc(size, KM_SLEEP);
	}
#if defined (ZFS_DEBUG) && defined (_KERNEL)
	srccopy = kmem_alloc(size, KM_SLEEP);
	bcopy(src, srccopy, size);
#endif /* DEBUG */
	dest = zio_buf_alloc(size);
	bzero(dest, size);
	*destp = dest;
	/*
	 * Note that the size is NOT ciphertext.cd_length because
	 * for CCM (and similar) mode(s) that includes the MAC, which we
	 * place elsewhere.  Also for zil blocks the cd_length is
	 * shorter than the src/dest buffer we deal with in zio.
	 */
	if (type == DMU_OT_INTENT_LOG) {
		iovcnt = zil_set_crypto_data(src, size, dest,
		    &srciov, &dstiov, &plaintext.cd_length, B_TRUE);

		maclen = zio_crypt_table[crypt].ci_zil_maclen;
		if (iovcnt == 0) {
			err = 0;
			goto out;
		}
		srcuio.uio_iov = srciov;
		srcuio.uio_iovcnt = iovcnt;
		plaintext.cd_format = CRYPTO_DATA_UIO;
		plaintext.cd_offset = 0;
		plaintext.cd_uio = &srcuio;
		plaintext.cd_miscdata = NULL;

		dstiov[iovcnt].iov_base = mac;
		dstiov[iovcnt].iov_len = maclen;
		dstuio.uio_iov = dstiov;
		dstuio.uio_iovcnt = iovcnt + 1;
		ciphertext.cd_length = plaintext.cd_length + maclen;
	} else {
		dstiov = kmem_alloc(sizeof (iovec_t) * 2, KM_SLEEP);

		SET_CRYPTO_DATA(plaintext, src, size);

		maclen = zio_crypt_table[crypt].ci_maclen;
		dstiov[0].iov_base = dest;
		dstiov[0].iov_len = size;
		dstiov[1].iov_base = mac;
		dstiov[1].iov_len = maclen;
		dstuio.uio_iov = dstiov;
		dstuio.uio_iovcnt = 2;
		ciphertext.cd_length = size + maclen;
	}
#ifdef _KERNEL
	srcuio.uio_segflg = dstuio.uio_segflg = UIO_SYSSPACE;
#else
	srcuio.uio_segflg = dstuio.uio_segflg = UIO_USERSPACE;
#endif /* _KERNEL */
	ciphertext.cd_format = CRYPTO_DATA_UIO;
	ciphertext.cd_offset = 0;
	ciphertext.cd_uio = &dstuio;
	ciphertext.cd_miscdata = NULL;

	/*
	 * Can NOT use inplace crypto here otherwise we endup
	 * encrypting the copy in the ARC.  Having encrypted
	 * data in the ARC is an interesting idea - particularly
	 * if we want to use crypto keys to enhance access control.
	 * However that isn't the current goal, and even it it was
	 * encrypted content in the ARC might not be the best solution.
	 * Given that we can control which datasets have data in the ARC
	 * or L2ARC using the primarycache and secondary cache
	 * properties that is probably the best solution to not storing
	 * large volumes of data that is encrypted on disk in the clear
	 * in memory.
	 */
	mech = zio_crypt_setup_mech_gen_iv(crypt, type, dedup, key, txg,
	    bookmark, src, plaintext.cd_length, iv);
	ASSERT(mech != NULL);
retry:
#if _KERNEL
    printk("zio_crypt 1\n");
#endif
	err = crypto_encrypt(mech, &plaintext, &key->zk_key, key->zk_ctx_tmpl,
	    &ciphertext, NULL);

#if _KERNEL
    printk("zio_crypt back with %d\n", err);

	switch (err) {
	case CRYPTO_SUCCESS:
		err = 0;
		break;
	case CRYPTO_BUSY:
		goto retry;
	case CRYPTO_KEY_HANDLE_INVALID:
	case CRYPTO_KEY_NEEDED:
	case CRYPTO_KEY_CHANGED:
	case CRYPTO_PIN_INCORRECT:
	case CRYPTO_PIN_EXPIRED:
	case CRYPTO_PIN_LOCKED:
	case CRYPTO_USER_NOT_LOGGED_IN:
		err = ENOKEY;
		break;
	case CRYPTO_OLD_CTX_TEMPLATE:
		key->zk_ctx_tmpl_valid = B_FALSE;
		crypto_destroy_ctx_template(key->zk_ctx_tmpl);
		goto retry;
	default:
		cmn_err(CE_WARN,
		    "zio_encrypt_data: crypto_encrypt %x\n", err);
		err = EIO;
	}

    printk("zio_crypt free mech\n");
#endif

	zio_crypt_free_mech(mech);

#ifdef _KERNEL
	if (err == 0)
		ASSERT3U(bcmp(src, dest, size), !=, 0);
#endif /* _KERNEL */
out:
#if defined (ZFS_DEBUG) && defined (_KERNEL)
	ASSERT3U(bcmp(src, srccopy, size), ==, 0);
	kmem_free(srccopy, size);
#endif /* _DEBUG */
	if (srciov != NULL) {
		kmem_free(srciov, sizeof (iovec_t) * srcuio.uio_iovcnt);
	}
	if (dstiov != NULL) {
		kmem_free(dstiov, sizeof (iovec_t) * dstuio.uio_iovcnt);
	}
	if (lsrc) {
		kmem_free(src, size);
		src = NULL;
	}

#if _KERNEL
    printk("zio_crypt leaving. %d\n", err);
#endif

#endif

	return (err);
}

/*
 * zio_decrypt_data
 *
 * To be called only from the zio pipeline.
 */
int
zio_decrypt_data(zcrypt_key_t *key, zbookmark_t *bookmark,
    uint64_t txg, int type, void *src, uint64_t srcsize, char *mac, char *iv,
    void *dest, uint64_t destsize)
{
	int err = EIO;
#if _KERNEL
	crypto_data_t ciphertext, plaintext;
	crypto_mechanism_t *mech;
	iovec_t *srciov = NULL, *dstiov = NULL;
	uio_t srcuio = { 0 }, dstuio = { 0 };
	size_t maclen;
	uint_t iovcnt;

	ASSERT3U(destsize, <=, ZIO_CRYPT_MAX_CCM_DATA);

#ifdef _KERNEL
	srcuio.uio_segflg = dstuio.uio_segflg = UIO_SYSSPACE;
#else
	srcuio.uio_segflg = dstuio.uio_segflg = UIO_USERSPACE;
#endif /* _KERNEL */
	ciphertext.cd_format = CRYPTO_DATA_UIO;
	ciphertext.cd_offset = 0;
	ciphertext.cd_uio = &srcuio;
	ciphertext.cd_miscdata = NULL;
	plaintext.cd_format = CRYPTO_DATA_UIO;
	plaintext.cd_offset = 0;
	plaintext.cd_uio = &dstuio;
	plaintext.cd_miscdata = NULL;

	ASSERT(mac != NULL);
	if (type == DMU_OT_INTENT_LOG) {
		iovcnt = zil_set_crypto_data(src, srcsize, dest,
		    &srciov, &dstiov, &plaintext.cd_length, B_FALSE);
		if (iovcnt == 0)
			return (0);
		maclen = zio_crypt_table[key->zk_crypt].ci_zil_maclen;
		dstuio.uio_iovcnt = iovcnt;
		dstuio.uio_iov = dstiov;

		ciphertext.cd_length = plaintext.cd_length + maclen;
		srcuio.uio_iov = srciov;
		srcuio.uio_iovcnt = iovcnt + 1;
		srcuio.uio_iov[iovcnt].iov_base = mac;
		srcuio.uio_iov[iovcnt].iov_len = maclen;

		mech = zio_crypt_setup_mech_gen_iv(key->zk_crypt, type,
		    B_FALSE, key, txg, bookmark, NULL,
		    ciphertext.cd_length, iv);
	} else {
		srciov = kmem_alloc(sizeof (iovec_t) * 2, KM_SLEEP);

		maclen = zio_crypt_table[key->zk_crypt].ci_maclen;

		srciov[0].iov_base = src;
		srciov[0].iov_len = srcsize;
		srciov[1].iov_base = mac;
		srciov[1].iov_len = maclen;
		srcuio.uio_iov = srciov;
		srcuio.uio_iovcnt = 2;
		ciphertext.cd_length = srcsize + maclen;

		SET_CRYPTO_DATA(plaintext, dest, destsize);

		mech = zio_crypt_setup_mech_with_iv(key->zk_crypt, type,
		    ciphertext.cd_length, iv);
	}

	ASSERT(mech != NULL);
retry:
	err = crypto_decrypt(mech, &ciphertext, &key->zk_key, key->zk_ctx_tmpl,
	    &plaintext, NULL);

	switch (err) {
	case CRYPTO_SUCCESS:
		err = 0;
		break;
	case CRYPTO_BUSY:
		goto retry;
	case CRYPTO_KEY_HANDLE_INVALID:
	case CRYPTO_KEY_NEEDED:
	case CRYPTO_KEY_CHANGED:
	case CRYPTO_PIN_INCORRECT:
	case CRYPTO_PIN_EXPIRED:
	case CRYPTO_PIN_LOCKED:
	case CRYPTO_USER_NOT_LOGGED_IN: {
		err = ENOKEY;
		break;
	}
	case CRYPTO_OLD_CTX_TEMPLATE:
		key->zk_ctx_tmpl_valid = B_FALSE;
#if _KERNEL
		crypto_destroy_ctx_template(key->zk_ctx_tmpl);
#endif
		goto retry;
	case CRYPTO_INVALID_MAC:
		err = ECKSUM;
#if _KERNEL
        printk("zio_crypt setting ECKSUM\n");
#endif
		break;
	default:
		cmn_err(CE_WARN, "zio_decrypt_data crypto_decrypt: %x\n", err);
		err = EIO;
	}

	zio_crypt_free_mech(mech);
	if (srciov != NULL) {
		kmem_free(srciov, sizeof (iovec_t) * srcuio.uio_iovcnt);
	}
	if (dstiov != NULL) {
		kmem_free(dstiov, sizeof (iovec_t) * dstuio.uio_iovcnt);
	}
#endif
	return (err);
}


/*
 * Encrypted Crash Dump device support.
 *
 * Dumps don't fo through the ZIO pipeline so we need a different
 * method of encrypting/decrypting the dump data.
 * In place crypto is used here unlike in the ZIO pipeline.
 * We also use AES in CTR mode because we aren't filling in blkptrs
 * here we have no place to put a MAC.
 */
static int
zvol_dump_crypt_common(spa_t *spa, uint64_t objset,
    char *iv, size_t ivlen, char *buf, size_t bufsz,
    boolean_t encrypt)
{
	int err = CRYPTO_SUCCESS;
#ifdef _KERNEL
	crypto_mechanism_t mech;
	crypto_data_t cdt;
	static zcrypt_key_t *k = NULL;
	static crypto_mech_type_t mechtype;
	CK_AES_CTR_PARAMS *ctrp;

	if (k == NULL) {
		k = zcrypt_key_lookup(spa, objset, 0);
		if (k == NULL) {
			return (ENOKEY);
		}
		/*
		 * Note there is no matching release for this but we are
		 * panicking so it doesn't matter.
		 */
		zcrypt_key_hold(k, FTAG);
		mechtype = crypto_mech2id(SUN_CKM_AES_CTR);
		if (mechtype == CRYPTO_MECH_INVALID)
			return (EINVAL);
	}

	SET_CRYPTO_DATA(cdt, buf, bufsz);
	mech.cm_type = mechtype;
	ctrp = kmem_zalloc(sizeof (CK_AES_CTR_PARAMS), KM_SLEEP);
	bcopy(iv, &ctrp->cb, ivlen);
	ctrp->ulCounterBits = 8;
	mech.cm_param = (char *)ctrp;
	mech.cm_param_len = sizeof (CK_AES_CTR_PARAMS);

    printk("zio_crypt 2\n");

	if (encrypt) {
		err = crypto_encrypt(&mech, &cdt, &k->zk_key, NULL, NULL, NULL);
	} else {
		err = crypto_decrypt(&mech, &cdt, &k->zk_key, NULL, NULL, NULL);
	}

	if (err != 0)
		return (EINVAL);
#endif
	return (err);
}

int
zvol_dump_encrypt(spa_t *spa, uint64_t objset, dva_t *dva,
    const void *buf, size_t bufsz)
{
	return (zvol_dump_crypt_common(spa, objset, (char *)dva,
	    sizeof (dva_t), (char *)buf, bufsz, B_TRUE));
}

int
zvol_dump_decrypt(spa_t *spa, uint64_t objset, dva_t *dva,
    const void *buf, size_t bufsz)
{
	return (zvol_dump_crypt_common(spa, objset, (char *)dva,
	    sizeof (dva_t), (char *)buf, bufsz, B_FALSE));
}
