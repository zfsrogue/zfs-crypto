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

#include <sys/dmu_objset.h>
#include <sys/dsl_crypto.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/dmu_tx.h>
#include <sys/spa_impl.h>
#include <sys/zap.h>
#include <sys/zcrypt.h>
#include <sys/zfs_context.h>
#include <sys/zio_crypt.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

int dsl_keychain_load(dsl_dataset_t *ds, int crypt, zcrypt_key_t *wrappingkey);
int dsl_keychain_load_dd(dsl_dir_t *dd, uint64_t dsobj,
    int crypt, zcrypt_key_t *wrappingkey);

static void
dsl_keychain_create_obj(dsl_dir_t *dd, dmu_tx_t *tx)
{
	objset_t *mos = dd->dd_pool->dp_meta_objset;
	dmu_buf_will_dirty(dd->dd_dbuf, tx);
	dd->dd_phys->dd_keychain_obj = zap_create_flags(mos,
	    0, ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY,
	    DMU_OT_DSL_KEYCHAIN, SPA_MINBLOCKSHIFT, SPA_MINBLOCKSHIFT,
	    DMU_OT_NONE, 0, tx);
}

static void
dsl_keychain_set_key(dsl_dir_t *dd, dmu_tx_t *tx,
    caddr_t wkeybuf, size_t wkeylen, uint64_t rekey_date)
{
	objset_t *mos = dd->dd_pool->dp_meta_objset;
	uint64_t keychain_zapobj = dd->dd_phys->dd_keychain_obj;
	uint64_t props_zapobj = dd->dd_phys->dd_props_zapobj;

	ASSERT(keychain_zapobj != 0);
	VERIFY(zap_update_uint64(mos, keychain_zapobj,
	    (uint64_t *)&tx->tx_txg, 1, 1, wkeylen, wkeybuf, tx) == 0);
	VERIFY(zap_update(mos, props_zapobj,
	    zfs_prop_to_name(ZFS_PROP_REKEYDATE),
	    8, 1, (void *)&rekey_date, tx) == 0);
}

static void
dsl_keychain_clone_phys(dsl_dataset_t *src, dsl_dir_t *dd,
    dmu_tx_t *tx, zcrypt_key_t *dwkey)
{
	objset_t *mos = dd->dd_pool->dp_meta_objset;
	uint64_t keychain = dd->dd_phys->dd_keychain_obj;
	caddr_t wrappedkey = NULL;
	size_t wkeylen = 0;
	zcrypt_keystore_node_t *kn;
	zcrypt_keychain_node_t *n;
	uint64_t newest_txg = src->ds_phys->ds_creation_txg;

	kn = zcrypt_keystore_find_node(dsl_dataset_get_spa(src),
	    src->ds_object, B_FALSE);
	if (kn == NULL) {
		kn = zcrypt_keystore_find_node(dsl_dataset_get_spa(src),
		    src->ds_dir->dd_phys->dd_head_dataset_obj, B_FALSE);
	}
	ASSERT(kn != NULL);
	ASSERT(dwkey != NULL);

	/*
	 * Walk the in memory AVL tree representation of the keychain
	 * creating new keychain entries using our wrappingkey, stopping
	 * when we reach keychain entries created after the snapshot we
	 * are cloning from.
	 */
	mutex_enter(&kn->skn_lock);
	for (n = avl_first(&kn->skn_keychain);
	    n != NULL && n->dkn_txg <= newest_txg;
	    n = AVL_NEXT(&kn->skn_keychain, n)) {
		VERIFY(zcrypt_wrap_key(dwkey, n->dkn_key, &wrappedkey,
		    &wkeylen, zio_crypt_select_wrap(dwkey->zk_crypt)) == 0);
		VERIFY(zap_update_uint64(mos, keychain, &n->dkn_txg,
		    1, 1, wkeylen, wrappedkey, tx) == 0);
		kmem_free(wrappedkey, wkeylen);
	}
	mutex_exit(&kn->skn_lock);
}

/*
 * dsl_crypto_key_gen - Generate dataset key
 *
 * Generate a new key for this dataset based on its encryption property type.
 * Store the key as a usable zcrypt_key_t in the in memory keystore and
 * put the wrapped version of it in the on disk keychain.
 *
 * returns 0 on success
 */
int
dsl_crypto_key_create(dsl_dir_t *dd, dsl_dataset_phys_t *dsphys,
    uint64_t dsobj, dsl_crypto_ctx_t *ctx, dmu_tx_t *tx)
{
	int error = -1;
#ifdef DEBUG
	zcrypt_key_t *debugkey;
#endif /* DEBUG */
	zcrypt_key_t *wrappingkey, *dslkey;
	caddr_t wkeybuf = NULL;
	size_t wkeylen = 0;
	uint64_t crypt;
	spa_t *spa = dd->dd_pool->dp_spa;
	zcrypt_keystore_node_t *skn;

	if (ctx == NULL) {
		return (0);
	}

	crypt = ctx->dcc_crypt;
	if (crypt == ZIO_CRYPT_OFF || crypt == ZIO_CRYPT_INHERIT) {
		return (0);
	}

	crypt = zio_crypt_select(crypt, ZIO_CRYPT_ON_VALUE);
	wrappingkey = ctx->dcc_wrap_key;
	skn = zcrypt_keystore_insert(spa, dsobj, wrappingkey);
	if (skn == NULL) {
		error = ENOKEY;
		goto out;
	}

	dslkey = zcrypt_key_gen(crypt);
	zcrypt_key_hold(wrappingkey, FTAG);
	error = zcrypt_wrap_key(wrappingkey, dslkey,
	    &wkeybuf, &wkeylen, zio_crypt_select_wrap(crypt));
	if (error != 0) {
		zcrypt_key_free(dslkey);
		spa_history_log_internal(spa, "key create", tx,
		    "failed dataset = %llu unable to wrap key", dsobj, error);
		goto out;
	}
	dsl_keychain_create_obj(dd, tx);
	dsl_keychain_set_key(dd, tx, wkeybuf, wkeylen,
	    dsphys->ds_creation_time);
	zcrypt_keychain_insert(&skn->skn_keychain,
	    dsphys->ds_creation_txg, dslkey);
	if (ctx->dcc_salt != 0) {
		objset_t *mos = dd->dd_pool->dp_meta_objset;
		uint64_t props_zapobj = dd->dd_phys->dd_props_zapobj;

		error = zap_update(mos, props_zapobj,
		    zfs_prop_to_name(ZFS_PROP_SALT), 8, 1,
		    (void *)&ctx->dcc_salt, tx);
	}
	if (error == 0)
		spa_history_log_internal(spa, "key create", tx,
		    "succeeded dataset = %llu", dsobj);
#ifdef DEBUG
	ASSERT3U(zcrypt_unwrap_key(wrappingkey, crypt,
	    wkeybuf, wkeylen, &debugkey), ==, 0);
	zcrypt_key_compare(dslkey, debugkey);
	zcrypt_key_free(debugkey);
#endif /* DEBUG */
out:
	zcrypt_key_release(wrappingkey, FTAG);
	if (wkeylen > 0) {
		kmem_free(wkeybuf, wkeylen);
	}

	return (error);
}

/*
 * dsl_crypto_key_clone
 *
 * Our caller (dmu_objset_create_sync) must have a lock on the dataset.
 */
int
dsl_crypto_key_clone(dsl_dir_t *dd, dsl_dataset_phys_t *dsphys,
    uint64_t dsobj, dsl_dataset_t *clone_origin,
    dsl_crypto_ctx_t *ctx, dmu_tx_t *tx)
{
	zcrypt_key_t *txgkey;
	zcrypt_key_t *wrappingkey = NULL;
	dsl_dataset_t *origin;
	uint64_t crypt;
	spa_t *spa = dd->dd_pool->dp_spa;
	int error = 0;

	ASSERT(ctx != NULL);

	if (BP_IS_HOLE(&dsphys->ds_bp)) {
		origin = ctx->dcc_origin_ds;
	} else {
		origin = clone_origin;
	}
	ASSERT(origin != NULL);

	/*
	 * Need to look at the value of crypt on the origin snapshot
	 * since it is sticky for encryption.
	 */
	VERIFY(dsl_prop_get_ds(origin, zfs_prop_to_name(ZFS_PROP_ENCRYPTION),
                           8, 1, &crypt,/* DSL_PROP_GET_EFFECTIVE,*/ NULL) == 0);

	if (crypt == ZIO_CRYPT_OFF) {
		return (0);
	}

	wrappingkey = ctx->dcc_wrap_key;

	dsl_keychain_create_obj(dd, tx);
	dsl_keychain_clone_phys(origin, dd, tx, wrappingkey);

	if (ctx->dcc_salt != 0) {
		objset_t *mos = dd->dd_pool->dp_meta_objset;
		uint64_t props_zapobj = dd->dd_phys->dd_props_zapobj;

		error = zap_update(mos, props_zapobj,
		    zfs_prop_to_name(ZFS_PROP_SALT), 8, 1,
		    (void *)&ctx->dcc_salt, tx);
	}

	if (ctx->dcc_clone_newkey) {
		caddr_t wkeybuf;
		size_t wkeylen;
		/*
		 * Generate a new key and add it to the keychain
		 * to be valid from this txg onwards.
		 */
		zcrypt_key_hold(wrappingkey, FTAG);
		txgkey = zcrypt_key_gen(crypt);
		VERIFY(zcrypt_wrap_key(wrappingkey, txgkey,
		    &wkeybuf, &wkeylen, zio_crypt_select_wrap(crypt)) == 0);
		zcrypt_key_release(wrappingkey, FTAG);
		dsl_keychain_set_key(dd, tx, wkeybuf, wkeylen,
		    dsphys->ds_creation_time);
		kmem_free(wkeybuf, wkeylen);
		zcrypt_key_free(txgkey);
		spa_history_log_internal(spa, "key create", tx,
		    "rekey succeeded dataset = %llu from dataset = %llu",
		    dsobj, clone_origin->ds_object);
	} else {
		spa_history_log_internal(spa, "key create", tx,
		    "succeeded dataset = %llu from dataset = %llu",
		    dsobj, clone_origin->ds_object);
	}

	if (wrappingkey != NULL) {
		error = dsl_keychain_load_dd(dd, dsobj, crypt, wrappingkey);
	}

	return (error);
}

zfs_crypt_key_status_t
dsl_dataset_keystatus(dsl_dataset_t *ds, boolean_t dp_config_rwlock_held)
{
	/*
	 * Sneaky way of determining if this is an encrypted dataset
	 * by looking for a keychain obj so we can avoid calling
	 * dsl_prop_get_ds and all the locking issues that can entail
	 * given when we can be called.
	 */
	if (ds == NULL)
		return (ZFS_CRYPT_KEY_UNAVAILABLE);
	if (ds->ds_dir != NULL && ds->ds_dir->dd_phys != NULL &&
	    ds->ds_dir->dd_phys->dd_keychain_obj == 0) {
		return (ZFS_CRYPT_KEY_NONE);
	}
	if (zcrypt_keystore_find_node(dsl_dataset_get_spa(ds),
	    ds->ds_object, dp_config_rwlock_held)) {
		return (ZFS_CRYPT_KEY_AVAILABLE);
	}
	return (ZFS_CRYPT_KEY_UNAVAILABLE);
}

int
dsl_dataset_keystatus_byname(dsl_pool_t *dp, const char *dsname,
    zfs_crypt_key_status_t *keystatus)
{
	dsl_dataset_t *ds;
	int error;

	error = dsl_dataset_hold(dp, dsname, FTAG, &ds);
	if (error != 0) {
		return (error);
	}

	*keystatus = dsl_dataset_keystatus(ds, B_FALSE);
	dsl_dataset_rele(ds, FTAG);

	return (0);
}

/*
 * dsl_crypto_key_unload
 *
 * Remove the key from the in memory keystore.
 *
 * First we have to remove the minor node for a ZVOL or unmount
 * the filesystem.  This is so that we flush all pending IO for it to disk
 * so we won't need to encrypt anything with this key.  Anything in flight
 * should already have a lock on the keys it needs.
 * We can't assume that userland has already successfully unmounted the
 * dataset though in many cases it will have.
 *
 * If the key can't be removed return the failure back to our caller.
 */
int
dsl_crypto_key_unload(const char *dsname)
{
	dsl_dataset_t *ds;
	objset_t *os;
	int error;
	spa_t *spa;
    dsl_pool_t *dp;
#ifdef _KERNEL
	dmu_objset_type_t os_type;
	//vfs_t *vfsp;
    struct vfsmount *vfsp;
#endif /* _KERNEL */

    error = dsl_pool_hold(dsname, FTAG, &dp);
    if (error != 0)
        return (error);

	/* XXX - should we use own_exclusive() here? */
	if ((error = dsl_dataset_hold(dp, dsname, FTAG, &ds)) != 0) {
        dsl_pool_rele(dp, FTAG);
		return (error);
    }

	if ((error = dmu_objset_from_ds(ds, &os)) != 0) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (error);
	}

#ifdef _KERNEL
	/*
	 * Make sure that the device node has gone for ZVOLs
	 * and that filesystems are umounted.
	 */
#if 0 // FIXME
	os_type = dmu_objset_type(os);
	if (os_type == DMU_OST_ZVOL) {
		error = zvol_remove_minor(dsname);
		if (error == ENXIO)
			error = 0;
	} else if (os_type == DMU_OST_ZFS) {
		vfsp = zfs_get_vfs(dsname);
		if (vfsp != NULL) {
			error = vn_vfswlock(vfsp->vfs_vnodecovered);
			VFS_RELE(vfsp);
			if (error == 0)
				error = dounmount(vfsp, 0, CRED());
		}
	}
	if (error != 0) {
		dsl_dataset_rele(ds, FTAG);
		return (error);
	}
#endif

#endif /* _KERNEL */

	/*
	 * Make sure all dbufs are synced.
	 *
	 * It is essential for encrypted datasets to ensure that
	 * there is no further pending IO before removing the key.
	 */
	if (dmu_objset_is_dirty(os, 0)) // FIXME, 0?
		txg_wait_synced(dmu_objset_pool(os), 0);
	dmu_objset_evict_dbufs(os);

	spa = dsl_dataset_get_spa(ds);
	error = zcrypt_keystore_remove(spa, ds->ds_object);

	dsl_dataset_rele(ds, FTAG);
    dsl_pool_rele(dp, FTAG);
	return (error);
}

int
dsl_crypto_key_load(const char *dsname, zcrypt_key_t *wrappingkey)
{
	dsl_dataset_t *ds;
	uint64_t crypt;
	int error;
    dsl_pool_t *dp;

    error = dsl_pool_hold(dsname, FTAG, &dp);
    if (error != 0)
        return (error);

	if ((error = dsl_dataset_hold(dp, dsname, FTAG, &ds)) != 0) {
        dsl_pool_rele(dp, FTAG);
		return (error);
    }
	/*
	 * This is key load not key change so if ds->ds_key is already
	 * set we fail.
	 */
	if (zcrypt_keystore_find_node(dsl_dataset_get_spa(ds),
	    ds->ds_object, B_FALSE) != NULL) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (EEXIST);
	}

	/*
	 * Find out what size of key we expect.
	 *
	 * For now the wrapping key size (and type) matches the size
	 * of the dataset key, this may not always be the case
	 * (particularly if we ever support wrapping dataset keys
	 * with asymmetric keys (eg RSA)).
	 *
	 * When alternate wrapping keys are added it maybe done using
	 * a index property.
	 */
	rrw_enter(&ds->ds_dir->dd_pool->dp_config_rwlock, RW_READER, FTAG);

	error = dsl_prop_get_ds(ds, zfs_prop_to_name(ZFS_PROP_ENCRYPTION),
                            8, 1, &crypt, NULL/*, DSL_PROP_GET_EFFECTIVE*/);
	rrw_exit(&ds->ds_dir->dd_pool->dp_config_rwlock, FTAG);
	if (error != 0) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (error);
	}

	if (crypt == ZIO_CRYPT_OFF) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (ENOTSUP);
	}

	ASSERT(crypt != ZIO_CRYPT_INHERIT);

	error = dsl_keychain_load(ds, crypt, wrappingkey);
	dsl_dataset_rele(ds, FTAG);
    dsl_pool_rele(dp, FTAG);
	return (error);
}

int
dsl_crypto_key_inherit(const char *dsname)
{
	char keysource[MAXNAMELEN];
	char setpoint[MAXNAMELEN];
	dsl_dataset_t *ids;
	int error;
	zcrypt_key_t *wrappingkey;
	zfs_crypt_key_status_t keystatus;
	spa_t *spa;
    dsl_pool_t *dp;

	/*
	 * Try inheriting the wrapping key from our parent
	 */
    error = dsl_pool_hold(dsname, FTAG, &dp);
    if (error != 0)
        return (error);

	error = dsl_dataset_keystatus_byname(dp, dsname, &keystatus);
	if (error != 0) {
        dsl_pool_rele(dp, FTAG);
		return (error);
    }
	if (keystatus == ZFS_CRYPT_KEY_NONE) {
        dsl_pool_rele(dp, FTAG);
		return (0);
    }
	if (keystatus == ZFS_CRYPT_KEY_AVAILABLE) {
        dsl_pool_rele(dp, FTAG);
		return (EEXIST);
    }

	error = dsl_prop_get(dsname, zfs_prop_to_name(ZFS_PROP_KEYSOURCE), 1,
	    sizeof (keysource), &keysource, setpoint);
	if (error != 0) {
        dsl_pool_rele(dp, FTAG);
		return (error);
    }

	if (strcmp(setpoint, dsname) == 0) {
        dsl_pool_rele(dp, FTAG);
		return (ENOENT);
    }

	error = dsl_dataset_hold(dp, setpoint, FTAG, &ids);
	if (error != 0) {
        dsl_pool_rele(dp, FTAG);
		return (error);
    }

	spa = dsl_dataset_get_spa(ids);
	wrappingkey = zcrypt_key_copy(zcrypt_keystore_find_wrappingkey(spa,
	    ids->ds_object));
	dsl_dataset_rele(ids, FTAG);
    dsl_pool_rele(dp, FTAG);

	if (wrappingkey == NULL)
		return (ENOENT);

	error = dsl_crypto_key_load(dsname, wrappingkey);

	return (error);
}

/*
 * dsl_crypto_key_new - generate a new key from this txg onwards
 * The new key is generate in dsl_crypto_key_new() so that we don't
 * call the blocking random_get_bytes() in sync context.
 */
struct knarg {
	zcrypt_keystore_node_t *kn_skn;
	zcrypt_key_t	*kn_txgkey;
	char		*kn_wkeybuf;
	size_t		kn_wkeylen;
    dsl_dataset_t *kn_ds;
};

/*ARGSUSED*/
static int
dsl_crypto_key_new_check(void *arg1, dmu_tx_t *tx)
{
	return (0);
}

static void
dsl_crypto_key_new_sync(void *arg1, dmu_tx_t *tx)
{
	struct knarg *kn = arg1;
	dsl_dataset_t *ds = kn->kn_ds;

	/*
	 * Generate a new key and add it to the keychain to be valid from
	 * this txg onwards.
	 */
	dsl_keychain_set_key(ds->ds_dir, tx, kn->kn_wkeybuf, kn->kn_wkeylen,
	    gethrestime_sec());
	zcrypt_keychain_insert(&kn->kn_skn->skn_keychain,
	    tx->tx_txg, kn->kn_txgkey);

	spa_history_log_internal(dsl_dataset_get_spa(ds), "key create", tx,
	    "rekey succeeded dataset = %llu", ds->ds_object);
}

int
dsl_crypto_key_new(const char *dsname)
{
	dsl_dataset_t *ds;
	objset_t *os;
	zcrypt_keystore_node_t *skn;
	spa_t *spa;
	struct knarg arg;
	int error;
    dsl_pool_t *dp;
    void *cookie;

    error = dsl_pool_hold(dsname, FTAG, &dp);
    if (error != 0)
        return (error);

	if ((error = dsl_dataset_hold(dp, dsname, FTAG, &ds)) != 0) {
        dsl_pool_rele(dp, FTAG);
		return (error);
    }

	if (dsl_dataset_is_snapshot(ds)) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (ENOTSUP);
	}

	if ((error = dmu_objset_from_ds(ds, &os)) != 0) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (error);
	}

	if (os->os_crypt == ZIO_CRYPT_OFF) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (ENOTSUP);
	}

	ASSERT(os->os_crypt != ZIO_CRYPT_INHERIT);

	/*
	 * Need the keychain and wrapping key to already be available.
	 */
	spa = dsl_dataset_get_spa(ds);
	skn = zcrypt_keystore_find_node(spa, ds->ds_object, B_FALSE);
	if (skn == NULL) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (ENOENT);
	}

	ASSERT(ds != NULL);
	ASSERT(ds->ds_objset != NULL);

	//zil_suspend_dmu_sync(dmu_objset_zil(os));
	zil_suspend(dsname, &cookie);

	arg.kn_skn = skn;
	arg.kn_txgkey = zcrypt_key_gen(os->os_crypt);
    arg.kn_ds = ds;
	zcrypt_key_hold(skn->skn_wrapkey, FTAG);
	VERIFY(zcrypt_wrap_key(skn->skn_wrapkey, arg.kn_txgkey,
	    &arg.kn_wkeybuf, &arg.kn_wkeylen,
	    zio_crypt_select_wrap(os->os_crypt)) == 0);

	error = dsl_sync_task(spa->spa_name, dsl_crypto_key_new_check,
	    dsl_crypto_key_new_sync, &arg, 1);

	kmem_free(arg.kn_wkeybuf, arg.kn_wkeylen);

	zcrypt_key_release(skn->skn_wrapkey, FTAG);

	//zil_resume_dmu_sync(dmu_objset_zil(os));
	zil_resume(os);

	dsl_dataset_rele(ds, FTAG);
    dsl_pool_rele(dp, FTAG);

	if (error)
		zcrypt_key_free(arg.kn_txgkey);
	return (error);
}

/*
 * Dataset Wrapping Key Change
 */
struct wkey_change_arg {
	char			*ca_parent;
	zcrypt_key_t		*ca_old_key;
	zcrypt_key_t		*ca_new_key;
	list_t			ca_nodes;
	nvlist_t		*ca_props;
    dsl_dataset_t *ca_ds;
};

struct kcnode {
	list_node_t		kc_node;
	dsl_dataset_t		*kc_ds;
};

/*ARGSUSED*/
static int
dsl_crypto_key_change_check(void *arg1, dmu_tx_t *tx)
{
	return (0);
}

struct kcs {
    dsl_dataset_t *kcs_ds;
    struct wkey_change_arg *kcs_ca;
};

/*
 * dsl_crypto_key_change
 *
 * The old key must already be present in memory since the user interface
 * doesn't provide away to prompt or retrieve the old key.
 */
static void
dsl_crypto_key_change_sync(void *arg, dmu_tx_t *tx)
{
	struct wkey_change_arg *ca = arg;
	dsl_dataset_t *ds = ca->ca_ds;
	size_t wkeylen;
	char *wkeybuf = NULL;
	zcrypt_key_t *txgkey;
	zap_cursor_t zc;
	zap_attribute_t za;
	objset_t *mos;
	uint64_t keychain_zapobj;
	spa_t *spa;
	zcrypt_keystore_node_t *zkn;

	ASSERT(RRW_WRITE_HELD(&ds->ds_dir->dd_pool->dp_config_rwlock));

	mos = ds->ds_dir->dd_pool->dp_meta_objset;
	keychain_zapobj = ds->ds_dir->dd_phys->dd_keychain_obj;

	/*
	 * To allow for the case were the keychains of child datasets
	 * are not loaded (ie an explicit 'zfs key -u tank/fs/sub' had
	 * been done some time before doing 'zfs key -c tank/fs') we itterate
	 * over the zap objects on disk rather than copying from the
	 * in memory keystore node.
	 */
	for (zap_cursor_init(&zc, mos, keychain_zapobj);
	    zap_cursor_retrieve(&zc, &za) == 0;
	    zap_cursor_advance(&zc)) {
		wkeylen = za.za_num_integers;
		wkeybuf = kmem_alloc(wkeylen, KM_PUSHPAGE);
		VERIFY(zap_lookup_uint64(mos, keychain_zapobj,
		    (uint64_t *)za.za_name, 1, 1, wkeylen, wkeybuf) == 0);
		VERIFY(zcrypt_unwrap_key(ca->ca_old_key,
		    ds->ds_objset->os_crypt, wkeybuf, wkeylen, &txgkey) == 0);
		kmem_free(wkeybuf, wkeylen);
		VERIFY(zcrypt_wrap_key(ca->ca_new_key, txgkey,
		    &wkeybuf, &wkeylen,
		    zio_crypt_select_wrap(ds->ds_objset->os_crypt)) == 0);
		zcrypt_key_free(txgkey);
		VERIFY(zap_update_uint64(mos, keychain_zapobj,
		    (uint64_t *)za.za_name, 1, 1, wkeylen, wkeybuf, tx) == 0);
		kmem_free(wkeybuf, wkeylen);
	}

	zap_cursor_fini(&zc);

	spa = dsl_dataset_get_spa(ds);

	/*
	 * If the wrapping key is loaded switch the in memory copy now.
	 */
	zkn = zcrypt_keystore_find_node(spa, ds->ds_object, B_FALSE);
	if (zkn != NULL) {
		zcrypt_key_free(zkn->skn_wrapkey);
		zkn->skn_wrapkey = zcrypt_key_copy(ca->ca_new_key);
	}

	spa_history_log_internal(spa, "key change", tx,
	    "succeeded dataset = %llu", ds->ds_object);
}

static int
dsl_crypto_key_change_find(const char *dsname, void *arg)
{
	struct wkey_change_arg *ca = arg;
	struct kcnode *kcn;
	dsl_dataset_t *ds;
	objset_t *os;
	uint64_t crypt;
	char caource[MAXNAMELEN];
	char setpoint[MAXNAMELEN];
	int err;
    dsl_pool_t *dp;

    err = dsl_pool_hold(dsname, FTAG, &dp);
    if (err != 0)
        return (err);

	kcn = kmem_alloc(sizeof (struct kcnode), KM_SLEEP);
	if ((err = dsl_dataset_hold(dp, dsname, kcn, &ds)) != 0) {
		kmem_free(kcn, sizeof (struct kcnode));
        dsl_pool_rele(dp, FTAG);
		return (err);
	}

	if ((err = dmu_objset_from_ds(ds, &os)) != 0) {
		dsl_dataset_rele(ds, kcn);
        dsl_pool_rele(dp, FTAG);
		kmem_free(kcn, sizeof (struct kcnode));
		return (err);
	}

	/*
	 * Check that this child dataset of ca->parent
	 * is actually inheriting keysource from ca->parent and
	 * not somewhere else (eg local, or some other dataset).
	 */
	rrw_enter(&ds->ds_dir->dd_pool->dp_config_rwlock, RW_READER, FTAG);
	VERIFY(dsl_prop_get_ds(ds, zfs_prop_to_name(ZFS_PROP_ENCRYPTION),
                           8, 1, &crypt, NULL/*, DSL_PROP_GET_EFFECTIVE*/) == 0);
	VERIFY(dsl_prop_get_ds(ds, zfs_prop_to_name(ZFS_PROP_KEYSOURCE), 1,
                           sizeof (caource), &caource, setpoint/*, DSL_PROP_GET_EFFECTIVE*/) == 0);
	rrw_exit(&ds->ds_dir->dd_pool->dp_config_rwlock, FTAG);
	if (crypt == ZIO_CRYPT_OFF ||
	    ((strcmp(ca->ca_parent, setpoint) != 0 &&
	    strcmp(ca->ca_parent, dsname) != 0))) {
		dsl_dataset_rele(ds, kcn);
        dsl_pool_rele(dp, FTAG);
		kmem_free(kcn, sizeof (struct kcnode));
		return (0);
	}

	//dsl_sync_task_create(ca->ca_dstg, dsl_crypto_key_change_check,
    //  dsl_crypto_key_change_sync, ds, arg, 1);
    ca->ca_ds = ds;
    err = dsl_sync_task(dsname, dsl_crypto_key_change_check,
                          dsl_crypto_key_change_sync, arg,
                          1);

	kcn->kc_ds = ds;
	list_insert_tail(&ca->ca_nodes, kcn);

    dsl_dataset_rele(ds, kcn);
    dsl_pool_rele(dp, FTAG);
	return (0);
}

int
dsl_crypto_key_change(char *dsname, zcrypt_key_t *newkey, nvlist_t *props)
{
	struct wkey_change_arg *ca;
	struct kcnode *kcn;
	dsl_dataset_t *ds;
	dsl_props_arg_t pa;
	spa_t *spa;
	int err;
	//dsl_sync_task_group_t *dstg;
	zcrypt_key_t *oldkey;
    dsl_pool_t *dp;

	ASSERT(newkey != NULL);
	ASSERT(dsname != NULL);

    err = dsl_pool_hold(dsname, FTAG, &dp);
    if (err != 0)
        return (err);

	if ((err = dsl_dataset_hold(dp, dsname, FTAG, &ds)) != 0) {
        dsl_pool_rele(dp, FTAG);
		return (err);
    }

	/*
	 * Take the spa lock here so that new datasets can't get
	 * created below us while we are doing a wrapping key change.
	 * This is to avoid them being created with the wrong inherited
	 * wrapping key.
	 */
	err = spa_open(dsname, &spa, FTAG);
	if (err) {
        dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		return (err);
    }
	oldkey = zcrypt_key_copy(zcrypt_keystore_find_wrappingkey(spa,
	    ds->ds_object));
	if (oldkey == NULL) {
		dsl_dataset_rele(ds, FTAG);
        dsl_pool_rele(dp, FTAG);
		spa_close(spa, FTAG);
		return (ENOENT);
	}
	ca = kmem_alloc(sizeof (struct wkey_change_arg), KM_SLEEP);
	ca->ca_new_key = newkey;
	ca->ca_old_key = oldkey;
	ca->ca_parent = dsname;
	ca->ca_props = props;

	list_create(&ca->ca_nodes, sizeof (struct kcnode),
	    offsetof(struct kcnode, kc_node));

	zcrypt_key_hold(ca->ca_old_key, FTAG);
	zcrypt_key_hold(ca->ca_new_key, FTAG);

	//ca->ca_dstg = dstg = dsl_sync_task_group_create(spa_get_dsl(spa));

	err = dmu_objset_find(dsname, dsl_crypto_key_change_find,
	    ca, DS_FIND_CHILDREN);

	/*
	 * If this is the "top" dataset in this keychange it gets
	 * the keysource and salt properties updated.
	 */
	pa.pa_props = props;
	pa.pa_source = ZPROP_SRC_LOCAL;
	//pa.pa_flags = 0;
	//pa.pa_zone = curzone;
	//dsl_sync_task_create(ca->ca_dstg, NULL, dsl_props_set_sync, ds, &pa, 2);
    dsl_props_set(dsname, ZPROP_SRC_LOCAL, props);

	//if (err == 0)
	//	err = dsl_sync_task_group_wait(dstg);

	while ((kcn = list_head(&ca->ca_nodes))) {
		list_remove(&ca->ca_nodes, kcn);
		dsl_dataset_rele(kcn->kc_ds, kcn);
		kmem_free(kcn, sizeof (struct kcnode));
	}

	//dsl_sync_task_group_destroy(ca->ca_dstg);

	/*
	 * We are finished so release and free both the old and new keys.
	 * We can free even the new key because everyone got a copy of it
	 * not a reference to this one.
	 */
	zcrypt_key_release(ca->ca_old_key, FTAG);
	zcrypt_key_free(ca->ca_old_key);
	zcrypt_key_release(ca->ca_new_key, FTAG);
	zcrypt_key_free(ca->ca_new_key);

	kmem_free(ca, sizeof (struct wkey_change_arg));
	dsl_dataset_rele(ds, FTAG);
    dsl_pool_rele(dp, FTAG);

	spa_close(spa, FTAG);

	return (err);
}

int
dsl_keychain_load(dsl_dataset_t *ds, int crypt, zcrypt_key_t *wrappingkey)
{
	return (dsl_keychain_load_dd(ds->ds_dir, ds->ds_object,
	    crypt, wrappingkey));
}


int
dsl_keychain_load_dd(dsl_dir_t *dd, uint64_t dsobj,
    int crypt, zcrypt_key_t *wrappingkey)
{
	zap_cursor_t zc;
	zap_attribute_t za;
	objset_t *mos = dd->dd_pool->dp_meta_objset;
	uint64_t keychain_zapobj = dd->dd_phys->dd_keychain_obj;
	zcrypt_key_t *txgkey;
	zcrypt_keystore_node_t *skn;
	caddr_t wrappedkey;
	size_t wkeylen;
	spa_t *spa = dd->dd_pool->dp_spa;
	int unwrapped = 0, entries = 0;

	/*
	 * Basic algorithm is start with the ds_keychain_obj
	 * and iterate using zap_cursor_*() unwraping the
	 * values (the actual encryption keys) into zcrypt_key_t's
	 * and calling zcrypt_keychain_insert() to put them into the dsl AVL
	 * tree of keys.
	 */
	zcrypt_key_hold(wrappingkey, FTAG);
	skn = zcrypt_keystore_insert(spa, dsobj, wrappingkey);
	ASSERT(skn != NULL);
	mutex_enter(&skn->skn_lock);
	for (zap_cursor_init(&zc, mos, keychain_zapobj);
	    zap_cursor_retrieve(&zc, &za) == 0;
	    zap_cursor_advance(&zc)) {
		entries++;
		wkeylen = za.za_num_integers;
		wrappedkey = kmem_alloc(wkeylen, KM_PUSHPAGE);
		VERIFY3U(zap_lookup_uint64(mos, keychain_zapobj,
		    (uint64_t *)&za.za_name, 1, 1,
		    za.za_num_integers, wrappedkey), ==, 0);
		if (zcrypt_unwrap_key(wrappingkey, crypt,
		    wrappedkey, wkeylen, &txgkey) != 0) {
			kmem_free(wrappedkey, wkeylen);
			continue;
		}
		unwrapped++;
		kmem_free(wrappedkey, wkeylen);
		zcrypt_keychain_insert(&skn->skn_keychain,
		    *(uint64_t *)za.za_name, txgkey);
	}
	zap_cursor_fini(&zc);

	mutex_exit(&skn->skn_lock);
	zcrypt_key_release(wrappingkey, FTAG);

	if (entries > 0 && unwrapped == 0) {
		/* Wrong wrapping key passed */
		(void) zcrypt_keystore_remove(spa, dsobj);
		return (EACCES);
	}

	/*
	 * If we didn't unwrap everything we have possible corruption.
	 * If an attempt is ever made to decrypt blocks either we won't
	 * find the key (ENOKEY) or we will use the wrong key which
	 * will result in the MAC failing to verify so  ECKSUM will be
	 * set in zio->io_error which will result in an ereport being
	 * logged because the zio_read() failed.
	 * When we are running DEBUG lets ASSERT this instead.
	 */
	ASSERT3U(entries, ==, unwrapped);

	return (0);
}
