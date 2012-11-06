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
 * Copyright (c) 2008, 2011, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Common routines/data used by zfs and zpool and zio crypto functions.
 */

#include <sys/zio_crypt.h>

/*
 * Cryptographic Algorithm table.
 *
 * NOTE that some crypto mechanisms require the key length in the
 * crypto_key_t to be specified in bits not bytes.  Bytes are used
 * here since we kmem_alloc based on these values.
 *
 * on == aes-128-ccm
 *
 * Algorithm/Mode    Keylen	maclen  ZIL     dedup Option_name
 *                   Bytes              maclen  safe
 */
zio_crypt_info_t zio_crypt_table[ZIO_CRYPT_FUNCTIONS] = {
	{ "",			0,	0,	0, B_FALSE, "inherit"},
	{SUN_CKM_AES_CCM,	16,	12,	8, B_TRUE,  "on"},
	{"",			0,	0,	0, B_FALSE, "off"},
	{SUN_CKM_AES_CCM,	16,	12,	8, B_TRUE,  "aes-128-ccm"},
	{SUN_CKM_AES_CCM,	24,	12,	8, B_TRUE,  "aes-192-ccm"},
    {SUN_CKM_AES_CCM,	32,	12,	8, B_TRUE,  "aes-256-ccm"},
    {SUN_CKM_AES_GCM,	16,	12,	8, B_FALSE, "aes-128-gcm"},
    {SUN_CKM_AES_GCM,	24,	12,	8, B_FALSE, "aes-192-gcm"},
    {SUN_CKM_AES_GCM,	32,	12,	8, B_FALSE, "aes-256-gcm"},
    {SUN_CKM_AES_CTR,	16,	0,	0, B_FALSE, "aes-128-ctr"},
};

/*
 * Wrapping key table.
 *
 * This is separate from the zio_crypt_table because the IV and MAC lengths
 * could be different.  It will also likely contain algorithms in the future
 * that wouldn't be used for encrypting data (eg RSA).
 *
 * 	Algorithm/Mode		IV	MAC	NAME
 */
zio_crypt_wrap_info_t zio_crypt_wrap_table[ZIO_CRYPT_WRAP_FUNCTIONS] = {
	{SUN_CKM_AES_CCM,	13,	16,	"aes-ccm"},
	{SUN_CKM_AES_GCM,	13,	16,	"aes-gcm"},
};
