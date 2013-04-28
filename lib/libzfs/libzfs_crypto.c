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

/*
 * Cutting out sample code and running under Solaris 11, the key transforms
 * come out as:
 *
 * Using key 'This.Is.A.Key' with len 13
 * The salt picked was:
 * 0xf2 0x61 0x01 0x50 0x73 0x54 0x9a 0xd1
 * The produced key is len 16:
 * 0x5c 0x95 0x64 0x42 0x00 0x82 0x1c 0x9e 0xd4 0xac 0x01 0x83 0xc4 0x9c 0x14 0x97
 *
 * So this data needs to be replicated on Linux to be compatible.
 *
 */


#include <libintl.h>
//#include <kmfapi.h>
//#include <security/pkcs11.h>
//#include <cryptoutil.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <libgen.h>
#include <sys/fs/zfs.h>
#include <sys/zio_crypt.h>
#include <curl/curl.h>

#include "zfs_namecheck.h"
#include "zfs_prop.h"
#include "libzfs_impl.h"

#define	MAXPROMPTLEN (ZFS_MAXNAMELEN + 35)   /* 35 = prompt - dataset name */


/*
 * Constants and functions for parsing/validating
 * the keysource property
 */
const char *FMT_RAW = "raw";
const char *FMT_HEX = "hex";
const char *FMT_PASSPHRASE = "passphrase";
const char *LOC_PROMPT = "prompt";
const char *LOC_FILE = "file:///";
const char *LOC_PKCS11 = "pkcs11:";
const char *LOC_HTTP = "http://";
const char *LOC_HTTPS = "https://";

typedef enum key_format {
	KEY_FORMAT_NONE = 0,
	KEY_FORMAT_RAW,
	KEY_FORMAT_HEX,
	KEY_FORMAT_PASSPHRASE
} key_format_t;

typedef enum key_locator {
	KEY_LOCATOR_NONE = 0,
	KEY_LOCATOR_PROMPT,
	KEY_LOCATOR_FILE_URI,
	KEY_LOCATOR_PKCS11_URI,
	KEY_LOCATOR_HTTPS_URI
} key_locator_t;


static boolean_t
parse_format(key_format_t *format, char *s, int len)
{

	if (!s)
		return (B_FALSE);

	if (strncmp(FMT_RAW, s, len) == 0 && len == strlen(FMT_RAW))
		*format = KEY_FORMAT_RAW;
	else if (strncmp(FMT_HEX, s, len) == 0 && len == strlen(FMT_HEX))
		*format = KEY_FORMAT_HEX;
	else if (strncmp(FMT_PASSPHRASE, s, len) == 0 &&
	    len == strlen(FMT_PASSPHRASE))
		*format = KEY_FORMAT_PASSPHRASE;
	else
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
parse_locator(key_locator_t *locator, char *s, int len, char **uri)
{

	if (!s)
		return (B_FALSE);

	if (len == strlen(LOC_PROMPT) &&
	    strncmp(LOC_PROMPT, s, strlen(LOC_PROMPT)) == 0) {
		*locator = KEY_LOCATOR_PROMPT;
		return (B_TRUE);
	}

	if (len > strlen(LOC_FILE) &&
	    (strncmp(LOC_FILE, s, strlen(LOC_FILE)) == 0)) {
		*locator = KEY_LOCATOR_FILE_URI;
		*uri = s;
		return (B_TRUE);
	}

#if 0 // FIXME
	if (len > strlen(LOC_PKCS11) &&
	    (strncmp(LOC_PKCS11, s, strlen(LOC_PKCS11)) == 0)) {
		pkcs11_uri_t pk11uri;

		/*
		 * Validate the PKCS#11 URI by parsing it out,
		 * and checking that an object is specified.
		 * Every other part of the PKCS#11 URI is optional.
		 */
		if (pkcs11_parse_uri(s, &pk11uri) != PK11_URI_OK)
			return (B_FALSE);
		if (pk11uri.object == NULL) {
			pkcs11_free_uri(&pk11uri);
			return (B_FALSE);
		}
		pkcs11_free_uri(&pk11uri);
		*locator = KEY_LOCATOR_PKCS11_URI;
		*uri = s;
		return (B_TRUE);
	}
#endif

	if ((len > strlen(LOC_HTTPS) &&
	    (strncmp(LOC_HTTPS, s, strlen(LOC_HTTPS)) == 0)) ||
	    (len > strlen(LOC_HTTP) &&
	    (strncmp(LOC_HTTP, s, strlen(LOC_HTTP)) == 0))) {
		*locator = KEY_LOCATOR_HTTPS_URI;
		*uri = s;
		return (B_TRUE);
	}

	return (B_FALSE);
}

static boolean_t
keysource_prop_parser(char *prop_value, key_format_t *format,
    key_locator_t *locator, char **uri)
{
	int len;
	int prop_len;
	char *s = prop_value;

	*format = KEY_FORMAT_NONE;
	*locator = KEY_LOCATOR_NONE;

	if (!prop_value)
		return (B_FALSE);

	prop_len = strlen(prop_value);
	if (prop_len > ZFS_MAXPROPLEN)
		return (B_FALSE);

	for (len = 0; len < prop_len; len++)
		if (s[len] == ',')
			break;

	/* If we are at the end of the key property, there is a problem */
	if (len == prop_len)
		return (B_FALSE);

	if (!parse_format(format, s, len))
		return (B_FALSE);

	s = s + len + 1;
	len = prop_len - len - 1;

	return (parse_locator(locator, s, len, uri));
}

static void
zfs_cmd_target_dsname(zfs_cmd_t *zc, zfs_crypto_zckey_t cmd,
    char *dsname, size_t dsnamelen)
{
	int at;
	/*
	 * The name needs to be that of the dataset we are creating.
	 * Using zc_value is wrong when doing a clone because it shows
	 * the name of the origin snapshot. However it is correct when
	 * doing a zfs recv,  use zc_value upto the @ which is the
	 * name of the dataset getting created.
	 */
	if (cmd == ZFS_CRYPTO_RECV) {
		at = strcspn(zc->zc_value, "@");
		(void) strlcpy(dsname, zc->zc_value,
		    MIN(at + 1, dsnamelen));
		if (strlen(dsname) == 0) {
			(void) strlcpy(dsname, zc->zc_name, dsnamelen);
		}
	} else {
		(void) strlcpy(dsname, zc->zc_name, dsnamelen);
	}
}

static boolean_t
zfs_can_prompt_if_needed(char *keysource)
{
	key_format_t format;
	key_locator_t locator;
	char *uri;
	const char SMF_FS_LOCAL[] = "svc:/system/filesystem/local:default";

	if (!keysource_prop_parser(keysource, &format, &locator, &uri))
		return (B_FALSE);

	if (locator != KEY_LOCATOR_PROMPT)
		return (B_TRUE);

	if (getenv("SMF_FMRI") != NULL &&
	    strcmp(getenv("SMF_FMRI"), SMF_FS_LOCAL) == 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}


/*
 * Move this to a header file
 */
int crypto_pass2key(unsigned char *keydata, size_t keydatalen,
                    void *salt, size_t saltlen,
                    size_t desired_keylen,
                    void **out_keydata, size_t *out_keylen);
int pkcs11_read_data(char *filename, void **dbuf, size_t *dlen);


/*
 * Linux does not have the same limitation that Solaris has, of limiting
 * getpass() to only 8 chars. Linux limit is 128 chars.
 *
 * However, it is listed as 'Obsolete' so an alternate implementation may be
 * required.
 */
static char *getpassphrase(const char *prompt)
{
    return getpass(prompt);
}

/*
 * This could possibly go somewhere more appropriate
 */
/*
 * This function takes a char[] and length of hexadecimal values and
 * returns a malloc'ed byte array with the length of that new byte array.
 * The caller needs to provide a pointer to where this new malloc'ed byte array
 * will be passed back; as well as, a pointer for the length of the new
 * byte array.
 *
 * The caller is responsible for freeing the malloc'ed array when done
 *
 * The return code is 0 if successful, otherwise the errno value is returned.
 */
int
hexstr_to_bytes(char *hexstr, size_t hexlen, uchar_t **bytes, size_t *blen)
{
    int i, ret = 0;
    unsigned char ch;
    uchar_t *b = NULL;

    *bytes = NULL;
    *blen = 0;

    if (hexstr == NULL || (hexlen % 2 == 1))
        return (EINVAL);

    if (hexstr[0] == '0' && ((hexstr[1] == 'x') || (hexstr[1] == 'X'))) {
        hexstr += 2;
        hexlen -= 2;
    }

    *blen = (hexlen / 2);

    b = malloc(*blen);
    if (b == NULL) {
        *blen = 0;
        return (errno);
    }

    for (i = 0; i < hexlen; i++) {
        ch = (unsigned char) *hexstr;

        if (!isxdigit(ch)) {
            ret = EINVAL;
            goto out;
        }

        hexstr++;

        if ((ch >= '0') && (ch <= '9'))
            ch -= '0';
        else if ((ch >= 'A') && (ch <= 'F'))
            ch = ch - 'A' + 10;
        else if ((ch >= 'a') && (ch <= 'f'))
            ch = ch - 'a' + 10;

        if (i & 1)
            b[i/2] |= ch;
        else
            b[i/2] = (ch << 4);
    }

 out:
    if (b != NULL && ret != 0) {
        free(b);
        *blen = 0;
    } else
        *bytes = b;

    return (ret);
}





static int
get_passphrase(libzfs_handle_t *hdl, char **passphrase,
    size_t *passphraselen, key_format_t format, zfs_cmd_t *zc,
    zfs_crypto_zckey_t cmd)
{
	char prompt[MAXPROMPTLEN];
	char *tmpbuf = NULL;
	int min_psize = 8;
	char dsname[MAXNAMELEN];

	zfs_cmd_target_dsname(zc, cmd, dsname, sizeof (dsname));
	if (format == KEY_FORMAT_HEX) {
		min_psize = 2 *
		    zio_crypt_table[zc->zc_crypto.zic_crypt].ci_keylen;
		if (hdl->libzfs_crypt.zc_is_key_change) {
			(void) snprintf(prompt, MAXPROMPTLEN, "%s \'%s\': ",
			    dgettext(TEXT_DOMAIN,
			    "Enter new hexadecimal key for"),
			    dsname);
		} else {
			(void) snprintf(prompt, MAXPROMPTLEN, "%s \'%s\': ",
			    dgettext(TEXT_DOMAIN,
			    "Enter hexadecimal key for"), dsname);
		}
	} else {
		if (hdl->libzfs_crypt.zc_is_key_change) {
			(void) snprintf(prompt, MAXPROMPTLEN, "%s \'%s\': ",
			    dgettext(TEXT_DOMAIN,
			    "Enter new passphrase for"), dsname);
		} else {
			(void) snprintf(prompt, MAXPROMPTLEN, "%s \'%s\': ",
			    dgettext(TEXT_DOMAIN,
			    "Enter passphrase for"), dsname);
		}
	}

	tmpbuf = getpassphrase(prompt);
	if (tmpbuf == NULL && errno == ENXIO)
		return (EAGAIN);
	if (tmpbuf == NULL || strlen(tmpbuf) < min_psize) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "Must be at least %d characters.\n"), min_psize);
		return (EAGAIN);
	}

	*passphrase = strdup(tmpbuf);
	tmpbuf = NULL;

	/*
	 * A create/clone/recv or wrapping key change needs to reprompt.
	 * Loading the key is the only case were we don't reprompt.
	 */
	if (cmd != ZFS_CRYPTO_KEY_LOAD) {
		(void) snprintf(prompt, MAXPROMPTLEN,
		    dgettext(TEXT_DOMAIN, "Enter again: "));

		tmpbuf = getpassphrase(prompt);
		if (tmpbuf == NULL ||
		    strcmp(*passphrase, tmpbuf) != 0) {
			/* clean up */
			free(*passphrase);
			*passphrase = NULL;
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "They don't match.\n"));
			return (EAGAIN);
		}
	}

	*passphraselen = strlen(*passphrase);
	return (0);
}

void
libzfs_crypto_set_key(libzfs_handle_t *hdl, char *key, size_t keylen)
{
	hdl->libzfs_crypt.zc_key_data = key;
	hdl->libzfs_crypt.zc_key_data_len = keylen;
}

void
zfs_crypto_set_key(zfs_handle_t *zhp, char *key, size_t keylen)
{
	libzfs_crypto_set_key(zhp->zfs_hdl, key, keylen);
}

void
zfs_crypto_set_clone_newkey(zfs_handle_t *zhp)
{
	zhp->zfs_hdl->libzfs_crypt.zc_clone_newkey = B_TRUE;
}

#if 0 // FIXME
static int
prompt_pkcs11_pin(libzfs_handle_t *hdl, zfs_cmd_t *zc, zfs_crypto_zckey_t cmd,
    pkcs11_uri_t *p11uri, char **pin, uint32_t *pinlen)
{
	char prompt[MAXPROMPTLEN];
	char *input;
	char dsname[MAXNAMELEN];

	/*
	 * If the PKCS#11 uri has a pinfile argument read the pin from
	 * there.
	 *
	 * Otherwise if the libzfs_handle_t has crypto data we assume this is
	 * the PIN given we can only be in here with a PKCS#11 uri.
	 *
	 * Finally if that is empty then if we can prompt then do so using
	 * getpassphrase().
	 *
	 * Abuse zfs_can_prompt_if_needed() by pretending we are
	 * "passphrase,prompt".
	 */
	if (p11uri->pinfile) {
		struct stat sbuf;
		int pinfd = open(p11uri->pinfile, O_RDONLY);
		char *pbuf;

		if (pinfd == -1)
			return (-1);
		if (fstat(pinfd, &sbuf) != 0)
			return (-1);
		pbuf = zfs_alloc(hdl, sbuf.st_size);
		if (read(pinfd, pbuf, sbuf.st_size) != sbuf.st_size) {
			free(pbuf);
			return (-1);
		}
		(void) close(pinfd);
		pbuf[sbuf.st_size] = '\0';
		*pinlen = sbuf.st_size;
		if (pbuf[sbuf.st_size - 1] == '\n' ||
		    pbuf[sbuf.st_size - 1] == '\r') {
			*pinlen = *pinlen - 1;
		}
		*pin = pbuf;
		return (0);
	}

	if (hdl->libzfs_crypt.zc_key_data != NULL &&
	    hdl->libzfs_crypt.zc_key_data_len != 0) {
		*pinlen = hdl->libzfs_crypt.zc_key_data_len;
		*pin = zfs_alloc(hdl, *pinlen);
		bcopy(hdl->libzfs_crypt.zc_key_data, *pin, *pinlen);
		return (0);
	}
	if (!zfs_can_prompt_if_needed("passphrase,prompt")) {
		errno = ENOTTY;
		return (-1);
	}

	zfs_cmd_target_dsname(zc, cmd, dsname, sizeof (dsname));
	if (p11uri->token)  {
		(void) snprintf(prompt, MAXPROMPTLEN,
		    dgettext(TEXT_DOMAIN,
		    "Enter '%s' PKCS#11 token PIN for '%s': "),
		    p11uri->token, dsname);
	} else {
		(void) snprintf(prompt, MAXPROMPTLEN,
		    dgettext(TEXT_DOMAIN,
		    "Enter PKCS#11 token PIN for '%s': "), dsname);
	}
	input = getpassphrase(prompt);

	if (input != NULL) {
		*pin = strdup(input);
		*pinlen = strlen(*pin);
	} else {
		return (-1);
	}
	return (0);
}

static int
get_pkcs11_key_value(libzfs_handle_t *hdl, zfs_cmd_t *zc,
    zfs_crypto_zckey_t cmd, pkcs11_uri_t *p11uri,
    char **keydata, size_t *keydatalen)
{
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	KMF_KEY_CLASS keyclass = KMF_SYMMETRIC;
	KMF_ENCODE_FORMAT format = KMF_FORMAT_RAWKEY;
	KMF_ATTRIBUTE attr[10];
	KMF_KEY_HANDLE keys;
	KMF_CREDENTIAL cred;
	KMF_RAW_SYM_KEY rkey;
	KMF_HANDLE_T kmfh;
	KMF_RETURN err;
	boolean_t true_val = B_TRUE;
	CK_SLOT_ID slot;
	CK_TOKEN_INFO info;
	size_t n = 0;
	uint32_t numkeys = 0; /* Ask for all of the named keys */
	char *token = NULL;

	if (kmf_initialize(&kmfh, NULL, NULL) != KMF_OK) {
		errno = EINVAL;
		return (-1);
	}

	kmf_set_attr_at_index(attr, n++, KMF_KEYSTORE_TYPE_ATTR, &kstype,
	    sizeof (kstype));
	if (p11uri->token) {
		token = strdup((const char *)p11uri->token);
	} else {
		/* If the token wasn't set we assume the metaslot */
		token = strdup(METASLOT_TOKEN_LABEL);
	}
	kmf_set_attr_at_index(attr, n++, KMF_TOKEN_LABEL_ATTR,
	    token, strlen(token));
	kmf_set_attr_at_index(attr, n++, KMF_READONLY_ATTR,
	    &true_val, sizeof (true_val));
	kmf_set_attr_at_index(attr, n++, KMF_TOKEN_BOOL_ATTR,
	    &true_val, sizeof (true_val));

	err = kmf_configure_keystore(kmfh, n, attr);
	if (err != KMF_OK)
		goto out;

	if ((err = kmf_pk11_token_lookup(kmfh, token, &slot)) != KMF_OK ||
	    (err = C_GetTokenInfo(slot, &info)) != CKR_OK)
		goto out;
	/* Always prompt for PIN since the key is likey CKA_SENSITIVE */
	if (prompt_pkcs11_pin(hdl, zc, cmd, p11uri, &cred.cred,
	    &cred.credlen) != 0)
		goto out;
	kmf_set_attr_at_index(attr, n++, KMF_CREDENTIAL_ATTR,
	    &cred, sizeof (KMF_CREDENTIAL));

	kmf_set_attr_at_index(attr, n++, KMF_KEYLABEL_ATTR,
	    p11uri->object, strlen((const char *)p11uri->object));
	kmf_set_attr_at_index(attr, n++, KMF_KEYCLASS_ATTR, &keyclass,
	    sizeof (keyclass));
	kmf_set_attr_at_index(attr, n++, KMF_ENCODE_FORMAT_ATTR, &format,
	    sizeof (format));
	kmf_set_attr_at_index(attr, n++, KMF_COUNT_ATTR,
	    &numkeys, sizeof (numkeys));

	err = kmf_find_key(kmfh, n, attr);
	if (err != KMF_OK || numkeys != 1)
		goto out;

	kmf_set_attr_at_index(attr, n++, KMF_KEY_HANDLE_ATTR, &keys,
	    sizeof (KMF_KEY_HANDLE));
	err = kmf_find_key(kmfh, n, attr);
	err = kmf_get_sym_key_value(kmfh, &keys, &rkey);
	if (err != KMF_OK)
		goto out;
	if (rkey.keydata.len == *keydatalen) {
		*keydata = zfs_alloc(hdl, rkey.keydata.len);
		bcopy(rkey.keydata.val, *keydata, rkey.keydata.len);
	}
	*keydatalen = rkey.keydata.len;
	kmf_free_bigint(&rkey.keydata);

out:
	if (token != NULL)
		free(token);
	(void) kmf_finalize(kmfh);

	if (numkeys == 1 && err == KMF_OK) {
		return (0);
	} else if (err == KMF_ERR_AUTH_FAILED) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "PKCS#11 token login failed."));
	} else if (numkeys == 0) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "PKCS#11 token object not found."));
	} else if (numkeys > 1) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "keysource points to multiple PKCS#11"
		    " objects"));
	}

	ASSERT(errno != 0);
	return (-1);
}
#endif

struct cb_arg_curl {
	libzfs_handle_t	*cb_hdl;
	char		*cb_keydata;
	size_t		cb_keydatalen;
};

/*ARGSUSED*/
static size_t
get_keydata_curl(void *ptr, size_t size, size_t nmemb, void *arg)
{
	struct cb_arg_curl *cb = arg;
	size_t datalen = size * nmemb;

	if (ptr == NULL || datalen == 0)
		return (0);

	cb->cb_keydatalen = datalen;
	cb->cb_keydata = zfs_alloc(cb->cb_hdl, datalen);
	bcopy(ptr, cb->cb_keydata, datalen);

	return (datalen);
}

static int
key_hdl_to_zc(libzfs_handle_t *hdl, zfs_handle_t *zhp, char *keysource,
    int crypt, zfs_cmd_t *zc, zfs_crypto_zckey_t cmd)
{
    //	CK_SESSION_HANDLE session;
	int ret = 0;
	key_format_t format;
	key_locator_t locator;
	char *uri;
	//pkcs11_uri_t p11uri;
	size_t keylen = zio_crypt_table[crypt].ci_keylen;
	char *keydata = NULL;
	size_t keydatalen = 0;
	char *tmpkeydata = NULL;
	size_t tmpkeydatalen = 0;
	uint64_t salt;
	struct cb_arg_curl cb_curl = { 0 };

	zc->zc_crypto.zic_clone_newkey = hdl->libzfs_crypt.zc_clone_newkey;

	if (!keysource_prop_parser(keysource, &format, &locator, &uri)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "invalid keysource property."));
		return (-1);
	}

	/*
	 * First check if there was anything in the handle already
	 * if so we use that and we are done with locating the data.
	 * Note that we may be looking at other fields
	 * and zic_clone_newkey even if zc_key_data_len is empty.
	 *
	 * We allow this regardless of the locator so that things
	 * like a PAM module can provide the passphrase but the user
	 * can still have "passphrase,prompt" to use zfs(1M) interactively.
	 */
	if (hdl->libzfs_crypt.zc_key_data_len != 0) {
		keydata = zfs_alloc(hdl, hdl->libzfs_crypt.zc_key_data_len);
		bcopy(hdl->libzfs_crypt.zc_key_data, keydata,
		    hdl->libzfs_crypt.zc_key_data_len);
		keydatalen = hdl->libzfs_crypt.zc_key_data_len;
		goto format_key;
	}

	/*
	 * Get the key from the URI or prompt for it.
	 * If the format is raw then prompting is a simple read(2)
	 * otherwise we put up a prompt saying what we are asking for.
	 * We can't do this with the 'zfs mount -a' that is in
	 * sys:/system/filesystem/local:default but we shouldn't
	 * cause errors or warnings there either.
	 */
	switch (locator) {
	case KEY_LOCATOR_PROMPT:
		if (format == KEY_FORMAT_RAW) {
			keydata = zfs_alloc(hdl, keylen);
			errno = 0;
			keydatalen = read(STDIN_FILENO, keydata, keylen);
			if (keydatalen != keylen) {
				free(keydata);
				return (-1);
			}
            tmpkeydatalen = keydatalen;
		} else {
			int tries = 0;
			do {
				/* get_passphrase allocates keydata */
				ret = get_passphrase(hdl, &keydata,
				    &keydatalen, format, zc, cmd);
			} while (ret != 0 && ++tries < 3);
			if (ret)
				return (-1);
		}
		break;
	case KEY_LOCATOR_FILE_URI:
		/*
		 * Need to tell pkcs11_read_data() how big of a key
		 * we want in case the locator URI is a device (eg, /dev/random)
		 * to be read from and not a file.
		 *
		 * Note that pkcs11_read_data allocates memory with malloc
		 * that we need to free.
		 */
		keydatalen = keylen;
		ret = pkcs11_read_data(&(uri[7]),
		    (void **)&keydata, &keydatalen);
		if (ret != 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "failed to read key file: %s"), strerror(ret));
			errno = ret;
			return (-1);
		}
		break;

	case KEY_LOCATOR_PKCS11_URI:
#if 0 // FIXME
		keydatalen = keylen;
		/*
		 * Parse out the PKCS#11 URI and
		 * get the value of the wrapping key.
		 */
		if (pkcs11_parse_uri(uri, &p11uri) != PK11_URI_OK) {
			errno = EINVAL;
			return (-1);
		}
		ret = get_pkcs11_key_value(hdl, zc, cmd, &p11uri,
		    &keydata, &keydatalen);
		pkcs11_free_uri(&p11uri);
		if (ret != 0) {
			return (-1);
		}
#endif
		break;
	case KEY_LOCATOR_HTTPS_URI: {
		CURL *curl_hdl = curl_easy_init();
		CURLcode cerr;

		cerr = curl_easy_setopt(curl_hdl, CURLOPT_URL, uri);
		if (cerr != CURLE_OK)
			goto curl_fail;
		cerr = curl_easy_setopt(curl_hdl, CURLOPT_FAILONERROR, 1L);
		if (cerr != CURLE_OK)
			goto curl_fail;
		cerr = curl_easy_setopt(curl_hdl, CURLOPT_WRITEFUNCTION,
		    get_keydata_curl);
		if (cerr != CURLE_OK)
			goto curl_fail;
		cb_curl.cb_hdl = hdl;
		cerr = curl_easy_setopt(curl_hdl, CURLOPT_WRITEDATA,
		    &cb_curl);
		if (cerr != CURLE_OK)
			goto curl_fail;
		cerr = curl_easy_perform(curl_hdl);
curl_fail:
		/*
		 * Just deal with libcurl errors here, reading the wrong key
		 * size is dealt with generically in the format_key section.
		 */
		if (cerr != 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "failed to retreive key from '%s': '%s'"),
			    uri, curl_easy_strerror(cerr));
			return (-1);
		}

		keydata = cb_curl.cb_keydata;
		keydatalen = cb_curl.cb_keydatalen;

		curl_easy_cleanup(curl_hdl);
		break;

        case KEY_LOCATOR_NONE: // Avoid Warning
            break;
		}
	}

format_key:
	if (keydata == NULL || keydatalen == 0) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "key can not be of zero size"));
		errno = ret;
		return (-1);
	}

	/*
	 * Now that we have the key do any transform that is necessary
	 * such as turning the hex format into raw or in the case of
	 * a passphrase running it through PKCS#5 to get the raw key.
	 *
	 * Note that zic_keydata is not malloc'd memory so that we
	 * don't have to worry about our caller freeing it.
	 */
	switch (format) {
	case KEY_FORMAT_RAW:
		bcopy(keydata, zc->zc_crypto.zic_keydata, keydatalen);
		zc->zc_crypto.zic_keydatalen = keydatalen;
		zc->zc_crypto.zic_salt = 0;
		break;
	case KEY_FORMAT_HEX:
		/*
		 * If the keylen is not on the byte boundary, in terms of hex
		 * format, and that extra char is a linefeed, we can trim it
		 */
		if (keydatalen == (keylen * 2) + 1 &&
		    keydata[keydatalen] == '\n') {
			keydatalen--;
		}

		/*
		 * hexstr_to_bytes allocates memory with malloc
		 * but we want the data in zic_keydata which isn't malloc'd
		 * so to avoid a memory leak we use a tmpkeydata buffer
		 * and bcopy it.
		 */
		ret = hexstr_to_bytes(keydata, keydatalen,
		    (uchar_t **)&tmpkeydata, &tmpkeydatalen);

		if (ret) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "invalid hex format key."));
			errno = EACCES;
			ret = -1;
			goto out;
		}

		bcopy(tmpkeydata, zc->zc_crypto.zic_keydata, tmpkeydatalen);
		bzero(tmpkeydata, tmpkeydatalen);
		free(tmpkeydata);
		zc->zc_crypto.zic_keydatalen = tmpkeydatalen;
		zc->zc_crypto.zic_salt = 0;
		break;
	case KEY_FORMAT_PASSPHRASE:
		/* Remove any extra linefeed that may be on the end */
		if (keydata[keydatalen - 1] == '\n')
			keydatalen--;

		if (cmd == ZFS_CRYPTO_KEY_LOAD) {
			salt = zfs_prop_get_int(zhp, ZFS_PROP_SALT);
		} else {

            //get_random_bytes((void *)&salt, sizeof (uint64_t));
            // Static salt during test
            int fd;
            fd = open("/dev/random", O_RDONLY);
            if ((fd < 0) ||
                read(fd, (void *)&salt, sizeof(salt)) != sizeof(salt)) {
                zfs_error_aux(hdl,
                              dgettext(TEXT_DOMAIN,
                                       "failed to open /dev/random"));
                errno = EINVAL;
                ret = -1;
                goto out;
            }
            close(fd);

            if (0) {
                unsigned char *p;
                p = (unsigned char *)&salt;
                p[0] =  0xf2;
                p[1] =  0x61;
                p[2] =  0x01;
                p[3] =  0x50;
                p[4] =  0x73;
                p[5] =  0x54;
                p[6] =  0x9a;
                p[7] =  0xd1;
            }
		}

        // FIXME
        //tmpkeydata = strdup(keydata);
        //tmpkeydatalen = keydatalen;

#if 0 // FIXME
		ret = SUNW_C_GetMechSession(CKM_PKCS5_PBKD2, &session);
		if (ret) {
			zfs_error_aux(hdl,
			    dgettext(TEXT_DOMAIN,
			    "failed to access CKM_PKCS5_PBKD2: %s."),
			    pkcs11_strerror(ret));
			errno = EINVAL;
			ret = -1;
			goto out;
		}

		/*
		 * pkcs11_PasswdToKey allocates memory with malloc
		 * but we want the data in zic_keydata which isn't malloc'd
		 * so to avoid a memory leak we use a tmpkeydata buffer
		 * and bcopy it.
		 */
		ret = pkcs11_PasswdToKey(session, keydata, keydatalen,
		    (void *)&salt, sizeof (uint64_t), CKK_AES,
		    keylen, (void **)&tmpkeydata, &tmpkeydatalen);

		(void) C_CloseSession(session);

		if (ret) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "failed to generate key: %s."),
			    pkcs11_strerror(ret));
			errno = EINVAL;
			ret = -1;
			goto out;
		}
#endif

        crypto_pass2key((unsigned char *)keydata, keydatalen,
                        (void *)&salt, sizeof(salt),
                        keylen, (void **)&tmpkeydata, &tmpkeydatalen);

		bcopy(tmpkeydata, zc->zc_crypto.zic_keydata, tmpkeydatalen);
		bzero(tmpkeydata, tmpkeydatalen);
		free(tmpkeydata);
		zc->zc_crypto.zic_keydatalen = tmpkeydatalen;
		zc->zc_crypto.zic_salt = salt;
		break;

	default:
		ASSERT(format);
	}

	if (zc->zc_crypto.zic_keydatalen != keylen) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "key length invalid. expected %lu bytes have %lu"),
		    keylen, zc->zc_crypto.zic_keydatalen);
		errno = EIO;
		ret = -1;
	}

    if (tmpkeydatalen) // Only decrease if NOT zero.
        tmpkeydatalen--;
	while (zc->zc_crypto.zic_keydata[tmpkeydatalen] == 0 &&
	    tmpkeydatalen > 0)
		tmpkeydatalen--;

	if (tmpkeydatalen == 0) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
                                    "invalid all zeros key %lu"), tmpkeydatalen);
		errno = EIO;
		ret = -1;
	}
out:
	if (keydata) {
		bzero(keydata, keydatalen);
		free(keydata);
	}

	return (ret);
}

int
zfs_key_load(zfs_handle_t *zhp, boolean_t mount, boolean_t share,
    boolean_t recursive)
{
	zfs_handle_t *pzhp = NULL;
	zprop_source_t propsrctype;
	char source[ZFS_MAXNAMELEN];
	char keysource[MAXNAMELEN];
	uint64_t ret, crypt, keystatus;
	zfs_cmd_t zc = { {0 }};
	char errbuf[1024];


	(void) strlcpy(zc.zc_name, zfs_get_name(zhp), sizeof (zc.zc_name));
	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot load key for '%s'"), zc.zc_name);

	zfs_refresh_properties(zhp);

	crypt = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);
	if (crypt == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "encryption not enabled on dataset %s."), zc.zc_name);
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}

	keystatus = zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS);

	if (keystatus == ZFS_CRYPT_KEY_AVAILABLE && !recursive) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "already loaded."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}

	if (zfs_prop_get(zhp, ZFS_PROP_KEYSOURCE, keysource, ZFS_MAXNAMELEN,
	    &propsrctype, source, sizeof (source), FALSE) != 0) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "no keysource property available."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}

	if (propsrctype == ZPROP_SRC_INHERITED) {
#if 0 // FIXME
		if (strcmp(source, ZONE_INVISIBLE_SOURCE) == 0) {
			zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
			    "key must be loaded from global zone."));
			return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
		}
#endif
		pzhp = make_dataset_handle(zhp->zfs_hdl, source);
		if (pzhp == NULL) {
			errno = EINVAL;
			return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
		}
		keystatus = zfs_prop_get_int(pzhp, ZFS_PROP_KEYSTATUS);
		zfs_close(pzhp);
	}

	if (propsrctype == ZPROP_SRC_DEFAULT) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "invalid keysource property."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}

	if (!zfs_can_prompt_if_needed(keysource)) {
		errno = ENOTTY;
		return (-1);
	}
	/*
	 * NONE we are the top ds asking for crypto so we
	 * need to get and load the key.
	 *
	 * UNAVAILABLE we need to load the key of a higher level
	 * dataset.
	 *
	 * AVAILABLE we are done other than filling in who we
	 * are inheriting the wrapping key from.
	 */
	if (propsrctype == ZPROP_SRC_INHERITED &&
	    keystatus == ZFS_CRYPT_KEY_AVAILABLE) {
		(void) strlcpy(zc.zc_crypto.zic_inherit_dsname, source,
		    sizeof (zc.zc_crypto.zic_inherit_dsname));
		ret = zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_CRYPTO_KEY_INHERIT, &zc);
		goto out;
	}

	zc.zc_crypto.zic_crypt = crypt;

	ret = key_hdl_to_zc(zhp->zfs_hdl, zhp, keysource, crypt, &zc,
	    ZFS_CRYPTO_KEY_LOAD);
	if (ret != 0) {
		if (errno == ENOTTY)
			ret = 0;
		goto out;
	}

	ret = zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_CRYPTO_KEY_LOAD, &zc);
out:
	if (ret != 0) {
		if (errno == EACCES) {
			zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
			    "incorrect key."));
			return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
		} else if (!recursive) {
			if (errno == EEXIST) {
				zfs_error_aux(zhp->zfs_hdl,
				    dgettext(TEXT_DOMAIN, "already loaded."));
			} else if (zhp->zfs_hdl->libzfs_desc_active == 0) {
				zfs_error_aux(zhp->zfs_hdl, strerror(errno));
			}
			return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
		}
	}

	zfs_refresh_properties(zhp);
	if (mount) {
		if (zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM) {
			if (recursive) {
				ret = zfs_mountall(zhp, 0);
			} else {
				ret = zfs_mount(zhp, NULL, 0);
			}
			if (ret == 0 && share) {
				ret = zfs_share(zhp);
			}
		}
	}

	return (ret);
}

int
zfs_key_unload(zfs_handle_t *zhp, boolean_t force)
{
	zfs_cmd_t zc = { { 0 }};
	int ret = 0;
	int terrno;
	int type = zfs_get_type(zhp);
	char errbuf[1024];

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot unload key for '%s'"), zfs_get_name(zhp));

	if (zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION) == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "no key to unload when encryption=off."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}
	if (zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS) !=
	    ZFS_CRYPT_KEY_AVAILABLE) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "key not present."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}

	/*
	 * We need to be sure that all the data has been written to
	 * disk before we unload the key so we first have to attempt
	 * an unmount, if that fails we don't continue with the key unload
	 * and instead return the error from zfs_umount.
	 */
	if (type == ZFS_TYPE_FILESYSTEM) {
		if (zfs_is_mounted(zhp, NULL)) {
			ret = zfs_unmountall(zhp, force ? MS_FORCE : 0);
			if (ret) {
				zfs_error_aux(zhp->zfs_hdl,
				    dgettext(TEXT_DOMAIN,
				    "failed to unload key: unmount failed"));
				return (zfs_error(zhp->zfs_hdl,
				    EZFS_KEYERR, errbuf));
			}
		}
	}

	(void) strlcpy(zc.zc_name, zfs_get_name(zhp), sizeof (zc.zc_name));

	errno = 0;
	ret = zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_CRYPTO_KEY_UNLOAD, &zc);
	terrno = errno;
	if (ret != 0) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "failed to unload key: %s"), strerror(terrno));
		errno = terrno;	/* make sure it is the zfs_ioctl errno */
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}
	zfs_refresh_properties(zhp);

	return (0);
}

int
zfs_key_new(zfs_handle_t *zhp)
{
	char errbuf[1024];
	zfs_cmd_t zc = { { 0 } };

	(void) strlcpy(zc.zc_name, zfs_get_name(zhp), sizeof (zc.zc_name));

	if (zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_CRYPTO_KEY_NEW, &zc) != 0) {
		(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
		    "cannot create new key for '%s'"), zc.zc_name);
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}
	return (0);
}

int
zfs_key_change(zfs_handle_t *zhp, boolean_t recursing, nvlist_t *props)
{
	char errbuf[1024];
	int ret;
	zfs_cmd_t zc = { { 0 } };
	char keysource[ZFS_MAXNAMELEN];
	uint64_t crypt;
	zprop_source_t propsrctype = ZPROP_SRC_NONE;
	char propsrc[ZFS_MAXNAMELEN] = { 0 };

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot change wrapping key for '%s'"), zfs_get_name(zhp));
	crypt = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);
	if (crypt == ZIO_CRYPT_OFF) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "cannot change key when encryption=off"));
		goto error;
	}

	switch (zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS)) {
	case ZFS_CRYPT_KEY_NONE:
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "inconsistent state encryption enabled but "
		    "key not defined."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	case ZFS_CRYPT_KEY_UNAVAILABLE:
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "load existing key first: 'zfs key -l <dataset>'."));
		goto error;
	}

	(void) zfs_prop_get(zhp, ZFS_PROP_KEYSOURCE, keysource,
	    ZFS_MAXNAMELEN, &propsrctype, propsrc, ZFS_MAXNAMELEN, B_TRUE);
	if (!(propsrctype & ZPROP_SRC_LOCAL ||
	    propsrctype & ZPROP_SRC_RECEIVED)) {
		if (recursing)
			return (0);
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "keysource property not local, change key on '%s'."),
		    propsrc);
		goto error;
	}

	zhp->zfs_hdl->libzfs_crypt.zc_is_key_change = B_TRUE;

	/*
	 * The only thing we currently expect in props is a keysource
	 * if we have props without keysource then that isn't valid.
	 */
	if (props != NULL) {
		char *nkeysource;
		ret = nvlist_lookup_string(props,
		    zfs_prop_to_name(ZFS_PROP_KEYSOURCE), (char **)&nkeysource);
		if (ret != 0) {
			zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
			    "invalid props for key change; expected "
			    "%s property missing."),
			    zfs_prop_to_name(ZFS_PROP_KEYSOURCE));
			goto error;
		}
		(void) strlcpy(keysource, nkeysource, sizeof (keysource));
	}

	(void) strlcpy(zc.zc_name, zfs_get_name(zhp), sizeof (zc.zc_name));
	zc.zc_crypto.zic_crypt = crypt;

	if (!zfs_can_prompt_if_needed(keysource)) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "unable to prompt for new wrapping key."));
		errno = ENOTTY;
		goto error;
	}

	ret = key_hdl_to_zc(zhp->zfs_hdl, zhp, keysource, crypt, &zc,
	    ZFS_CRYPTO_KEY_CHANGE);
	if (props != NULL) {
		if (zcmd_write_src_nvlist(zhp->zfs_hdl, &zc, props) != 0)
			goto error;
	}
	if (ret == 0) {
		/* Send change to kernel */
		ret = zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_CRYPTO_KEY_CHANGE, &zc);
		zcmd_free_nvlists(&zc);
		if (ret != 0) {
			return (zfs_standard_error(zhp->zfs_hdl,
			    errno, errbuf));
		}
		zfs_refresh_properties(zhp);
		return (ret);
	}
error:
	zcmd_free_nvlists(&zc);
	return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
}

/*
 * This is to verify that the proposed keysource property change via
 * 'zfs set', and internal functions is valid.
 */
boolean_t
zfs_valid_set_keysource_change(zfs_handle_t *zhp, char *old_src, char *new_src)
{
	key_format_t old_format, new_format;
	key_locator_t old_locator, new_locator;
	char *uri;
	boolean_t valid;

	/*
	 * If we are calling this from a change key operation or a clone
	 * the valid keysource changes have no restrictions.
	 */
	if ((zhp->zfs_type == ZFS_TYPE_SNAPSHOT &&
	    (zhp->zfs_head_type == ZFS_TYPE_VOLUME ||
	    zhp->zfs_head_type == ZFS_TYPE_FILESYSTEM)) ||
	    (zhp->zfs_hdl->libzfs_crypt.zc_is_key_change == B_TRUE)) {
		return (zfs_valid_keysource(new_src));
	}

	/*
	 * If we are calling this from a set property operation, the valid
	 * keysources are limited to the same format
	 */
	valid = keysource_prop_parser(new_src, &new_format, &new_locator, &uri);
	if (!valid)
		return (B_FALSE);

	valid = keysource_prop_parser(old_src, &old_format, &old_locator, &uri);
	if (old_format != new_format) {
		return (B_FALSE);
	}

	return (valid);
}

/* Validate the keysource provided is a valid keysource */
boolean_t
zfs_valid_keysource(char *keysource)
{
	key_format_t format;
	key_locator_t locator;
	char *uri;

	if (keysource == NULL)
		return (B_FALSE);

	return (keysource_prop_parser(keysource, &format, &locator, &uri));
}

/*
 * zfs_crypto_zckey
 *
 * Called for creating new filesystems and clones and receiving.
 *
 * For encryption != off get the key material.
 */
int
zfs_crypto_zckey(libzfs_handle_t *hdl, zfs_crypto_zckey_t cmd,
                 nvlist_t *props, zfs_cmd_t *zc, zfs_type_t type)
{
	uint64_t crypt = ZIO_CRYPT_INHERIT, pcrypt = ZIO_CRYPT_DEFAULT;
	char *keysource = NULL;
	int ret = 0;
	int keystatus;
	zfs_handle_t *pzhp = NULL;
	boolean_t inherit_crypt = B_TRUE;
	boolean_t inherit_keysource = B_TRUE;
	boolean_t recv_existing = B_FALSE;
	boolean_t recv_clone = B_FALSE;
	boolean_t keysource_free = B_FALSE;
	zprop_source_t propsrctype = ZPROP_SRC_DEFAULT;
	char propsrc[ZFS_MAXNAMELEN];
	char errbuf[1024];
	char target[MAXNAMELEN];
	char parent[MAXNAMELEN];
	char *strval;

	zfs_cmd_target_dsname(zc, cmd, target, sizeof (target));
	if (zfs_parent_name(target, parent, sizeof (parent)) != 0)
		parent[0] = '\0';
	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot create '%s'"), target);

	if (props != NULL) {
		if (nvlist_lookup_string(props,
		    zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &strval) == 0) {
			(void) zfs_prop_string_to_index(ZFS_PROP_ENCRYPTION,
			    strval, &crypt);
			inherit_crypt = B_FALSE;
		} else if (nvlist_lookup_uint64(props,
		    zfs_prop_to_name(ZFS_PROP_ENCRYPTION), &crypt) == 0) {
			inherit_crypt = B_FALSE;
		} else {
			inherit_crypt = B_TRUE;
		}
		if (nvlist_lookup_string(props,
		    zfs_prop_to_name(ZFS_PROP_KEYSOURCE), &keysource) == 0) {
			inherit_keysource = B_FALSE;
		}
	}

	if (cmd == ZFS_CRYPTO_CREATE) {
		pzhp = make_dataset_handle(hdl, parent);
	} else if (cmd == ZFS_CRYPTO_CLONE) {
		zfs_handle_t *szhp = make_dataset_handle(hdl, zc->zc_value);
		if (szhp == NULL) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "parent not found"));
			(void) zfs_error(hdl, EZFS_NOENT, errbuf);
			ret = -1;
			goto out;
		}
		crypt = zfs_prop_get_int(szhp, ZFS_PROP_ENCRYPTION);
		zfs_close(szhp);
		pzhp = make_dataset_handle(hdl, parent);
	} else if (cmd == ZFS_CRYPTO_RECV) {
		if (zfs_dataset_exists(hdl, target, ZFS_TYPE_DATASET)) {
			pzhp = make_dataset_handle(hdl, target);
			pcrypt = zfs_prop_get_int(pzhp, ZFS_PROP_ENCRYPTION);
			if (crypt != pcrypt && crypt != ZIO_CRYPT_INHERIT) {
				const char *stream_crypt_str = NULL;
				const char *pcrypt_str = NULL;
				(void) zfs_prop_index_to_string(
				    ZFS_PROP_ENCRYPTION, pcrypt,
				    &pcrypt_str);
				(void) zfs_prop_index_to_string(
				    ZFS_PROP_ENCRYPTION, crypt,
				    &stream_crypt_str);
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "stream encryption '%s'(%llu) differs "
				    "from receiving dataset value '%s'(%llu)"),
				    stream_crypt_str, crypt,
				    pcrypt_str, pcrypt);
				ret = -1;
				goto out;
			}
			inherit_crypt = B_TRUE;
			inherit_keysource = B_TRUE;
			recv_existing = B_TRUE;
		} else {
			if (strlen(zc->zc_string) != 0) {
				pzhp = make_dataset_handle(hdl, zc->zc_string);
				recv_clone = B_TRUE;
			} else {
				pzhp = make_dataset_handle(hdl, parent);
			}
		}
	}

	if (cmd != ZFS_CRYPTO_PCREATE) {
		if (pzhp == NULL) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "parent not found"));
			(void) zfs_error(hdl, EZFS_NOENT, errbuf);
			ret = -1;
			goto out;
		}
		pcrypt = zfs_prop_get_int(pzhp, ZFS_PROP_ENCRYPTION);
	}

	if (pcrypt != ZIO_CRYPT_OFF && crypt == ZIO_CRYPT_OFF) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "invalid "
		    "encryption value. dataset must be encrypted."));
		(void) zfs_error(hdl, EZFS_KEYERR, errbuf);
		ret = -1;
		goto out;
	}

	if (crypt == ZIO_CRYPT_INHERIT) {
		crypt = pcrypt;
	}

	/*
	 * If we have nothing to do then bail out, but make one last check
	 * that keysource wasn't specified when there is no crypto going on.
	 */
	if (crypt == ZIO_CRYPT_OFF && !inherit_keysource) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, "keysource "
		    "can not be specified when encryption is off."));
		(void) zfs_error(hdl, EZFS_KEYERR, errbuf);
		ret = -1;
		goto out;
	} else if (crypt == ZIO_CRYPT_OFF) {
		ret = 0;
		goto out;
	}

    /*
     * If we are creating a volume, pick the valid cipher
     */
    /* If encryption is on, and volume, change it to valid cipher. */
    if ((type == ZFS_TYPE_VOLUME) && (crypt != ZIO_CRYPT_OFF)) {
        crypt = ZIO_CRYPT_AES_128_CTR;
        /* We also have to write out the prop, in the case of inheritance
           or it will be using the wrong cipher */
        VERIFY(nvlist_add_uint64(props,
               zfs_prop_to_name(ZFS_PROP_ENCRYPTION), crypt) == 0);
    }


	/*
	 * Need to pass down the inherited crypt value so that
	 * dsl_crypto_key_gen() can see the same that we saw.
	 */
	zc->zc_crypto.zic_crypt = crypt;
	zc->zc_crypto.zic_clone_newkey = hdl->libzfs_crypt.zc_clone_newkey;

	/*
	 * Here we have encryption on so we need to find a valid keysource
	 * property.
	 *
	 * Now lets see if we have an explicit setting for keysource and
	 * we have validate it; otherwise, if we inherit then it is already
	 * validated.
	 */
	if (!inherit_keysource) {
		if (!zfs_valid_keysource(keysource)) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "invalid keysource \"%s\""), keysource);
			(void) zfs_error(hdl, EZFS_KEYERR, errbuf);
			ret = -1;
			goto out;
		}
		/*
		 * If keysource is local then encryption has to be as well
		 * otherwise we could end up with the wrong sized keys.
		 */
		if (inherit_crypt) {
			VERIFY(nvlist_add_uint64(props,
			    zfs_prop_to_name(ZFS_PROP_ENCRYPTION), crypt) == 0);
			VERIFY(nvlist_add_uint64(props,
			    zfs_prop_to_name(ZFS_PROP_CHECKSUM),
			    ZIO_CHECKSUM_SHA256_MAC) == 0);
		}
	} else {
		/* Get the already validated keysource from our parent */
		keysource = zfs_alloc(hdl, ZFS_MAXNAMELEN);
		if (keysource == NULL) {
			ret = no_memory(hdl);
			goto out;
		}
		keysource_free = B_TRUE;
		if (pzhp != NULL && zfs_prop_get(pzhp, ZFS_PROP_KEYSOURCE,
		    keysource, ZFS_MAXNAMELEN, &propsrctype, propsrc,
		    sizeof (propsrc), FALSE) != 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "keysource must be provided."));
			(void) zfs_error(hdl, EZFS_KEYERR, errbuf);
			ret = -1;
			goto out;
		}

		if (recv_existing) {
			(void) strlcpy(propsrc, target, sizeof (propsrc));
		} else if (recv_clone) {
			(void) strlcpy(propsrc,
			    zc->zc_string, sizeof (propsrc));
		} else if (propsrctype == ZPROP_SRC_LOCAL ||
		    propsrctype == ZPROP_SRC_RECEIVED) {
			(void) strlcpy(propsrc, parent, sizeof (propsrc));
		} else if (propsrctype == ZPROP_SRC_DEFAULT &&
		    pcrypt == ZIO_CRYPT_OFF) {
			/*
			 * "Default" to "passphrase,prompt".  The obvious
			 * thing to do would be to set this in zfs_prop.c
			 * as the property default.  However that doesn't
			 * work here because we don't want keysource set
			 * for datasets that have encryption=off.  If we
			 * ever change the default to encryption=on then
			 * the default of keysource can change too.
			 * This is needed because of how inheritance happens
			 * with defaulted properties, they show up as
			 * "default" not "inherit" but we need "inherit"
			 * to find the wrapping key if we are actually
			 * inheriting keysource.
			 */
			inherit_keysource = B_FALSE;
			if (props == NULL) {
				VERIFY(0 == nvlist_alloc(&props,
				    NV_UNIQUE_NAME, 0));
			}
			(void) strlcpy(keysource, "passphrase,prompt",
			    ZFS_MAXNAMELEN);
			VERIFY(nvlist_add_string(props,
			    zfs_prop_to_name(ZFS_PROP_KEYSOURCE),
			    keysource) == 0);
			VERIFY(nvlist_add_uint64(props,
			    zfs_prop_to_name(ZFS_PROP_ENCRYPTION), crypt) == 0);
			VERIFY(nvlist_add_uint64(props,
			    zfs_prop_to_name(ZFS_PROP_CHECKSUM),
			    ZIO_CHECKSUM_SHA256_MAC) == 0);
			goto load_key;
		} else if (propsrctype == ZPROP_SRC_DEFAULT &&
		    pcrypt != ZIO_CRYPT_OFF) {
			abort();
#if 0 // FIXME
		} else if (strcmp(propsrc, ZONE_INVISIBLE_SOURCE) == 0) {
			/*
			 * Assume key is available and handle failure ioctl
			 * ENOKEY errors later.
			 */
			zc->zc_crypto.zic_cmd = ZFS_IOC_CRYPTO_KEY_INHERIT;
			(void) strlcpy(zc->zc_crypto.zic_inherit_dsname,
			    propsrc, sizeof (zc->zc_crypto.zic_inherit_dsname));
			ret = 0;
			goto out;
#endif
		} else if (propsrctype != ZPROP_SRC_DEFAULT) {
			if (pzhp != NULL)
				zfs_close(pzhp);
			VERIFY((pzhp = make_dataset_handle(hdl, propsrc)) != 0);
		}
		keystatus = zfs_prop_get_int(pzhp, ZFS_PROP_KEYSTATUS);
		/*
		 * AVAILABLE we are done other than filling in who we
		 * are inheriting the wrapping key from.
		 *
		 * UNAVAILABLE we need to load the key of a higher level
		 * dataset.
		 */
		if (keystatus == ZFS_CRYPT_KEY_AVAILABLE) {
			zc->zc_crypto.zic_cmd = ZFS_IOC_CRYPTO_KEY_INHERIT;
			(void) strlcpy(zc->zc_crypto.zic_inherit_dsname,
			    propsrc, sizeof (zc->zc_crypto.zic_inherit_dsname));
			ret = 0;
			goto out;
		} else if (keystatus == ZFS_CRYPT_KEY_UNAVAILABLE) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "zfs key -l %s required."), parent);
			(void) zfs_error(hdl, EZFS_KEYERR, errbuf);
			ret = -1;
			goto out;
		}
	}
load_key:
	if (!zfs_can_prompt_if_needed(keysource)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "unable to prompt for key material keysource = \"%s\"\n"),
		    keysource);
		errno = ENOTTY;
		return (-1);
	}
	ret = key_hdl_to_zc(hdl, NULL, keysource, crypt, zc, cmd);
	if (ret != 0) {
		ret = -1;
		(void) zfs_error(hdl, EZFS_KEYERR, errbuf);
		goto out;
	}
	zc->zc_crypto.zic_cmd = ZFS_IOC_CRYPTO_KEY_LOAD;
	ret = 0;
out:
	if (pzhp)
		zfs_close(pzhp);
	if (keysource_free)
		free(keysource);

	return (ret);
}

/*
 * zfs_crypto_rename_check
 *
 * Can't rename "out" of same hierarchy if keysource would change.
 *
 * If this dataset isn't encrypted we allow the rename, unless it
 * is being placed "below" an encrypted one.
 */
int
zfs_crypto_rename_check(zfs_handle_t *zhp, zfs_cmd_t *zc)
{
	uint64_t crypt, pcrypt;
	zfs_handle_t *pzhp;
	zprop_source_t propsrctype, ppropsrctype;
	char keysource[ZFS_MAXNAMELEN];
	char pkeysource[ZFS_MAXNAMELEN];
	char propsrc[ZFS_MAXNAMELEN];
	char psource[ZFS_MAXNAMELEN];
	char oparent[ZFS_MAXNAMELEN];
	char nparent[ZFS_MAXNAMELEN];
	char errbuf[1024];

	if (zhp->zfs_type == ZFS_TYPE_SNAPSHOT)
		return (0);

	(void) zfs_parent_name(zc->zc_name, oparent, sizeof (oparent));
	(void) zfs_parent_name(zc->zc_value, nparent, sizeof (nparent));
	/* Simple rename in place */
	if (strcmp(oparent, nparent) == 0) {
		return (0);
	}

	(void) snprintf(errbuf, sizeof (errbuf), dgettext(TEXT_DOMAIN,
	    "cannot rename '%s'"), zfs_get_name(zhp));

	crypt = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);

	/* parent should never be null */
	pzhp = make_dataset_handle(zhp->zfs_hdl, nparent);
	if (pzhp == NULL) {
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "failed to obtain parent to check encryption property."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}
	pcrypt = zfs_prop_get_int(pzhp, ZFS_PROP_ENCRYPTION);

	/* If no crypt involved then we are done. */
	if (crypt == ZIO_CRYPT_OFF && pcrypt == ZIO_CRYPT_OFF) {
		zfs_close(pzhp);
		return (0);
	}

	/* Just like create time no unencrypted below encrypted . */
	if (crypt == ZIO_CRYPT_OFF && pcrypt != ZIO_CRYPT_OFF) {
		zfs_close(pzhp);
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "Can not move unencrypted dataset below "
		    "encrypted datasets."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}

	/*
	 * From here on we need to check that keysource is
	 * from the same dataset if it is being inherited
	 */
	if (zfs_prop_get(zhp, ZFS_PROP_KEYSOURCE, keysource,
	    ZFS_MAXNAMELEN, &propsrctype,
	    propsrc, sizeof (propsrc), FALSE) != 0) {
		zfs_close(pzhp);
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "keysource must be provided."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}

	if (propsrctype == ZPROP_SRC_LOCAL) {
		zfs_close(pzhp);
		return (0);
	}

	if (zfs_prop_get(pzhp, ZFS_PROP_KEYSOURCE, pkeysource,
	    ZFS_MAXNAMELEN, &ppropsrctype,
	    psource, sizeof (psource), FALSE) != 0) {
		zfs_close(pzhp);
		zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
		    "keysource must be provided."));
		return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
	}

	if (propsrctype == ZPROP_SRC_INHERITED &&
	    ((strcmp(propsrc, nparent) == 0) ||
	    (strcmp(propsrc, psource) == 0))) {
		zfs_close(pzhp);
		return (0);
	}

	zfs_close(pzhp);
	zfs_error_aux(zhp->zfs_hdl, dgettext(TEXT_DOMAIN,
	    "keysource doesn't allow for rename, make keysource local."));
	return (zfs_error(zhp->zfs_hdl, EZFS_KEYERR, errbuf));
}

boolean_t
zfs_is_encrypted(zfs_handle_t *zhp)
{
	int crypt = zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION);

	return (!(crypt == ZIO_CRYPT_OFF));
}
