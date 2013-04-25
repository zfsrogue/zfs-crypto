#include <sys/cmn_err.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "sha1.h"




/*
 * HMAC-SHA-1 (from RFC 2202).
 */
static void
hmac_sha1(const uint8_t *text, size_t text_len, const uint8_t *key,
          size_t key_len, uint8_t digest[SHA1_DIGEST_LENGTH])
{
	SHA1_CTX ctx;
	uint8_t k_pad[SHA1_BLOCK_LENGTH];
	uint8_t tk[SHA1_DIGEST_LENGTH];
	int i;

	if (key_len > SHA1_BLOCK_LENGTH) {
		SHA1Init(&ctx);
		SHA1Update(&ctx, key, key_len);
		SHA1Final(tk, &ctx);

		key = tk;
		key_len = SHA1_DIGEST_LENGTH;
	}

	bzero(k_pad, sizeof k_pad);
	bcopy(key, k_pad, key_len);
	for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
		k_pad[i] ^= 0x36;

	SHA1Init(&ctx);
	SHA1Update(&ctx, k_pad, SHA1_BLOCK_LENGTH);
	SHA1Update(&ctx, text, text_len);
	SHA1Final(digest, &ctx);

	bzero(k_pad, sizeof k_pad);
	bcopy(key, k_pad, key_len);
	for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
		k_pad[i] ^= 0x5c;

	SHA1Init(&ctx);
	SHA1Update(&ctx, k_pad, SHA1_BLOCK_LENGTH);
	SHA1Update(&ctx, digest, SHA1_DIGEST_LENGTH);
	SHA1Final(digest, &ctx);
}


int
pkcs5_pbkdf2(const unsigned char *pass, size_t pass_len,
             const unsigned char *salt,
             size_t salt_len,
             uint8_t *key, size_t key_len,
             unsigned int rounds)
{
	uint8_t *asalt, obuf[SHA1_DIGEST_LENGTH];
	uint8_t d1[SHA1_DIGEST_LENGTH], d2[SHA1_DIGEST_LENGTH];
	unsigned int i, j;
	unsigned int count;
	size_t r;

	if (rounds < 1 || key_len == 0)
		return -1;
	if (salt_len == 0 || salt_len > SIZE_MAX - 4)
		return -1;
	if ((asalt = malloc(salt_len + 4)) == NULL)
		return -1;

	memcpy(asalt, salt, salt_len);

	for (count = 1; key_len > 0; count++) {
		asalt[salt_len + 0] = (count >> 24) & 0xff;
		asalt[salt_len + 1] = (count >> 16) & 0xff;
		asalt[salt_len + 2] = (count >> 8) & 0xff;
		asalt[salt_len + 3] = count & 0xff;
		hmac_sha1(asalt, salt_len + 4, pass, pass_len, d1);
		memcpy(obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			hmac_sha1(d1, sizeof(d1), pass, pass_len, d2);
			memcpy(d1, d2, sizeof(d1));
			for (j = 0; j < sizeof(obuf); j++)
				obuf[j] ^= d1[j];
		}

		r = MIN(key_len, SHA1_DIGEST_LENGTH);
		memcpy(key, obuf, r);
		key += r;
		key_len -= r;
	};
	bzero(asalt, salt_len + 4);
	free(asalt);
	bzero(d1, sizeof(d1));
	bzero(d2, sizeof(d2));
	bzero(obuf, sizeof(obuf));

	return 0;
}


/*
 *
 * RFC2898:
 *
 * In Solaris, even when passed CKK_AES, the PKR function for key generation
 * is still SHA1-HMAC.
 *
 */
//#define VERBOSE
int crypto_pass2key(unsigned char *keydata, size_t keydatalen,
                    void *salt, size_t saltlen,
                    size_t desired_keylen,
                    void **out_keydata, size_t *out_keylen)
{
    unsigned char *key;
    int ret;

    key = calloc(desired_keylen, 1);
    if (!key) return -1;

    ret = pkcs5_pbkdf2(keydata, keydatalen,
                       salt, saltlen,
                       key, desired_keylen,
                       1000); /* Solaris uses 1000 iterations */

    if (out_keydata)
        *out_keydata = key;
    if (out_keylen)
        *out_keylen = desired_keylen;

    return ret;
}


/* OpenSolaris */

/*
 * Read file into buffer.  Used to read raw key data or initialization
 * vector data.  Buffer must be freed by caller using free().
 *
 * If file is a regular file, entire file is read and dlen is set
 * to the number of bytes read.  Otherwise, dlen should first be set
 * to the number of bytes requested and will be reset to actual number
 * of bytes returned.
 *
 * Return 0 on success and errno on error.
 */
int
pkcs11_read_data(char *filename, void **dbuf, size_t *dlen)
{
    int     fd = -1;
    struct stat statbuf;
    boolean_t plain_file;
    void    *filebuf = NULL;
    size_t  filesize = 0;
    int ret = 0;

    if (filename == NULL || dbuf == NULL || dlen == NULL)
        return (-1);

    if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) == -1) {
        ret = errno;
        goto error;
    }

    if (fstat(fd, &statbuf) == -1) {
        ret = errno;
        goto error;
    }

    if (S_ISREG(statbuf.st_mode)) {
        /* read the entire regular file */
        filesize = statbuf.st_size;
        plain_file = B_TRUE;
    } else {
        /* read requested bytes from special file */
        filesize = *dlen;
        plain_file = B_FALSE;
    }

    if (filesize == 0) {
        /*
         * for decrypt this is an error; for digest this is ok;
         * make it ok here but also set dbuf = NULL and dlen = 0
         * to indicate there was no data to read and caller can
         * retranslate that to an error if it wishes.
         */
        (void) close(fd);
        *dbuf = NULL;
        *dlen = 0;
        return (0);
    }

    if ((filebuf = malloc(filesize)) == NULL) {
        ret = errno;
        goto error;
    }

    if (plain_file) {
        /* either it got read or it didn't */
        if (read(fd, filebuf, filesize) != filesize) {
            ret = errno;
            goto error;
        }
    } else {
        /* reading from special file may need some coaxing */
        char    *marker = (char *)filebuf;
        size_t  left = filesize;
        ssize_t nread;

        for (/* */; left > 0; marker += nread, left -= nread) {
            /* keep reading it's going well */
            nread = read(fd, marker, left);
            if (nread > 0 || (nread == 0 && errno == EINTR)) {
                errno = 0;
                continue;
            }

            /* might have to be good enough for caller */
            if (nread == 0 && errno == EAGAIN)
                break;

            /* anything else is an error */
            if (errno) {
                ret = errno;
                goto error;
            }
        }
        /* reset to actual number of bytes read */
        filesize -= left;
    }

    (void) close(fd);
    *dbuf = filebuf;
    *dlen = filesize;
    return (0);

error:
    if (filebuf != NULL) {
        free(filebuf);
    }
    if (fd != -1)
        (void) close(fd);

    return (ret);
}
