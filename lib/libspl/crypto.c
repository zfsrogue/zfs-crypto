#include <sys/cmn_err.h>

#include <assert.h>
#include <string.h>

#include "aes.h"



void cipher(char *keydata, size_t keydatalen,
            char *input, size_t inputlen,
            char *output, size_t outputlen)
{



}



/*
 *
 * RFC2898
 *
 */
int crypto_pass2key(unsigned char *keydata, size_t keydatalen,
                    void *salt, size_t saltlen,
                    size_t desired_keylen,
                    void **out_keydata, size_t *out_keylen)
{
    unsigned char *work   = NULL;
    unsigned char *buffer = NULL;
    unsigned int iterations = 1000; // As specified by Solaris
    unsigned int len, i;
    int ret = -1;
    aes_context aes;
    unsigned char iv[16] = { 0 };
    unsigned char statickey[16] = { 0 };

    printf("In crypto_pass2key: keylen %ld\n", keydatalen);

    // This needs fixing, we use at-most 16 chars of the password.
    memcpy(statickey, keydata, keydatalen < sizeof(statickey) ? keydatalen :
           sizeof(statickey));

    if (aes_setkey_enc(&aes, statickey, sizeof(statickey) * 8)) goto out;

    printf("Key set ok\n");

    // Sun uses ITERATIONS=1000
    // "i" is 4 byte integer of iterations
    len = saltlen + sizeof(iterations);

    work = calloc(1, len);
    if (!work) goto out;

    buffer = calloc(1, desired_keylen);
    if (!buffer) goto out;

    memcpy(work, salt, saltlen);
    memcpy(&work[saltlen], &iterations, sizeof(iterations));

    // First iteration: keydata is key, on "salt+iterations".
    // Following iterations: keydata is key, on previous result.

    for((ret = aes_crypt_cbc(&aes, AES_ENCRYPT,
                             desired_keylen, iv, work, buffer)), i = 0;
        !ret && (i < iterations);
        i++) {

        ret = aes_crypt_cbc(&aes, AES_ENCRYPT,
                            desired_keylen, iv, buffer, buffer);

    }

    if (i < iterations) goto out;


    printf("Done with keygen: %ld\n", desired_keylen);
    for (i = 0; i < desired_keylen; i++)
        printf("0x%02x ", buffer[i]);
    printf("\n");


    if (out_keydata) {
        *out_keydata = buffer;
        buffer = NULL; // Caller will free
    }
    if (out_keylen) *out_keylen = desired_keylen;

    ret = 0; // Return success

 out:
    if (buffer) free(buffer);
    if (work) free(work);

    return ret;
}




