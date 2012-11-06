#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/zcrypt.h>
#include <sys/zio_crypt.h>
#include <sys/zio.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/crypto/api.h>


int crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
               crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *mac,
               crypto_call_req_t *cr)
{
#if _KERNEL
    printk("crypto_mac\n");
#endif
    return 0;
}



int crypto_decryptX(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *plaintext, crypto_call_req_t *cr)
{
#if _KERNEL
    unsigned char *src;
    unsigned char *dst;
    size_t len = 0;
    int i;

    if (ciphertext->cd_format != CRYPTO_DATA_RAW) {
        printk("crypto_decrypt  cd_format is NOT RAW?! %d\n", ciphertext->cd_format);
        return -1;
    }

    if (plaintext && plaintext->cd_format != CRYPTO_DATA_RAW) {
        printk("crypto_decrypt  cd_format is NOT RAW?! %d\n", plaintext->cd_format);
        return -1;
    }

    src = (unsigned char *)ciphertext->cd_raw.iov_base;
    len = (size_t) ciphertext->cd_raw.iov_len;

    if (plaintext && plaintext->cd_raw.iov_base)
        dst = (unsigned char *)plaintext->cd_raw.iov_base;
    else
        dst = src;

    printk("crypto_decrypt (%p -> %p) 0x%04lx\n",
           src, dst, (unsigned long)len);

    for (i = 0; i < len; i++)
        //dst[i] = isalpha(src[i]) ? src[i]^0x20 : src[i];
        dst[i] = src[i];

    // Notify caller.
    if (cr && cr->cr_callback_func) {
        printk("   notifying caller\n");
        cr->cr_callback_func(cr->cr_callback_arg, cr->cr_reqid);
        return CRYPTO_QUEUED;
    }

#endif
    return CRYPTO_SUCCESS;
}

int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
    crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *plaintext,
    crypto_call_req_t *cr)
{
#if _KERNEL
    unsigned char *src;
    unsigned char *dst;
    size_t len = 0;
    int i;
    unsigned int numiov = 0, curriov = 0, iovlen = 0;
    uio_t *srcuio = NULL;
    iovec_t *srciov = NULL;

    // Decrypt, we will get UIO -> RAW
    printk("crypto_decrypt  ciphertext cd_format %d, plaintext %d\n",
           ciphertext->cd_format, plaintext->cd_format);

    // DST is always RAW
    if (plaintext->cd_format != CRYPTO_DATA_RAW) {
        printk("crypto_decrypt  cd_format is NOT RAW?! %d\n", plaintext->cd_format);
        return CRYPTO_FAILED;
    }

    // SRC can be RAW, or UIO
    if ((plaintext->cd_format == CRYPTO_DATA_UIO) &&
        (plaintext->cd_uio->uio_segflg == UIO_USERSPACE)) {
        printk("crypto_decrypt  cipher cd_format is UIO?! segment is %s!!!\n",
               ciphertext->cd_uio->uio_segflg == UIO_USERSPACE ? "user" : "system");
        return CRYPTO_FAILED;
    }

    // We dont support MBLK at all
    if (plaintext->cd_format == CRYPTO_DATA_MBLK) {
        printk("crypto_decrypt  cipher cd_format is MBLK?!\n");
        return CRYPTO_FAILED;
    }

    // We do not handle callbacks (so far they've not been needed)
    if (cr != NULL) {
      printk("crypto_decrypt with callback request not supported\n");
      return CRYPTO_FAILED;
    }

    dst = (unsigned char *)plaintext->cd_raw.iov_base;
    len = (size_t) plaintext->cd_length;

    if (ciphertext && ciphertext->cd_raw.iov_base)
        src = (unsigned char *)ciphertext->cd_raw.iov_base;
    else
        src = dst;

    if (ciphertext->cd_format == CRYPTO_DATA_UIO) {
      srcuio = ciphertext->cd_uio;
      numiov = srcuio->uio_iovcnt;
      curriov = 0;
      iovlen = 0; // Forces read of first iov.
      srciov = srcuio->uio_iov;
      printk("crypto_decrypt: UIO :  with %u iovs: total 0x%04lx/0x%04lx\n",
             numiov,
             (unsigned long)len,
             (unsigned long)plaintext->cd_raw.iov_len);
    }

    if (numiov == 0) {
      printk("crypto_decrypt (%p -> %p) 0x%04lx/0x%04lx (offset 0x%04lx: numiov %u)\n",
	     src, dst,
             (unsigned long)len,
             (unsigned long)plaintext->cd_raw.iov_len,
             (unsigned long)plaintext->cd_offset,
             numiov);
    }

    for (i = 0; i < len; i++) {

        if (numiov && !iovlen) { // uses UIO, and ran out of space, move to next

            src = srciov[ curriov ].iov_base;
            iovlen = srciov[ curriov ].iov_len;

            printk("crypto_decrypt IOV (%p -> %p) curriov %u, iovlen 0x%04lx\n",
                   src, dst, curriov, (unsigned long)iovlen);

            curriov++; // Ready next.
            if (curriov >= numiov) { // out of dst space
                if (i < len) printk("crypto_decrypt ran outof dst space before src i=%d\n", i);
                break;
            }
        } // if numiov

        // ENCRYPT!
        dst[i] = isalpha(src[i]) ? src[i]^0x20 : src[i];
        // dst[i] = src[i];

        // Decrease UIO, if used
        if (iovlen) iovlen--;
    }

    printk("crypto_decrypt: done\n");
    return CRYPTO_SUCCESS;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}



int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
    crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *ciphertext,
    crypto_call_req_t *cr)
{
#if _KERNEL
    unsigned char *src;
    unsigned char *dst;
    size_t len = 0;
    int i;
    unsigned int numiov = 0, curriov = 0, iovlen = 0;
    uio_t *dstuio = NULL;
    iovec_t *dstiov = NULL;

    // SOURCE is always RAW
    if (plaintext->cd_format != CRYPTO_DATA_RAW) {
        printk("crypto_encrypt  cd_format is NOT RAW?! %d\n", plaintext->cd_format);
        return CRYPTO_FAILED;
    }

    // DST can be RAW, or UIO
    if ((ciphertext->cd_format == CRYPTO_DATA_UIO) &&
        (ciphertext->cd_uio->uio_segflg == UIO_USERSPACE)) {
        printk("crypto_encrypt  cipher cd_format is UIO?! segment is %s!!!\n",
               ciphertext->cd_uio->uio_segflg == UIO_USERSPACE ? "user" : "system");
        return CRYPTO_FAILED;
    }

    // We dont support MBLK at all
    if (ciphertext->cd_format == CRYPTO_DATA_MBLK) {
        printk("crypto_encrypt  cipher cd_format is MBLK?!\n");
        return CRYPTO_FAILED;
    }

    // We do not handle callbacks (so far they've not been needed)
    if (cr != NULL) {
      printk("cyrpto_encrypt with callback request not supported\n");
      return CRYPTO_FAILED;
    }

    src = (unsigned char *)plaintext->cd_raw.iov_base;
    len = (size_t) plaintext->cd_length;

    if (ciphertext && ciphertext->cd_raw.iov_base)
        dst = (unsigned char *)ciphertext->cd_raw.iov_base;
    else
        dst = src;

    if (ciphertext->cd_format == CRYPTO_DATA_UIO) {
      dstuio = ciphertext->cd_uio;
      numiov = dstuio->uio_iovcnt;
      curriov = 0;
      iovlen = 0; // Forces read of first iov.
      dstiov = dstuio->uio_iov;
      printk("crypto_encrypt: UIO :  with %u iovs: total 0x%04lx/0x%04lx\n",
             numiov,
             (unsigned long)len,
             (unsigned long)plaintext->cd_raw.iov_len);
    }

    if (numiov == 0) {
      printk("crypto_encrypt (%p -> %p) 0x%04lx/0x%04lx (offset 0x%04lx: numiov %u)\n",
	     src, dst,
             (unsigned long)len,
             (unsigned long)plaintext->cd_raw.iov_len,
             (unsigned long)plaintext->cd_offset,
             numiov);
    }

    for (i = 0; i < len; i++) {

        if (numiov && !iovlen) { // uses UIO, and ran out of space, move to next

            dst = dstiov[ curriov ].iov_base;
            iovlen = dstiov[ curriov ].iov_len;

            printk("crypto_encrypt IOV (%p -> %p) curriov %u, iovlen 0x%04lx\n",
                   src, dst, curriov, (unsigned long)iovlen);

            curriov++; // Ready next.
            if (curriov >= numiov) { // out of dst space
                if (i < len) printk("crypto_encrypt ran outof dst space before src i=%d\n", i);
                break;
            }
        } // if numiov

        // ENCRYPT!
        dst[i] = isalpha(src[i]) ? src[i]^0x20 : src[i];
        //dst[i] = src[i];

        // Decrease UIO, if used
        if (iovlen) iovlen--;
    }

    printk("crypto_encrypt: done\n");
    return CRYPTO_SUCCESS;
#endif
    ASSERT(1==0);
    return CRYPTO_FAILED;
}

int crypto_create_ctx_template(crypto_mechanism_t *mech,
    crypto_key_t *key, crypto_ctx_template_t *tmpl, int kmflag)
{
    return 0;
}

void crypto_destroy_ctx_template(crypto_ctx_template_t tmpl)
{
    return;
}

crypto_mech_type_t crypto_mech2id(crypto_mech_name_t name)
{
    if (!name || !*name)
        return CRYPTO_MECH_INVALID;

#if _KERNEL
    printk("called crypto_mech2id '%s'\n", name);
#endif
    if (name && !strcmp("CKM_AES_CCM", name)) return 1;
    return CRYPTO_MECH_INVALID;
}

#if !_KERNEL
char *getpassphrase(const char *prompt)
{
    printf("Asking for password here: \n");
    return "I'M LIZARD QUEEN";
}
#endif

boolean_t
avl_is_empty(avl_tree_t *tree)
{
	ASSERT(tree);
	return (tree->avl_numnodes == 0);
}
