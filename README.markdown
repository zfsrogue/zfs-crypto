
Welcome to the unofficial zfs-crypto branch.

This is the experimental 'features-flags' branch, with
special pool upgrade additions.

If you run a legacy pool version=30, this branch will let you
import and upgrade your pool to the standard pool version=5000,
and it will set feature@encryption for any filesystem using
encryption.

It is to aid those who happen to use zfs-crypto with pool version=30
for the short window that it was available. Before the feature@
pool version became standard.

To make it clear, this branch has nothing to do with Sun, Oracle,
ZFSOnLinux, OpenSolaris, IllumOS, OpenIndiana, SmartOS, FreeBSD etc.

There are new files,

zcrypt.c
zcrypt.h
zio_crypt.c
zio_crypt.h
dsl_crypto.c
dsl_crypto.h
libzfs_crypto.c
zcrypt_common.c

which are kept "as is" as much as possible, including (possibly
irrelevant) headers.

The crypto/api/ header files are from OpenSolaris.

The crypto/api implementation is brand new, and supports "bare
minimum" features as needed by ZFS only.

Current support is in BETA. Real ciphers are used, but key generation
function could do with more work. It is NOT compatible with Solaris pools.
Currently it is the authentication MAC that appears to differ.

* MACs are in use, but compute_mac() is empty, not called?

* Key needs to be CK_AES prepared, better than current

* All "// FIXME" should be inspected. In particular, known areas
  which differ are PROP_ALIAS, PROP_INHERIT, crypto vs userquota,

* Removed KEY methods "https URI" (requires curl) and pkcs11 types.

* The pool version is now 5000, and added feature flag
  "feature@encryption".

* feature@encryption goes active if any ZFS are created with encryption=on.

* Allow for readonly import of active feature@encryption, so that the non-
  encrypted filesystems could be recovered.


Example:

```

# zfs create -o encryption=aes-256-gcm mypool/BOOM
  Enter passphrase for 'mypool/BOOM':
  Enter again:
  kernel: [11266.250594] spl-crypto: Cipher test 'CKM_AES_CCM' -> 'sun-ccm(aes)' successful.
# zfs list
  NAME          USED  AVAIL  REFER  MOUNTPOINT
  mypool        142K   984M    31K  /mypool
  mypool/BOOM    31K   984M    31K  /mypool/BOOM

# zpool get all mypool

mypool  feature@async_destroy  enabled                local
mypool  feature@encryption     active                 local

```

zfs/rogue
