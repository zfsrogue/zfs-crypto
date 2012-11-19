
Welcome to the unofficial zfs-crypto branch.

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

* Undo the POOL VERSION=30, put it back to 28, and make CRYPTO be a
  "Named Extension" instead. ZFS On Linux currently does not support
  "feature@" properties.


Example:

# zfs create -o encryption=aes-256-gcm mypool/BOOM
  Enter passphrase for 'mypool/BOOM':
  Enter again:
  kernel: [11266.250594] spl-crypto: Cipher test 'CKM_AES_CCM' -> 'sun-ccm(aes)' successful.
# zfs list
  NAME          USED  AVAIL  REFER  MOUNTPOINT
  mypool        142K   984M    31K  /mypool
  mypool/BOOM    31K   984M    31K  /mypool/BOOM


zfs/rogue
