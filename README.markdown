
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


Current support is at "proof of concept" level only. It is NOT usable.


Required work before Alpha:

* Implement (at least) default cipher, instead of current XOR$20

* Implement MAC checksum, currently checksum errors are ignored.

* Prompt for key (getpassphrase) needs implementing. It is possible
  that getpass() will suffice on Linux, as it does not limit input to
  8 chars.

* Key needs to be CK_AES prepared.

* Cipher functions need to be moved to SPL/ layer.

* All "// FIXME" should be inspected. In particular, known areas
  which differ are PROP_ALIAS, PROP_INHERIT, crypto vs userquota,

* Removed KEY methods "https URI" (requires curl) and pkcs11 types.

* Undo the POOL VERSION=30, put it back to 28, and make CRYPTO be a
  "Named Extension" instead.


Current output:

<pre>
# dd if=/dev/zero of=~/src/pool-image.bin bs=1M count=1024

# zpool create -f mypool ~/src/pool-image.bin

# zfs create -o encryption=on mypool/BOOM

in key_hdl_to_zc
in get_assphrase
Should ask for password here:
Should ask for password here:
Key is 'I'M LIZARD QUEEN' and is len 16
Nov  5 15:47:36 zfsdev kernel: [  324.188602] in CREATE
Nov  5 15:47:36 zfsdev kernel: [  324.188606]  version OK
[...]
Nov  5 15:47:36 zfsdev kernel: [  324.219017] crypto_decrypt IOV (ffff88003a98b200 -> ffff88003a98ba00) curriov 0, iovlen 0x0200
Nov  5 15:47:36 zfsdev kernel: [  324.219019] crypto_decrypt: done
Nov  5 15:47:36 zfsdev kernel: [  324.219020] zio_decrypt exit

# mkdir /mypool/BOOM/This.Directory.Is.Hopefully.Encrypted

# hexdump -C ../pool-image.bin |less

0041b440  07 00 00 00 00 00 00 40  00 00 00 00 00 00 74 48  |.......@......tH|
0041b450  49 53 2e 64 49 52 45 43  54 4f 52 59 2e 69 53 2e  |IS.dIRECTORY.iS.|
0041b460  68 4f 50 45 46 55 4c 4c  59 2e 65 4e 43 52 59 50  |hOPEFULLY.eNCRYP|
0041b470  54 45 44 00 00 00 00 00  00 00 00 00 00 00 00 00  |TED.............|
</pre>

zfs/rogue
