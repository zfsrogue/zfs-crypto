
Welcome to the unofficial zfs-crypto branch.

This is the experimental 'features-flags' branch.

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

Current support is in BETA.

Importing a Solaris pool can be done using:
 Solaris: zpool create -o version=30 -O version=5 thepool $devices...
 Solaris: zfs create -o encryption=aes-256-ccm thepool/secure
 Linux: zpool import -N thepool
 Linux: zpool upgrade thepool
 Linux: zfs mount thepool/secure


* MACs are in use, but compute_mac() is empty, not called?

* All "// FIXME" should be inspected. In particular, known areas
  which differ are PROP_ALIAS, PROP_INHERIT, crypto vs userquota,

* Removed KEY methods "https URI" (requires curl) and pkcs11 types.



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

======================================================================
striped, unencrypted
======================================================================

$ tiotest -t8 -f 200 -d /striped_zpool/
Tiotest results for 8 concurrent io threads:
,----------------------------------------------------------------------.
| Item                  | Time     | Rate         | Usr CPU  | Sys CPU |
+-----------------------+----------+--------------+----------+---------+
| Write        1600 MBs |    3.2 s | 502.596 MB/s |  37.4 %  | 1290.1 % |
| Random Write   31 MBs |    0.3 s | 120.682 MB/s |   0.0 %  | 903.7 % |
| Read         1600 MBs |    0.3 s | 4682.758 MB/s | 222.4 %  | 5104.2 % |
| Random Read    31 MBs |    0.0 s | 4521.777 MB/s |   0.0 %  | 5787.9 % |
`----------------------------------------------------------------------'
Tiotest latency results:
,-------------------------------------------------------------------------.
| Item         | Average latency | Maximum latency | % >2 sec | % >10 sec |
+--------------+-----------------+-----------------+----------+-----------+
| Write        |        0.015 ms |        8.793 ms |  0.00000 |   0.00000 |
| Random Write |        0.026 ms |        7.953 ms |  0.00000 |   0.00000 |
| Read         |        0.006 ms |        9.339 ms |  0.00000 |   0.00000 |
| Random Read  |        0.007 ms |        0.030 ms |  0.00000 |   0.00000 |
|--------------+-----------------+-----------------+----------+-----------|
| Total        |        0.011 ms |        9.339 ms |  0.00000 |   0.00000 |
`--------------+-----------------+-----------------+----------+-----------'


======================================================================
zfs-crypt aes-256-ccm
======================================================================

$ tiotest -t8 -f 200 -d /striped_zpool/fs/
Tiotest results for 8 concurrent io threads:
,----------------------------------------------------------------------.
| Item                  | Time     | Rate         | Usr CPU  | Sys CPU |
+-----------------------+----------+--------------+----------+---------+
| Write        1600 MBs |    7.4 s | 216.343 MB/s |   5.4 %  | 742.1 % |
| Random Write   31 MBs |    0.2 s | 180.906 MB/s |  92.6 %  | 775.7 % |
| Read         1600 MBs |    0.3 s | 5341.238 MB/s |  73.4 %  | 6276.0 % |
| Random Read    31 MBs |    0.0 s | 4783.407 MB/s | 4898.2 %  | 1224.6 % |
`----------------------------------------------------------------------'
Tiotest latency results:
,-------------------------------------------------------------------------.
| Item         | Average latency | Maximum latency | % >2 sec | % >10 sec |
+--------------+-----------------+-----------------+----------+-----------+
| Write        |        0.026 ms |      835.720 ms |  0.00000 |   0.00000 |
| Random Write |        0.021 ms |        0.087 ms |  0.00000 |   0.00000 |
| Read         |        0.006 ms |        0.245 ms |  0.00000 |   0.00000 |
| Random Read  |        0.006 ms |        0.025 ms |  0.00000 |   0.00000 |
|--------------+-----------------+-----------------+----------+-----------|
| Total        |        0.016 ms |      835.720 ms |  0.00000 |   0.00000 |
`--------------+-----------------+-----------------+----------+-----------'


======================================================================
LUKS volumes with plain ZFS
======================================================================

dmcrypt/luks cipher/keysize: aes-xts-plain64, 512
------------------------------------------------------------------------------------
tiotest -t 8 -f 200 -d /striped_crypt/
Tiotest results for 8 concurrent io threads:
,----------------------------------------------------------------------.
| Item                  | Time     | Rate         | Usr CPU  | Sys CPU |
+-----------------------+----------+--------------+----------+---------+
| Write        1600 MBs |    3.4 s | 477.243 MB/s |  11.9 %  | 1169.2 % |
| Random Write   31 MBs |    0.5 s |  68.848 MB/s |  52.9 %  | 332.7 % |
| Read         1600 MBs |    0.3 s | 4999.844 MB/s | 318.7 %  | 5899.8 % |
| Random Read    31 MBs |    0.0 s | 4510.030 MB/s | 5051.2 %  | 1154.6 % |
`----------------------------------------------------------------------'
Tiotest latency results:
,-------------------------------------------------------------------------.
| Item         | Average latency | Maximum latency | % >2 sec | % >10 sec |
+--------------+-----------------+-----------------+----------+-----------+
| Write        |        0.031 ms |       69.994 ms |  0.00000 |   0.00000 |
| Random Write |        0.066 ms |       35.496 ms |  0.00000 |   0.00000 |
| Read         |        0.006 ms |       15.828 ms |  0.00000 |   0.00000 |
| Random Read  |        0.007 ms |        0.030 ms |  0.00000 |   0.00000 |
|--------------+-----------------+-----------------+----------+-----------|
| Total        |        0.019 ms |       69.994 ms |  0.00000 |   0.00000 |
`--------------+-----------------+-----------------+----------+-----------'



dmcrypt/luks cipher/keysize: aes-cbc-essiv:sha256, 256
-----------------------------------------------------------------------------------
tiotest -t 8 -f 200 -d /striped_crypt/
Tiotest results for 8 concurrent io threads:
,----------------------------------------------------------------------.
| Item                  | Time     | Rate         | Usr CPU  | Sys CPU |
+-----------------------+----------+--------------+----------+---------+
| Write        1600 MBs |    3.4 s | 467.855 MB/s |  37.4 %  | 1121.4 % |
| Random Write   31 MBs |    0.3 s | 105.175 MB/s |  80.8 %  | 518.3 % |
| Read         1600 MBs |    0.3 s | 5061.753 MB/s | 126.5 %  | 6150.0 % |
| Random Read    31 MBs |    0.0 s | 4566.711 MB/s |   0.0 %  | 5845.4 % |
`----------------------------------------------------------------------'
Tiotest latency results:
,-------------------------------------------------------------------------.
| Item         | Average latency | Maximum latency | % >2 sec | % >10 sec |
+--------------+-----------------+-----------------+----------+-----------+
| Write        |        0.028 ms |       59.958 ms |  0.00000 |   0.00000 |
| Random Write |        0.070 ms |       27.873 ms |  0.00000 |   0.00000 |
| Read         |        0.006 ms |        0.168 ms |  0.00000 |   0.00000 |
| Random Read  |        0.007 ms |        0.030 ms |  0.00000 |   0.00000 |
|--------------+-----------------+-----------------+----------+-----------|
| Total        |        0.017 ms |       59.958 ms |  0.00000 |   0.00000 |
`--------------+-----------------+-----------------+----------+-----------'

```

zfs/rogue
