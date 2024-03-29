# HHVM ext_session (Beta)
HHVM 4.3 modified ext_session for HHVM without ext_session.

### Tested with HHVM 4.56

## License

This software source files are licensed under PHP 3.01 and MIT licenses.

`SPDX-License-Identifier: PHP-3.01 AND MIT`

## Description
Port ext_session from HHVM 4.3. Only "memcache" and "files" saving handler left.

## Installation:

#### 0.
Install dependences
```shell
apt-get install hhvm-dev libjemalloc-dev libgoogle-glog-dev libboost-all-dev libtbb-dev zlib1g-dev
```

try:
```shell
hphpize
```

In case of "-bash: hphpize: command not found" try following actions (Replace _YOUR_HHVM_VERSION_):

#### 0.1.
Move content from /__ PGKROOT__/lib/ to /opt/hhvm/_YOUR_HHVM_VERSION_/

#### 0.2.
```shell
export hphpizepatch=/opt/hhvm/_YOUR_HHVM_VERSION_/bin/
make
```

#### 0.3.
In case of "low-ptr-def.h" error try to generate file

```shell
cd /opt/hhvm/_YOUR_HHVM_VERSION_/include/hphp/util
wget raw.githubusercontent.com/facebook/hhvm/HHVM-4.8/hphp/tools/generate-low-ptr.sh
chmod 777 generate-low-ptr.sh
export INSTALL_DIR=/opt/hhvm/_YOUR_HHVM_VERSION_/include/hphp/util
./generate-low-ptr.sh --low
```

#### 0.4.
Dependency cases:
Manually download from github.com/facebook/hhvm/third-party/_REQUIRED_DEPENDENCY_/_SRC_/ 
to 
/opt/hhvm/_YOUR_HHVM_VERSION_/include/

#### Use your branch!

For example folly for HHVM 4.8:
https://github.com/facebook/hhvm/
-> select Branch HHVM-4.8

-> go to: "third-party/folly/src"

-> clone or download (copy link "Download ZIP")

-> cd /opt/hhvm/4.8.8/include/

-> wget https://github.com/facebook/folly/archive/8f6d3b107d07324f2876e021948f2c36186ae369.zip (Your link)

-> Open downloaded ZIP

-> Go to folly-8f6d3b107d07324f2876e021948f2c36186ae369

-> extract folly dir to /opt/hhvm/4.8.8/include/

hphp/util/hphp-config.h:
-> https://github.com/facebook/hhvm/
-> select Branch HHVM-4.8
-> go to: "hphp/util/"
-> open file "hphp-config.h.in" and copy content
-> cd /opt/hhvm/4.8.8/include/hphp/util/
-> nano hphp-config.h
-> right mouse click
-> Ctrl + O -> Enter -> Ctrl + X


#### 0.5.
Additional dependency problems.
Try to download hhvm -> hphp folder content into /usr/include/hphp (Use your branch!)

-> cd /usr/include/
-> apt-get install unzip
-> wget wget https://github.com/facebook/hhvm/archive/refs/heads/HHVM-4.8.zip
-> unzip HHVM-4.8.zip
-> rm HHVM-4.8.zip
-> move hphp folder form /usr/include/hhvm-HHVM-4-8 to /usr/include/
-> copy hphp folder form /usr/include/ to /opt/hhvm/4.8.8/include/

#### 1. 
```shell
	make
```
	
ext_session.so will be saved to /etc/hhvm/

#### 2.
add "hhvm.extensions[ext_session] = ext_session.so" -> /etc/hhvm/php.ini and /etc/hhvm/server.ini

#### 3.
Service HHVM restart


## Usage:

### functions
```
session_cache_expire
session_cache_limiter
session_commit
session_decode
session_destroy
session_encode
session_get_cookie_params
session_id - limited to only get session id (for Crypto support)
session_name - limited to only get session name (for Crypto support)
session_register_shutdown
session_set_cookie_params
session_start
session_status
session_unset
session_write_close
```

#### new functions to get/set $_SESSION global variable data
```
session_set(string $key, mixed $value) : void
session_get(mixed $key = null) : mixed
session_isset(string $key) : bool
session_remove(string $key) : void
```

### interfaces
```
SessionHandlerInterface
```

### Handler Modules
```
MemcacheSessionModule -> session.save_handler = memcache
FileSessionModule -> session.save_handler = file
```

### Additional
```
class Crypto(string $crypto_secret)
public function decrypt(string $id, string $data) : string
public function encrypt(string $id, string $data) : string
```

https://www.php.net/manual/en/book.session.php

### Additional ini options:
```
session.memcache_persistent 		(Default = "0")
session.memcache_host 			(Default = "localhost")
session.memcache_port 			(Default = "11211")

session.crypto_cookie_time_user_key	(Default = "2592000") (time() + sec.)
session.use_crypto_storage_user_key	(Default = "0")
session.use_crypto_storage		(Default = "0")
session.crypto_secret			(Default = "X") !should be changed if session.use_crypto_storage == 1!
session.digest_algo			(Default = "sha256")
session.cipher_algo			(Default = "aes-256-ctr")
session.cipher_keylen			(Default = "32")
session.crypto_expire			(Default = "2592000")
```
