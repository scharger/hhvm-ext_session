# HHVM ext_session (Beta)
Ported original HHVM ext_session from HHVM 4.3.
Only memcache storage method exists.

### Tested with HHVM 4.8 and 3.27

## Description
Port ext_session from HHVM 4.3. Only memcache saving handler left.

## Installation:

#### 0.
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

-> go to: "third-party"

-> go to: "folly"

-> go to: "src"

-> clone or download (copy link "Download ZIP")

-> cd /opt/hhvm/4.8.8/include/

-> wget https://github.com/facebook/folly/archive/8f6d3b107d07324f2876e021948f2c36186ae369.zip (Your link)

-> Open downloaded ZIP

-> Go to folly-8f6d3b107d07324f2876e021948f2c36186ae369

-> extract folly dir to /opt/hhvm/4.8.8/include/

#### 1. 
```shell
	make
```
	
ext_session.so will be saved to /etc/hhvm/

#### 2.
add "hhvm.extensions[hhvm_stemmer] = ext_session.so" -> /etc/hhvm/php.ini and /etc/hhvm/server.ini

#### 3.
Service HHVM restart


## Usage:

### Additional ini options:

session.memcache_host (Default = "localhost")
session.memcache_port (Default = "11211")

https://www.php.net/manual/en/book.session.php