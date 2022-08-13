<?hh // partial
/*
-------------------------Crypto Lib-------------------------
MIT License

Original work Copyright (c) 2017 Vladislav Yarmak
Modified work Copyright (c) 2020 Artūras Kaukėnas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

final class Crypto {
	private string $secret;
	private string $digest_algo;
	private string $cipher_algo;
	private int $expire;
	private int $cipher_keylen;
	private mixed $digest_len;
    private mixed $cipher_ivlen;
    private $overwritten = array();
    private $opened = false;
	
	const string UINT32_LE_PACK_CODE       	=   "V";
	const int UINT32_SIZE               	=   4;
	const int RFC2965_COOKIE_SIZE      		=   4096;
	const int MIN_OVERHEAD_PER_COOKIE   	=   3;
	const int METADATA_SIZE             	=   4; //UINT32_SIZE;

    public function __construct(string $crypto_secret) : bool {
		if ($crypto_secret is bool) {
			throw new \Exception("Crypto Session failed. crypto_secret not specified");
			return false;
		}
		
		$crypto_secret = (string) $crypto_secret;
        if (!$crypto_secret ?? false) {
            throw new \Exception("Crypto Session failed. crypto_secret wrong");
			return false;
        }
        $this->secret = $crypto_secret;
		/////////////////////////////////////////////////////
		
		$digest_algo = \ini_get("session.digest_algo");
		if ($digest_algo is bool) {
			throw new \Exception("Crypto Session failed. session.digest_algo not specified");
			return false;
		}
		
		$digest_algo = (string) $digest_algo;
        if (!\in_array($digest_algo, \hash_algos())) {
			throw new \Exception("Crypto Session failed. session.digest_algo wrong");
			return false;
        }
        $this->digest_algo = $digest_algo;
		/////////////////////////////////////////////////////
		
		$cipher_algo = \ini_get("session.cipher_algo");
		if ($cipher_algo is bool) {
			throw new \Exception("Crypto Session failed. session.cipher_algo not specified");
			return false;
		}
		
		$cipher_algo = (string) $cipher_algo;
        if (!\in_array($cipher_algo, \openssl_get_cipher_methods(true))) {
			throw new \Exception("Crypto Session failed. session.cipher_algo wrong");
			return false;
        }
        $this->cipher_algo = $cipher_algo;
		/////////////////////////////////////////////////////
		
		$cipher_keylen = \ini_get("session.cipher_keylen");
		if ($cipher_keylen is bool) {
			throw new \Exception("Crypto Session failed. session.cipher_keylen not specified");
			return false;
		}
		
		$cipher_keylen = (int) $cipher_keylen;
		if ($cipher_keylen < 1) {
            throw new \Exception("Crypto Session failed. session.cipher_keylen wrong");
        }
        $this->cipher_keylen = $cipher_keylen;
		/////////////////////////////////////////////////////
		
		$expire = \ini_get("session.crypto_expire");
		if ($expire is bool) {
			throw new \Exception("Crypto Session failed. session.crypto_expire not specified");
			return false;
		}
		
		$expire = (int) $expire;
		if ($expire < 1) {
            throw new \Exception("Crypto Session failed. session.crypto_expire wrong");
        }
        $this->expire = $expire;
		/////////////////////////////////////////////////////
		
		$this->digest_len = \strlen(\hash($this->digest_algo, "", true));
        $this->cipher_ivlen = \openssl_cipher_iv_length($this->cipher_algo);
		
        if (($this->digest_len === false) || ($this->cipher_ivlen === false)) {
			throw new \Exception("Crypto Session failed. session.digest_algo OR/AND session.cipher_algo wrong");
		}
		
		return true;
    }
	
	public function decrypt(string $id, string $input) : string {
		$input = $this->base64_urlsafe_decode($input);
		if ($input === false) {
			return "";
		}
		
		$digest = \substr($input, 0, $this->digest_len);
		if ($digest === false) {
			return "";
		}

		$message = \substr($input, $this->digest_len);
		if ($message === false) {
			return "";
		}

        if (!
			$this->hash_equals(
				\hash_hmac($this->digest_algo, $id.$message, $this->secret, true),
				$digest
			)
		) {
            return "";
        }

        $valid_till_bin = \substr($message, 0, self::METADATA_SIZE);
        $valid_till_tmp = \unpack(self::UINT32_LE_PACK_CODE, $valid_till_bin);
		
		if (!isset($valid_till_tmp[1])) {
			return "";
		}
		
		$valid_till = (int) $valid_till_tmp[1];
		

        if (\time() > $valid_till) {
            return "";
        }

        $iv = \substr($message, self::METADATA_SIZE, $this->cipher_ivlen);
        $ciphertext = \substr($message, self::METADATA_SIZE + $this->cipher_ivlen);

        $key = $this->pbkdf2($this->digest_algo, $this->secret, $id.$valid_till_bin, 1, $this->cipher_keylen, true);
        $data = \openssl_decrypt($ciphertext, $this->cipher_algo, $key, \OPENSSL_RAW_DATA, $iv);
        if ($data === false) {
            throw new \Exception("Session data decrypt failed. OpenSSL error.");
        }

        return $data;
	}
	
	public function encrypt(string $id, string $data) {
        $expires = \time() + $this->expire;
        $valid_till_bin = \pack(self::UINT32_LE_PACK_CODE, $expires);

        $iv = \openssl_random_pseudo_bytes($this->cipher_ivlen);
        $key = $this->pbkdf2($this->digest_algo, $this->secret, $id.$valid_till_bin, 1, $this->cipher_keylen, true);

		if (\function_exists("\str_replace_with_count")) {
			$ciphertext = \openssl_encrypt_with_tag($data, $this->cipher_algo, $key, \OPENSSL_RAW_DATA, $iv);
		} else {
				$ciphertext = \openssl_encrypt($data, $this->cipher_algo, $key, \OPENSSL_RAW_DATA, $iv);
		}

        if ($ciphertext === false) {
            throw new \Exception("Session data encrypt failed. OpenSSL error.");
        }

        $meta = $valid_till_bin;
        $message = $meta.$iv.$ciphertext;

        $digest = \hash_hmac($this->digest_algo, $id.$message, $this->secret, true);
        $output = $this->base64_urlsafe_encode($digest.$message);

		return $output;
	}
	
	private function hash_equals(string $a, string $b) : bool {
		$ret = \strlen($a) ^ \strlen($b);
		$ret |= \array_sum(\unpack("C*", $a^$b));
		return !$ret;
	}
	
	private function base64_urlsafe_encode(string $input) : string {
        return \strtr(\base64_encode($input), array("+" => "-", "/" => "_", "=" => ""));
    }

    private function base64_urlsafe_decode(string $input) : string {
        $translated = \strtr($input, array("-" => "+", "_" => "/"));
        $padded = \str_pad($translated, ( (int)((\strlen($input) + 3) / 4) ) * 4, "=", \STR_PAD_RIGHT);
        return \base64_decode($padded);
    }

    /*
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
     * $key_length - The length of the derived key in bytes.
     * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
     * Returns: A $key_length-byte key derived from the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     */
    private function pbkdf2(string $algorithm, string $password, string $salt, int $count, int $key_length, bool $raw_output = false) {
        $algorithm = \strtolower($algorithm);
        if(!\in_array($algorithm, \hash_algos(), true)) {
            \trigger_error('PBKDF2 ERROR: Invalid hash algorithm.', \E_USER_ERROR);
		}
        if (($count <= 0) || ($key_length <= 0)) {
            \trigger_error('PBKDF2 ERROR: Invalid parameters.', \E_USER_ERROR);
		}
        if (\function_exists("hash_pbkdf2")) {
            // The output length is in NIBBLES (4-bits) if $raw_output is false!
            if (!$raw_output) {
                $key_length = $key_length * 2;
            }
            return \hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }

        $hash_length = \strlen(\hash($algorithm, "", true));
        $block_count = \ceil($key_length / $hash_length);

        $output = "";
        for($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . \pack("N", $i);
            // first iteration
            $last = $xorsum = \hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = \hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if($raw_output) {
            return \substr($output, 0, $key_length);
        } else {
				return \bin2hex(\substr($output, 0, $key_length));
		}
    }
}

/*
	-------------------------ext_session functions-------------------------
   +----------------------------------------------------------------------+
   | ext_session functions                                                |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010-present Facebook, Inc. (http://www.facebook.com)  |
   | Copyright (c) 1997-2010 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   
   Updated by Artūras Kaukėnas
*/


  /**
   * Return current cache expire
   *
   * @param string $new_cache_expire - If new_cache_expire is given, the
   *   current cache expire is replaced with new_cache_expire.     Setting
   *   new_cache_expire is of value only, if session.cache_limiter is set to
   *   a value different from nocache.
   *
   * @return int - Returns the current setting of session.cache_expire. The
   *   value returned should be read in minutes, defaults to 180.
   */
  function session_cache_expire(mixed $new_cache_expire = null): int {
    $ret = (int) \ini_get('session.cache_expire');
    if ($new_cache_expire !== null) {
      $val = (string)$new_cache_expire;
      \ini_set('session.cache_expire', (int)$val);
    }
    return $ret;
  }

  /**
   * Get and/or set the current cache limiter
   *
   * @param string $cache_limiter - If cache_limiter is specified, the name
   *   of the current cache limiter is changed to the new value.   Possible
   *   values    Value Headers sent     public        private_no_expire
   *    private        nocache
   *
   * @return string - Returns the name of the current cache limiter.
   */
  function session_cache_limiter(mixed $cache_limiter = null): string {
    $ret = (string) \ini_get('session.cache_limiter');
    if ($cache_limiter !== null) {
      \ini_set('session.cache_limiter', (string) $cache_limiter);
    }
    return $ret;
  }

  /**
   * Alias of session_write_close()
   */
  function session_commit(): void {
    session_write_close();
  }

  /**
   * Decodes session data from a session encoded string
   *
   * @param string $data - The encoded data to be stored.
   *
   * @return bool -
   */
  <<__Native>>
  function session_decode(string $data): bool;

  /**
   * Destroys all data registered to a session
   *
   * @return bool -
   */
  <<__Native>>
  function session_destroy(): bool;

  /**
   * Encodes the current session data as a session encoded string
   *
   * @return string - Returns the contents of the current session encoded.
   */
  <<__Native>>
  function session_encode(): mixed;

  /**
   * Get the session cookie parameters
   *
   * @return array - Returns an array with the current session cookie
   *   information, the array contains the following items:    "lifetime" -
   *   The lifetime of the cookie in seconds.     "path" - The path where
   *   information is stored.     "domain" - The domain of the cookie.
   *   "secure" - The cookie should only be sent over secure connections.
   *   "httponly" - The cookie can only be accessed through the HTTP
   *   protocol.
   */
  function session_get_cookie_params(): array<string, mixed> {
    return array(
      'lifetime' => (int) \ini_get('session.cookie_lifetime'),
      'path'     => (string) \ini_get('session.cookie_path'),
      'domain'   => (string) \ini_get('session.cookie_domain'),
      'secure'   => (bool) \ini_get('session.cookie_secure'),
      'httponly' => (bool) \ini_get('session.cookie_httponly')
    );
  }

  /**
   * Get current session id
   * @return string - session_id() returns the session id for the current
   *   session or the empty string ("") if there is no current session (no
   *   current session id exists).
   */
	<<__Native>>
	function session_id(?string $id = null): string;

  /**
   * Get the current session name
   * @return string - Returns the name of the current session.
   */
	function session_name(mixed $name = null): string {
		return (string) \ini_get('session.name');
	}

  /**
   * Session shutdown function
   *
   * @return void -
   */
  function session_register_shutdown(): void {
    register_shutdown_function('session_write_close');
  }

  /**
   * Set the session cookie parameters
   *
   * @param int|array $lifetime_or_options - Lifetime of the session cookie, defined in
   *   seconds OR options.
   * @param string $path - Path on the domain where the cookie will work.
   *   Use a single slash ('/') for all paths on the domain.
   * @param string $domain - Cookie domain, for example 'www.php.net'. To
   *   make cookies visible on all subdomains then the domain must be
   *   prefixed with a dot like '.php.net'.
   * @param bool $secure - If TRUE cookie will only be sent over secure
   *   connections.
   * @param bool $httponly - If set to TRUE then PHP will attempt to send
   *   the httponly flag when setting the session cookie.
   *
   * @return void -
   */
function session_set_cookie_params(
	mixed $lifetime_or_options,
	?string $path = null,
	?string $domain = null,
	?bool $secure = null,
	?bool $httponly = null
): void {
	$lifetimeF 		= null;
	$pathF 			= null;
	$domainF 		= null;
	$secureF 		= null;
	$httponlyF 		= null;

	if (\is_object($lifetime_or_options)) {
		$lifetime_or_options = (array) $lifetime_or_options;
    }

	if (\is_array($lifetime_or_options)) {
		if (isset($lifetime_or_options['lifetime'])) {
			if ($lifetime_or_options['lifetime'] is int) {
				$lifetimeF = $lifetime_or_options['lifetime'];
			}
		}

		if (isset($lifetime_or_options['path'])) {
			if ($lifetime_or_options['path'] is string) {
				$pathF = $lifetime_or_options['path'];
			}
		}

		if (isset($lifetime_or_options['domain'])) {
			if ($lifetime_or_options['domain'] is string) {
				$domainF = $lifetime_or_options['domain'];
			}
		}

		if (isset($lifetime_or_options['secure'])) {
			if ($lifetime_or_options['secure'] is bool) {
				$secureF = $lifetime_or_options['secure'];
			}
		}

		if (isset($lifetime_or_options['httponly'])) {
			if ($lifetime_or_options['httponly'] is bool) {
				$httponlyF = $lifetime_or_options['httponly'];
			}
		}
	}

	if ($lifetime_or_options is int) {
		$lifetimeF = $lifetime_or_options;
	}

	if ($path is string) {
		$pathF = $path;
	}

	if ($domain is string) {
		$domainF = $domain;
	}

	if ($secure is bool) {
		$secureF = $secure;
	}

	if ($httponly is bool) {
		$httponlyF = $httponly;
	}

	if (\ini_get('session.use_cookies')) {
		if ($lifetimeF !== null) {
			\ini_set('session.cookie_lifetime', $lifetimeF);
		}

		if ($pathF !== null) {
			\ini_set('session.cookie_path', $pathF);
		}

		if ($domainF !== null) {
			\ini_set('session.cookie_domain', $domainF);
		}

		if ($secureF !== null) {
			\ini_set('session.cookie_secure', $secureF);
		}

		if ($httponlyF !== null) {
			\ini_set('session.cookie_httponly', $httponlyF);
		}
    }
}

  /**
   * Start new or resume existing session
   *
   * @return bool - This function returns TRUE if a session was
   *   successfully started, otherwise FALSE.
   */
  <<__Native>>
  function session_start(): bool;

  /**
   * Returns the current session status
   *
   * @return int - PHP_SESSION_DISABLED if sessions are disabled.
   *   PHP_SESSION_NONE if sessions are enabled, but none exists.
   *   PHP_SESSION_ACTIVE if sessions are enabled, and one exists.
   */
  <<__Native>>
  function session_status(): int;

  /**
   * Free all session variables
   *
   * @return void -
   */
  <<__Native>>
  function session_unset(): void;

  /**
   * Write session data and end session
   *
   * @return void -
   */
  <<__Native>>
  function session_write_close(): void;
  
	function session_set(string $key, mixed $value) : void {
		$session_var = \HH\global_get("_SESSION");
		$session_var[$key] = $value;
		\HH\global_set("_SESSION", $session_var);
	}
  
	function session_get($key) : mixed {
		$session_var = \HH\global_get("_SESSION");
		return $session_var[$key];
	}
	
	function session_isset($key) : bool {
		return isset(\HH\global_get("_SESSION")[$key]);
	}
	
	function session_remove($key) : void {
		$session_var = \HH\global_get("_SESSION");
		unset($session_var[$key]);
		\HH\global_set("_SESSION", $session_var);
	}

/*
	-----------------------SessionHandlerInterface-------------------------
   +----------------------------------------------------------------------+
   | SessionHandlerInterface                                              |
   +----------------------------------------------------------------------+
   | Copyright (c) 2010-present Facebook, Inc. (http://www.facebook.com)  |
   | Copyright (c) 1997-2010 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   
   Updated by Artūras Kaukėnas
*/

interface SessionHandlerInterface {
	public function close() : bool;
	public function destroy(string $sessionId) : bool;
	public function gc(mixed $maxLifetime) : mixed;
	public function open(mixed $name) : bool;
	public function read(mixed $sessionId) : mixed;
	public function write(mixed $sessionId, mixed $data) : bool;
}

/*
	-------------------------MemcacheSessionModule-------------------------
   +----------------------------------------------------------------------+
   |  MemcacheSessionModule for HHVM                                      |
   +----------------------------------------------------------------------+
   | Copyright (c) 2020-present Artūras Kaukėnas						  |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/
  
final class MemcacheSessionModule implements SessionHandlerInterface {
	private \Memcache $mc;
	private $cryptoStorage;
	private $cryptoStorage_user_key;
	private bool $use_crypto_storage = false;
	private string $crypto_secret = "X";
	
	private bool $use_crypto_storage_user_key = false;
	private string $crypto_secret_user_key = "X";
	
	private bool $openCalled = false;
	private bool $connected = false;
	
	private int $gc_maxlifetime = 10;

	public function close() : bool {
		if (!$this->connected) {
			return true;
		}
		$this->mc->close();
		$this->connected = false;
		return true;
	}

	public function destroy(string $sessionId) : bool {
		if (!$this->connected) {
			return true;
		}
		
		$this->mc->delete($sessionId);
		return true;
	}

	public function gc(mixed $maxLifetime) : mixed {
		return 0;
	}
  
	public function open(mixed $name) : bool {
		$this->openCalled = true;
		
		if ($this->connected) {
			return true;
		}
		
		$use_crypto_storage = \ini_get("session.use_crypto_storage");
		if (!$use_crypto_storage is bool) {
			$use_crypto_storage = (int) $use_crypto_storage;			
			if ($use_crypto_storage == 1) {
				$crypto_secret = \ini_get("session.crypto_secret");
				if ($crypto_secret is bool) {
					throw new \Exception("Session open failed. session.crypto_secret wrong or not specified");
					return $this->connected;
				}
				$crypto_secret = (string) $crypto_secret;
				
				if ($crypto_secret == "X") {
					throw new \Exception("Session open failed. session.crypto_secret should be changed");
					return $this->connected;
				}
				
				$this->crypto_secret = $crypto_secret;
				$this->use_crypto_storage = true;
			}
		}
		
		$use_crypto_storage_user_key = \ini_get("session.use_crypto_storage_user_key");
		if (!$use_crypto_storage_user_key is bool) {
			$use_crypto_storage_user_key = (int) $use_crypto_storage_user_key;			
			if ($use_crypto_storage_user_key == 1) {
				$coockieKey = \md5("coockieKey");
				if (!isset($_COOKIE[$coockieKey])) {
					$crypto_secret_user_key = \bin2hex(\random_bytes(5));
					$coockieTime = (int) \ini_get("session.crypto_cookie_time_user_key");
					if ($coockieTime > 0) {
						$coockieTime = (time()+$coockieTime);
					}
					\setcookie($coockieKey, $crypto_secret_user_key, $coockieTime);
				} else {
						$crypto_secret_user_key = $_COOKIE[$coockieKey];
				}

				$this->crypto_secret_user_key = \md5($crypto_secret_user_key);
				$this->use_crypto_storage_user_key = true;
			}
		}
		if ($this->use_crypto_storage) {
			$this->cryptoStorage = new Crypto($this->crypto_secret);
		}
		
		if ($this->use_crypto_storage_user_key) {
			$this->cryptoStorage_user_key = new Crypto($this->crypto_secret_user_key);
		}
		
		$host = \ini_get("session.memcache_host");
		if ($host is bool) {
			throw new \Exception("Session open failed. session.memcache_host wrong or not specified");
			return $this->connected;
		}
		
		$host = (string) $host;
		
		$port = \ini_get("session.memcache_port");
		if ($port is bool) {
			$port = null;
		} else {
				$port = (int) $port;
		}
		
	
		$this->mc = new \Memcache;
		
		$pconnectR = false;
		$pconnect = \ini_get("session.memcache_persistent");
		if (!$pconnect is bool) {
			if ((int) $pconnect == 1) {
				$pconnectR = true;
			}
		}
		
		if ($pconnectR) {
			$conn = $this->mc->pconnect($host, $port);
		} else {		
				$conn = $this->mc->connect($host, $port);
		}
		
		if ($conn !== false) {
			$this->connected = true;
		} else {
				throw new \Exception("Session open error. Memcache connection failed");
		}
		
		$this->gc_maxlifetime = (int) \ini_get('session.gc_maxlifetime');
		
		return $this->connected;
	}

	public function read(mixed $sessionId) : mixed {
		if (!$this->openCalled) {
			$this->open("", "");
		}
		
		if (!$this->connected) {
			throw new \Exception("Session read error: (memcache not connected. SessionID:".$sessionId.")");
			return false;
		}
		
		$data = $this->mc->get($sessionId);
		if (!$data) {
			return "";
		}
		
		if ($this->use_crypto_storage) {
			$data = $this->cryptoStorage->decrypt($sessionId, $data);
			if ($data == "") {
				$this->mc->delete($sessionId);
				return "";
			}
			
		}
		if ($this->use_crypto_storage_user_key) {
			$data = $this->cryptoStorage_user_key->decrypt($sessionId, $data);
			if ($data == "") {
				$this->mc->delete($sessionId);
				return "";
			}
		}
		return $data;
	}

	public function write(mixed $sessionId, mixed $data) : bool {
		if (!$this->openCalled) {
			$this->open("", "");
		}
		
		if (!$this->connected) {
			throw new \Exception("Session write error: (memcache not connected. SessionID:".$sessionId.")");
			return false;
		}
		
		$data = (string) $data;
		
		if ($this->use_crypto_storage) {
			$data = $this->cryptoStorage->encrypt($sessionId, $data);
			if ($data == "") {
				throw new \Exception("Session write error: (encrypt error)");
				return false;
			}
			
		}

		if ($this->use_crypto_storage_user_key) {
			$data = $this->cryptoStorage_user_key->encrypt($sessionId, $data);
			if ($data == "") {
				throw new \Exception("Session write error: (encrypt error)");
				return false;
			}
		}
		
		$ret = $this->mc->set($sessionId, $data, MEMCACHE_COMPRESSED, $this->gc_maxlifetime);
		if ($ret == false) {
			throw new \Exception("Session write error: (sessionId:".$sessionId);
		}
		
		return $ret;
	}
}

/*
	-------------------------FileSessionModule----------------------------
   +----------------------------------------------------------------------+
   | FileSessionModule for HHVM                                           |
   +----------------------------------------------------------------------+
   | Copyright (c) 2020-present Artūras Kaukėnas						  |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
*/

final class FileSessionModule implements SessionHandlerInterface {
	private bool $prepared = false;
	
	private string $file_name = "";
	private string $_FILE_PATCH = "";
	
	private $cryptoStorage;
	private $cryptoStorage_user_key;
	private bool $use_crypto_storage = false;
	private string $crypto_secret = "X";
	
	private bool $use_crypto_storage_user_key = false;
	private string $crypto_secret_user_key = "X";
	
	private bool $openCalled = false;
	
	private int $gc_maxlifetime = 10;

	public function close() : bool {
		$this->prepared = false;
		return true;
	}

	public function destroy(string $file_name) : bool {
		if (!\file_exists($this->_FILE_PATCH.$file_name)) {
			return true;
		}
		
		try {
			\unlink($this->_FILE_PATCH.$file_name);
		} catch (\Exception $e) {
		}
		return true;
	}

	public function gc(mixed $maxLifetime) : mixed {
		if (!$this->prepared) {
			return false;
		}
		
		if (!$maxLifetime is int) {
			$maxLifetime = (int) $maxLifetime;
		}
		
		if ($maxLifetime < 1) {
			return 0;
		}		
		
		$nrdels = 0;
		
		$allFiles = \scandir($this->_FILE_PATCH);
		
		foreach ($allFiles as $file) {
			if (($file == ".") || ($file == "..")) {
				continue;
			}
			
			if (\is_dir($this->_FILE_PATCH.$file)) {
				continue;
			}
			
			$mtime = @\filemtime($this->_FILE_PATCH.$file);
			if ($mtime is bool) {
				continue;
			}
			
			if (\time() - \filemtime($this->_FILE_PATCH.$file) > $maxLifetime) {
				$this->destroy($file);
				$nrdels++;
			}
		}
		return $nrdels;
	}
  
	public function open(mixed $name) : bool {
		$this->prepared = false;
		
		$savePath = \ini_get("session.save_path");
		
		if ($savePath is bool) {
			throw new \Exception("Session open failed. ini session.save_path not specified");
			return $this->prepared;
		}
		
		$savePath = (string) $savePath;
		
		$this->openCalled = true;
		
		if ($this->prepared) {
			return true;
		}
		
		if (!$name is string) {
			$this->name = "";
			throw new \Exception("Session open failed. Session name incorrect");
			return $this->prepared;
		}
		
		$this->name = $name;
		$this->_FILE_PATCH = $savePath;
		
		if (\file_exists($savePath)) {
			if (!\is_dir($savePath)) {
				throw new \Exception("Session open failed. session.save_path (".$savePath.") is not a directory");
				return $this->prepared;
			}
		} else {
				@\mkdir($savePath, 0600, true);
		}
		
		if (!\is_dir($savePath)) {
			throw new \Exception("Session open failed. session.save_path (".$savePath.") is not a directory");
			return $this->prepared;
		}
		
		if (!\is_writable($savePath)) {
			throw new \Exception("Session open failed. session.save_path is not writable");
			return $this->prepared;
		}
		
		$use_crypto_storage = \ini_get("session.use_crypto_storage");
		if (!$use_crypto_storage is bool) {
			$use_crypto_storage = (int) $use_crypto_storage;			
			if ($use_crypto_storage == 1) {
				$crypto_secret = \ini_get("session.crypto_secret");
				if ($crypto_secret is bool) {
					throw new \Exception("Session open failed. session.crypto_secret wrong or not specified");
					return $this->prepared;
				}
				$crypto_secret = (string) $crypto_secret;
				
				if ($crypto_secret == "X") {
					throw new \Exception("Session open failed. session.crypto_secret should be changed");
					return $this->prepared;
				}
				
				$this->crypto_secret = $crypto_secret;
				$this->use_crypto_storage = true;
			}
		}
		
		$use_crypto_storage_user_key = \ini_get("session.use_crypto_storage_user_key");
		if (!$use_crypto_storage_user_key is bool) {
			$use_crypto_storage_user_key = (int) $use_crypto_storage_user_key;			
			if ($use_crypto_storage_user_key == 1) {
				$coockieKey = \md5("coockieKey");
				if (!isset($_COOKIE[$coockieKey])) {
					$crypto_secret_user_key = \bin2hex(\random_bytes(5));
					$coockieTime = (int) \ini_get("session.crypto_cookie_time_user_key");
					if ($coockieTime > 0) {
						$coockieTime = (time()+$coockieTime);
					}
					\setcookie($coockieKey, $crypto_secret_user_key, $coockieTime);
				} else {
						$crypto_secret_user_key = $_COOKIE[$coockieKey];
				}

				$this->crypto_secret_user_key = \md5($crypto_secret_user_key);
				$this->use_crypto_storage_user_key = true;
			}
		}
		if ($this->use_crypto_storage) {
			$this->cryptoStorage = new Crypto($this->crypto_secret);
		}
		
		if ($this->use_crypto_storage_user_key) {
			$this->cryptoStorage_user_key = new Crypto($this->crypto_secret_user_key);
		}
	
		$this->prepared = true;
		
		$this->gc_maxlifetime = (int) \ini_get('session.gc_maxlifetime');
		
		return $this->prepared;
	}

	public function read(mixed $sessionId) : mixed {
		if (!$this->openCalled) {
			$this->open($this->_FILE_PATCH, $sessionId);
		}
		
		if (!$this->prepared) {
			throw new \Exception("Session read error: (Session not prepared. SessionID:".$sessionId.")");
			return false;
		}
		
		if ($sessionId == "") {
			throw new \Exception("Session read error: (Session not prepared. SessionID:".$sessionId.")");
			return false;
		}
		
		if (!\file_exists($this->_FILE_PATCH.$sessionId)) {
			return "";
		}
		
		try {
			$data = \file_get_contents($this->_FILE_PATCH.$sessionId);
		} catch (\Exception $e) {
				throw new \Exception("Session read error: (File read error. SessionID:".$sessionId.")");
				return false;
		}
		
		if ($data is bool) {
			return "";
		}
		
		if ($this->use_crypto_storage) {
			$data = $this->cryptoStorage->decrypt($sessionId, $data);
			if ($data == "") {
				$this->destroy($sessionId);
				return "";
			}
			
		}
		if ($this->use_crypto_storage_user_key) {
			$data = $this->cryptoStorage_user_key->decrypt($sessionId, $data);
			if ($data == "") {
				$this->destroy($sessionId);
				return "";
			}
		}
		return $data;
	}

	public function write(mixed $sessionId, mixed $data) : bool {
		if (!$this->openCalled) {
			$this->open($this->_FILE_PATCH, $sessionId);
		}
		
		if (!$this->prepared) {
			throw new \Exception("Session write error: (Session not prepared. SessionID:".$sessionId.")");
			return false;
		}
		
		if ($sessionId == "") {
			throw new \Exception("Session write error: (Session not prepared. SessionID:".$sessionId.")");
			return false;
		}
		
		try {
			$fp = \fopen($this->_FILE_PATCH.$sessionId, "w+");
		} catch (\Exception $e) {
				throw new \Exception("Session write error: (File open error. SessionID:".$sessionId.")");
				return false;
		}
		
		if ($fp is bool) {
			throw new \Exception("Session write error: (File open error. SessionID:".$sessionId.")");
			return false;
		}

		$null = null;
		@\flock($fp, \LOCK_EX, inout $null);

		$data = (string) $data;
		
		if ($this->use_crypto_storage) {
			$data = $this->cryptoStorage->encrypt($sessionId, $data);
			if ($data == "") {
				throw new \Exception("Session write error: (encrypt error)");
				@\flock($fp, \LOCK_UN, inout $null);
				@\fclose($fp);
				return false;
			}
			
		}

		if ($this->use_crypto_storage_user_key) {
			$data = $this->cryptoStorage_user_key->encrypt($sessionId, $data);
			if ($data == "") {
				throw new \Exception("Session write error: (encrypt error)");
				@\flock($fp, \LOCK_UN, inout $null);
				@\fclose($fp);
				return false;
			}
		}
		
		$ret = @\fwrite($fp, $data);
		
		@\flock($fp, \LOCK_UN, inout $null);
		
		if ($ret is bool) {
			@\fclose($fp);
			\unlink($this->_FILE_PATCH.$sessionId);
			throw new \Exception("Session write error: (File writing error. SessionID:".$sessionId.")");
			return false;
		} else {
				$ret = true;
		}
		
		@\fclose($fp);
		
		return $ret;
	}
}