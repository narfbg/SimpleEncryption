<?php
/**
 * Copyright (c) 2014, Andrey Andreev <narf@devilix.net>
 * All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * Simple Encryption for PHP
 *
 * A simple symmetric encryption library, currently providing
 * AES-256-CTR-HMAC-SHA256 as the only available encryption method.
 *
 * @package	SimpleEncryption
 * @author	Andrey Andreev <narf@devilix.net>
 * @copyright	Copyright (c) 2014, Andrey Andreev <narf@devilix.net>
 * @license	http://opensource.org/licenses/ISC ISC License (ISC)
 * @link	https://github.com/narfbg/SimpleEncryption
 */
namespace Narf\SimpleEncryption;

class Secret {

	const VERSION = '0.2-alpha';

	// These are passed to the constructor to specify the
	// input data type. In the future, when the default
	// encryption scheme changes, the ENCRYPTED value will
	// change as well, and another constant will be added
	// for (decryption) backwards compatibility.
	const PLAINTEXT = 0;
	const ENCRYPTED = 1;

	// Data placeholders
	private $inputText, $inputType, $masterKey;

	// Configuration values
	private static $handler;
	private static $mbstringOverride;

	/**
	 * __construct()
	 *
	 * @param	string	$inputText	Input text
	 * @param	int	$inputType	Input type
	 * @param	string	$masterKey	Master key
	 */
	public function __construct($inputText, $masterKey = null, $inputType = null)
	{
		// Initial configuration
		if ( ! isset(self::$handler))
		{
			// @codeCoverageIgnoreStart
			if (extension_loaded('mcrypt')) self::$handler = 'mcrypt';
			elseif (extension_loaded('openssl')) self::$handler = 'openssl';
			else throw new \RuntimeException('No encryption handler available. You need to install one of MCrypt or OpenSSL.');
			// @codeCoverageIgnoreEnd

			self::$mbstringOverride = (extension_loaded('mbstring') && ini_get('mbstring.func_overload'));
		}

		// Validate input type
		if (isset($inputType))
		{
			if ($inputType === self::ENCRYPTED && ! isset($masterKey))
			{
				throw new \InvalidArgumentException('Input type is Secret::ENCRYPTED, but there is no key.');
			}
			elseif ($inputType !== self::PLAINTEXT && $inputType !== self::ENCRYPTED)
			{
				throw new \InvalidArgumentException('Input type must be Secret::PLAINTEXT or Secret::ENCRYPTED');
			}

			$this->inputType = $inputType;
		}

		// Validate key (length) if it exists, and guess the input type if necessary
		if (isset($masterKey))
		{
			if ( ! preg_match('/^[0-9a-f]{64}$/i', $masterKey))
			{
				throw new \InvalidArgumentException('Invalid key format, please use getKey() to create your own keys.');
			}

			$this->masterKey = pack('H*', $masterKey);
			isset($this->inputType) OR $this->inputType = self::ENCRYPTED;
		}
		elseif ( ! isset($this->inputType)) $this->inputType = self::PLAINTEXT;

		$this->inputText = $inputText;
	}

	/**
	 * getCipherText()
	 *
	 * Does the following:
	 *
	 *  - If the input was an encrypted message, calls getPlainText() to decrypt it
	 *  - If the input was a plain-text message and no master key is set, the key is generated
	 *  - Generates a random IV
	 *  - Derives a cipher and a HMAC key from the master key, via HKDF
	 *  - Encrypts the plainText message and prepends the IV to it
	 *  - Prepends a HMAC-SHA256 message to the cipher text encodes it using Base64
	 *
	 * The result is not cached and the whole process is repeated for each call,
	 * resulting in different IV and cipher text every time.
	 *
	 * @return	string	Cipher text
	 */
	public function getCipherText()
	{
		if (isset($this->masterKey)) $iv = self::getRandomBytes(16, true);
		else list($this->masterKey, $iv) = str_split(self::getRandomBytes(48, true), 32);

		list($cipherKey, $hmacKey) = str_split(self::hkdf($this->masterKey, 'sha512', 64, 'aes-256-ctr-hmac-sha256'), 32);

		$data = ($this->inputType === self::PLAINTEXT)
			? $this->inputText
			: $this->getPlainText();

		if (($data = $this->{self::$handler.'Encrypt'}($data, $cipherKey, $iv)) === false)
		{
			// @codeCoverageIgnoreStart
			throw new \RuntimeException('Error during encryption procedure.');
			// @codeCoverageIgnoreEnd
		}

		return base64_encode(hash_hmac('sha256', $iv.$data, $hmacKey, true).$iv.$data);
	}

	/**
	 * getPlainText()
	 *
	 * Does the following:
	 *
	 *  - If the input was a plain-text message, simply returns it
	 *  - The cipher and HMAC keys are derived from the master key
	 *  - Validates and strips Base64 encoding
	 *  - Calls authenticate(), which strips the Base64 encoding and HMAC message
	 *  - Separates the IV and decrypts the message
	 *
	 * The result is cached to speed-up subsequent calls.
	 *
	 * @return	string	Plain-text message
	 */
	public function getPlainText()
	{
		if ($this->inputType === self::PLAINTEXT)
		{
			return $this->inputText;
		}

		list($cipherKey, $hmacKey) = str_split(self::hkdf($this->masterKey, 'sha512', 64, 'aes-256-ctr-hmac-sha256'), 32);

		// authenticate() receives $data by reference
		$data = $this->inputText;
		$this->authenticate($data, $hmacKey);

		$data = $this->{self::$handler.'Decrypt'}(
			self::substr($data, 16),
			$cipherKey,
			self::substr($data, 0, 16)
		);

		if ($data === false)
		{
			// @codeCoverageIgnoreStart
			throw new \RuntimeException('Error during decryption procedure.');
			// @codeCoverageIgnoreEnd
		}

		return $data;
	}

	/**
	 * getKey()
	 *
	 * Generates a key, unless already set, and then returns it.
	 *
	 * @return	string	Key
	 */
	public function getKey()
	{
		isset($this->masterKey) OR $this->masterKey = self::getRandomBytes(32, true);
		return bin2hex($this->masterKey);
	}

	/**
	 * getRandomBytes()
	 *
	 * Reads the specified amount of data from the system's PRNG.
	 *
	 * @param	int	$length	Desired output length
	 * @return	string	A pseudo-random stream of bytes
	 */
	public static function getRandomBytes($length, $rawOutput = false)
	{
		if ( ! is_int($length) OR $length < 1)
		{
			throw new \InvalidArgumentException('Length must be an integer larger than 0.');
		}

		// @codeCoverageIgnoreStart
		if (defined('MCRYPT_DEV_URANDOM'))
		{
			if (($output = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM)) !== false)
			{
				return ($rawOutput) ? $output : bin2hex($output);
			}
		}

		if (is_readable('/dev/urandom') && ($fp = fopen('/dev/urandom', 'rb')) !== false)
		{
			stream_set_chunk_size($fp, $length);
			$output = fread($fp, $length);
			fclose($fp);
			if ($output !== false)
			{
				return ($rawOutput) ? $output : bin2hex($output);
			}
		}

		if (function_exists('openssl_random_pseudo_bytes'))
		{
			$cryptoStrong = null;
			if (($output = openssl_random_pseudo_bytes($length, $cryptoStrong)) !== false && $cryptoStrong)
			{
				return ($rawOutput) ? $output : bin2hex($output);
			}
		}

		throw new \RuntimeException('No reliable PRNG source is available on the system.');
		// @codeCoverageIgnoreEnd
	}

	/**
	 * hkdf()
	 *
	 * An RFC5869-compliant HMAC Key Derivation Function implementation.
	 *
	 * @link	https://tools.ietf.org/rfc/rfc5869.txt
	 * @param	string	$key	Input key material
	 * @param	string	$digest	Hashing algorithm
	 * @param	int	$length	Desired output length
	 * @param	string	$info	Context/application-specific info
	 * @param	string	$salt	Salt
	 * @return	string	A pseudo-random stream of bytes
	 */
	public static function hkdf($key, $digest, $length = null, $info = '', $salt = null)
	{
		static $digests;
		isset($digests) OR $digests = array('sha512' => 64);

		if ( ! isset($digests[$digest]))
		{
			if (in_array($digest, hash_algos(), true)) $digests[$digest] = self::strlen(hash($digest, '', true));
			else throw new \InvalidArgumentException('Unknown HKDF algorithm: '.$digest);
		}

		if ( ! isset($length))
		{
			$length = $digests[$digest];
		}
		elseif ( ! is_int($length) OR $length < 1 OR $length > (255 * $digests[$digest]))
		{
			throw new \InvalidArgumentException('HKDF output length for '.$digest.' must be an integer between 1 and '.(255 * $digests[$digest]));
		}

		self::strlen($salt) OR $salt = str_repeat("\x0", $digests[$digest]);
		$prk = hash_hmac($digest, $key, $salt, true);
		$key = '';
		for ($keyBlock = '', $blockIndex = 1; self::strlen($key) < $length; $blockIndex++)
		{
			$keyBlock = hash_hmac($digest, $keyBlock.$info.chr($blockIndex), $prk, true);
			$key .= $keyBlock;
		}

		return self::substr($key, 0, $length);
	}

	/**
	 * authenticate()
	 *
	 * Validates and strips Base64 encoding, then separates the HMAC message from
	 * the cipher text and verifies them in a way that prevents timing attacks.
	 *
	 * @param	string	&$cipherText	Cipher text
	 * @param	string	$hmacKey	HMAC key
	 * @return	void
	 */
	private function authenticate(&$cipherText, $hmacKey)
	{
		if (($length = self::strlen($cipherText)) <= 32 OR ($length % 4) !== 0)
		{
			throw new \RuntimeException('Authentication failed: Invalid length');
		}
		elseif (($cipherText = base64_decode($cipherText, true)) === false)
		{
			throw new \RuntimeException('Authentication failed: Input data is not a valid Base64 string.');
		}

		$hmacRecv = self::substr($cipherText, 0, 32);
		$cipherText = self::substr($cipherText, 32);
		$hmacCalc = hash_hmac('sha256', $cipherText, $hmacKey, true);

		/**
		 * Double HMAC verification
		 *
		 * Protects against timing side-channel attacks by randomizing the
		 * attacker's guess input instead of trying to directly compare in
		 * a constant time fashion. The latter is apparently not always
		 * possible due to run-time or compile-time optimizations.
		 *
		 * Reference: https://www.isecpartners.com/blog/2011/february/double-hmac-verification.aspx
		 *
		 * A note on MD5 usage here:
		 *
		 * As explained, the goal is simply to change the strings being
		 * compared, so we don't need a strong algorithm, just a fast one.
		 */
		if (hash_hmac('md5', $hmacRecv, $hmacKey) !== hash_hmac('md5', $hmacCalc, $hmacKey))
		{
			throw new \RuntimeException('Authentication failed: HMAC mismatch');
		}
	}

	/**
	 * mcryptEncrypt()
	 *
	 * @param	string	$data	Plain text
	 * @param	string	$key	Encryption key
	 * @param	string	$iv	IV
	 * @return	string	Cipher text
	 */
	private function mcryptEncrypt($data, $key, $iv)
	{
		return mcrypt_encrypt('rijndael-128', $key, $data, 'ctr', $iv);
	}

	/**
	 * mcryptDecrypt()
	 *
	 * @param	string	$data	Cipher text
	 * @param	string	$key	Encryption key
	 * @param	string	$iv	IV
	 * @return	string	Plain text
	 */
	private function mcryptDecrypt($data, $key, $iv)
	{
		return mcrypt_decrypt('rijndael-128', $key, $data, 'ctr', $iv);
	}

	/**
	 * opensslEncrypt()
	 *
	 * @param	string	$data	Plain text
	 * @param	string	$key	Encryption key
	 * @param	string	$iv	IV
	 * @return	string	Cipher text
	 */
	private function opensslEncrypt($data, $key, $iv)
	{
		return openssl_encrypt($data, 'aes-256-ctr', $key, 1, $iv);
	}

	/**
	 * opensslDecrypt()
	 *
	 * @param	string	$data	Cipher text
	 * @param	string	$key	Encryption key
	 * @param	string	$iv	IV
	 * @return	string	Plain text
	 */
	private function opensslDecrypt($data, $key, $iv)
	{
		return openssl_decrypt($data, 'aes-256-ctr', $key, 1, $iv);
	}

	/**
	 * __sleep()
	 *
	 * Prevents serialization to avoid accidental data leaks.
	 */
	public final function __sleep()
	{
		throw new \RuntimeException('Serialization is not allowed!');
		return array();
	}

	/**
	 * strlen()
	 *
	 * We use this to make sure that we're counting bytes
	 * instead of multibyte characters.
	 *
	 * @param	string	$string	Input string
	 * @return	int
	 */
	private static function strlen($string)
	{
		return (self::$mbstringOverride === true)
			? \mb_strlen($string, '8bit')
			: \strlen($string);
	}

	/**
	 * substr()
	 *
	 * We use this to make sure that we're cutting at byte
	 * counts instead of multibyte character boundaries.
	 *
	 * @param	string	$string	Input string
	 * @param	int	$start	Starting byte index
	 * @param	int	$length	Output string length
	 * @return	string	Output string
	 */
	private static function substr($string, $start, $length = null)
	{
		if (self::$mbstringOverride === true)
		{
			return \mb_substr($string, $start, $length, '8bit');
		}

		// Unlike mb_substr(), substr() returns an empty string
		// if we pass null as the $length value.
		return isset($length)
			? \substr($string, $start, $length)
			: \substr($string, $start);
	}

}