<?php
use Narf\SimpleEncryption\Secret;

class SecretTest extends PHPUnit_Framework_TestCase {

	private $mcrypt, $openssl, $mbstring;

	/**
	 * Setup
	 *
	 * Detects MCrypt, OpenSSL, mbstring availability.
	 */
	public function setUp()
	{
		$this->mcrypt = extension_loaded('mcrypt');
		$this->openssl = extension_loaded('openssl');
		$this->mbstring = extension_loaded('mbstring');
	}

	/**
	 * __construct() one-time configuration tests
	 *
	 * @runInSeparateProcess
	 */
	public function testSelfConfiguration()
	{
		if ( ! $this->mcrypt && ! $this->openssl)
		{
			try
			{
				new Secret('dummy');
				return $this->fail('ext/mcrypt, ext/openssl are not available, but instantiation succeeded.');
			}
			catch (RuntimeException $e)
			{
				$this->assertEquals(
					'No encryption handler available. You need to install one of MCrypt or OpenSSL.',
					$e->getMessage()
				);
				return $this->markTestIncomplete('ext/mcrypt, ext/openssl are not available.');
			}
		}

		// We'll need some reflection magic ...
		$reflection = new ReflectionClass(new Secret('dummy'));
		$handler = $reflection->getProperty('handler');
		$mbstring = $reflection->getProperty('mbstringOverride');
		$handler->setAccessible(true);
		$mbstring->setAccessible(true);

		$this->assertTrue(
			$handler->isStatic(),
			'Secret::$handler should be set only once, but is not static.'
		);

		$this->assertTrue(
			$mbstring->isStatic(),
			'Secret::$mbstringOverride should be set only once, but is not static.'
		);

		$this->assertEquals(
			$this->mcrypt ? 'mcrypt' : 'openssl',
			$handler->getValue(),
			sprintf(
				'Secret::$handler was not properly configured.',
				var_export($this->mcrypt ? 'mcrypt' : 'openssl', true),
				var_export($handler->getValue(), true)
			)
		);

		$this->assertEquals(
			$this->mbstring && ini_get('mbstring.func_overload'),
			$mbstring->getValue(),
			sprintf(
				'Secret::$mbstringOverride was set to %s, but mbstring%s is %s enabled.',
				var_export($mbstring->getValue(), true),
				$this->mbstring ? '.func_overload' : '',
				ini_get('mbstring.func_overload') ? '' : 'not'
			)
		);

		// Configuration should only be executed once
		$handler->setValue($this->mcrypt ? 'openssl' : 'mcrypt');
		$mbstring->setValue( ! ($this->mbstring && ini_get('mbstring.func_overload')));
		new Secret('dummy');

		$this->assertEquals(
			$this->mcrypt ? 'openssl' : 'mcrypt',
			$handler->getValue(),
			'Secret::$handler was configured twice.'
		);

		$this->assertEquals(
			! ($this->mbstring && ini_get('mbstring.func_overload')),
			$mbstring->getValue(),
			'Secret::$mbstringOverride was configured twice.'
		);
	}

	/**
	 * strlen(), substr() generic tests
	 *
	 * @depends	testSelfConfiguration
	 * @runInSeparateProcess
	 */
	public function testMbstringOverrideBasic()
	{
		list($strlen, $substr,) = $this->getMbstringOverrides();
		$this->doMbstringOverrideAssertions($strlen, $substr);
	}

	/**
	 * strlen(), substr() extensive tests
	 *
	 * This will test the override even if it's not necessary
	 * for the library's operation on the system. Also, having
	 * this as a separate test allows us to mark it as skipped
	 * without preventing other tests from executing.
	 *
	 * @depends	testMbstringOverrideBasic
	 * @runInSeparateProcess
	 */
	public function testMbstringOverrideExtensive()
	{
		if ( ! $this->mbstring)
		{
			return $this->markTestSkipped('ext/mbstring is not available.');
		}
		elseif (ini_get('mbstring.func_overload'))
		{
			return $this->markTestSkipped('mbstring.func_override is enabled');
		}

		list($strlen, $substr, $property) = $this->getMbstringOverrides();
		$property->setValue( ! $property->getvalue());

		$this->doMbstringOverrideAssertions($strlen, $substr);
	}

	/**
	 * getMbstringOverrides()
	 *
	 * Returns accessible reflections for Secret::strlen(),
	 * Secret::substr() and Secret::$mbstringOverride.
	 *
	 * @coversNothing
	 */
	private function getMbstringOverrides()
	{
		$reflection = new ReflectionClass(new Secret('dummy'));
		$strlen = $reflection->getMethod('strlen');
		$substr = $reflection->getMethod('substr');
		$property = $reflection->getProperty('mbstringOverride');
		$strlen->setAccessible(true);
		$substr->setAccessible(true);
		$property->setAccessible(true);

		return array($strlen, $substr, $property);
	}

	/**
	 * strlen(), a byte-safe version
	 *
	 * @coversNothing
	 */
	private function strlen($str)
	{
		return ($this->mbstring) ? mb_strlen($str, '8bit') : strlen($str);
	}

	/**
	 * substr(), a byte-safe version
	 *
	 * @coversNothing
	 */
	private function substr($str, $start, $length = null)
	{
		if ($this->mbstring)
		{
			return mb_substr($str, $start, $length, '8bit');
		}

		return isset($length)
			? substr($str, $start, $length)
			: substr($str, $start);
	}

	/**
	 * doMbstringOverrideAssertions()
	 *
	 * Convenience method to do the mbstring override assertions on
	 * demand, as we'll probably need to do that multiple times.
	 *
	 * The string 'осем' is cyrilic, utf-8, which means 2 bytes per
	 * character, or 8 in total, and it happens to mean 'eight'
	 * in Bulgarian ;)
	 *
	 * @covers	Secret::strlen
	 * @covers	Secret::substr
	 */
	private function doMbstringOverrideAssertions(&$strlen, &$substr)
	{
		$this->assertEquals(8, $strlen->invoke(null, 'осем'), 'Secret::strlen() is not byte-safe!');

		$this->assertEquals('осем', $substr->invoke(null, 'осем', 0));
		$this->assertEquals(7, $this->strlen($substr->invoke(null, 'осем', 1)));
		$this->assertEquals(2, $this->strlen($substr->invoke(null, 'осем', 1, 2)));
		$this->assertEquals(3, $this->strlen($substr->invoke(null, 'осем', 0, 3)));
		$this->assertEquals(1, $this->strlen($substr->invoke(null, 'осем', -1)));
		$this->assertEquals(1, $this->strlen($substr->invoke(null, 'осем', -3, 1)));
		// Throw-in a single-byte character, just in case
		$this->assertEquals('0с', $substr->invoke(null, '0сем', 0, 3), 'Secret::substr() is not byte-safe!');
	}

	/**
	 * __construct() input sanitization
	 *
	 * @depends	testMbstringOverrideBasic
	 */
	public function testConstructInvalidParams()
	{
		// Invalid key, lower length
		$test = false;
		try { new Secret('dummy', str_repeat('0', rand(0,63))); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::__construct() accepts keys with invalid length.');

		// Invalid key, higher length
		$test = false;
		try { new Secret('dummy', str_repeat('0', rand(65,128))); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::__construct() accepts keys with invalid length.');

		// Invalid key, not hex
		$test = false;
		try { new Secret('dummy', str_repeat('0', rand(0, 63)).'g'); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::__construct() accepts non-hexadecimal keys.');

		// Invalid input type
		$test = false;
		try { new Secret('dummy', str_repeat('0', 64), 'This triggers exception'); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::__construct() accepts invalid input types.');

		// Type Secret::ENCRYPTED, but with no key (logical error)
		$test = false;
		try { new Secret('dummy', null, Secret::ENCRYPTED); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::__construct() accepts type Secret::ENCRYPTED with no key.');
	}

	/**
	 * __construct() valid usage tests
	 *
	 * @depends	testConstructInvalidParams
	 * @runInSeparateProcess
	 */
	public function testConstructValidUsage()
	{
		$instance = new Secret('A secret message');
		$reflection = new ReflectionClass($instance);
		$inputText = $reflection->getProperty('inputText');
		$inputType = $reflection->getProperty('inputType');
		$masterKey = $reflection->getProperty('masterKey');
		$inputText->setAccessible(true);
		$inputType->setAccessible(true);
		$masterKey->setAccessible(true);

		// Text only: $inputType = Secret::PLAINTEXT
		$this->assertEquals('A secret message', $inputText->getValue($instance), 'Secret::$inputText was not (properly) set.');
		$this->assertEquals(Secret::PLAINTEXT, $inputType->getValue($instance), 'Secret::$inputType was not (properly) set.');
		$this->assertNull($masterKey->getValue($instance), 'Secret::$masterKey is set, but it was not provided.');

		// Text and key: $inputType = Secret::ENCRYPTED
		$instance = new Secret('Another secret message', str_repeat('01', 32));
		$this->assertEquals('Another secret message', $inputText->getValue($instance), 'Secret::$inputText was not (properly) set.');
		$this->assertEquals(Secret::ENCRYPTED, $inputType->getValue($instance), 'Secret::$inputType was not (properly) set.');
		$this->assertEquals(str_repeat("\x1", 32), $masterKey->getValue($instance), 'Secret::$masterKey was not (properly) set.');

		// Text, key and type (plaintext)
		$instance = new Secret('dummy', str_repeat('02', 32), Secret::PLAINTEXT);
		$this->assertEquals(Secret::PLAINTEXT, $inputType->getValue($instance), 'Secret::$inputType was not (properly) set.');
		$this->assertEquals(str_repeat("\x2", 32), $masterKey->getValue($instance), 'Secret::$masterKey was not (properly) set.');

		// Text, key and type (encrypted)
		$instance = new Secret('dummy', str_repeat('03', 32), Secret::ENCRYPTED);
		$this->assertEquals(Secret::ENCRYPTED, $inputType->getValue($instance), 'Secret::$inputType was not (properly) set.');

		// Text and type, no key
		$instance = new Secret('dummy', null, Secret::PLAINTEXT);
		$this->assertEquals(Secret::PLAINTEXT, $inputType->getValue($instance), 'Secret::$inputType was not (properly) set.');
	}

	/**
	 * getRandomBytes() tests
	 */
	public function testGetRandomBytes()
	{
		$test = false;
		try { Secret::getRandomBytes('1'); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::getRandomBytes() accepts non-integer lenghts.');

		$test = false;
		try { Secret::getRandomBytes(0); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::getRandomBytes() accepts zero lengths.');

		$test = false;
		try { Secret::getRandomBytes(-1); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::getRandomBytes() accepts negative lengths.');

		try
		{
			foreach (array(16, 32, 48) as $expectedLength)
			{
				// Default output type: hex-encoded
				$receivedLength = $this->strlen(Secret::getRandomBytes($expectedLength));
				$this->assertEquals($expectedLength * 2, $receivedLength, 'Secret::getRandomBytes() returned '.$receivedLength.' characters, but '.($expectedLength * 2).' were expected.');
				$receivedLength = $this->strlen(Secret::getRandomBytes($expectedLength, true));
				$this->assertEquals($expectedLength, $receivedLength, 'Secret::getRandomBytes() returned '.$receivedLength.' bytes, but '.$expectedLength.' were expected.');
			}
		}
		catch (RuntimeException $e)
		{
			$this->markTestIncomplete('No reliable PRNG is available.');
		}
	}

	/**
	 * getKey() with pre-set key tests
	 *
	 * @depends	testConstructValidUsage
	 */
	public function testGetKeyWithKey()
	{
		$instance = new Secret('dummy', str_repeat('03', 32));
		$this->assertEquals(str_repeat('03', 32), $instance->getKey(), 'Secret::getKey() returned a wrong key.');
		$instance = new Secret('dummy', str_repeat('04', 32));
		$this->assertEquals(str_repeat('04', 32), $instance->getKey(), 'Secret::getKey() returned a wrong key.');
	}

	/**
	 * getKey() with no pre-set key tests
	 *
	 * @depends	testConstructValidUsage
	 * @depends	testGetRandomBytes
	 */
	public function testGetKeyNoKey()
	{
		$instance = new Secret('dummy');
		$key = $instance->getKey();
		$this->assertEquals(64, $this->strlen($key), 'Secret::getKey() returned a wrong key.');
		// Make sure the generated key was retained
		$this->assertEquals($key, $instance->getKey(), 'Secret::getKey() does not retain self-generated keys.');
	}

	/**
	 * HMAC-SHA-2 tests
	 *
	 * Runs HMAC-SHA-2 test vectors, specified by RFC 4231.
	 *	http://www.ietf.org/rfc/rfc4231.txt
	 *
	 * @coversNothing
	 */
	public function testHMACSHA2()
	{
		// HMAC-SHA-2 tests
		// Test case 1
		$key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
		$data = "Hi There";

		$this->assertEquals(
			'896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22',
			hash_hmac('sha224', $data, $key, false),
			'HMAC SHA-224 test vector 1 failed!'
		);
		$this->assertEquals(
			'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
			hash_hmac('sha256', $data, $key, false),
			'HMAC SHA-256 test vector 1 failed!'
		);
		$this->assertEquals(
			'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
			hash_hmac('sha384', $data, $key, false),
			'HMAC SHA-384 test vector 1 failed!'
		);
		$this->assertEquals(
			'87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
			hash_hmac('sha512', $data, $key, false),
			'HMAC SHA-512 test vector 1 failed!'
		);

		// Test case 2: Test with a key shorter  than the length of the HMAC output
		$key = "\x4a\x65\x66\x65";
		$data = "what do ya want for nothing?";

		$this->assertEquals(
			'a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44',
			hash_hmac('sha224', $data, $key, false),
			'HMAC SHA-224 test vector 2 failed!'
		);
		$this->assertEquals(
			'5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
			hash_hmac('sha256', $data, $key, false),
			'HMAC SHA-256 test vector 2 failed!'
		);
		$this->assertEquals(
			'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
			hash_hmac('sha384', $data, $key, false),
			'HMAC SHA-384 test vector 2 failed!'
		);
		$this->assertEquals(
			'164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
			hash_hmac('sha512', $data, $key, false),
			'HMAC SHA-512 test vector 2 failed!'
		);

		// Test case 3: Test with a combined length of key and data that is larger than 64 bytes (=block-size of SHA-224 and SHA-256)
		$key = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
		$data = "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd";

		$this->assertEquals(
			'7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea',
			hash_hmac('sha224', $data, $key, false),
			'HMAC SHA-224 test vector 3 failed!'
		);
		$this->assertEquals(
			'773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
			hash_hmac('sha256', $data, $key, false),
			'HMAC SHA-256 test vector 3 failed!'
		);
		$this->assertEquals(
			'88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27',
			hash_hmac('sha384', $data, $key, false),
			'HMAC SHA-384 test vector 3 failed!'
		);
		$this->assertEquals(
			'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
			hash_hmac('sha512', $data, $key, false),
			'HMAC SHA-512 test vector 3 failed!'
		);

		// Test case 4: Test with combined length of key and data that is larger than 64 bytes (= block-size of SHA-224 and SHA-256)
		$key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";
		$data = "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd";

		$this->assertEquals(
			'6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a',
			hash_hmac('sha224', $data, $key, false),
			'HMAC SHA-224 test vector 4 failed!'
		);
		$this->assertEquals(
			'82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
			hash_hmac('sha256', $data, $key, false),
			'HMAC SHA-256 test vector 4 failed!'
		);
		$this->assertEquals(
			'3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb',
			hash_hmac('sha384', $data, $key, false),
			'HMAC SHA-384 test vector 4 failed!'
		);
		$this->assertEquals(
			'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
			hash_hmac('sha512', $data, $key, false),
			'HMAC SHA-512 test vector 4 failed!'
		);

		// Test case 5: Test with a truncation of output to 128 bits
		$key = "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
		$data = "Test With Truncation";

		$this->assertEquals(
			'0e2aea68a90c8d37c988bcdb9fca6fa8',
			substr(hash_hmac('sha224', $data, $key, false), 0, 32),
			'HMAC SHA-224 test vector 5 failed!'
		);
		$this->assertEquals(
			'a3b6167473100ee06e0c796c2955552b',
			substr(hash_hmac('sha256', $data, $key, false), 0, 32),
			'HMAC SHA-256 test vector 5 failed!'
		);
		$this->assertEquals(
			'3abf34c3503b2a23a46efc619baef897',
			substr(hash_hmac('sha384', $data, $key, false), 0, 32),
			'HMAC SHA-384 test vector 5 failed!'
		);
		$this->assertEquals(
			'415fad6271580a531d4179bc891d87a6',
			substr(hash_hmac('sha512', $data, $key, false), 0, 32),
			'HMAC SHA-512 test vector 5 failed!'
		);

		// Test case 6: Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512)
		$key = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
		$data = "Test Using Larger Than Block-Size Key - Hash Key First";

		$this->assertEquals(
			'95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e',
			hash_hmac('sha224', $data, $key, false),
			'HMAC SHA-224 test vector 6 failed!'
		);
		$this->assertEquals(
			'60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
			hash_hmac('sha256', $data, $key, false),
			'HMAC SHA-256 test vector 6 failed!'
		);
		$this->assertEquals(
			'4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952',
			hash_hmac('sha384', $data, $key, false),
			'HMAC SHA-384 test vector 6 failed!'
		);
		$this->assertEquals(
			'80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
			hash_hmac('sha512', $data, $key, false),
			'HMAC SHA-512 test vector 6 failed!'
		);

		// Test case 7: Test with a key and data that is larger than 128 bytes (= block-size of SHA-384 and SHA-512)
		$key = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
		$data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

		$this->assertEquals(
			'3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1',
			hash_hmac('sha224', $data, $key, false),
			'HMAC SHA-224 test vector 7 failed!'
		);
		$this->assertEquals(
			'9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
			hash_hmac('sha256', $data, $key, false),
			'HMAC SHA-256 test vector 7 failed!'
		);
		$this->assertEquals(
			'6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e',
			hash_hmac('sha384', $data, $key, false),
			'HMAC SHA-384 test vector 7 failed!'
		);
		$this->assertEquals(
			'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
			hash_hmac('sha512', $data, $key, false),
			'HMAC SHA-512 test vector 7 failed!'
		);
	}

	/**
	 * hkdf() tests
	 *
	 * Runs test vectors specified by RFC 5689, Appendix A.
	 *	https://tools.ietf.org/rfc/rfc5869.txt
	 *
	 * Because our implementation is a single method instead of being
	 * split into hkdf_extract() and hkdf_expand(), we cannot test for
	 * the PRK value. As long as the OKM is correct though, it's fine.
	 *
	 * @depends	testHMACSHA2
	 */
	public function testHKDF()
	{
		// A.1: Basic test case with SHA-256
		$this->assertEquals(
			"\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65",
			Secret::hkdf(
				"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
				'sha256',
				42,
				"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
				"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
			),
			'HKDF test vector 1 failed!'
		);
		// A.2: Test with SHA-256 and longer inputs/outputs
		$this->assertEquals(
			"\xb1\x1e\x39\x8d\xc8\x03\x27\xa1\xc8\xe7\xf7\x8c\x59\x6a\x49\x34\x4f\x01\x2e\xda\x2d\x4e\xfa\xd8\xa0\x50\xcc\x4c\x19\xaf\xa9\x7c\x59\x04\x5a\x99\xca\xc7\x82\x72\x71\xcb\x41\xc6\x5e\x59\x0e\x09\xda\x32\x75\x60\x0c\x2f\x09\xb8\x36\x77\x93\xa9\xac\xa3\xdb\x71\xcc\x30\xc5\x81\x79\xec\x3e\x87\xc1\x4c\x01\xd5\xc1\xf3\x43\x4f\x1d\x87",
			Secret::hkdf(
				"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
				'sha256',
				82,
				"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
				"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
			),
			'HKDF test vector 2 failed!'
		);
		// A.3: Test with SHA-256 and zero-length salt/info
		$this->assertEquals(
			"\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f\x71\x5f\x80\x2a\x06\x3c\x5a\x31\xb8\xa1\x1f\x5c\x5e\xe1\x87\x9e\xc3\x45\x4e\x5f\x3c\x73\x8d\x2d\x9d\x20\x13\x95\xfa\xa4\xb6\x1a\x96\xc8",
			Secret::hkdf(
				"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
				'sha256',
				42,
				'',
				null
			),
			'HKDF test vector 3 failed!'
		);
		// A.4: Basic test case with SHA-1
		$this->assertEquals(
			"\x08\x5a\x01\xea\x1b\x10\xf3\x69\x33\x06\x8b\x56\xef\xa5\xad\x81\xa4\xf1\x4b\x82\x2f\x5b\x09\x15\x68\xa9\xcd\xd4\xf1\x55\xfd\xa2\xc2\x2e\x42\x24\x78\xd3\x05\xf3\xf8\x96",
			Secret::hkdf(
				"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
				'sha1',
				42,
				"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
				"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
			),
			'HKDF test vector 4 failed!'
		);
		// A.5: Test with SHA-1 and longer inputs/output
		$this->assertEquals(
			"\x0b\xd7\x70\xa7\x4d\x11\x60\xf7\xc9\xf1\x2c\xd5\x91\x2a\x06\xeb\xff\x6a\xdc\xae\x89\x9d\x92\x19\x1f\xe4\x30\x56\x73\xba\x2f\xfe\x8f\xa3\xf1\xa4\xe5\xad\x79\xf3\xf3\x34\xb3\xb2\x02\xb2\x17\x3c\x48\x6e\xa3\x7c\xe3\xd3\x97\xed\x03\x4c\x7f\x9d\xfe\xb1\x5c\x5e\x92\x73\x36\xd0\x44\x1f\x4c\x43\x00\xe2\xcf\xf0\xd0\x90\x0b\x52\xd3\xb4",
			Secret::hkdf(
				"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
				'sha1',
				82,
				"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
				"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
			),
			'HKDF test vector 5 failed!'
		);
		// A.6: Test with SHA-1 and zero-length salt/info
		$this->assertEquals(
			"\x0a\xc1\xaf\x70\x02\xb3\xd7\x61\xd1\xe5\x52\x98\xda\x9d\x05\x06\xb9\xae\x52\x05\x72\x20\xa3\x06\xe0\x7b\x6b\x87\xe8\xdf\x21\xd0\xea\x00\x03\x3d\xe0\x39\x84\xd3\x49\x18",
			Secret::hkdf(
				"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
				'sha1',
				42,
				'',
				null
			),
			'HKDF test vector 6 failed!'
		);
		// A.7: Test with SHA-1, salt not provided (defaults to HashLen zero octets), zero-length info
		$this->assertEquals(
			"\x2c\x91\x11\x72\x04\xd7\x45\xf3\x50\x0d\x63\x6a\x62\xf6\x4f\x0a\xb3\xba\xe5\x48\xaa\x53\xd4\x23\xb0\xd1\xf2\x7e\xbb\xa6\xf5\xe5\x67\x3a\x08\x1d\x70\xcc\xe7\xac\xfc\x48",
			Secret::hkdf(
				"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
				'sha1',
				42,
				'',
				null
			),
			'HKDF test vector 7 failed!'
		);

		// Test default length, it must match the digest size
		$this->assertEquals(64, $this->strlen(Secret::hkdf('foobar', 'sha512')), 'Secret::hkdf() default output length does not match the size of the hash function output.');

		// Test maximum length (RFC5869 says that it must be up to 255 times the digest size)
		$this->assertEquals(8160, $this->strlen(Secret::hkdf('foobar', 'sha256', 32 * 255)), 'Secret::hkdf() cannot return OKM with a length of 255 times the hash function output.');

		// Invalid length
		$test = false;
		try { Secret::hkdf('foobar', 'whirlpool', 64 * 255 + 1); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::hkdf() accepts lengths larger than 255 times the hash function output.');

		// Invalid hash function
		$test = false;
		try { Secret::hkdf('foobar', '<nonExistentHashFunction>'); }
		catch (InvalidArgumentException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::hkdf() accepts unknown hash functions.');
	}

	/**
	 * authenticate() test
	 *
	 * @depends	testHMACSHA2
	 */
	public function testAuthenticate()
	{
		$instance = new Secret('plain-text');
		$reflection = new ReflectionClass($instance);
		$authenticate = $reflection->getMethod('authenticate');
		$authenticate->setAccessible(true);

		// Invalid length, shorter than the hash size
		$test = false;
		try { $authenticate->invoke($instance, 'shorter than 32 characters', 'hmacKey'); }
		catch (RuntimeException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::authenticate() accepts messages with invalid lengths.');

		// Invalid length, longer than the hash size, but not dividable by 4 (this is a Base64-validity check too)
		$test = false;
		try { $authenticate->invoke($instance, str_repeat('0', 33), 'hmacKey'); }
		catch (RuntimeException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::authenticate() accepts messages with invalid lengths.');

		// Valid length, but not valid Base64
		$test = false;
		try { $authenticate->invoke($instance, str_repeat('1', 31).'$', 'hmacKey'); }
		catch (RuntimeException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::authenticate() accepts invalid Base64 strings.');

		// Invalid key
		$test = false;
		try { $authenticate->invoke($instance, "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7", "\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a"); }
		catch (RuntimeException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::authenticate() failed to trigger an error for a HMAC with a wrong key.');

		// Invalid hash
		$test = false;
		try { $authenticate->invoke($instance, "\xa0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7", "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"); }
		catch (RuntimeException $e) { $test = true; }
		$this->assertTrue($test, 'Secret::authenticate() failed to trigger an error for a forged HMAC.');

		// Valid usage, should strip the Base64 encoding and HMAC after validating it
		$data = 'dummy string';
		$data = base64_encode(hash_hmac('sha256', $data, str_repeat('32', 32), true).$data);
		// ReflectionMethod is dumb and doesn't understand references
		$authenticate->invokeArgs($instance, array(&$data, str_repeat('32', 32)));
		$this->assertEquals($data, 'dummy string', 'Secret::authenticate() does not strip Base64 encoding and/or the HMAC message after validating them.');
	}

	/**
	 * AES-256-CTR tests
	 *
	 * Runs AES-256-CTR test vectors, as specified by NIST SP 800-38A, Appendix F.5.
	 *	http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
	 *
	 * @depends	testSelfConfiguration
	 * @runInSeparateProcess
	 */
	public function testAES256CTR()
	{
		// AES-256-CTR tests
		// All data matches for the encrypt, decrypt tests
		$vectorsKey = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
		$vectors = array(
			// Block #1
			1 => array(
				'iv' => "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
				'plainText' => "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
				'cipherText' => "\x60\x1e\xc3\x13\x77\x57\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2\x28"
			),
			// Block #2
			2 => array(
				'iv' => "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xff\x00",
				'plainText' => "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
				'cipherText' => "\xf4\x43\xe3\xca\x4d\x62\xb5\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5"
			),
			// Block #3
			3 => array(
				'iv' => "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xff\x01",
				'plainText' => "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef",
				'cipherText' => "\x2b\x09\x30\xda\xa2\x3d\xe9\x4c\xe8\x70\x17\xba\x2d\x84\x98\x8d"
			),
			// Block #4
			4 => array(
				'iv' => "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xff\x02",
				'plainText' => "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
				'cipherText' => "\xdf\xc9\xc5\x8d\xb6\x7a\xad\xa6\x13\xc2\xdd\x08\x45\x79\x41\xa6"
			),
		);

		$instance = new Secret('dummy');
		$reflection = new ReflectionClass($instance);

		if ($this->mcrypt)
		{
			$mcryptEncrypt = $reflection->getMethod('mcryptEncrypt');
			$mcryptDecrypt = $reflection->getMethod('mcryptDecrypt');
			$mcryptEncrypt->setAccessible(true);
			$mcryptDecrypt->setAccessible(true);
		}

		if ($this->openssl)
		{
			$opensslEncrypt = $reflection->getMethod('opensslEncrypt');
			$opensslDecrypt = $reflection->getMethod('opensslDecrypt');
			$opensslEncrypt->setAccessible(true);
			$opensslDecrypt->setAccessible(true);
		}

		foreach ($vectors as $block => $test)
		{
			if ($this->mcrypt)
			{
				$this->assertEquals(
					$test['cipherText'],
					$mcryptEncrypt->invoke($instance, $test['plainText'], $vectorsKey, $test['iv']),
					'AES-256-CTR test vector '.$block.' failed with Secret::mcryptEncrypt()!'
				);
				$this->assertEquals(
					$test['plainText'],
					$mcryptDecrypt->invoke($instance, $test['cipherText'], $vectorsKey, $test['iv']),
					'AES-256-CTR test vector '.$block.' failed with Secret::mcryptDecrypt()!'
				);
			}

			if ($this->openssl)
			{
				$this->assertEquals(
					$test['cipherText'],
					$opensslEncrypt->invoke($instance, $test['plainText'], $vectorsKey, $test['iv']),
					'AES-256-CTR test vector '.$block.' failed with Secret::opensslEncrypt()!'
				);
				$this->assertEquals(
					$test['plainText'],
					$opensslDecrypt->invoke($instance, $test['cipherText'], $vectorsKey, $test['iv']),
					'AES-256-CTR test vector '.$block.' failed with Secret::opensslDecrypt()!'
				);
			}
		}
	}

	/**
	 * getPlainText(), getCipherText(), overall usage tests
	 *
	 * @depends	testConstructValidUsage
	 * @depends	testGetKeyWithKey
	 * @depends	testGetKeyNoKey
	 * @depends	testAuthenticate
	 * @depends	testHKDF
	 * @depends	testAES256CTR
	 * @runInSeparateProcess
	 */
	public function testUsage()
	{
		try
		{
			// Test encryption
			$instance = new Secret('Test message');
			$cipherText = $instance->getCipherText();
			$this->assertEquals(1, preg_match('#^[A-Za-z0-9+=/]{80}$#', $cipherText), 'Secret::getCipherText() produced an unexpected result.');
			// A 128-bit key should be automatically generated
			$reflection = new ReflectionClass($instance);
			$key = $reflection->getProperty('masterKey');
			$key->setAccessible(true);
			$this->assertEquals(32, $this->strlen($key->getValue($instance)), 'Secret::getCipherText() does not (properly) generate keys.');

			// A new getCipherText() call shouldn't produce the same output
			$this->assertNotEquals($cipherText, $instance->getCipherText(), 'Secret::getCipherText() produced the same cipherText in a subsequent call.');

			// Now decrypt with the key we've got
			$instance = new Secret($cipherText, bin2hex($key->getValue($instance)));
			$this->assertEquals('Test message', $instance->getPlainText(), 'Secret::getPlainText() does not properly decrypt data.');

			// Again, any getCipherText() call should encrypt anew, with a new IV
			$cipherTextNew = $instance->getCipherText();
			$this->assertNotEquals($cipherText, $cipherTextNew, 'Secret::getCipherText() produced the same cipherText that was previously decrypted.');
			// We'll check the IVs as well
			$this->assertNotEquals(
				$this->substr(base64_decode($cipherText, true), 32, 16),
				$this->substr(base64_decode($cipherTextNew, true), 32, 16),
				'Secret::getCipherText() reuses IVs!'
			);

			// getCipherText() shouldn't generate keys if we have provided them
			$instance = new Secret('Another test', str_repeat('0', 64), Secret::PLAINTEXT);
			$instance->getCipherText(); // If the next assertion fails, this is the problem
			$this->assertEquals(str_repeat('0', 64), $instance->getKey(), 'Secret::getCipherText() generates keys even when they were provided.');

			// Our plain-text should be returned too
			$this->assertEquals('Another test', $instance->getPlainText());
		}
		catch (RuntimeException $e)
		{
			$this->markTestIncomplete('PRNG error');
		}
	}

	/**
	 * Key derivation test
	 *
	 * @depends	testUsage
	 * @depends	testHKDF
	 */
	public function testKeyDerivation()
	{
		$instance = new Secret('Test', str_repeat('af', 32), Secret::PLAINTEXT);
		$cipherText = $instance->getCipherText();
		list(, $hmacKey) = str_split(Secret::hkdf(str_repeat("\xaf", 32), 'sha512', 64, 'aes-256-ctr-hmac-sha256'), 32);
		$this->assertEquals(
			hash_hmac('sha256', $this->substr(base64_decode($cipherText), 32), $hmacKey, true),
			$this->substr(base64_decode($cipherText), 0, 32),
			'Secret::getCipherText() did not properly derive keys.'
		);
	}

	/**
	 * Serialization protection test
	 *
	 * @depends	testConstructValidUsage
	 * @expectedException	RuntimeException
	 */
	public function testSerialization()
	{
		$instance = new Secret('Serialize this');
		serialize($instance);
	}

}