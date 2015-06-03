

Simple Encryption for PHP
=========================

A PHP library for symmetric encryption, making it easy, safe and accessible for everybody.

**EXPERIMENTAL! DO NOT use this library until the 1.0 version is tagged!**

[![Build Status](https://travis-ci.org/narfbg/SimpleEncryption.svg?branch=master)](https://travis-ci.org/narfbg/SimpleEncryption)

Introduction
------------

Everybody wants to do encryption, for one reason or another. The problem is, very few people know enough about cryptography to implement it properly. It might seem easy, or trivial, but for your own good, trust me when I say this: IT'S NOT!

Most people don't even know the difference between encryption and hashing, and there's a good reason why cryptography is a science subject in its own right. Being a good, experienced, even exceptional developer is often not enough. MCrypt alone is not enough.

That is why cryptography experts will tell you to never write your own crypto code and always to use well-vetted, time-tested libraries that will *make all the choices for you*. Taking a choice away from you might not sound good at first, but really, it is.  
There are so many choices to be made and so many wrong ones in particular, that chances are, you're not even aware of all of them, let alone qualified to make them.

In the PHP world, there's another, rather large problem - there are few cryptography libraries that do everything right *(and a lot more that don't)*, and I've never seen one that is easy to use.  
Even with the good ones, it's really easy to screw up.

*SimpleEncryption* is an attempt to solve all of this.  

*Note: The library is well-covered with unit tests, but not audited yet. I'm hoping that crypto experts within the OSS community will do the latter.*

### Technical details

If you must know, this is what *SimpleEncryption* utilizes:

- AES-256-CTR for encryption (yes, the IV is always random)
- HMAC SHA-256 for authentication (encrypt, then HMAC; safe from timing attacks)
- HKDF for key derivation (one key for encryption, one for authentication)

Requirements
------------

- PHP 5.4
- OpenSSL extension

Installation and loading
------------------------

TODO: Link to downloads & packagist, once published.

Then of course, you'll need to link to the library in your own code, either by using the [PSR-4](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md)-compliant autoloader, or manually, like this:

	require_once('path/to/SimpleEncryption/src/Secret.php');

And finally, import it into your own namespace:

	use \Narf\SimpleEncryption\Secret;

Usage
-----

### Encrypting data

All you need to to is to just create a `Secret` object with your confidential data and then call its `getCipherText()` method. The library will automatically create an encryption key, which you can get via the `getKey()` method:

	$mySecret = new Secret('My secret message!');

	$encryptedData = $mySecret->getCipherText();
	$key = $mySecret->getKey();

### Decrypting data

Decrypting data is just as easy, simply create a `Secret` object with the previously encrypted data and the encryption key, then call the `getPlainText()` method to do the actual decryption:

	$mySecret = new Secret($encryptedData, $key);
	echo $mySecret->getPlainText();

### Creating and using your own keys

While having different encryption keys for each piece of encrypted data is always the safe bet, this is not always practical. Therefore, sometimes you'll need to pass your own key to the `Secret` class before encrypting data.

Before showing how to actually use your own keys however, it's important to note that an encryption key MUST NOT be just a password, nor the output of a hashing function. It MUST NOT be anything that is readable as standard ASCII. If you need to create your own key, use the `Secret::getRandomBytes()` method:

	$yourKey = Secret::getRandomBytes(32);

(the length has to be 32 bytes, or 64 when hex-encoded, but the library will not let you pass a key with a different size anyway)

Now, after you have a key, in order to encrypt data with it, you'll have to pass it to the `Secret` class *before* encryption.  
However, since creating a `Secret` object with a key would usually mean that you're providing it with already encrypted data, you'll have to manually tell it what the input type is.

This is done by passing one of `Secret::PLAINTEXT` or `Secret::ENCRYPTED` as the third parameter:

	$yourSecret = new Secret('Your secret message', $yourKey, Secret::PLAINTEXT);
	$encryptedData = $yourSecret->getCipherText();

For convenience, `Secret::ENCRYPTED` is also accepted, although it's not functionally required:

	$yourSecret = new Secret($encryptedData, $yourKey, Secret::ENCRYPTED);
	$plaintextData = $yourSecret->getPlainText();

### Error handling

In case of an error, such as missing a CSPRNG source or failed authentication, the Secret class will throw a `RuntimeException`.  
Therefore, in order to avoid leaking sensitive data, you'll need to catch such exceptions:

	try
	{
		$secret = new Secret($encryptedData, $encryptionKey);
		$plainText = $secret->getCipherText();
	}
	catch (\RuntimeException $e)
	{
		// Handle the error
	}

Class reference
---------------

- **void __construct($inputText[, $masterKey = null[, $inputType = null]])**  
  **$inputText**: The input data  
  **$masterKey**: Hex-encoded encryption key  
  **$inputType**: One of `null`, `Secret::PLAINTEXT` or `Secret::ENCRYPTED`  

  If `$inputType` is not provided, then providing an encryption key means that `$inputText` is encrypted data, and vice-versa, not providing a key means that `$inputText` is a plain-text.

- **string getCipherText()**

  Encrypts (anew) and returns the data, generating a key in the process, if necessary.

- **string getPlainText()**

  Decrypts (if necessary) and returns the plain-text version of the secret data.

- **string getKey()**

  Returns the hex-encoded encryption key, regardless if it was pre-set or if it is a newly generated one.

- **string static getRandomBytes($length[, $rawOutput = false])**  
  **$length**: Output length (binary size)
  **$rawOutput**: Whether to return raw binary data or a hex-encoded string

  Returns a stream of randomly generated bytes, suitable for creating encryption keys.

- **string static hkdf($key, $digest[, $length = null[, info = ''[, $salt = null]]])**  
  **$key**: Input key material (binary)  
  **$digest**: HMAC digest (algorithm)  
  **$length**: Output length  
  **$info**: Application/context specific information  
  **$salt**: Salt  

  An [RFC 5869](https://tools.ietf.org/rfc/rfc5869.txt)-compatible HKDF implementation. Used internally by the library and exposed because there's no reason not to. If you don't know what it is, you don't need it.
