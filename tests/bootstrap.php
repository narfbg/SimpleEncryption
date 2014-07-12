<?php
spl_autoload_register(function($class) {
	$namespace = 'Narf\\SimpleEncryption\\';
	$nsLength = strlen($namespace);

	if (strncmp($namespace, $class, $nsLength) !== 0)
	{
		// Not our namespace, jump to next autoloader
		return;
	}

	$path = '/../src/'.substr(str_replace('\\', DIRECTORY_SEPARATOR, $class), $nsLength).'.php';
	file_exists(__DIR__.$path) && require_once(__DIR__.$path);
});