--TEST--
Testing: suhosin.executor.func.blacklist=max
--SKIPIF--
<?php include "../skipifnotcli.inc"; ?>
--INI--
suhosin.log.sapi=64
suhosin.executor.func.blacklist=max
--FILE--
<?php
	echo 'a';
	abs(1);
	echo 'b';
	max(1,2);
	echo 'c';
	abs(1);
	echo 'd';
?>
--EXPECTF--
abALERT - function blacklisted: max() (attacker 'REMOTE_ADDR not set', file '%s', line 5)

Warning: max() has been disabled for security reasons in %s on line 5
