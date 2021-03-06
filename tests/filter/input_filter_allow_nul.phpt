--TEST--
input filter: allow NUL bytes
--INI--
suhosin.log.syslog=0
suhosin.log.sapi=0
suhosin.log.stdout=255
suhosin.log.script=0
suhosin.request.disallow_nul=0
suhosin.get.disallow_nul=0
suhosin.post.disallow_nul=0
suhosin.cookie.disallow_nul=0
magic_quotes_gpc=Off
--SKIPIF--
<?php include('../skipif.inc'); ?>
--COOKIE--
var1=xx%001;var2=2;var3=xx%003;var4=4;
--GET--
var1=xx%001&var2=2&var3=xx%003&var4=4&
--POST--
var1=xx%001&var2=2&var3=xx%003&var4=4&
--FILE--
<?php
var_dump($_GET);
var_dump($_POST);
var_dump($_COOKIE);
?>
--EXPECTF--
array(4) {
  ["var1"]=>
  string(4) "xx 1"
  ["var2"]=>
  string(1) "2"
  ["var3"]=>
  string(4) "xx 3"
  ["var4"]=>
  string(1) "4"
}
array(4) {
  ["var1"]=>
  string(4) "xx 1"
  ["var2"]=>
  string(1) "2"
  ["var3"]=>
  string(4) "xx 3"
  ["var4"]=>
  string(1) "4"
}
array(4) {
  ["var1"]=>
  string(4) "xx 1"
  ["var2"]=>
  string(1) "2"
  ["var3"]=>
  string(4) "xx 3"
  ["var4"]=>
  string(1) "4"
}
