--TEST--
session user handler recursive crash - issue suhosin#60
--SKIPIF--
<?php include "../skipifcli.inc"; ?>
--ENV--
return <<<END
HTTP_USER_AGENT=test
END;
--INI--
suhosin.session.encrypt=On
suhosin.session.cryptkey=D3F4UL7
suhosin.session.cryptua=On
suhosin.session.cryptdocroot=Off
suhosin.session.cryptraddr=0
suhosin.session.checkraddr=0
--FILE--
<?php
$foo = "";

class MySessionHandlerA implements SessionHandlerInterface
{
	public function close() {return TRUE;}
	public function destroy($session_id) {return TRUE;}
	public function gc($maxlifetime) {return TRUE;}
	public function open($save_path, $name) { global $foo; $foo .= "A\n"; return TRUE;}
	public function read($session_id ) {return TRUE;}
	public function write($session_id, $session_data) {return TRUE;}
}

session_set_save_handler(new MySessionHandlerA(), true);
session_start();
session_destroy();

//

class MySessionHandlerB extends MySessionHandlerA
{
	public function open($save_path, $name) { global $foo; $foo .= "B\n"; return TRUE;}
}

session_set_save_handler(new MySessionHandlerB(), true);
session_start();
session_destroy();

//

class MySessionHandlerC extends MySessionHandlerA
{
	public function open($save_path, $name) { global $foo; $foo .= "C\n"; return TRUE;}
}

session_set_save_handler(new MySessionHandlerC(), true);
session_start();
session_destroy();


echo $foo;
--EXPECTF--
A
B
C
