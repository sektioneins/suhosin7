<?php 
if (php_sapi_name()=='cli') { 
	print 'skip - SAPI == cli'; 
} else {
if(!extension_loaded("suhosin7")) 
	print "skip - SUHOSIN7 extension not available"; 
}
?>
