<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/Authentication.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
	case 'GET':
		$action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
		break;
	case 'POST':
		$action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
		break;

	default:
		$action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
		break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /

if ($action=="get"){
	$ProjectFolders=USERSPACE_PATH."/Templates";
	$files1 = scandir($ProjectFolders);
	$files2= count($files1)-2;
	$i=0;
	echo '{"total":"'.$files2.'","configs":[';

	foreach ($files1 as $key => $value){
		$i++;
		if ( ($value == ".") or ($value== "..") ){}
		else {
			echo '{"name":"'.$value.'"}';
			if ($i < count($files1)){echo ",";}
		} 
	}

	echo ']}';
}
?>