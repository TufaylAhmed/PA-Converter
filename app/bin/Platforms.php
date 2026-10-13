<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/database.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $dusage_version     = (string) (isset($_GET['dusage_version'])  ? $_GET['dusage_version'] : '');
        break;
    case 'POST':
        $dusage_version     = (string) (isset($_POST['dusage_version'])  ? $_POST['dusage_version'] : '');
        break;
    default:
        $dusage_version     = (string) (isset($_POST['dusage_version'])  ? $_POST['dusage_version'] : '');
        break;
}

$dusage_version = $pandb->real_escape_string($dusage_version);

if($dusage_version == ""){
    $dusage_version = "8.0";
}

$getAll=$pandb->query("SELECT p.id, p.name, p.icon FROM platforms p, panos_capacity pc 
                        WHERE p.id = pc.platform_id AND pc.panos = '$dusage_version' ORDER BY name ASC;");

//echo "SELECT p.id, p.name, p.icon FROM platforms p, panos_capacity pc
//                        WHERE p.id = pc.platform_id AND pc.panos = '$dusage_version' ORDER BY name ASC";

$count=$getAll->num_rows;
if ($count>0){
	while ($data=$getAll->fetch_object()){
		$myData[]=$data;
	}	
}
else {
	$myData="";
}
echo '{"total":"'.$count.'","platforms":'.json_encode($myData).'}';
?>