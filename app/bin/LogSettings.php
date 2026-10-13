<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once '../libs/shared.php';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
	case 'GET':
		$action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
		$type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
		$project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
		$start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
		$limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
		break;
	case 'POST':
		$action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
		$type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
		$project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
		$start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
		$limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
		break;

	default:
		$action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
		$type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
		$project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
		$start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
		$limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
		break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//
//$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
//$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);

//$project="test";

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);

//$type="filter_duplicated_name";
//$action="get";

if ($action=="get"){
    if ($type=="all_forwarding_profiles"){
        $query=generate_query("objects");
        $getAll=$projectdb->query("SELECT name,name_ext,used,id,checkit,devicegroup,vsys,type,ipaddress,cidr,description,fqdn,v4,v6,vtype,source,tag,'address' as table_name  "
                . "FROM address $query ;");
        $count=$getAll->num_rows;
        $getLimit=$projectdb->query("SELECT name,name_ext,used,id,checkit,devicegroup,vsys,type,ipaddress,cidr,description,fqdn,v4,v6,vtype,source,tag,'address' as table_name "
                . "FROM address $query ORDER BY name ASC LIMIT $start, $limit;");
        $x=0;
        while ($data=$getLimit->fetch_object()){
                $data->id=$x++;
                $myData[]=$data;
        }
        if ($count==0){$myData="";}
        echo '{"total":"'.$count.'","address":'.json_encode($myData).'}';
    }
}
?>