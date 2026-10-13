<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);

# Access Control
if(!checkProjectRights($project,'update')){
    echo '{"total":"0","schedules":[]}';
    return;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);

if ($action=="get"){
	if ($type=="schedules"){
    	$query=generate_query("objects");
//		$getAll=$projectdb->query("SELECT id as idx,id,name,vsys,devicegroup,source,xml, 'schedules' as table_name  "
//                        . "FROM schedules $query "
//                        . "UNION SELECT id as idx,id,name,'shared' as vsys,devicegroup,source,xml, 'shared_schedules' as table_name  "
//                        . "FROM shared_schedules $query ;");
		$getAll=$projectdb->query("SELECT id as idx,id,name,vsys,devicegroup,source,xml, 'schedules' as table_name  "
                        . "FROM schedules $query ;");
		
                $count=$getAll->num_rows;
//		$getLimit=$projectdb->query("SELECT id as idx,id,name,vsys,devicegroup,source,xml, 'schedules' as table_name  "
//                        . "FROM schedules $query "
//                        . "UNION SELECT id as idx,id,name,'shared' as vsys,devicegroup,source,xml, 'shared_schedules' as table_name  "
//                        . "FROM shared_schedules $query ORDER BY name ASC LIMIT $start, $limit;");	
                $getLimit=$projectdb->query("SELECT id as idx,id,name,vsys,devicegroup,source,xml, 'schedules' as table_name  "
                        . "FROM schedules $query ORDER BY name ASC LIMIT $start, $limit;");	
		$x=0;
		if ($count>0){
			while ($data=$getLimit->fetch_object()){
				$data->id=$x++;
				$myData[]=$data;
			}
		}
		if ($count==0){$myData="";}
		echo '{"total":"'.$count.'","schedules":'.json_encode($myData).'}';
    }
    elseif ($type=="schedules_all"){		
		$query=generate_query("objects");
		//$getLimit=$projectdb->query("SELECT id as idx, name, id, 'service.gif' as type,'services' as table_name "
                //        . "FROM services $query "
                //        . "UNION SELECT id as idx, name, id, 'shared_services.gif' as type,'shared_services' as table_name "
                //        . "FROM shared_services $query;");
                $getLimit=$projectdb->query("SELECT id as idx, name, id, if (vsys = 'shared', 'shared_schedules.png', 'schedules.png') AS type, 'schedules' as table_name "
                        . "FROM schedules $query ;");
		$count=$getLimit->num_rows;
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