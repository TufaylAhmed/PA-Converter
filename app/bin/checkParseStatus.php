<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//require_once('./Authentication.php');
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

$jobid = "";
$project = "";

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
	case 'GET':
		$project = (string) (isset($_GET['project']) ? $_GET['project'] : '');
		$jobid   = (string) (isset($_GET['jobid'])   ? $_GET['jobid'] : '');
		break;
	case 'POST':
		$project = (string) (isset($_POST['project']) ? $_POST['project'] : '');
		break;

	default:
		$project = (string) (isset($_POST['project']) ? $_POST['project'] : '');
		break;
}
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);

// Validations
if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
    http_response_code(401);
    header("HTTP/1.1 401 Unauthorized");
    header("Location: /401");
    exit;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$jobid = $projectdb->real_escape_string($jobid);

//$result=$projectdb->query("SELECT percentage,message FROM project_status WHERE project='$project' AND id=$jobid;");
$result=$projectdb->query("SELECT percentage,message FROM project_status WHERE id='$jobid';");
if ($result->num_rows>0){
	$row=$result->fetch_assoc();
	echo '{"percentage":"'.$row['percentage'].'","message":"'.$row['message'].'"}';
}
else{
	echo '{"percentage":"0","message":"Initializing..."}';
}
?>