<?php
# Copyright (c) 2014 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/shared.php';

//require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/database.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

if(!accessControl("any", ['user.admin', 'server.admin'])){
    $message = array();
    $message['code'] = false;
    $message['msg'] = 'Your account does not have server listing rights';
    return $message;
}
global $pandbRBAC;


if (isset($_POST['action'])) {
    if ($_POST['action']=="prune")
    $pandbRBAC->query("DELETE FROM auditlogs WHERE datetime < now() - interval 30 day");
    echo json_encode(array("success"=>true));
    exit(0);
}


$start              = $pandbRBAC->real_escape_string((integer) (isset($_GET['start'])  ? $_GET['start'] : ''));
$limit              = $pandbRBAC->real_escape_string((integer) (isset($_GET['limit'])  ? $_GET['limit'] : ''));
$log_search_message =(string) $_GET['log_search_message'];
$log_search_action  =(string) $_GET['log_search_action'];

$addQuery=array();
$data=array();
$addQueryTotal="";
if ($log_search_action!=""){
    $log_search_action=$pandbRBAC->real_escape_string($log_search_action);
    $addQuery[]=" action like '%$log_search_action%' ";
}
if ($log_search_message!=""){
    $log_search_message=$pandbRBAC->real_escape_string($log_search_message);
    $addQuery[]=" message like '%$log_search_message%' ";
}

if (count($addQuery)>0){
    $addQueryTotal=" WHERE ".implode(" AND ",$addQuery);
}

if ($start!=''){
    $addLimit=" LIMIT $start,$limit ";
}

$getLogs=$pandbRBAC->query("SELECT * FROM auditlogs $addQueryTotal ORDER BY id DESC;");
$total=$getLogs->num_rows;
$getLogs=$pandbRBAC->query("SELECT * FROM auditlogs $addQueryTotal ORDER BY id DESC $addLimit;");
if ($getLogs->num_rows>0){
    while($getLogsData=$getLogs->fetch_assoc()){
        $data[]=$getLogsData;
    }
}

echo json_encode(array('total' => count($data), 'audit' => $data));

