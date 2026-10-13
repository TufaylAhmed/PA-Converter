<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';
//Dependencies
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/bestpractices/bpat.php';


$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}


//$_SERVER['REQUEST_METHOD']="GET";


switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':

        break;
    case 'POST':
        $project        = (string)  (isset($_POST['project'])       ? $_POST['project'] : '');
        $rules          = (string)  (isset($_POST['rules'])         ? $_POST['rules'] : '');
        $applyto        = (string)  (isset($_POST['applyto'])       ? $_POST['applyto'] : 'all');
        $log_start      = (string)  (isset($_POST['log_start'])     ? $_POST['log_start'] : 'off');
        $dsri           = (string)  (isset($_POST['dsri'])          ? $_POST['dsri'] : 'off');
        $params=[
            "applyto"=>$applyto,
            "dsri"=>$dsri,
            "log_start"=>$log_start
        ];
        $message = remediate_rules($project,$rules,$params);
        echo json_encode(array('success' => $message['code'], 'msg' => [$message['msg']]));
        break;
    default:
        $project     = (string)  (isset($_POST['project'])    ? $_POST['project'] : '');
        break;
}

function remediate_rules($project,$rules,ARRAY $params){
    global $projectdb;
    if(!checkProjectRights($project,'update')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to modify this project contents';
        echo json_encode($message);
        return $message;
    }

    $projectdb = selectDatabase($project);
    $getSource=$projectdb->query("SELECT id FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
    if ($getSource->num_rows==1){
        $getSourceData=$getSource->fetch_assoc();
        $source=$getSourceData['id'];
    }
    else{
        $message['code']=false;
        $message["msg"]="There is NO Base-Config selected.";
        return $message;
    }
    take_snapshot_last($project);
    if ($params['dsri']==true){
        if ($params['applyto']=="all"){
            $projectdb->query("UPDATE security_rules SET dsri=0 WHERE source='$source';");
            $projectdb->query("UPDATE bpat_bpcheck SET result='pass' WHERE name='Disable Server Response Inspection';");
        }
        else{
            if ($rules!=""){
                $projectdb->query("UPDATE security_rules SET dsri=0 WHERE source='$source' AND id IN ($rules);");
                $projectdb->query("UPDATE bpat_bpcheck SET result='pass' WHERE name='Disable Server Response Inspection' AND rule_lid IN ($rules);");
            }
        }
    }

    if ($params['log_start']==true){
        if ($params['applyto']=="all"){
            $projectdb->query("UPDATE security_rules SET log_start=0 WHERE source='$source';");
            $projectdb->query("UPDATE bpat_bpcheck SET result='pass' WHERE name='Not Logging at Start of Session';");
        }
        else{
            if ($rules!=""){
                $projectdb->query("UPDATE security_rules SET log_start=0 WHERE source='$source' AND id IN ($rules);");
                $projectdb->query("UPDATE bpat_bpcheck SET result='pass' WHERE name='Not Logging at Start of Session' AND rule_lid IN ($rules);");
            }
        }
    }
    $message['code']=true;
    $message["msg"]="Done.";
    return $message;
}
