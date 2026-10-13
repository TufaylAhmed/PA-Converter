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
require_once INC_ROOT.'/libs/common/bestpractices/remediation.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':

        break;
    case 'POST':
        $project    = (string)  (isset($_POST['project'])    ? $_POST['project'] : '');
        $bpcheks    = (string)  (isset($_POST['rules'])      ? $_POST['rules'] : 'all');
        $topic      = (string)  (isset($_POST['topic'])      ? $_POST['topic'] : '');
        $mode       = (string)  (isset($_POST['mode'])       ? $_POST['mode'] : 'all');
        $type       = (string)  (isset($_POST['type'])       ? $_POST['type'] : 'fw');
        $params=[
            "bpcheks"=>$bpcheks,
            "topic"=>$topic,
            "mode"=>$mode,
            "type"=>$type
        ];
        $message = remediate($project,$bpcheks,$params);
        echo json_encode(array('success' => $message['code'], 'msg' => [$message['msg']]));
        break;
    default:
        break;
}

function remediate($project,$bpchecks,$params){
$message=array();

    global $projectdb;

    if(!checkProjectRights($project,'update')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to see this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);
    $container=array();
    $bpchecks_container=array();
    $getSource=$projectdb->query("SELECT id,ispanorama FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
    if ($getSource->num_rows==1){
        $getSourceData=$getSource->fetch_assoc();
        $source=$getSourceData['id'];
        $ispanorama=$getSourceData['ispanorama'];
        $version=calcVersion($source);
    }
    else{
        $message['code']=false;
        return $message["msg"]="There is NO Base-Config selected.";
    }
    $bpcheks=$params['bpcheks'];


    if ($bpcheks=="all"){


    }
    else{

        $getAllTopics=$projectdb->query("SELECT topic_id FROM bpat_bpcheck WHERE check_id in ($bpcheks) AND (result='fail' OR result='') group by topic_id;");
        if ($getAllTopics->num_rows>0){
            while($getAllTopicsData=$getAllTopics->fetch_assoc()){
                $topic_id=$getAllTopicsData['topic_id'];
                $getTopic=$projectdb->query("SELECT * FROM bpat_topic WHERE id='$topic_id';");
                if ($getTopic->num_rows==1){
                    $getTopicData=$getTopic->fetch_assoc();
                    $template=$getTopicData['template'];
                    $template_name=$getTopicData['template_name'];
                    $vsys=$getTopicData['vsys'];
                    switch ($getTopicData['subtype']){
                        case "device_dynamic_updates":
                        case "template_dynamic_updates":
                        case "dynamic_updates":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_wildfire_settings":
                        case "wildfire":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_management_interface_settings":
                        case "management_interface_settings":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_services_settings":
                        case "services":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_session_settings":
                        case "session":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_authentication_settings":
                        case "authentication_settings":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_content_id_settings":
                        case "content_id":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_general_settings":
                        case "general_settings":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_logging_reporting_settings":
                        case "logging_reporting_settings":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_minimum_password_complexity_settings":
                        case "minimum_password_complexity":
                            remediate_mgt_config($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "panorama_settings":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_telemetry_settings":
                        case "telemetry":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                        case "device_administrators":
                        case "administrators":
                            remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version);
                            break;
                    }


                }
            }
        }

    }







$message['code']=true;
$message["msg"]="Done.";
return $message;

}
