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

require_once INC_ROOT.'/libs/database.php';

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
        $project     = $pandb->real_escape_string((string)     (isset($_GET['project'])    ? $_GET['project'] : ''));
        $start       = $pandb->real_escape_string((string)     (isset($_GET['start'])      ? $_GET['start'] : ''));
        $limit       = $pandb->real_escape_string((string)     (isset($_GET['limit'])      ? $_GET['limit'] : ''));
        $message = list_bpat_rules($project,$start,$limit);
        if($message['code']) {
            echo json_encode(array('total' => $message['total'], 'rules' => $message['msg']));
        }
        else{
            echo '{"total":"0","bpat":[]}';
        }
        break;
    case 'POST':
        break;
    default:
        $project     = $pandb->real_escape_string((string)  (isset($_POST['project'])    ? $_POST['project'] : ''));
        break;
}

function list_bpat_rules($project,$start,$limit){
    global $projectdb;
    if(!checkProjectRights($project,'view')){
        $message = [
            'code' => false,
            'total'=> 0,
            'msg' => array()];
        return $message;
    }

    $projectdb = selectDatabase($project);
    $root=array();
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

    # Load the Descriptions from the CSV File
    $csv=load_csv_description_from_www();

    $getTopics=$projectdb->query("SELECT * FROM bpat_topic WHERE  timestamp in (SELECT MAX(timestamp) from bpat_topic) AND source='$source' AND topic='policies' AND subtype='security_rules';");
    $topicsInMemory=array();
    $topics_ids=array();
    $record=array();
    if($getTopics->num_rows>0){
        $count=0;
        while ($topics = $getTopics->fetch_assoc()){
            $all_topics[]=$topics['id'];
            $topic_id=$topics['id'];
            $configuration=json_decode($topics['configuration'],true);
            $rule_lid=$topics['rule_lid'];

            if (isset($configuration['rule_name'])){
                $rule_name=$configuration['rule_name'];
            }

            if (isset($configuration['vsys'])){
                $vsys=$configuration['vsys'];
            }

            if (isset($configuration['rulebase'])){
                $rulebase=$configuration['rulebase'];
            }

            if (isset($configuration['rule_enabled'])){
                $rule_enabled=$configuration['rule_enabled'];
            }



            $topicsInMemory[$topic_id]=[
                "rule_name"     =>$rule_name,
                "vsys"          => $vsys,
                "rulebase"      => $rulebase,
                "rule_enabled"  => $rule_enabled,
                "rule_lid"      => $rule_lid
            ];
        }

        # Read the bpchecks
        $getBPChecks=$projectdb->query("SELECT * FROM bpat_bpcheck WHERE topic_id IN (".implode(",",$all_topics).");");
        if ($getBPChecks->num_rows>0){
            $total=$getBPChecks->num_rows;
            $record=array();
            $count_checks=0;
            $count_passed=0;
            while($getBPChecksData=$getBPChecks->fetch_assoc()){
                $topic_id=$getBPChecksData['topic_id'];
                $name=$getBPChecksData['name'];
                $result=$getBPChecksData['result'];

                if (isset($record[$topic_id])){
                    $count_checks++;
                    if ($result=="pass"){
                        $count_passed++;
                        $result=1;
                    }
                    else{
                        $result=0;
                    }
                    if (isset($csv[$getBPChecksData['check_id']])){
                        $desc[]=htmlentities($csv[$getBPChecksData['check_id']]['description']);
                    }
                    $record[$topic_id][$name]=$result;
                    $record[$topic_id]["progress"]=round($count_passed/$count_checks,2);
                    $record[$topic_id]['description']=$desc;
                }
                else{
                    $count_passed=0;
                    $count_checks=0;
                    $count_checks++;
                    $desc=array();
                    if (isset($csv[$getBPChecksData['check_id']])){
                        $title=$csv[$getBPChecksData['check_id']]['title'];
                        $desc[]=htmlentities($csv[$getBPChecksData['check_id']]['description']);
                    }
                    else{
                        $title=$desc="";
                    }

                    if ($result=="pass"){
                        $count_passed++;
                        $result=1;
                    }
                    else{
                        $result=0;
                    }
                    $record[$topic_id][$name]=$result;
                    $record[$topic_id]['rule_name']=$topicsInMemory[$topic_id]['rule_name'];
                    $record[$topic_id]['vsys']=$topicsInMemory[$topic_id]['vsys'];
                    $record[$topic_id]['rulebase']=$topicsInMemory[$topic_id]['rulebase'];
                    $record[$topic_id]['rule_enabled']=$topicsInMemory[$topic_id]['rule_enabled'];
                    $record[$topic_id]['rule_lid']=$topicsInMemory[$topic_id]['rule_lid'];
                }
            }
        }
    }
    /*
    $getTopics=$projectdb->query("SELECT * FROM bpat_topic WHERE  timestamp in (SELECT MAX(timestamp) from bpat_topic) AND source='$source' AND topic='policies' AND subtype='security_rules';");
    $record=array();
    if($getTopics->num_rows>0){
        $count=0;
        while ($topics = $getTopics->fetch_assoc()){
            $vsys=$rule_name="";
            $topic_id=$topics['id'];
            $configuration=json_decode($topics['configuration'],true);

            if (isset($configuration['rule_name'])){
                $rule_name=$configuration['rule_name'];
            }

            if (isset($configuration['vsys'])){
                $vsys=$configuration['vsys'];
            }

            if (isset($configuration['rulebase'])){
                $rulebase=$configuration['rulebase'];
            }

            if (isset($configuration['rule_enabled'])){
                $rule_enabled=$configuration['rule_enabled'];
            }

            $record[$count]=[
                "rule_name"     =>$rule_name,
                "vsys"          => $vsys,
                "rulebase"      => $rulebase,
                "rule_enabled"  => $rule_enabled
            ];

            # Read the bpchecks
            $getBPChecks=$projectdb->query("SELECT * FROM bpat_bpcheck WHERE topic_id='$topic_id';");

            if ($getBPChecks->num_rows>0){
                $count_passed=0;
                $total=$getBPChecks->num_rows;
                while($getBPChecksData=$getBPChecks->fetch_assoc()){
                    $name=$getBPChecksData['name'];
                    $result=$getBPChecksData['result'];

                    if (isset($description[$getBPChecksData['check_id']])){
                        $title=$description[$getBPChecksData['check_id']]['title'];
                        $desc=htmlentities($description[$getBPChecksData['check_id']]['description']);
                    }
                    else{
                        $title=$desc="";
                    }

                    if ($result=="pass"){
                        $count_passed++;
                        //$result="<i class=\"fa fa-check fa-lg color_green\" aria-hidden=\"true\" data-qtip=\"$desc\"></i>";
                        $result=1;
                    }
                    else{
                        //$result="<i class=\"fa fa-times fa-lg color_red\" aria-hidden=\"true\" data-qtip=\"$desc\"></i>";
                        $result=0;
                    }

                    $record[$count][$name]=$result;
                    $record[$count]["progress"]=round($count_passed/$total,2);
                    $record[$count]['description']=$desc;

                }
            }

            $count++;




        }
    }
    */
    $message = array();
    $message['code'] = true;
    $message['total']= count($record);
    $message['msg'] = array_values($record);
    return $message;
}

