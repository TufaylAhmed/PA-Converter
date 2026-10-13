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
require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';
require_once INC_ROOT.'/libs/database.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

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
        $project    = $pandb->real_escape_string((string)  (isset($_GET['project'])    ? $_GET['project'] : ''));
        $template   = $pandb->real_escape_string((string)  (isset($_GET['template'])   ? $_GET['template'] : ''));
        $vsys       = $pandb->real_escape_string((string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : ''));
        $message = list_bpat($project,$vsys,$template);
        if($message['code']) {
            echo json_encode($message['msg']);
        }
        else{
            echo json_encode(array('text' => 'root', 'leaf'=>true ,'children' => array() ));
        }
        break;
    case 'POST':
        $project     = $pandb->real_escape_string((string)  (isset($_POST['project'])    ? $_POST['project'] : ''));
        $message = import_json_bpat($project);
        echo json_encode(array('success' => $message['code']));
        break;
    default:
        $project     = $pandb->real_escape_string((string)  (isset($_POST['project'])    ? $_POST['project'] : ''));
        break;
}

function import_json_bpat($project){
    global $app;

    $projectObj = $app->project->where("name", $project)->first();
    $keyObj = $app->accessKey->where("type","project")->where("lid",$projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    $decryptedPath = USERSPACE_PATH."/projects/".$project."/MT-".$project.".xml";
    $encryptedPath = "$decryptedPath.dat";
    if (file_exists($encryptedPath)){
        $contents = $encryptor->decryptFromFile($encryptedPath);
        file_put_contents($decryptedPath,$contents);
    }

    try {
        if (file_exists($decryptedPath)) {
            $json_output = USERSPACE_PATH . "/projects/" . $project . "/MT-" . $project . ".json";
            $exec = "export LANG=en_US.UTF-8;export LC_ALL=en_US.UTF-8;bpa-legacy-cli -x $decryptedPath --flatten -o $json_output";
            //$exec = "export LANG=en_US.UTF-8;export LC_ALL=en_US.UTF-8;bpa-cli publish-json -x $decryptedPath best_practices --flatten -o $json_output";
            $out = shell_exec($exec);

            unlink($decryptedPath);  //Delete the XML file

            $message = array();
            if (file_exists($json_output)) {
                $bpat = json_decode(file_get_contents($json_output), true);

                # Remove file
                unlink($json_output);

                $all_checks = array();
                global $projectdb;
                $projectdb = selectDatabase($project);
                $timestamp = date("Y-m-d H:i:s");

                $getSource = $projectdb->query("SELECT id,ispanorama FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
                if ($getSource->num_rows == 1) {
                    $getSourceData = $getSource->fetch_assoc();
                    $source = $getSourceData['id'];
                    $ispanorama = $getSourceData['ispanorama'];
                }
                else {
                    return $message["msg"] = "There is NO Base-Config selected.";
                }

                if ($ispanorama == 1) {
                    $loadTemplate = $projectdb->query("SELECT id,name FROM templates_mapping WHERE source='$source';");
                    $myTemplates = array();
                    if ($loadTemplate->num_rows > 0) {
                        while ($loadTemplateData = $loadTemplate->fetch_assoc()) {
                            $myTemplates[$loadTemplateData['name']]['id'] = $loadTemplateData['id'];
                        }
                    }
                }

                # Load Rule_LIDS
                $rulesInMemory = map_bpat_with_ruleid($source,$ispanorama);

                # Checks with Auto-Remedation
                $remediation_ids = array(
                    '88',
                    '91',
                    '94',
                    '95',
                    '96',
                    '97',
                    '102',
                    '103',
                    '104',
                    '105',
                    '107',
                    '108',
                    '109',
                    '110',
                    '111',
                    '112',
                    '113',
                    '114',
                    '115',
                    '116',
                    '117',
                    '119',
                    '120',
                    '188',
                    '189',
                    '190',
                    '194',
                    '195',
                    '197'
                );


                #Remove Old Checks
                $projectdb->query("TRUNCATE bpat_topic");
                $projectdb->query("TRUNCATE bpat_bpcheck");

                $getTopicID = $projectdb->query("SELECT max(id) as maxid FROM bpat_topic;");
                if ($getTopicID->num_rows == 1) {
                    $getTopicIDData = $getTopicID->fetch_assoc();
                    $topic_id = $getTopicIDData['maxid'] + 1;
                } else {
                    $topic_id = 1;
                }

                foreach (array_keys($bpat) as $key) {
                    $topic_raw = explode(".", $key);
                    $topic = $topic_raw[0];
                    $subtype = end($topic_raw);
                    $xpath = implode("/", $topic_raw);
                    $template = "";
                    $vsys = "";
                    foreach ($bpat[$key] as $record) {
                        if (isset($record['configuration'])) {
                            $configuration = $record['configuration'];
                        } else {
                            $configuration = array("template_name" => "", "device_group" => "");
                        }

                        if (($ispanorama == 1) AND ($topic == "panorama")) {
                            $template_name = "";
                            $vsys = "";
                            $template = 0;
                        }
                        elseif (($ispanorama == 1) AND (($topic == "device") OR ($topic == "network"))) {
                            if (isset($configuration['template_name'])) {
                                $template_name = $configuration['template_name'];
                                if (isset($myTemplates[$template_name]['id'])) {
                                    $template = $myTemplates[$template_name]['id'];
                                } else {
                                    $template = 0;
                                }
                            } else {
                                $template_name = "";
                            }

                            if (isset($configuration['vsys'])) {
                                $vsys = $configuration['vsys'];
                            } else {
                                $vsys = "";
                            }
                        }
                        elseif (($ispanorama == 1) AND (($topic == "policies") OR ($topic == "objects"))) {

                            if (!isset($configuration['vsys'])) {
                                //print $topic;print "-".$subtype;print_r($record);
                            } else {
                                $vsys = $configuration['vsys'];
                            }
                            $template_name = "";
                        }
                        else {
                            if (isset($configuration['vsys'])) {
                                $vsys = $configuration['vsys'];
                            } else {
                                $vsys = "";
                            }
                            $template_name = "";
                            $template = 0;
                        }

                        if (($topic == "policies") AND ($subtype == "security_rules")) {
                            if (isset($rulesInMemory[$configuration['rule_name']][$configuration['vsys']][$configuration['rulebase']])) {
                                $rule_lid = $rulesInMemory[$configuration['rule_name']][$configuration['vsys']][$configuration['rulebase']]['id'];
                            }
                        } else {
                            $rule_lid = "";
                        }
                        $all_topics[] = "('$topic_id','" . addslashes(json_encode($configuration)) . "','$topic','$subtype','$xpath','$template_name','$timestamp','$template','$vsys','$source','$rule_lid')";
                        $template = "";
                        if ((isset($record['bp_check'])) AND (count($record['bp_check']) > 0)) {

                            foreach ($record['bp_check'] as $unitCheck) {
                                if (isset($unitCheck['message'])) {
                                    $message = addslashes($unitCheck['message']);
                                } else {
                                    $message = "";
                                }
                                if (isset($unitCheck['id'])) {
                                    $id = $unitCheck['id'];
                                } else {
                                    $id = "";
                                }
                                if (isset($unitCheck['name'])) {
                                    $name = $unitCheck['name'];
                                } else {
                                    $name = "";
                                }
                                if (isset($unitCheck['type'])) {
                                    $type = $unitCheck['type'];
                                } else {
                                    $type = "";
                                }
                                if (isset($unitCheck['result'])) {
                                    $result = $unitCheck['result'];
                                } else {
                                    $result = "";
                                }
                                if (in_array($id, $remediation_ids)) {
                                    $remediation = 1;
                                } else {
                                    $remediation = 0;
                                }
                                $all_checks[] = "('$topic_id','$id','$message','$name','$type','$result','$rule_lid','$remediation')";
                            }
                        }
                        $topic_id++;
                    }
                }

                # Output
                if (count($all_topics) > 0) {
                    $projectdb->query("INSERT INTO bpat_topic (id,configuration,topic,subtype,xpath,template_name,timestamp,template,vsys,source,rule_lid) VALUES " . implode(",", $all_topics) . ";");
                    unset($all_topics);
                    if (count($all_checks) > 0) {
                        $projectdb->query("INSERT INTO bpat_bpcheck (topic_id,check_id,message,name,type,result,rule_lid,remediation) VALUES " . implode(",", $all_checks) . ";");
                        //echo "INSERT INTO bpat_bpcheck (topic_id,check_id,message,name,type,result,rule_lid,remediation) VALUES " . implode(",", $all_checks) . ";";
                        unset($all_checks);
                    }
                }


                $message = array();
                $message['code'] = true;
                return $message;
            }
        }

    }
    catch (Exception $e) {
        unlink($decryptedPath);
        $message = array();
        $message['code'] = false;
        return $message;
    }

    $message = array();
    $message['code']=false;
    return $message;
}

function list_bpat($project,$vsys="all",$template="all"){
    global $projectdb;
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
    //$csv=load_csv_description();
    $csv=load_csv_description_from_www();

    if (($vsys!="all") AND ($vsys!="")){
        $add_vsys=" AND vsys='$vsys' ";
    }
    else{
        $add_vsys="";
    }

    if (($template!="all") AND ($template!="")){
        $add_template=" AND template='$template' ";
    }
    else{
        $add_template="";
    }

    $getTopics=$projectdb->query("SELECT * FROM bpat_topic WHERE  timestamp in (SELECT MAX(timestamp) from bpat_topic) AND source='$source' AND subtype!='security_rules' $add_vsys $add_template;");
    $bpat=array();
    $topicsUsed=array();
    $collector=array();
    $bpchecks=array();
    if($getTopics->num_rows>0){
        while ($topics = $getTopics->fetch_assoc()){

            $bpat[$topics['id']]['topic']=$topics['topic'];
            # while xpath item != subtype
            # text = xpath item, children = array
            $bpat[$topics['id']]['subtype']=$topics['subtype'];
            $bpat[$topics['id']]['vsys']=$topics['vsys'];
            $bpat[$topics['id']]['template_name']=$topics['template_name'];
            $bpat[$topics['id']]['xpath']=$topics['xpath'];
            //$bpat['subtype'][]=$topics['subtype'];
            $topicsUsed[]=$topics['id'];
            $xpathUsed[]=$topics['xpath'];
        }

        $bpchecksAll=array();
        $getBPChecks=$projectdb->query("SELECT * FROM bpat_bpcheck WHERE topic_id IN (".implode(",",$topicsUsed).");");
        if ($getBPChecks->num_rows>0){
            $fake_counter=0;
            $fake_counter2=0;
            while($bpcheck=$getBPChecks->fetch_assoc()){
                if ($bpcheck['result']=="pass"){
                    $icon="fa fa-check fa-lg color_green";
                }
                else{
                    $icon="fa fa-times fa-lg color_red";
                }

                if (isset($csv[$bpcheck['check_id']])){
                    $title=$csv[$bpcheck['check_id']]['title'];
                    $desc=$csv[$bpcheck['check_id']]['description'];

                    $rationale=$csv[$bpcheck['check_id']]['rationale'];
                    $references=$csv[$bpcheck['check_id']]['references'];
                    if ($references=="None"){$references="";}
                }
                else{
                    $title=$description="";
                }

//                $bpchecks[$bpcheck['topic_id']][] = [
                $bpchecks[$bpat[$bpcheck['topic_id']]['xpath']][] = [
                    "topic"     =>  $desc,
                    "subtype"   =>  $bpat[$bpcheck['topic_id']]['subtype'],
                    "check_id"  =>  $bpcheck['check_id'],
                    "result"    =>  $bpcheck['result'],
                    "type"      =>  $bpcheck['type'],
                    "name"      =>  $bpcheck['name'],
                    "leaf"      =>  true,
                    "message"   =>  $bpcheck['message'],
                    "vsys"      =>  $bpat[$bpcheck['topic_id']]['vsys'],
                    "template_name" => $bpat[$bpcheck['topic_id']]['template_name'],
                    "iconCls" => $icon,
                    "title"     => $title,
                    "description" => addslashes($desc),
                    "progress" => ($bpcheck['result']=="pass")? 1:0,
                    "xpath"     => $bpat[$bpcheck['topic_id']]['xpath'],
                    "topic_id"      => $bpcheck['topic_id'],
                    "rationale"     => addslashes($rationale),
                    "references"    =>$references

                ];
                $desc="";$title="";$rationale="";$references="";
            }

        }
    }

    $collector = array('text' => 'root', 'children' => array() );
    foreach($bpchecks as $xpath0 => $xcheck){
        $xpath = explode("/",$xpath0);
        $collector = add_bp_checks_to_tree($collector, $xpath, $xcheck);
    }


    $message = array();
    $message['code'] = true;
    $message['text'] = "root";
    $message['msg'] = $collector;
    return $message;

}

function xxlist_bpat($project){
    global $projectdb;
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

    if (file_exists(INC_ROOT.'/libs/best_practice_assessment_ngfw_pano/best_practice_assessment/bpat_documentation.csv')){
        ini_set('auto_detect_line_endings',TRUE);
        $handle = fopen(INC_ROOT.'/libs/best_practice_assessment/bpat_documentation.csv','r');
        $description=array();
        while ( ($data = fgetcsv($handle,0,';') ) !== FALSE ) {
            $description[$data[0]]['title']=$data[7];
            $description[$data[0]]['description']=$data[9];
        }
        ini_set('auto_detect_line_endings',FALSE);
    }

//    $bpat[$topics['id']]['topic']=$topics['topic'];

    $getTopics=$projectdb->query("SELECT * FROM bpat_topic WHERE  timestamp in (SELECT MAX(timestamp) from bpat_topic) AND source='$source' GROUP BY topic;");
    $bpat=array();
    if($getTopics->num_rows>0){
        while ($topics = $getTopics->fetch_assoc()){
            $topic_name=$topics['topic'];
            $total_passed_checks=0;
            $getByTopic=$projectdb->query("SELECT subtype FROM bpat_topic WHERE  timestamp in (SELECT MAX(timestamp) from bpat_topic) AND source='$source' AND topic='$topic_name' GROUP BY subtype;");
            if ($getByTopic->num_rows>0){
                $bpchecks=array();
                $each_bpcheckName=array();
                while ($getByTopicData=$getByTopic->fetch_assoc()){
                    $topic_subtype=$getByTopicData['subtype'];
                    $getSubType=$projectdb->query("SELECT * FROM bpat_topic WHERE  timestamp in (SELECT MAX(timestamp) from bpat_topic) AND source='$source' AND topic='$topic_name' AND subtype='$topic_subtype';");
                    if ($getSubType->num_rows>0){
                        while ($getSubTypeData=$getSubType->fetch_assoc()){
                            $vsys=$getSubTypeData['vsys'];
                            $template_name=$getSubTypeData['template_name'];
                            $topic_id=$getSubTypeData['id'];
                            $getBPChecks=$projectdb->query("SELECT * FROM bpat_bpcheck WHERE topic_id='$topic_id';");
                            if ($getBPChecks->num_rows>0){
                                while($bpcheck=$getBPChecks->fetch_assoc()){
                                   if ($bpcheck['result']=="pass"){
                                       $icon="fa fa-check fa-lg color_green";
                                   }
                                   else{
                                       $icon="fa fa-times fa-lg color_red";
                                   }

                                    if (isset($description[$bpcheck['check_id']])){
                                       $title=$description[$bpcheck['check_id']]['title'];
                                       $desc=$description[$bpcheck['check_id']]['description'];
                                    }
                                    else{
                                        $title=$description="";
                                    }



                                    $bpchecks[$bpcheck['name']][] = [
                                        "topic"     =>  $desc,
                                        "subtype"   =>  $topic_subtype,
                                        "check_id"  =>  $bpcheck['check_id'],
                                        "result"    =>  $bpcheck['result'],
                                        "type"      =>  $bpcheck['type'],
                                        "name"      =>  $bpcheck['name'],
                                        "leaf"      =>  true,
                                        "message"   =>  $bpcheck['message'],
                                        "vsys"      =>  $vsys,
                                        "template_name" => $template_name,
                                        "iconCls" => $icon,
                                        "title"     => $title,
                                        "description" => $desc,
                                        "progress" => ($bpcheck['result']=="pass")? 1:0
                                    ];
                                    $desc="";$title="";

                                }

                            }

                        }
                        if ( (isset($bpchecks)) AND (count($bpchecks)>0) ){
                            foreach (array_keys($bpchecks) as $bpcheckkey){
                                if (count($bpchecks[$bpcheckkey])>0){
                                    $leaf1=false;
                                }
                                else{
                                    $leaf1=true;
                                }

                                $total=count($bpchecks[$bpcheckkey]);
                                $passed=0;
                                $progress=0;
                                foreach ($bpchecks[$bpcheckkey] as $checking){
                                    if ($checking['result']=="pass"){
                                        $passed++;
                                    }
                                }
                                $progress=round($passed/$total);

                                $each_bpcheckName[] = [
                                    "topic"  => $bpcheckkey,
                                    "subtype"    =>'',
                                    "children"  => $bpchecks[$bpcheckkey],
                                    "leaf" => $leaf1,
                                    "progress" => $progress
                                ];
                            }
                        }
                        else{
                            $each_bpcheckName=array();
                        }
                        unset($bpchecks);
                    }




                    if (count($each_bpcheckName)>0){
                        $leaf=false;
                    }
                    else{
                        $leaf=true;
                    }

                    if ($topic_subtype!="security_rules"){
                        $each_subtype[] = [
                            "topic"  => $topic_subtype,
                            "subtype"    =>'',
                            "children"  => $each_bpcheckName,
                            "leaf" => $leaf,
                            "progress" => $progress
                        ];
                        unset($each_bpcheckName);
                    }



                    /*if (count($each_subtype)>0){
                        $leaf=false;
                    }
                    else{
                        $leaf=true;
                    }
                    $each_topic[]= [
                        "topic"  =>$topic_name,
                        "subtype"    => '',
                        "children"  => $each_subtype,
                        "leaf" => $leaf
                    ];
                    unset($each_subtype);*/

                }
            }
            if (count($each_subtype)>0){
                $leaf=false;
            }
            else{
                $leaf=true;
            }
            $root[]= [
                "topic"  =>$topic_name,
                "subtype"    => '',
                "children"  => $each_subtype,
                "leaf" => $leaf,
                "progress" => 0.6
            ];
            unset($each_subtype);
            unset($each_topic);
        }
    }

    $message = array();
    $message['code'] = true;
    $message['text'] = "root";
    $message['msg'] = $root;
    return $message;
}


