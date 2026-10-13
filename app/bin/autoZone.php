<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//require_once('./Authentication.php');
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';

require_once INC_ROOT.'/bin/messaging/MessageSender.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        break;
    case 'POST':
        $message = applyAutoZone($data);
        echo json_encode(array('success' => $message['code'], 'jobid' => $message['msg']));
        exit();
        break;
    default:
        break;
}

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $project = $app->project->where('name',$data['project'])->first();

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'projects',
        'parentId'      => $project->id,
        'description'   => $description .' '.$data['project'],
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerTask(ARRAY $data, $user, INT $jobID, STRING $processCode, STRING $processName){
    global $app;

    if(!isset($data['params'])){
        $data['params'] = '';
    }
    $data['userId'] = $user->id;

    $params = [
        'job_id'        => $jobID,
        'taskType'      => 'Apply Autozone',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    $job = $app->job->where('id', $jobID)->first();
    $jobParams = [
        'tasks' => $job->tasks +1,
    ];
    $job->update($jobParams);

    if($job->parentJob != ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks +1,
        ];
        $parentJob->update($parentJobParams);
    }

    return $task->id;
}

function applyAutoZone(array $data){
    global $projectdb;
    $project = $data['project'];
    $projectdb = selectDatabase($project);

    $vr = $data['vr'];
    $source = $data['source'];
    $vsys = $data['vsys'];
    $templateID = $data['templateID'] ?? null;

//    $autozone_options_source    = $data['autozone_options_source'];
//    $autozone_options_destination =$data['autozone_options_destination'];

    $tags = $data['autozone_tag'];
    $doFrom = isset($data['autozone_options_source']) && ($data['autozone_options_source'] == 'on' || $data['autozone_options_source'] == true);
    $doTo =   isset($data['autozone_options_destination']) && ($data['autozone_options_destination'] == 'on' || $data['autozone_options_destination'] == true);
    $applyNat = isset($data['applyNat']) && $data['applyNat'] == '1';
    $ruleIds = $data['data'] ?? '';
    $autozone_apply = $data['autozone_apply'] ?? '';

    //Collect all the rule_ids that should be autozoned
    if($autozone_apply === 'all'){
        $ruleIds = array();
    }
    else {
        if ($ruleIds === 'all' || $ruleIds === '') {
            $ruleIds = array();
        } else {
            $ruleIds = explode(',', $ruleIds);
        }
    }


    if($tags === ''){
        $tags = array();
    }
    else{
        $tags = explode(',',$tags);
    }

    if (!isset($is_override_active)) {
        $is_override_active = "off";
    }

    global $app;
    $user = $app->container->sentinel->getUser();
    $api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));
    $data_individual = [
        'project'   =>$project,
        'source'    =>$source,
        'vsys'      =>$vsys,
        'templateID'=>$templateID,
        'vr'        =>$vr,
        'ruleIds'   =>$ruleIds,
        'tags'      =>$tags,
        'applyNat'  =>$applyNat,
        'doFrom'    =>$doFrom,
        'doTo'      =>$doTo,
        'key'       => $api_key
    ];

    $autozone_type = $data['autozone_rule'] ?? 'security';
    //Is this a NAT Autozone
    if($autozone_type == "nat"){
        $jobID = registerJob($data_individual, $user, "NAT Autozone on project:$project, source:$source, vsys:$vsys, template:$templateID ");
        $taskID = registerTask($data_individual, $user, $jobID, "AutoZonePolicy_NAT", "Apply Autozone on NAT Policy");
        call_autoZone($data_individual, $user, $taskID, "AutoZonePolicy_NAT");

        $message = array();
        $message['code'] = true;
        $message['msg'] = $jobID;
    }
    else{
    //    //Check the minimum conditions for autozone are met
    //    if (($vr != "") AND ( ($autozone_options_source == "on") OR ( $autozone_options_destination == "on"))) {
    //        $projectdb->query("TRUNCATE TABLE project_status;");  //TODO: should not be performed this way, we have multitasking now, and background processes may be using the table
    //        add_progress($project, '0.00', 'Retrieving Reports');
    //        take_snapshot_last($project);  //Security
    //        ini_set('max_execution_time', 10000);
    //        ini_set("memory_limit", "1000M");
    //
    //        if ($autozone_rule == "security") {  //TODO: check whether we have defined to apply autozone via NAT or without NAT
    //            $rules_table = "security_rules";
    //            $tag_table = "security_rules_tag";
    //        } else {
    //            $rules_table = "nat_rules";
    //            $tag_table = "nat_rules_tag";
    //        }
    //
    //
    //        //Determine which security rules should be autozone'd
    //        if ($autozone_apply == "all") {
    //            #Create an array with all the rule_lid
    //            $getAllRules = $projectdb->query("SELECT id FROM $rules_table WHERE source='$source' AND vsys='$vsys' AND blocked='0';");
    //            if ($getAllRules->num_rows > 0) {
    //                while ($rule = $getAllRules->fetch_assoc()) {
    //                    $data3[] = $rule['id'];
    //                }
    //            }
    //            $allruleid = $data3;
    //            $selected = " AND rule_lid IN (" . implode(",", $data3) . ")";
    //            $selectedNat = " AND id IN (" . implode(",", $data3) . ")";
    //        }
    //        elseif ($autozone_apply == "selected") {
    //            $selected = " AND rule_lid IN ($data)";
    //            $selectedNat = " AND id IN ($data)";
    //            $allruleid = explode(",", $data);
    //        }
    //
    //        if ($autozone_tag != "") {
    //            $data2 = array();
    //            $getRules = $projectdb->query("SELECT rule_lid FROM $tag_table WHERE member_lid='$autozone_tag' AND table_name='tag' AND source='$source' AND vsys='$vsys' $selected;");
    //            if ($getRules->num_rows > 0) {
    //                while ($rule = $getRules->fetch_assoc()) {
    //                    $data2[] = $rule['rule_lid'];
    //                }
    //            }
    //            $selected = " AND rule_lid IN (" . implode(",", $data2) . ")";
    //            $selectedNat = " AND id IN (" . implode(",", $data2) . ")";
    //            $allruleid = $data2;
    //        }
    //
    //        if ($autozone_rule == "security") {
    //
    //            // NEW DEVELOPMENT TO CALCULATE ZONES
    //            $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
    //            //echo "ipMappgin\n";
    //            //print_r($ipMapping);
    //
    //            if ($autozone_options_source == "on") {
    //                $from_or_to = "from";
    //                $rule_or_nat = "rule";
    //                update_progress($project, "0.45", "Calculating Source Zones");
    //
    //                if ($is_override_active == "on") {
    //                    if (strtolower($autozone_zone_equal) == "any") {
    //                        if ($autozone_replace_by_zone != "none") {
    //                            $noany = array();
    //                            $out = array();
    //                            $getNoAny = $projectdb->query("SELECT rule_lid FROM security_rules_from WHERE source='$source' ANd vsys='$vsys' $selected");
    //                            if ($getNoAny->num_rows > 0) {
    //                                while ($getNoAnyData = $getNoAny->fetch_assoc()) {
    //                                    $noany[] = $getNoAnyData['rule_lid'];
    //                                }
    //                            }
    //                            $array_dif = array_diff($allruleid, $noany);
    //                            foreach ($array_dif as $key => $value) {
    //                                $out[] = "('$value','$autozone_replace_by_zone','$source','$vsys')";
    //                            }
    //                            if (count($out) > 0) {
    //                                $projectdb->query("INSERT INTO security_rules_from (rule_lid,name,source,vsys) VALUES " . implode(",", $out) . ";");
    //                            }
    //                        }
    //                    } else {
    //                        if ($autozone_replace_by_zone != "none") {
    //                            $getAll = $projectdb->query("UPDATE security_rules_from SET name='$autozone_replace_by_zone' WHERE source='$source' AND vsys='$vsys' $selected AND name='$autozone_zone_equal'");
    //                        } else {
    //                            $projectdb->query("DELETE FROM security_rules_from WHERE source='$source' AND vsys='$vsys' $selected AND name='$autozone_zone_equal';");
    //                        }
    //                    }
    //                } else {
    //                    $projectdb->query("DELETE FROM security_rules_from WHERE source='$source' AND vsys='$vsys' $selected;");
    //
    //                    calculateZonesFromIP4Mapping($ipMapping['ipv4'], $selected, $vsys, $source, "security_rules_src", $allruleid);
    //
    //                    /* $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE source='$source' AND vsys='$vsys' $selected;");
    //                      if ($getSRC->num_rows > 0) {
    //                      while ($getSRCData = $getSRC->fetch_assoc()) {
    //                      $member_lid = $getSRCData['member_lid'];
    //                      $table_name = $getSRCData['table_name'];
    //                      $rule_lid = $getSRCData['rule_lid'];
    //                      if (($table_name == "address") or ( $table_name == "shared_address")) {
    //                      search_zone_address($rule_lid, $member_lid, $vsys, $source, $vr, $table_name, $from_or_to, $rule_or_nat);
    //                      } else {
    //                      search_zone_group($rule_lid, $member_lid, $vsys, $source, $vr, $table_name, $from_or_to, $rule_or_nat);
    //                      }
    //                      }
    //                      } */
    //                }
    //            }
    //            if ($autozone_options_destination == "on") {
    //                $from_or_to = "to";
    //                $rule_or_nat = "rule";
    //
    //                update_progress($project, "0.9", "Calculating Destination Zones");
    //                if ($is_override_active == "on") {
    //                    if (strtolower($autozone_zone_equal) == "any") {
    //                        if ($autozone_replace_by_zone != "none") {
    //                            $noany = array();
    //                            $out = array();
    //                            $getNoAny = $projectdb->query("SELECT rule_lid FROM security_rules_to WHERE source='$source' ANd vsys='$vsys' $selected");
    //                            if ($getNoAny->num_rows > 0) {
    //                                while ($getNoAnyData = $getNoAny->fetch_assoc()) {
    //                                    $noany[] = $getNoAnyData['rule_lid'];
    //                                }
    //                            }
    //                            $array_dif = array_diff($allruleid, $noany);
    //                            foreach ($array_dif as $key => $value) {
    //                                $out[] = "('$value','$autozone_replace_by_zone','$source','$vsys')";
    //                            }
    //                            if (count($out) > 0) {
    //                                $projectdb->query("INSERT INTO security_rules_to (rule_lid,name,source,vsys) VALUES " . implode(",", $out) . ";");
    //                            }
    //                        }
    //                    } else {
    //                        if ($autozone_replace_by_zone != "none") {
    //                            $getAll = $projectdb->query("UPDATE security_rules_to SET name='$autozone_replace_by_zone' WHERE source='$source' AND vsys='$vsys' $selected AND name='$autozone_zone_equal'");
    //                        } else {
    //                            $projectdb->query("DELETE FROM security_rules_to WHERE source='$source' AND vsys='$vsys' $selected AND name='$autozone_zone_equal';");
    //                        }
    //                    }
    //                } else {
    //                    $projectdb->query("DELETE FROM security_rules_to WHERE source='$source' AND vsys='$vsys' $selected;");
    //
    //                    calculateZonesFromIP4Mapping($ipMapping['ipv4'], $selected, $vsys, $source, "security_rules_dst", $allruleid);
    //
    //                    /* $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE source='$source' AND vsys='$vsys' $selected;");
    //                      if ($getSRC->num_rows > 0) {
    //                      while ($getSRCData = $getSRC->fetch_assoc()) {
    //                      $member_lid = $getSRCData['member_lid'];
    //                      $table_name = $getSRCData['table_name'];
    //                      $rule_lid = $getSRCData['rule_lid'];
    //                      if (($table_name == "address") or ( $table_name == "shared_address")) {
    //                      //search_zone_address($rule_lid, $member_lid, $vsys, $source, $vr, $table_name, $from_or_to, $rule_or_nat);
    //
    //                      //getIPtoZoneRouteMapping($vsys, $source, $rule_lid, $vr);
    //
    //                      } else {
    //                      //search_zone_group($rule_lid, $member_lid, $vsys, $source, $vr, $table_name, $from_or_to, $rule_or_nat);
    //                      }
    //                      }
    //                      } */
    //                }
    //            }
    //
    //            update_progress($project, '1.00', 'Finished.');
    //            sleep(4);
    //            update_progress($project, '0', 'Ready');
    //        }
    //        elseif ($autozone_rule == "nat") {
    //
    //            // NEW DEVELOPMENT TO CALCULATE ZONES
    //            $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
    //
    //            if ($autozone_options_source == "on") {
    //
    //                if ($is_override_active == "on") {
    //                    if (strtolower($autozone_zone_equal) == "any") {
    //                        if ($autozone_replace_by_zone != "none") {
    //                            $noany = array();
    //                            $out = array();
    //                            $getNoAny = $projectdb->query("SELECT rule_lid FROM nat_rules_from WHERE source='$source' ANd vsys='$vsys' $selected");
    //                            if ($getNoAny->num_rows > 0) {
    //                                while ($getNoAnyData = $getNoAny->fetch_assoc()) {
    //                                    $noany[] = $getNoAnyData['rule_lid'];
    //                                }
    //                            }
    //                            $array_dif = array_diff($allruleid, $noany);
    //                            foreach ($array_dif as $key => $value) {
    //                                $out[] = "('$value','$autozone_replace_by_zone','$source','$vsys')";
    //                            }
    //                            if (count($out) > 0) {
    //                                $projectdb->query("INSERT INTO nat_rules_from (rule_lid,name,source,vsys) VALUES " . implode(",", $out) . ";");
    //                            }
    //                        }
    //                    } else {
    //                        if ($autozone_replace_by_zone != "none") {
    //                            $getAll = $projectdb->query("UPDATE nat_rules_from SET name='$autozone_replace_by_zone' WHERE source='$source' AND vsys='$vsys' $selected AND name='$autozone_zone_equal'");
    //                        } else {
    //                            $projectdb->query("DELETE FROM nat_rules_from WHERE source='$source' AND vsys='$vsys' $selected AND name='$autozone_zone_equal';");
    //                        }
    //                    }
    //                } else {
    //                    $from_or_to = "from";
    //                    $rule_or_nat = "nat";
    //                    update_progress($project, "0.45", "Calculating Source Zones");
    //                    $projectdb->query("DELETE FROM nat_rules_from WHERE source='$source' AND vsys='$vsys' $selected;");
    //
    //                    calculateZonesFromIP4Mapping($ipMapping['ipv4'], $selected, $vsys, $source, "nat_rules_src", $allruleid);
    //
    //                    /* $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_src WHERE source='$source' AND vsys='$vsys' $selected;");
    //                      if ($getSRC->num_rows > 0) {
    //                      while ($getSRCData = $getSRC->fetch_assoc()) {
    //                      $member_lid = $getSRCData['member_lid'];
    //                      $table_name = $getSRCData['table_name'];
    //                      $rule_lid = $getSRCData['rule_lid'];
    //                      if (($table_name == "address") or ( $table_name == "shared_address")) {
    //                      //search_zone_address($rule_lid, $member_lid, $vsys, $source, $vr, $table_name, $from_or_to, $rule_or_nat);
    //
    //
    //                      } else {
    //                      search_zone_group($rule_lid, $member_lid, $vsys, $source, $vr, $table_name, $from_or_to, $rule_or_nat);
    //                      }
    //                      }
    //                      } */
    //                }
    //            }
    //            if ($autozone_options_destination == "on") {
    //                if ($is_override_active == "on") {
    //                    if (strtolower($autozone_zone_equal) == "any") {
    //                        if ($autozone_replace_by_zone != "none") {
    //                            $noany = array();
    //                            $out = array();
    //                            $getNoAny = $projectdb->query("SELECT id FROM nat_rules WHERE source='$source' ANd vsys='$vsys' AND op_zone_to='' $selectedNat");
    //                            if ($getNoAny->num_rows > 0) {
    //                                while ($getNoAnyData = $getNoAny->fetch_assoc()) {
    //                                    $noany[] = $getNoAnyData['id'];
    //                                }
    //                            }
    //                            $array_dif = array_diff($allruleid, $noany);
    //                            if (count($array_dif) == 0) {
    //                                $array_dif = $allruleid;
    //                            }
    //
    //                            foreach ($array_dif as $key => $value) {
    //                                $projectdb->query("UPDATE nat_rules SET op_zone_to='$autozone_replace_by_zone' WHERE id='$value';");
    //                            }
    //                        }
    //                    } else {
    //                        if ($autozone_replace_by_zone != "none") {
    //                            $projectdb->query("UPDATE nat_rules SET op_zone_to='$autozone_replace_by_zone' WHERE source='$source' AND vsys='$vsys' AND op_zone_to='$autozone_zone_equal' $selectedNat ");
    //                        } else {
    //                            $projectdb->query("UPDATE nat_rules SET op_zone_to='' WHERE source='$source' AND vsys='$vsys' AND op_zone_to='$autozone_zone_equal' $selectedNat ;");
    //                        }
    //                    }
    //                } else {
    //                    $from_or_to = "to";
    //                    $rule_or_nat = "nat";
    //                    $projectdb->query("UPDATE nat_rules SET op_zone_to='' WHERE source='$source' AND vsys='$vsys' $selectedNat;");
    //                    update_progress($project, "0.9", "Calculating Destination Zones");
    //
    //                    calculateZonesFromIP4Mapping($ipMapping['ipv4'], $selected, $vsys, $source, "nat_rules_dst", $allruleid);
    //
    //
    //                    /* $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_dst WHERE source='$source' AND vsys='$vsys' $selected;");
    //                      if ($getSRC->num_rows > 0) {
    //                      $tozone = "";
    //                      while ($getSRCData = $getSRC->fetch_assoc()) {
    //                      $member_lid = $getSRCData['member_lid'];
    //                      $table_name = $getSRCData['table_name'];
    //                      $rule_lid = $getSRCData['rule_lid'];
    //
    //                      if (($table_name == "address") OR ( $table_name == "shared_address")) {
    //                      $tozone = search_zone_address_one($member_lid, $vsys, $source, $table_name);
    //                      $projectdb->query("UPDATE nat_rules SET op_zone_to='$tozone' WHERE source='$source' AND vsys='$vsys' AND id='$rule_lid';");
    //                      } elseif (($table_name == "address_groups_id") OR ( $table_name == "shared_address_groups_id")) {
    //                      if ($table_name == "address_groups_id") {
    //                      $table_name = "address_groups";
    //                      } else {
    //                      $table_name = "shared_address_groups";
    //                      }
    //                      $getMember = $projectdb->query("SELECT member_lid,table_name FROM $table_name WHERE lid='$member_lid' AND table_name!='address_groups_id' AND table_name!='shared_address_groups_id' LIMIT 1;");
    //                      if ($getMember->num_rows == 1) {
    //                      $getMemberData = $getMember->fetch_assoc();
    //                      $member_lid = $getMemberData['member_lid'];
    //                      $table_name = $getMemberData['table_name'];
    //                      $tozone = search_zone_address_one($member_lid, $vsys, $source, $table_name);
    //                      $projectdb->query("UPDATE nat_rules SET op_zone_to='$tozone' WHERE source='$source' AND vsys='$vsys' AND id='$rule_lid';");
    //                      }
    //                      }
    //                      }
    //                      } */
    //                }
    //            }
    //            update_progress($project, '1.00', 'Finished.');
    //            sleep(4);
    //            update_progress($project, '0', 'Ready');
    //        }
    //    }
    //    else {
    //        #echo json_encode(array('success'=>false,'message'=>'Missing Virtual Router or Select Calculate Source\/Destination'));
    //        update_progress($project, '1.00', 'Missing Virtual Router or Select Calculate Source\/Destination.');
    //    }
    //    ini_restore("memory_limit");

        //create_job
        if (($vr != "") && ( ($doFrom) || ($doTo))) {
            $jobID = registerJob($data_individual, $user, "Autozone on project:$project, source:$source, vsys:$vsys, templated:$templateID ");
            $taskID = registerTask($data_individual, $user, $jobID, "AutoZonePolicy", "Apply Autozone on Policy");
            call_autoZone($data_individual, $user, $taskID, "AutoZonePolicy");

            $message = array();
            $message['code'] = true;
            $message['msg'] = $jobID;
        }
        else{
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Missing Virtual Router or Select Calculate Source\/Destination.';
        }
    //    update_progress($project, '1.00', 'Finished.',$jobId);

    }
    return $message;
}

function call_autoZone(ARRAY $data, $user, INT $taskID, STRING $process){
    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'project'       => $data['project'],
        'params'        => [
            'taskId'        => $taskID,
            'data'        => $data,
            'userId'      => $user->id,
            'key'         => $data['key']
        ]
    ];

    sendMessage($message);

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Done';
    return $message;
}

function sendMessage($message){
    $messageSender = new MessageSender($message);
    $messageSender->send();
}

/**
 * @param $zoneIP4Mapping array  array of IP start-end to zone ie  Array( 0=>Array('start'=>0, 'end'=>50, 'zone'=>'internet') 1=>...  )
 * @param $objectIsNegated bool  IP4Mapping of this object will be inverted before doing resolution
 * @return string[] containing zones matched
 */

/*function calculateZonesFromIP4Mapping($zoneIP4Mapping, $selected, $vsys, $source, $table, $allruleid) {

    global $projectdb;

    $getSRC = $projectdb->query("SELECT rule_lid, member_lid, table_name FROM $table WHERE source='$source' AND vsys='$vsys' $selected;");
    if ($getSRC->num_rows > 0) {
        while ($getSRCData = $getSRC->fetch_assoc()) {

            $fakeMapping = Array();
            $objectsMapping = Array();
            $zones = Array();

            $member = "";
            $member_lid = $getSRCData['member_lid'];
            $table_name = $getSRCData['table_name'];
            $rule_lid = $getSRCData['rule_lid'];


            $objectsMapping = getIP4Mapping($member, $member_lid, $table_name);
            //echo "------------------------->FINAL: \n";
            //print_r($objectsMapping);
            // Negated, only security rules
            if (($table != "nat_rules_src") || ($table != "nat_rules_dst")) {

                $getIsNegated = $projectdb->query("SELECT negate_source, negate_destination, devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if ($getIsNegated->num_rows > 0) {
                    $getINData = $getIsNegated->fetch_assoc();
                    $negate_source = $getINData['negate_source'];
                    $negate_destination = $getINData['negate_destination'];
                    $devicegroup = $getINData['devicegroup'];
                }

                if ($table == "security_rules_src") {
                    if ($negate_source == "1") {
                        $fakeMapping['map'][] = Array('start' => 0, 'end' => ip2long('255.255.255.255'));
                        foreach ($objectsMapping['map'] as $entry) {
                            //echo "LOS OBJECTS MAPPING MAP SON: " .$entry. "\n";
                            //print_r($entry);
                            removeNetworkFromIP4Mapping($fakeMapping['map'], $entry);
                            //$objectsMapping = &$fakeMapping;
                            $objectsMapping = $fakeMapping;
                        }
                    }
                } elseif ($table == "security_rules_dst") {
                    if ($negate_destination == "1") {
                        $fakeMapping['map'][] = Array('start' => 0, 'end' => ip2long('255.255.255.255'));
                        foreach ($objectsMapping['map'] as $entry) {
                            //echo "LOS OBJECTS MAPPING MAP SON: " .$entry. "\n";
                            //print_r($entry);
                            removeNetworkFromIP4Mapping($fakeMapping['map'], $entry);
                            //$objectsMapping = &$fakeMapping;
                            $objectsMapping = $fakeMapping;
                        }
                    }
                }
            }

            foreach ($zoneIP4Mapping as &$zoneMapping) {
                $result = removeNetworkFromIP4Mapping($objectsMapping['map'], $zoneMapping);
                //echo "El result es: " .$result. "\n";
                if ($result != 0) {
                    $zones[$zoneMapping['zone']] = $zoneMapping['zone'];
                }
                if (count($objectsMapping) == 0)
                    break;
            }

            //echo "\n\n ------------------------------------------------------------------------------";
            //echo "\nLAS ZONAS!!";
            //print_r($zones);

            if ($table == "security_rules_src") {
                $table_to_save = "security_rules_from";
            } elseif ($table == "security_rules_dst") {
                $table_to_save = "security_rules_to";
            } elseif ($table == "nat_rules_src") {
                $table_to_save = "nat_rules_from";
            } elseif ($table == "nat_rules_dst") {
                $table_to_save = "nat_rules";
            }

            if ($table_to_save == "nat_rules") {

                $total_zones = count($zones);

                //print_r($zones);
                //echo "La zona 1 es: " .$zones['0']. "\n";
                if ($total_zones > 1) {
                    add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_lid . '] is usign more than one Zone as a Destination [' . implode(",", $zones) . ']', $source, 'Only one Destination Zone is allowed', 'rules', $rule_lid, 'nat_rules');
                }
                $zona = current($zones);
                $projectdb->query("UPDATE $table_to_save SET op_zone_to = '$zona' WHERE id = '$rule_lid' ;");
            } else {

                foreach ($zones as $zone) {

                    $getZone = $projectdb->query("SELECT id FROM $table_to_save WHERE name = '$zone' AND rule_lid = '$rule_lid' ;");

                    if ($getZone->num_rows == 0) {

                        $projectdb->query("INSERT INTO $table_to_save (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
            //return $zones;
        }
    }

    // Si la Destination está vacía de las nat rules, mirar si tiene [TP] Source, si tiene,
    // mirar la zona o interface (si tiene interface) y añadir la zona resultante al to
    if ($table == "nat_rules_dst") {

        $getNoAny = $projectdb->query("SELECT rule_lid FROM nat_rules_dst WHERE source = '$source' $selected");

        if ($getNoAny->num_rows == 0) {
            $array_dif = $allruleid;
        } elseif ($getNoAny->num_rows > 0) {
            while ($getNoAnyData = $getNoAny->fetch_assoc()) {
                $noany[] = $getNoAnyData['rule_lid'];
            }
            $array_dif = array_diff($allruleid, $noany);
        }

        foreach ($array_dif as $key => $rule_id) {
            //echo "EL QUE NO TIENE DESTINATION ES: " .$rule_id. "\n";

            $getType = $projectdb->query("SELECT tp_sat_address_type, tp_sat_interface FROM nat_rules WHERE id = '$rule_id';");
            if ($getType->num_rows > 0) {
                $getTypeData = $getType->fetch_assoc();
                $type_sat_address = $getTypeData['tp_sat_address_type'];
                $tp_sat_interface = $getTypeData['tp_sat_interface'];
            }

            if ($type_sat_address == "translated-address") {

                $getSRC = $projectdb->query("SELECT rule_lid, member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid = '$rule_id' 
                    UNION SELECT rule_lid, member_lid, table_name FROM nat_rules_translated_address_fallback WHERE rule_lid = '$rule_id';");
                if ($getSRC->num_rows > 0) {
                    while ($getSRCData = $getSRC->fetch_assoc()) {

                        $fakeMapping = Array();
                        $objectsMapping = Array();
                        $zones = Array();

                        $member = "";
                        $member_lid = $getSRCData['member_lid'];
                        $table_name = $getSRCData['table_name'];
                        $rule_lid = $getSRCData['rule_lid'];

                        $objectsMapping = getIP4Mapping($member, $member_lid, $table_name);

                        //print_r($objectsMapping);
                        foreach ($zoneIP4Mapping as &$zoneMapping) {
                            $result = removeNetworkFromIP4Mapping($objectsMapping['map'], $zoneMapping);
                            //echo "El result es: " .$result. "\n";
                            if ($result != 0) {
                                $zones[$zoneMapping['zone']] = $zoneMapping['zone'];
                            }
                            if (count($objectsMapping) == 0)
                                break;
                        }

                        $total_zones = count($zones);

                        if ($total_zones > 1) {
                            add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_lid . '] is usign more than one Zone as a Destination [' . implode(",", $zones) . ']', $source, 'Only one Destination Zone is allowed', 'rules', $rule_lid, 'nat_rules');
                        }
                        $zona = current($zones);
                        $projectdb->query("UPDATE nat_rules SET op_zone_to = '$zona' WHERE id = '$rule_lid' ;");

                        // Añadir en el log que hemos cogido la zona del [TP] Source
                        add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_lid . '] capturing zone from the Translated Address', $source, '', 'rules', $rule_lid, 'nat_rules');
                    }
                }
            }
            elseif ($type_sat_address == "interface-address") {
                $getZoneToInterface = $projectdb->query("SELECT zone FROM interfaces WHERE source = '$source' AND vsys = '$vsys' AND name = '$tp_sat_interface' LIMIT 1;");
                if ($getZoneToInterface->num_rows > 0) {
                    $getZTIData = $getZoneToInterface->fetch_assoc();
                    $zona_interface = $getZTIData['zone'];

                    $projectdb->query("UPDATE nat_rules SET op_zone_to = '$zona_interface' WHERE id = '$rule_id' ;");
                    add_log2('warning', 'Auto Zone Nat', 'Nat RuleID [' . $rule_id . '] capturing zone from the Translated Interfaces', $source, '', 'rules', $rule_lid, 'nat_rules');
                }
            }
        }//fin foreach
    }
}
*/

