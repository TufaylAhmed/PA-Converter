<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
error_reporting(E_ALL & ~E_NOTICE);

//require_once('./Authentication.php');
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once '../libs/shared.php';
require_once INC_ROOT.'/libs/common/palettes.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action      = (string)  (isset($_GET['action'])      ? $_GET['action'] : '');
        $type        = (string)  (isset($_GET['type'])        ? $_GET['type'] : ''); // zip / xml / device
        $project     = (string)  (isset($_GET['project'])     ? $_GET['project'] : '');
        $devicename  = (string)  (isset($_GET['devicename'])  ? $_GET['devicename'] : '');
        $start       = (integer) (isset($_GET['start'])       ? $_GET['start'] : '');
        $limit       = (integer) (isset($_GET['limit'])       ? $_GET['limit'] : '');
        $source      = (string)  (isset($_GET['source'])      ? $_GET['source'] : '');
        $vsys        = (string)  (isset($_GET['vsys'])        ? $_GET['vsys'] : '');
        $short       = (string)  (isset($_GET['short'])       ? $_GET['short'] : '');
        $filter      = (string)  (isset($_GET['filter'])      ? $_GET['filter'] : '');
        $id_cons     = (string)  (isset($_GET['id_cons'])     ? $_GET['id_cons'] : '');
        
        break;
    case 'POST':
        $action      = (string)  (isset($_POST['action'])      ? $_POST['action'] : '');
        $type        = (string)  (isset($_POST['type'])        ? $_POST['type'] : ''); // zip / xml / device
        $project     = (string)  (isset($_POST['project'])     ? $_POST['project'] : '');
        $devicename  = (string)  (isset($_POST['devicename'])  ? $_POST['devicename'] : '');
        $start       = (integer) (isset($_POST['start'])       ? $_POST['start'] : '');
        $limit       = (integer) (isset($_POST['limit'])       ? $_POST['limit'] : '');
        $source      = (string)  (isset($_POST['source'])      ? $_POST['source'] : '');
        $vsys        = (string)  (isset($_POST['vsys'])        ? $_POST['vsys'] : '');
        $short       = (string)  (isset($_POST['short'])       ? $_POST['short'] : '');
        $filter      = (string)  (isset($_POST['filter'])      ? $_POST['filter'] : '');
        $id_cons     = (string)  (isset($_POST['id_cons'])     ? $_POST['id_cons'] : '');
        break;

    default:
        $action      = (string)  (isset($_POST['action'])      ? $_POST['action'] : '');
        $type        = (string)  (isset($_POST['type'])        ? $_POST['type'] : ''); // zip / xml / device
        $project     = (string)  (isset($_POST['project'])     ? $_POST['project'] : '');
        $devicename  = (string)  (isset($_POST['devicename'])  ? $_POST['devicename'] : '');
        $start       = (integer) (isset($_POST['start'])       ? $_POST['start'] : '');
        $limit       = (integer) (isset($_POST['limit'])       ? $_POST['limit'] : '');
        $source      = (string)  (isset($_POST['source'])      ? $_POST['source'] : '');
        $vsys        = (string)  (isset($_POST['vsys'])        ? $_POST['vsys'] : '');
        $short       = (string)  (isset($_POST['short'])       ? $_POST['short'] : '');
        $filter      = (string)  (isset($_POST['filter'])      ? $_POST['filter'] : '');
        $id_cons     = (string)  (isset($_POST['id_cons'])     ? $_POST['id_cons'] : '');
        break;
}

global $projectdb;
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$source = $projectdb->real_escape_string($source);
$vsys = $projectdb->real_escape_string($vsys);
$short = $projectdb->real_escape_string($short);
$filter = $projectdb->real_escape_string($filter);
$id_cons = $projectdb->real_escape_string($id_cons);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit",PARSER_max_execution_memory);

$control = hasViewAccess($project);
if(! $control['permitted'])
    return $control['msg'];

if ($action=="get"){
    if($type=="rules" && $short == 'true'){
        $query ="SELECT id, name FROM security_rules WHERE source ='$source' AND vsys='$vsys' ORDER BY position";
        $result = $projectdb->query($query);
        $rules = array();
        if($result->num_rows >0){
            while($data = $result->fetch_assoc()){
                $rules[] = $data;
            }
        }

        $msg = [
            'total' => count($rules),
            'security' => $rules,
        ];
        echo json_encode($msg);
    }
    elseif ($type=="rules"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $ruleids = (string) (isset($_GET['new_cloned_rule']) ? $_GET['new_cloned_rule'] : '');
                $id_cons = (string) (isset($_GET['id_cons']) ? $_GET['id_cons'] : '');
                break;
            case 'POST':
                $ruleids = (string) (isset($_POST['new_cloned_rule']) ? $_POST['new_cloned_rule'] : '');
                $id_cons = (string) (isset($_POST['id_cons']) ? $_POST['id_cons'] : '');
                break;
            default:
                $ruleids = (string) (isset($_POST['new_cloned_rule']) ? $_POST['new_cloned_rule'] : '');
                $id_cons = (string) (isset($_POST['id_cons']) ? $_POST['id_cons'] : '');
                break;
        }

        $ruleids = $projectdb->real_escape_string($ruleids);
        $id_cons = $projectdb->real_escape_string($id_cons);

//        $sesysv = getVsysesDescIDs($projectdb,'shared',3);

        $vsyses = getVsyses($projectdb, $vsys, $source);
        $vsyses_filters = getVsyses($projectdb, $vsys, $source, 'quoted');
        $sesysv = array_reverse($vsyses);
        $secRulePacks = array();

        $rulesToPresent = array();

        //Step 1. Get the active security rules
        $colorPos = 900;
        $group_=0;
        foreach ($sesysv as $vsyse) {
            //Pre Rules
            //$color = $colorPalette['CreamyRed'][$colorPos];
            $color = $colorPalette['Pastel'][$colorPos];
            $colorPos -=200;
            $label = ($vsys == $vsyse) ? ("<i class=\"fa fa-map-marker\" style=\"font-size:16px; color:red;\" aria-hidden=\"true\"></i>&nbsp;<font color='#336989'><b>Pre-rulebase ".$vsyse."</b></font></u></b>") : "Pre-rulebase ".$vsyse;
            $rulesToPresent['pre'][$vsyse]['group'] = $group_;
            $rulesToPresent['pre'][$vsyse]['color'] = $color;
            $rulesToPresent['pre'][$vsyse]['label'] = $label;
            $rulesToPresent['pre'][$vsyse]['rules'] = getMatchingSecurityIds($ruleids, $source, $vsyse, $project, '0', $filter, $vsys, $id_cons);
            $rulesToPresent['pre'][$vsyse]['count'] = count($rulesToPresent['pre'][$vsyse]['rules']);
            $group_++;
        }

        $colorPos = 900 - (count($vsyses)-1)*200;
        foreach ($vsyses as $vsyse) {
            //Post Rules
            $color = $colorPalette['Pastel'][$colorPos];
            $colorPos += 200;
            $label = ($vsys == $vsyse) ? ("<i class=\"fa fa-map-marker\" style=\"font-size:16px; color:red;\" aria-hidden=\"true\"></i>&nbsp;<font color='#336989'><b>Post-rulebase ".$vsyse."</b></font></u></b>") : "Post-rulebase ".$vsyse;
            $rulesToPresent['post'][$vsyse]['group'] = $group_;
            $rulesToPresent['post'][$vsyse]['color'] = $color;
            $rulesToPresent['post'][$vsyse]['label'] = $label;
            $rulesToPresent['post'][$vsyse]['rules'] = getMatchingSecurityIds($ruleids, $source, $vsyse, $project, '1', $filter, $vsys, $id_cons);
            $rulesToPresent['post'][$vsyse]['count'] = count($rulesToPresent['post'][$vsyse]['rules']);
            $group_++;
        }

//        echo "Start: $start\t";
//        echo "Limit: $limit\n";
        $total = 0;
        foreach ($rulesToPresent['pre'] as $vsyse => $ruleToPresent){
            $amount = $ruleToPresent['count'];
            $total += $amount;

            if($limit <= 0){
                //We already collected all we needed to collect
                $rulesToPresent['pre'][$vsyse]['start'] = -1;
                $rulesToPresent['pre'][$vsyse]['length']= -1;
            }
            else{
                //We are still collecting
                if($start>0){
                    //we need to jump some entries still
                    if(($start-$amount)>0){
                        //We are jumping all this group, because it has less rules than the ones we are skipping
                        $rulesToPresent['pre'][$vsyse]['start'] = -1;
                        $rulesToPresent['pre'][$vsyse]['length']= -1;
                        $start -= $amount;
                    }
                    else{
                        $rulesToPresent['pre'][$vsyse]['start'] = $start;

                        if($amount - $start > $limit){
                            //We can collect all the rules from this group
                            $rulesToPresent['pre'][$vsyse]['length'] = $limit;
                            $limit = 0;
                        }
                        else{
                            //We can finish this group, but we still have rules to collect from the next group
                            $rulesToPresent['pre'][$vsyse]['length'] = $amount;
                            $limit -= ($amount - $start);
                        }
                        $start = 0;
                    }
                }
                else{
                    //We are already collecting from the begining
                    $rulesToPresent['pre'][$vsyse]['start'] = 0;
                    if($amount > $limit){
                        //We can collect all the rules from this group
                        $rulesToPresent['pre'][$vsyse]['length'] = $limit;
                        $limit = 0;
                    }
                    else{
                        $rulesToPresent['pre'][$vsyse]['length'] = $amount;
                        $limit -= $amount;
                    }
                }
            }
//            echo "$vsyse\t\tAmount: $amount\t Getting from ".$rulesToPresent['pre'][$vsyse]['start'] ." with ".$rulesToPresent['pre'][$vsyse]['length'] . "\t Start : $start\tLimit : $limit\n";
        }

        foreach ($rulesToPresent['post'] as $vsyse => $ruleToPresent){
            $amount = $ruleToPresent['count'];
            $total += $amount;

            if($amount == 0 || $limit <= 0){
                //We already collected all we needed to collect
                $rulesToPresent['post'][$vsyse]['start'] = -1;
                $rulesToPresent['post'][$vsyse]['length'] = -1;
            }
            else{
                //We are still collecting
                if($start>0){
                    //we need to jump some entries still
                    if(($start-$amount)>0){
                        //We are jumping all this group, because it has less rules than the ones we are skipping
                        $rulesToPresent['post'][$vsyse]['start'] = -1;
                        $rulesToPresent['post'][$vsyse]['length'] = -1;
                        $start -= $amount;
                    }
                    else{
                        $rulesToPresent['post'][$vsyse]['start'] = $start;

                        if($amount - $start > $limit){
                            //We can collect all the rules from this group
                            $rulesToPresent['post'][$vsyse]['length'] = $limit;
                            $limit = 0;
                        }
                        else{
                            //We can finish this group, but we still have rules to collect from the next group
                            $rulesToPresent['post'][$vsyse]['length'] = $amount;
                            $limit -= ($amount - $start);
                        }
                        $start = 0;
                    }
                }
                else{
                    //We are already collecting from the begining
                    $rulesToPresent['post'][$vsyse]['start'] = 0;
                    if($amount > $limit){
                        //We can collect all the rules from this group
                        $rulesToPresent['post'][$vsyse]['length'] = $limit;
                        $limit = 0;
                    }
                    else{
                        $rulesToPresent['post'][$vsyse]['length'] = $amount;
                        $limit -= $amount;
                    }
                }
            }
//            echo "$vsyse\t\tAmount: $amount\t Getting from ".$rulesToPresent['post'][$vsyse]['start'] ." with ".$rulesToPresent['post'][$vsyse]['length'] . "\t Start : $start\tLimit : $limit\n";
        }


        //Load all objects


        $inMemory = array();

        $rules = array();
        foreach ($rulesToPresent['pre'] as $vsyse => $ruleToPresent) {
            $ruleids = $ruleToPresent['rules'];
            $rules = array_merge($rules, array_slice($ruleids, $ruleToPresent['start'],$ruleToPresent['length']));
        }

        foreach ($rulesToPresent['post'] as $vsyse => $ruleToPresent) {
            $ruleids = $ruleToPresent['rules'];
            $rules = array_merge($rules, array_slice($ruleids, $ruleToPresent['start'],$ruleToPresent['length']));
        }

        if ((isset($rules) AND (count($rules)>0))){
            //Step 2. Get the ids ob the objects that will be requested
            /** SRC and DST */
            $query = "SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name UNION 
                  SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name";
            $result = $projectdb->query($query);
            if($result->num_rows > 0) {
                $listAddresses      = array();
                $listAddressGroups  = array();
                $listExternal       = array();
                $listRegions        = array();
                $listDefault_regions= array();
                while ($data = $result->fetch_assoc()) {
                    $table = $data['table_name'];
                    switch ($table) {
                        case "address":
                            $listAddresses[] = $data['member_lid'];
                            break;
                        case "address_groups_id":
                            $listAddressGroups[] = $data['member_lid'];
                            break;
                        case "regions":
                            $listRegions[] = $data['member_lid'];
                            break;
                        case "default_regions":
                            $listDefault_regions[] = $data['member_lid'];
                            break;
                        case "external_list":
                            $listExternal[] = $data['member_lid'];
                            break;
                        default:
                            break;
                    }
                }

//            $listAddresses = array_unique($listAddresses);
//            $listAddressGroups = array_unique($listAddressGroups);
//            $listRegions = array_unique($listRegions);
//            $listExternal = array_unique($listExternal);
                //Address
                if(count($listAddresses)>0) {
                    $query = "SELECT * FROM address WHERE id in (" . implode(',', $listAddresses) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['address'][$row['id']] = $row;
                    }
                }
                //AddGroups
                if(count($listAddressGroups)>0) {
                    $query = "SELECT * FROM address_groups_id WHERE id in (" . implode(',', $listAddressGroups) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['address_groups_id'][$row['id']] = $row;
                    }
                }
                //Regions
                if(count($listRegions)>0) {
                    $query = "SELECT * FROM regions WHERE id in (" . implode(',', $listRegions) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['regions'][$row['id']] = $row;
                    }
                }
                //ExternalLists
                if(count($listExternal)>0) {
                    $query = "SELECT * FROM external_list WHERE id in (" . implode(',', $listExternal) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['external_list'][$row['id']] = $row;
                    }
                }
                //Default Regions
                if(count($listDefault_regions)>0) {
                    $query = "SELECT * FROM default_regions WHERE id in (" . implode(',', $listDefault_regions) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['default_regions'][$row['id']] = $row;
                    }
                }
            }


            /** Services */
            $query = "SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name";
            $result = $projectdb->query($query);
            if($result->num_rows > 0){
                $listServices       = array();
                $listServiceGroups  = array();
                while ($data = $result->fetch_assoc()) {
                    $table = $data['table_name'];
                    switch ($table) {
                        case "services":
                            $listServices[] = $data['member_lid'];
                            break;
                        case "services_groups_id":
                            $listServiceGroups[] = $data['member_lid'];
                            break;
                        default:
                            break;
                    }
                }

//            $listServices = array_unique($listServices);
//            $listServiceGroups = array_unique($listServiceGroups);

                //Services
                if(count($listServices)>0) {
                    $query = "SELECT * FROM services WHERE id in (" . implode(',', $listServices) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['services'][$row['id']] = $row;
                    }
                }
                //Service Groups
                if(count($listServiceGroups)>0) {
                    $query = "SELECT * FROM services_groups_id WHERE id in (" . implode(',', $listServiceGroups) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['services_groups_id'][$row['id']] = $row;
                    }
                }
            }

            /** Applications */
            $query = "SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name";
            $result = $projectdb->query($query);
            if($result->num_rows > 0){
                $listApplications       = array();
                $listApplicationGroups  = array();
                $listApplicationFilters = array();
                $listDefaultApplications= array();
                while ($data = $result->fetch_assoc()) {
                    $table = $data['table_name'];
                    switch ($table) {
                        case "applications":
                            $listApplications[] = $data['member_lid'];
                            break;
                        case "applications_groups_id":
                            $listApplicationGroups[] = $data['member_lid'];
                            break;
                        case "applications_filters":
                            $listApplicationFilters[] = $data['member_lid'];
                            break;
                        case "default_applications":
                            $listDefaultApplications[] = $data['member_lid'];
                            break;
                        default:
                            break;
                    }
                }

//            $listApplications = array_unique($listApplications);
//            $listApplicationGroups = array_unique($listApplicationGroups);
//            $listApplicationFilters = array_unique($listApplicationFilters);
//            $listDefaultApplications = array_unique($listDefaultApplications);

                //Applications
                if(count($listApplications)>0) {
                    $query = "SELECT * FROM applications WHERE id in (" . implode(',', $listApplications) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['applications'][$row['id']] = $row;
                    }
                }
                //Application Groups
                if(count($listApplicationGroups)>0) {
                    $query = "SELECT * FROM applications_groups_id WHERE id in (" . implode(',', $listApplicationGroups) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['applications_groups_id'][$row['id']] = $row;
                    }
                }
                //Application Filters
                if(count($listApplicationFilters)>0) {
                    $query = "SELECT * FROM applications_filters WHERE id in (" . implode(',', $listApplicationFilters) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['applications_filters'][$row['id']] = $row;
                    }
                }
                //Default Application
                if(count($listDefaultApplications)>0) {
                    $query = "SELECT * FROM default_applications WHERE id in (" . implode(',', $listDefaultApplications) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['default_applications'][$row['id']] = $row;
                    }
                }
            }

            /** Zones */
            /*$query = "SELECT name FROM security_rules_from WHERE rule_lid in (".implode(',',$rules).") GROUP BY name UNION
                  SELECT name FROM security_rules_to   WHERE rule_lid in (".implode(',',$rules).") GROUP BY name";
            $result = $projectdb->query($query);
            if($result->num_rows > 0){
                $listZones       = array();
                while ($data = $result->fetch_assoc()) {
                    $listZones[] = $data['name'];
                }

                $listZones = array_unique($listZones);

                //Zones
                if(count($listZones)>0) {
                    $query = "SELECT * FROM zones WHERE id in (" . implode(',', $listZones) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['zones'][$row['id']] = $row;
                    }
                }
            } */

            /** Tags */
            $query = "SELECT member_lid, table_name FROM security_rules_tag WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name";
            $result = $projectdb->query($query);
            if($result->num_rows > 0){
                $listTags = array();
                while ($data = $result->fetch_assoc()) {
                    $table = $data['table_name'];
                    $listTags[] = $data['member_lid'];

                }

//            $listTags = array_unique($listTags);

                // Tags and Group Tags (PanOS 9.1)
                // Select all tags in memory because if necessary from tags and group tags
                //if(count($listTags)>0) {
                    //$query = "SELECT t.*, tc.color AS color_name FROM tag t, tag_colors tc WHERE t.id in (" . implode(',', $listTags) . ") AND t.color = tc.name";
                    $query = "SELECT t.*, tc.color AS color_name FROM tag t, tag_colors tc WHERE  t.color = tc.name";

                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['tag'][$row['id']] = $row;
                        $color = $row['color'];
                        //$inMemory['tag'][$row['id']]['rgb'] = $colorPalette['TagColors'][$color];
                        if ($color=="none"){
                            $inMemory['tag'][$row['id']]['rgb']="";
                        }
                        else{
                            $inMemory['tag'][$row['id']]['rgb'] = $row['color_name'];
                        }

                    }
                //}
            }

            /** Profiles */
            $query = "SELECT member_lid, table_name FROM security_rules_hip      WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name UNION 
                  SELECT member_lid, table_name FROM security_rules_profiles WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name";
            $result = $projectdb->query($query);
            if($result->num_rows > 0){
                $listProfiles       = array();
                $listProfilesGroups = array();
                while ($data = $result->fetch_assoc()) {
                    $table = $data['table_name'];
                    switch ($table) {
                        case "profiles":
                            $listProfiles[] = $data['member_lid'];
                            break;
                        case "profiles_groups":
                            $listProfilesGroups[] = $data['member_lid'];
                            break;
                        default:
                            break;
                    }
                }

//            $listProfiles = array_unique($listProfiles);
//            $listProfilesGroups = array_unique($listProfilesGroups);

                //Profiles
                $inMemory['profiles'][0] = array(
                    'id'=>0, 'name'=>'nohip',
                );
                if(count($listProfiles)>0) {
                    $query = "SELECT * FROM profiles WHERE id in (" . implode(',', $listProfiles) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['profiles'][$row['id']] = $row;
                    }
                }
                //Profiles Groups
                if(count($listProfilesGroups)>0) {
                    $query = "SELECT * FROM profiles_groups WHERE id in (" . implode(',', $listProfilesGroups) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['profiles_groups'][$row['id']] = $row;
                    }
                }
            }

            /** Add Images */
            getIconMemory($inMemory);


            /** Load the rule information */
//        print_r($rulesToPresent);
            foreach ($rulesToPresent['pre'] as $vsyse => $ruleToPresent) {
//            print_r($ruleToPresent);
                $ruleids = $ruleToPresent['rules'];
                $ruleids = array_slice($ruleids, $ruleToPresent['start'],$ruleToPresent['length']);
                if(count($ruleids)>0) {
                    $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '0', '', '', $ruleToPresent['color'], $ruleToPresent['group'], $ruleToPresent['label'], $inMemory);
                }
            }

            foreach ($rulesToPresent['post'] as $vsyse => $ruleToPresent) {
                $ruleids = $ruleToPresent['rules'];
                $ruleids = array_slice($ruleids, $ruleToPresent['start'],$ruleToPresent['length']);
                if(count($ruleids)>0) {
                    $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '1', '', '', $ruleToPresent['color'], $ruleToPresent['group'], $ruleToPresent['label'], $inMemory);
                }
            }
            $secRules = array();
            foreach($secRulePacks as $secRulePack){
                if (count($secRulePack['security'])>0) {
                    $secRules = array_merge($secRules, $secRulePack['security']);
                }
            }

        }
        else{
            $total=0;
            $secRules=array();
        }


        $result = [
            'total' => $total,
            'security' => $secRules,
        ];

        echo json_encode($result);
    }
    elseif ($type == "rules_known"){
    	
        $getRule=$projectdb->query("SELECT rule_id FROM phase2_known_apps GROUP BY rule_id;");
        if ($getRule->num_rows==1){
        	$data=$getRule->fetch_assoc();
        	$ruleids[]=$data['rule_id'];
            $vsyses = getVsyses($projectdb, $vsys, $source);

            $sesysv = array_reverse($vsyses);
            $secRulePacks = array();

            $group_ = 0;
            $colorPos = 900;
            foreach ($sesysv as $vsyse) {
                //Pre Rules
                $color = $colorPalette['Red'][$colorPos];
                $colorPos -=200;
//            $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '0', $start, $limit);
                $label = ($vsys == $vsyse) ? ("<i class=\"fa fa-map-marker\" style=\"font-size:16px; color:red;\" aria-hidden=\"true\"></i>&nbsp;<font color='#336989'><b>Pre-rulebase ".$vsyse."</b></font></u></b>") : "Pre-rulebase ".$vsyse;
                $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '0', '', '',$color, $group_, $label);
                $group_ ++;
            }

            $colorPos = 900 - (count($vsyses)-1)*200;
            foreach ($vsyses as $vsyse) {
                //Post Rules
                $color = $colorPalette['BlueGrey'][$colorPos];
                $colorPos += 200;
//            $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '1', $start, $limit);
                $label = ($vsys == $vsyse) ? ("<i class=\"fa fa-map-marker\" style=\"font-size:16px; color:red;\" aria-hidden=\"true\"></i>&nbsp;<font color='#336989'><b>Post-rulebase ".$vsyse."</b></font></u></b>") : "Post-rulebase ".$vsyse;
                $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '1', '', '',$color, $group_, $label);
                $group_ ++;
            }
            $secRules = array();
            foreach($secRulePacks as $secRulePack){
                if (count($secRulePack['security'])>0) {
                    $secRules = array_merge($secRules, $secRulePack['security']);
                }
            }

            $result = [
                'total' => $total,
                'security' => $secRules,
            ];

            echo json_encode($result);
//            $secRules = search_security_policies($ruleids,$source,$vsys,$project,$start,$limit);
        }
    }
    elseif ($type == "users_by_rulelid"){

        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_usr' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
         
            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid FROM security_rules_usr WHERE rule_lid IN ($lid) ;");
            if ($searchUsers->num_rows > 0) {	
                $data = array();
                $howmany = $searchUsers->num_rows;
                while ($row=$searchUsers->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = addslashes($row['name']);
                    $source = $row['source'];
                    $vsys = $row['vsys'];
                    $id = $row['id'];
                    
                    $isGroup = $projectdb->query("SELECT name FROM userid_group WHERE name = '$name' OR short_name = '$name';");
                    if ($isGroup->num_rows > 0) {
                        $image = 'user-groups.png';
                    }else{
                        $image = 'userp.png';
                    }
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'security_rules_usr' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'security_rules_usr', '$name', '$image','$vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT name, image AS img, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_usr' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data[] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, image AS img, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_usr' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    $howmany = $getBridgeData->num_rows;
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                    echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else {
            $getBridgeData = $projectdb->query("SELECT name, image AS img, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_usr' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
            if ($getBridgeData->num_rows >= 1) {
                $howmany = $getBridgeData->num_rows;
                while($getData = $getBridgeData->fetch_object()){
                    $data [] = $getData;
                }
                echo '{"total":"'.$howmany.'","rows":'.json_encode($data).'}'; 
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
		
    }
    elseif ($type == "from_by_rulelid"){
    	$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_from' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            
            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid FROM security_rules_from WHERE rule_lid IN ($lid);");

            if ($searchUsers->num_rows > 0) {	
                $data = array();
                $howmany = $searchUsers->num_rows;
                //while ($row = $searchUsers->fetch_object()){
                while ($row = $searchUsers->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'security_rules_from' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'security_rules_from', '$name', '', '0', '$user_id');");
                    }
                }

                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    $howmany = $getBridgeData->num_rows;
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                    echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }

        }
        else{
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
            if ($getBridgeData->num_rows >= 1) {
                $howmany = $getBridgeData->num_rows;
                while($getData = $getBridgeData->fetch_object()){
                    $data [] = $getData;
                }
                echo '{"total":"'.$howmany.'","rows":'.json_encode($data).'}'; 
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
        
    }
    elseif ($type == "to_by_rulelid"){
    	$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_to' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
         
            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid FROM security_rules_to WHERE rule_lid IN ($lid) ;");
            if ($searchUsers->num_rows > 0) {	
                $data = array();
                $howmany = $searchUsers->num_rows;
                while ($row = $searchUsers->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'security_rules_to' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image,  remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'security_rules_to', '$name', '', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_to' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_to' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    $howmany = $getBridgeData->num_rows;
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                    echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else{
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_to' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
            if ($getBridgeData->num_rows >= 1) {
                $howmany = $getBridgeData->num_rows;
                while($getData = $getBridgeData->fetch_object()){
                    $data [] = $getData;
                }
                echo '{"total":"'.$howmany.'","rows":'.json_encode($data).'}'; 
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type == "hip_by_rulelid"){

        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_hip' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
         
            $getHIP = $projectdb->query("SELECT id, source, vsys, table_name, member_lid, name, rule_lid FROM security_rules_hip WHERE rule_lid IN ($lid) ;");
            if ($getHIP->num_rows > 0){
                $Application = array();
                while($srv = $getHIP->fetch_assoc()){
                    $srv_table_name = $srv['table_name'];
                    $srv_member_lid = $srv['member_lid'];
                    $id = $srv['id'];
                    $rule_lid = $srv['rule_lid'];
                    if ($srv['name'] == "no-hip"){
                        $name="no-hip";
                        $image="shared_global-protect.gif";
                    }
                    else {
                        if ($srv_table_name=="profiles"){ 
                            $getSRV=$projectdb->query("SELECT name, vsys FROM profiles WHERE id='$srv_member_lid';");
                            $dataSRV=$getSRV->fetch_assoc();
                            $name=$dataSRV['name'];
                            $vsys_member=$dataSRV['vsys'];
                            if($vsys_member != "shared"){$image="global-protect.png";}else{$image="shared_global-protect.gif";}
                            $myip=$dataSRV['name'];
                        }
                    }
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$srv_member_lid' AND table_name_lid = '$srv_table_name' AND type = 'security_rules_hip' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$srv_member_lid', '$srv_table_name', 'security_rules_hip', '$name', '$image','$vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_hip' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $ids_sql = $getData['ids'];
                        $Application[]='{"img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'","id":"'.$ids_sql.'"}';
                    }
                }
                echo '{"total":"'.count($Application).'","rows":['.implode(",",$Application).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_hip' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $ids_sql = $getData['ids'];
                        $Application[]='{"img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'","id":"'.$ids_sql.'"}';
                    }
                    echo '{"total":"'.count($Application).'","rows":['.implode(",",$Application).']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else {
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_hip' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
            if ($getBridgeData->num_rows >= 1) {
                while($getData = $getBridgeData->fetch_assoc()){
                    $image_sql = $getData['image'];
                    $name_sql = $getData['name'];
                    $member_lid_sql = $getData['member_lid'];
                    $table_name_sql = $getData['table_name_lid'];
                    $source_sql = $getData['source'];
                    $vsys_sql = $getData['vsys'];
                    $ids_sql = $getData['ids'];
                    $Application[]='{"img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'","id":"'.$ids_sql.'"}';
                }
                echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Application).']}'; 
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type == "source_by_rulelid"){
    	$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_src' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            
            $getSource = $projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM security_rules_src WHERE rule_lid IN ($lid);");
            if ($getSource->num_rows>0){
                $Source=array();
                while($src=$getSource->fetch_assoc()){
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    $rule_lid = $src['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'security_rules_src' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$src_member_lid', '$src_table_name', 'security_rules_src', '$name', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source . '","vsys":"' . $vsys . '", "vsys_member":"' . $vsys_member . '", "id":"' . $ids_sql . '"}';
                    }
                }
                echo '{"total":"'.count($Source).'","rows":['.implode(",",$Source).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source . '","vsys":"' . $vsys . '", "vsys_member":"' . $vsys_member . '", "id":"' . $ids_sql . '"}';
                    }
                    echo '{"total":"' . count($Source) . '","rows":[' . implode(",", $Source) . ']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else{
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
            if ($getBridgeData->num_rows >= 1) {
                while($getData = $getBridgeData->fetch_assoc()){
                    $image_sql = $getData['image'];
                    $name_sql = $getData['name'];
                    $member_lid_sql = $getData['member_lid'];
                    $table_name_sql = $getData['table_name_lid'];
                    $source_sql = $getData['source'];
                    $vsys_sql = $getData['vsys'];
                    $vsys_member = $getData['vsys_member'];
                    $ids_sql = $getData['ids'];
                    $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source . '","vsys":"' . $vsys . '", "vsys_member":"' . $vsys_member . '", "id":"' . $ids_sql . '"}';
                }
                echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type == "destination_by_rulelid"){
    	$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_dst' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            $getSource = $projectdb->query("SELECT id,table_name,member_lid, rule_lid FROM security_rules_dst WHERE rule_lid IN ($lid) ;");
            if ($getSource->num_rows>0){
                $Source=array();
                while($src=$getSource->fetch_assoc()){
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    $rule_lid = $src['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'security_rules_dst' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$src_member_lid', '$src_table_name', 'security_rules_dst', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source . '","vsys":"' . $vsys . '", "vsys_member":"' . $vsys_member . '", "id":"' . $ids_sql . '"}';
                    }
                }
                echo '{"total":"'.count($Source).'","rows":['.implode(",",$Source).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source . '","vsys":"' . $vsys . '", "vsys_member":"' . $vsys_member . '", "id":"' . $ids_sql . '"}';
                    }
                    echo '{"total":"' . count($Source) . '","rows":[' . implode(",", $Source) . ']}';
                 }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else{
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
            if ($getBridgeData->num_rows >= 1) {
                while($getData = $getBridgeData->fetch_assoc()){
                    $image_sql = $getData['image'];
                    $name_sql = $getData['name'];
                    $member_lid_sql = $getData['member_lid'];
                    $table_name_sql = $getData['table_name_lid'];
                    $source_sql = $getData['source'];
                    $vsys_sql = $getData['vsys'];
                    $vsys_member = $getData['vsys_member'];
                    $ids_sql = $getData['ids'];
                    $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source . '","vsys":"' . $vsys . '", "vsys_member":"' . $vsys_member . '","id":"' . $ids_sql . '"}';
                }
                echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type == "target_by_rulelid") {

        $vsys = (string)(isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string)(isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string)(isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_target' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){

            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid, device_vsys FROM security_rules_target WHERE rule_lid IN ($lid) ;");
            if ($searchUsers->num_rows > 0) {
                $data = array();
                $howmany = $searchUsers->num_rows;
                while ($row = $searchUsers->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $device_vsys = $row['device_vsys'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'security_rules_target' AND name = '$name' AND vsys_member='$device_vsys' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'security_rules_target', '$name', '$vsys', '$device_vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT name, source, vsys as device_vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_target' AND remove = '0' AND user_id = '$user_id' ORDER BY name,vsys_member;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","target":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_target' AND remove = '0' AND user_id = '$user_id' ORDER BY name,vsys_member;");
                if ($getBridgeData->num_rows >= 1) {
                    $howmany = $getBridgeData->num_rows;
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                    echo '{"total":"'.count($data).'","target":'.json_encode($data).'}';
                }else{
                    echo '{"total":0,"target":[]}';
                }
            }
        }
        else{
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_target' AND remove = '0' AND user_id = '$user_id' ORDER BY name,vsys_member;");
            if ($getBridgeData->num_rows >= 1) {
                $howmany = $getBridgeData->num_rows;
                while($getData = $getBridgeData->fetch_object()){
                    $data [] = $getData;
                }
                echo '{"total":"'.$howmany.'","target":'.json_encode($data).'}';
            }else{
                echo '{"total":0,"target":[]}';
            }
        }

    }
    elseif ($type == "apps_by_rulelid"){
    	$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_app' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            $getApplications=$projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM security_rules_app WHERE rule_lid IN ($lid) ;");
            if ($getApplications->num_rows>0){
                $Application=array();
                while($srv=$getApplications->fetch_assoc()){
                    $srv_table_name = $srv['table_name'];
                    $srv_member_lid = $srv['member_lid'];
                    $id = $srv['id'];
                    $rule_lid = $srv['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("applications", $srv_table_name, $srv_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$srv_member_lid' AND table_name_lid = '$srv_table_name' AND type = 'security_rules_app' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$srv_member_lid', '$srv_table_name', 'security_rules_app', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member,ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_app' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Application[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                }
                echo '{"total":"'.count($Application).'","rows":['.implode(",",$Application).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member,ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_app' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Application[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                    echo '{"total":"'.count($Application).'","rows":['.implode(",",$Application).']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else{
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member,ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_app' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
            if ($getBridgeData->num_rows >= 1) {
                while($getData = $getBridgeData->fetch_assoc()){
                    $image_sql = $getData['image'];
                    $name_sql = $getData['name'];
                    $member_lid_sql = $getData['member_lid'];
                    $table_name_sql = $getData['table_name_lid'];
                    $source_sql = $getData['source'];
                    $vsys_sql = $getData['vsys'];
                    $vsys_member = $getData['vsys_member'];
                    $ids_sql = $getData['ids'];
                    $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source . '","vsys":"' . $vsys . '","id":"' . $ids_sql . '", "vsys_member":"' . $vsys_member . '"}';
                }
                echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type == "services_by_rulelid"){
    	$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_srv' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            $getServices=$projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM security_rules_srv WHERE rule_lid IN ($lid) ;");
            if ($getServices->num_rows>0){
                $Service=array();
                while($srv=$getServices->fetch_assoc()){
                    $srv_table_name = $srv['table_name'];
                    $srv_member_lid = $srv['member_lid'];
                    $id = $srv['id'];
                    $rule_lid = $srv['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("services", $srv_table_name, $srv_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$srv_member_lid' AND table_name_lid = '$srv_table_name' AND type = 'security_rules_srv' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$srv_member_lid', '$srv_table_name', 'security_rules_srv', '$name', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");

                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_srv' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Service[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'", "vsys_member":"' . $vsys_member . '"}';
                    }
                }
                echo '{"total":"'.count($Service).'","rows":['.implode(",",$Service).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_srv' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Service[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'", "vsys_member":"' . $vsys_member . '"}';
                    }
                    echo '{"total":"'.count($Service).'","rows":['.implode(",",$Service).']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else{
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member,ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_srv' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
            if ($getBridgeData->num_rows >= 1) {
                while($getData = $getBridgeData->fetch_assoc()){
                    $image_sql = $getData['image'];
                    $name_sql = $getData['name'];
                    $member_lid_sql = $getData['member_lid'];
                    $table_name_sql = $getData['table_name_lid'];
                    $source_sql = $getData['source'];
                    $vsys_sql = $getData['vsys'];
                    $vsys_member = $getData['vsys_member'];
                    $ids_sql = $getData['ids'];
                    $Service[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'", "vsys_member":"' . $vsys_member . '"}';
                }
                echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Service).']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type == "categories_by_rulelid"){
    	$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_categories' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            $searchCategories = $projectdb->query("SELECT id,source,vsys,name, rule_lid FROM security_rules_categories WHERE rule_lid IN ($lid) ;");
            if ($searchCategories->num_rows > 0){
                $data = array();
                $howmany = $searchCategories->num_rows;
                while ($row = $searchCategories->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $source = $row['source'];
                    $vsys = $row['vsys'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'security_rules_categories' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'security_rules_categories', '$name', '','$vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_categories' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_categories' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    $howmany = $getBridgeData->num_rows;
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                    echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else {
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_categories' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
            if ($getBridgeData->num_rows >= 1) {
                $howmany = $getBridgeData->num_rows;
                while($getData = $getBridgeData->fetch_object()){
                    $data [] = $getData;
                }
                echo '{"total":"'.$howmany.'","rows":'.json_encode($data).'}'; 
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }  
    }
    elseif ($type == "tags_by_rulelid"){
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $lid = $projectdb->real_escape_string($lid);

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_tag' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            $searchTag = $projectdb->query("SELECT srt.rule_lid as rule_lid, srt.member_lid as member_lid, tag.name as name, tag.color as color FROM security_rules_tag srt, tag WHERE srt.rule_lid IN ($lid) AND tag.id=srt.member_lid;");
            if ($searchTag->num_rows > 0) {
                $Tag = array();
                while ($Ttag=$searchTag->fetch_assoc()){
                    $tag_member_lid = $Ttag['member_lid'];
                    $tag_table_name='tag';
                    $rule_lid = $Ttag['rule_lid'];
                    $TagName=$Ttag['name'];
                    $realColor=$Ttag['color'];
                    $thenewtagcolor=$TagName;
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$tag_member_lid' AND table_name_lid = '$tag_table_name' AND name = '$TagName' AND type = 'security_rules_tag' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $image = "tags_$realColor.png";
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES ('NULL', '', '$rule_lid', '$tag_member_lid', '$tag_table_name', 'security_rules_tag', '$TagName', '$image','$vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_tag' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $ids_sql = $getData['member_lid'];
                        $Tag[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'"}';
                    }
                }
                echo '{"total":"'.count($Tag).'","rows":['.implode(",",$Tag).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'security_rules_tag' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $ids_sql = $getData['member_lid'];
                        $Tag[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source.'","vsys":"'.$vsys.'"}';
                    }
                    echo '{"total":"'.count($Tag).'","rows":['.implode(",",$Tag).']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
    }
    elseif ($type == "profiles"){

        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $profile_type = (string) (isset($_POST['profile_type']) ? $_POST['profile_type'] : $_GET['profile_type']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $profile_type = $projectdb->real_escape_string($profile_type);

        if ($profile_type=="virus"){$img="virus.gif"; $img_shared="shared_virus.gif";}
        elseif ($profile_type=="url-filtering"){$img="url_filter.gif"; $img_shared="shared_url_filter.gif";}
        elseif ($profile_type=="spyware"){$img="spyware.gif"; $img_shared="shared_spyware.gif";}
        elseif ($profile_type=="vulnerability"){$img="vulnerability.gif"; $img_shared="shared_vulnerability.gif";}
        elseif ($profile_type=="file-blocking"){$img="fileblocking.gif"; $img_shared="shared_fileblocking.gif";}
        elseif ($profile_type=="data-filtering"){$img="dlp_data_filter.gif"; $img_shared="shared_dlp_data_filter.gif";}
        elseif ($profile_type=="wildfire-analysis"){$img="wildfire_analysis.gif"; $img_shared="shared_wildfire_analysis.gif";}
        
        if ($source!="0"){$query="WHERE source='$source'";}
        else {$query="WHERE source!=''";}
        //if ($vsys!="all"){$query=$query."  AND (vsys='$vsys' OR vsys='shared')";}

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

        $getLimit=$projectdb->query("SELECT id AS idx, name, id, if (vsys = 'shared', '$img_shared', '$img') AS img 
            FROM profiles $query AND type='$profile_type' $sql_vsys;");
        $count=$getLimit->num_rows;
        $x=1;
        $myData[]=array("idx"=>0,"name"=>"None","img"=>$img);
        while ($data=$getLimit->fetch_object()){

            $data->idx=$data->id.";profiles";
            $data->id=$x++;
            $myData[]=$data;
        }
        if ($count==0){$count=1;}
        echo '{"total":"'.$count.'","rows":'.json_encode($myData).'}';
    }
    elseif ($type == "profiles_groups"){
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $profile_type = (string) (isset($_POST['profile_type']) ? $_POST['profile_type'] : $_GET['profile_type']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $profile_type = $projectdb->real_escape_string($profile_type);

        $img="profile_group.gif";
        $img_shared="shared_profile_group.gif";

        if ($source!="0"){$query="WHERE source='$source'";}
        else {$query="WHERE source!=''";}
        //if ($vsys!="all"){$query=$query."  AND (vsys='$vsys' OR vsys='shared')";}

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

        //$getLimit=$projectdb->query("SELECT id as idx, name, id, '$img' as img FROM profiles_groups $query;");
        $getLimit=$projectdb->query("SELECT id as idx, name, id, if (vsys = 'shared', '$img_shared', '$img') AS img FROM profiles_groups $query $sql_vsys;");
        
        $count=$getLimit->num_rows;
        $x=1;
        $myData[]=array("idx"=>0,"name"=>"None","id"=>0,"img"=>$img);
        while ($data=$getLimit->fetch_object()){

            $data->idx=$data->id.";profiles_groups";
            $data->id=$x++;
            $myData[]=$data;
        }
        if ($count==0){$count=1;}
        echo '{"total":"'.$count.'","rows":'.json_encode($myData).'}';
    }
    elseif ($type == "schedules"){
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);

        $img="schedules.png";
        $img_shared="shared_schedules.gif";

        if ($source!="0"){$query="WHERE source='$source'";}
        else {$query="WHERE source!=''";}
        //if ($vsys!="all"){$query=$query."  AND (vsys='$vsys' OR vsys='shared')";}

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

        //$getLimit=$projectdb->query("SELECT id as idx, name, id, '$img' as img FROM schedules $query;");
        $getLimit=$projectdb->query("SELECT id as idx, name, id, if (vsys = 'shared', '$img_shared', '$img') AS img FROM schedules $query $sql_vsys;");
        $count=$getLimit->num_rows;
        $x=1;
        $myData[]=array("idx"=>0,"name"=>"None","img"=>$img);
        while ($data=$getLimit->fetch_object()){

            $data->idx=$data->id.";schedules";
            $data->id=$x++;
            $myData[]=$data;
        }

        if ($count==0){$count=1;}
        echo '{"total":"'.$count.'","rows":'.json_encode($myData).'}';
    }
    elseif ($type == "log_forwarding"){
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);

        if ($source!="0"){ $query="WHERE source='$source'"; }
        else { $query="WHERE source!=''"; }

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

        if (preg_match("/WHERE/", $query)) {
            $query = $query . "  AND type='profiles' ";
        } else {
            $query = " WHERE type='profiles' ";
        }
        $getLimit=$projectdb->query("SELECT id as idx, name, id FROM log_settings $query $sql_vsys;");
        $count=$getLimit->num_rows;
        $x=1;
        $myData[]=array("idx"=>0,"name"=>"None");
        while ($data=$getLimit->fetch_object()){

            $data->idx=$data->id.";log_settings";
            $data->id=$x++;
            $myData[]=$data;
        }        
        if ($count==0){$count=1;}
        echo '{"total":"'.$count.'","rows":'.json_encode($myData).'}';
    }
}
elseif ($action=="set"){
    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to see this project contents';
        return $message;
    }
    if ($type=="remove_rule"){
            $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
            $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
            $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

            $vsys = $projectdb->real_escape_string($vsys);
            $source = $projectdb->real_escape_string($source);
            $ids = $projectdb->real_escape_string($ids);

            if ($ids!=""){
                take_snapshot_last($project);
                delete_security_rule($vsys,$source,$ids);
                $projectdb->query("DELETE FROM appid_rule_relation WHERE origin IN ($ids);");
                $projectdb->query("DELETE FROM appid_rule_relation WHERE clone IN ($ids);");
                $projectdb->query("DELETE FROM split_rules_unknown WHERE rule_lid IN ($ids);");

                add_log('ok', 'Remove Rules', 'Remove Security RulesID ['.$ids.'] ', $source, 'No Action Required', '2');
            }
    }
    elseif($type=="remove_target"){

        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $where_edit = (string) (isset($_POST['where']) ? $_POST['where'] : $_GET['where']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $ids = $projectdb->real_escape_string($ids);
        $where_edit = $projectdb->real_escape_string($where_edit);

        if($where_edit == "edit"){
            if ($ids != ""){

                $ids_explode = explode(",",$ids);

                foreach ($ids_explode AS $id_edit_table){
                    $getNameOld = $projectdb->query("SELECT name, vsys_member FROM edit_table WHERE id = '$id_edit_table' AND type = 'security_rules_target' AND user_id = '$user_id' AND remove = '0';");
                    if ($getNameOld->num_rows == 1) {
                        $dataNO = $getNameOld->fetch_assoc();
                        $name_old = $dataNO['name'];
                        $vsys_member_old = $dataNO['vsys_member'];
                    }

                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$name_old' AND vsys_member = '$vsys_member_old' AND source = '$source' AND type = 'security_rules_target' AND user_id = '$user_id';");
                }
            }
        }
        else{
            take_snapshot_last($project);
            if($ids != ""){
                $projectdb->query("DELETE FROM security_rules_target WHERE rule_lid IN ($ids);");
            }else{
                $projectdb->query("DELETE FROM security_rules_target WHERE source = '$source';");
            }

        }
        echo json_encode(array("success"=>true));
    }
    elseif ($type=="rename_duplicateds"){
            $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
            $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

            $vsys = $projectdb->real_escape_string($vsys);
            $source = $projectdb->real_escape_string($source);

            $getDupe=$projectdb->query("SELECT id,name, count(id) as t FROM security_rules WHERE source='$source' AND vsys='$vsys' GROUP by name HAVING t >1;");
            if ($getDupe->num_rows>0){
                    take_snapshot_last($project);
                    while($data=$getDupe->fetch_assoc()){
                            $name=$data['name'];
                            $rule_lid=$data['id'];
                            $x=1;
                            $getDupe2=$projectdb->query("SELECT id,name FROM security_rules WHERE source='$source' AND vsys='$vsys' AND name='$name' AND id!='$rule_lid';");
                            while($data2=$getDupe2->fetch_assoc()){
                                    $nameold=$data2['name'];
                                    $idold=$data2['id'];
                                    $namenew=$nameold."-".$x;
                                    $projectdb->query("UPDATE security_rules SET name='$namenew' WHERE id='$idold';");
                                    $x++;
                            }
                    }
            }
    }
    elseif ($type=="lock"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $ids = $projectdb->real_escape_string($ids);

        if ($ids!=""){
                take_snapshot_last($project);
                $projectdb->query("UPDATE security_rules SET blocked='1' WHERE id IN ($ids);");
                add_log('ok', 'Lock Rules', 'Lock Security RulesID ['.$ids.'] ', $source, 'No Action Required', '2');
        }
    }
    elseif ($type=="unlock"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $ids = $projectdb->real_escape_string($ids);

        if ($ids!=""){
                take_snapshot_last($project);
                $projectdb->query("UPDATE security_rules SET blocked='0' WHERE id IN ($ids);");
                add_log('ok', 'Unlock Rules', 'Unlick Security RulesID ['.$ids.'] ', $source, 'No Action Required', '2');
        }
    }
    elseif ($type=="save_position"){

        $ids    = (string)  (isset($_POST['ids'])    ? $_POST['ids']    : $_GET['ids']);
        $needle = (string)  (isset($_POST['id'])     ? $_POST['id']     : $_GET['id']);
        $moveto = (string)  (isset($_POST['moveto']) ? $_POST['moveto'] : $_GET['moveto']);

        $needle = $projectdb->real_escape_string($needle);
        $moveto = $projectdb->real_escape_string($moveto);
        $ids = $projectdb->real_escape_string($ids);

//        $ids = [4,5,1];
        require_once INC_ROOT.'/libs/common/rules/rules.php';
        $ids = json_decode($ids);
        $msg = moveRules($projectdb, $project, $source, $vsys, "security_rules", $ids, $moveto, $needle);
        echo json_encode($msg);
    }
    elseif ($type=="add_rule"){
            $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
            $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
            $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

            $vsys = $projectdb->real_escape_string($vsys);
            $source = $projectdb->real_escape_string($source);
            $ids = $projectdb->real_escape_string($ids);

            $initialPosition=intval($ids);
            $finalPosition=$initialPosition+1;

            if ($data=="0"){$initialPosition=1;$finalPosition=1;}
            if ($vsys==""){$vsys="vsys1";}
            if (($source!=0) AND ($vsys!="all")){
                    $projectdb->query("UPDATE security_rules SET position=position+1 WHERE position >= '$initialPosition' and source='$source' AND vsys='$vsys';");
                    $projectdb->query("INSERT INTO security_rules (source,vsys,disabled,log_end,action,position) values ('$source','$vsys','0','1','allow','$initialPosition');");
                    echo json_encode(array("success"=>true));
            }
            else {
                    echo json_encode(array("success"=>false));
            }
    }
    elseif ($type=="save_by_rulelid"){

        $vsys = $_POST['vsys'];
        $source = $_POST['source'];
        $name = $_POST['name'];
        $rule_lid = $_POST['rule_lid'];
        $description = $_POST['description'];
        $raction = $_POST['raction'];
        $negate_source = $_POST['negate_source'];
        $negate_destination = $_POST['negate_destination'];
        $log_start = $_POST['log_start'];
        $log_end = $_POST['log_end'];
        $dsri = $_POST['dsri'];
        $schedule = $_POST['schedule'];
        $qos = $_POST['qos'];
        $qos_value = $_POST['qos_value'];
        $profile_type = $_POST['profile_type'];
        $profiles_group = $_POST['profiles_group'];
        $profiles_antivirus = $_POST['profiles_antivirus'];
        $profiles_vulnerability = $_POST['profiles_vulnerability'];
        $profiles_spyware = $_POST['profiles_spyware'];
        $profiles_url = $_POST['profiles_url'];
        $profiles_fileblocking = $_POST['profiles_fileblocking'];
        $profiles_dlp = $_POST['profiles_dlp'];
        $profiles_wildfire = $_POST['profiles_wildfire'];
        $log_forwarding = $_POST['log_forwarding'];
        $rule_type = $_POST['rule_type'];
        $elements = array();
        $zone_from = $_POST['zone_from'];
        $zone_to = $_POST['zone_to'];
        $hip_profiles = $_POST['hip_profiles'];
        $url_category = $_POST['url_category'];
        $tags = $_POST['tags'];
        $target_negate = $_POST['target_negate'];
        $group_tag_id = $_POST['group_tag_id'];

        take_snapshot_last($project);

        if (($negate_source=="false") OR ($negate_source=="off")){$negate_source=0;}else{$negate_source=1;}
        if (($negate_destination=="false") OR ($negate_destination=="off")){$negate_destination=0;}else{$negate_destination=1;}
        if (($log_start=="false") OR ($log_start=="off")){$log_start=0;}else{$log_start=1;}
        if (($log_end=="false") OR ($log_end=="off")){$log_end=0;}else{$log_end=1;}
        if (($dsri=="false") OR ($dsri=="off")){$dsri=0;}else{$dsri=1;}
        if (isset($description)){$description=addslashes($description);}
        if ((!isset($target_negate)) OR ($target_negate=="")){$target_negate="no";}

        if ($rule_lid != "") {
            
            $query = "SELECT DISTINCT(type) FROM edit_table WHERE lid IN ($rule_lid) AND user_id = '$user_id' ;";
            $getTypeEdit = $projectdb->query($query);
            if ($getTypeEdit->num_rows > 0) {
                while($getTypeData = $getTypeEdit->fetch_assoc()){
                    
                    $type = $getTypeData['type'];
                    $names_edit = array();
                    
                    // Check event key remove from tagfield
                    if($type == "security_rules_from"){
                        $zone_from_explode = explode(",", $zone_from);
                        foreach ($zone_from_explode as $value) {
                            $names_edit[] = "'$value'";
                        }
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }
                    elseif($type == "security_rules_to"){
                        $zone_to_explode = explode(",", $zone_to);
                        foreach ($zone_to_explode as $value) {
                            $names_edit[] = "'$value'";
                        }
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }
                    elseif($type == "security_rules_hip"){
                        $hip_profiles_explode = explode(",", $hip_profiles);
                        foreach ($hip_profiles_explode as $value) {
                            $names_edit[] = "'$value'";
                        }
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }
                    elseif($type == "security_rules_categories"){
                        $url_category_explode = explode(",", $url_category);
                        foreach ($url_category_explode as $value) {
                            $names_edit[] = "'$value'";
                        }
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }
                    elseif($type == "security_rules_tag"){
                        $tags_explode = explode(",", $tags);
                        foreach ($tags_explode as $value) {
                            $names_edit[] = "'$value'";
                        }

                        //$projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND member_lid NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }
                    
                    // Add members to type of table to edit in edit
                    setMembersRules($rule_lid, $type, $vsys, $source, $user_id);

                }

                $securityRulesMan = new SecurityRulePANObject();
                $securityRulesMan->updateLayerLevel($projectdb, $rule_lid, $source);
            }
            
            if (preg_match("/,/",$rule_lid)){
                
                if ($raction==""){$addAction="";}else{$elements[]="action='$raction'";$addAction="action='$raction',";}
                if ($rule_type==""){$addType="";}else{$elements[]="rule_type='$rule_type'";$addType="rule_type='$rule_type',";}
                if ($log_forwarding==""){$addLogF="";
                }else{
                    if ($log_forwarding=="None"){$elements[]="log_forwarding=''";$addLogF="log_forwarding='',";
                    }else{$elements[]="log_forwarding='$log_forwarding'";$addLogF="log_forwarding='$log_forwarding',";}
                }
                if ($schedule==""){$addSchedules="";
                }else{
                    if ($schedule=="None"){$elements[]="schedule=''";$addSchedules="schedule='',";
                    }else{$elements[]="schedule='$schedule'";$addSchedules="schedule='$schedule',";}
                }
                
                if ($description != ""){$elements[]="description='$description'";}

                if(($group_tag_id == "") || ($group_tag_id == "None")){
                }else{
                    $elements[]="group_tag_id='$group_tag_id'";
                }

                if (($qos=="") AND ($qos_value=="")){$addQoS="";}else{$elements[]="qos='$qos',qos_value='$qos_value'";$addQoS="qos='$qos',qos_value='$qos_value',";}
                if ($profile_type==""){$addProfileType="";}else{$elements[]="profile_type='$profile_type'";$addProfileType="profile_type='$profile_type',";}
                if ($profiles_group==""){$addProfileGroup="";}else{$elements[]="profile_group='$profiles_group'";$addProfileGroup="profile_group='$profiles_group',";}
                if ($profile_type=="none"){$projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid IN ($rule_lid);");}
                //$projectdb->query("UPDATE security_rules SET $addAction $addType $addLogF $addQoS $addProfileType $addProfileGroup log_start='$log_start',log_end='$log_end' WHERE id IN ($rule_lid);");
                //$projectdb->query("UPDATE security_rules SET $addAction $addType $addLogF $addQoS $addProfileType $addProfileGroup WHERE id IN ($rule_lid);");
                if (count($elements)>0){
                    $projectdb->query("UPDATE security_rules SET ".implode(",",$elements)." WHERE id IN ($rule_lid);");
                    //print "UPDATE security_rules SET $addAction $addType $addLogF $addQoS $addProfileType $addProfileGroup WHERE id IN ($rule_lid);";
                }
            }
            else{

                $name = truncate_rulenames($name);

                if (($log_forwarding=="") || ($log_forwarding=="None")){$log_forwarding = "";}
                if (($schedule=="") || ($schedule=="None")){$schedule = "";}
                $projectdb->query("UPDATE security_rules 
                                          SET rule_type='$rule_type',name='$name',negate_source='$negate_source',
                                            negate_destination='$negate_destination',description='$description',
                                            action='$raction',log_start='$log_start',log_end='$log_end',log_forwarding='$log_forwarding',schedule='$schedule',
                                            dsri='$dsri',qos='$qos',qos_value='$qos_value',profile_type='$profile_type',profile_group='$profiles_group',target_negate='$target_negate', group_tag_id='$group_tag_id'
                                           WHERE id='$rule_lid';");
                if ($profile_type=="none"){$projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid ='$rule_lid';");}
            }
        }
        
    }
    elseif ($type=="clone"){
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);
        $position = (string) (isset($_POST['position']) ? $_POST['position'] : $_GET['position']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);
        $position = $projectdb->real_escape_string($position);

        $message = "";
        $rules = explode(",", $rule_lid);
        take_snapshot_last($project);
        foreach ($rules as $key => $value) {
            if ($rule_lid == 0) {
                $initialPosition = 0;
                $finalPosition = 1;
            } else {
                $initialPosition = "";
                $finalPosition = "";
            }
            if ($position == "above") {
                $finalPosition = "-1";
            }
            clone_security_rule($initialPosition, $finalPosition, $vsys, $source, $value, $message, $project);
        }
        echo json_encode(array("success" => true));
    } 
    /*elseif ($type=="pre_rules"){
            $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
            $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
            $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
            if ($ids!=""){
                    take_snapshot_last($project);
                    $projectdb->query("UPDATE security_rules SET preorpost='0' WHERE id IN ($ids);");
                    add_log('ok', 'Convert in Pre-Rules', 'Convert in Pre-Rules this Security RulesID ['.$ids.'] to Rule '.$lid.' ', $source, 'No Action Required', '2');
            }
    }
    elseif ($type=="post_rules"){
            $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
            $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
            $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
            if ($ids!=""){
                    take_snapshot_last($project);
                    $projectdb->query("UPDATE security_rules SET preorpost='1' WHERE id IN ($ids);");
                    add_log('ok', 'Convert in Post-Rules', 'Convert in Post-Rules this Security RulesID ['.$ids.'] to Rule '.$lid.' ', $source, 'No Action Required', '2');

            }
    }*/
    elseif ($type == "remove_from"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids != ""){
            $lids = explode(",", $ids);
            foreach ($lids as $key => $name){
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN ($rule_lid) AND name = '$name' AND type = 'security_rules_from' AND user_id = '$user_id';");
            } 
        }
    }
    elseif ($type == "remove_to"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids != ""){
            $lids = explode(",",$ids);
            foreach ($lids as $key => $name){
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN ($rule_lid) AND name = '$name' AND type = 'security_rules_to' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "remove_src"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids != ""){
            $rules = explode(",", $rule_lid);
            $idss = explode(",", $ids);
            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'security_rules_src' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                foreach ($rules as $key => $rule_lid){
                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid = '$rule_lid' AND type = 'security_rules_src' AND user_id = '$user_id';");
                }
            }
        }
    }
    elseif ($type == "remove_dst"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids!=""){
            $rules = explode(",", $rule_lid);
            $idss = explode(",", $ids);
            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'security_rules_dst' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                foreach ($rules as $key => $rule_lid){
                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid = '$rule_lid' AND type = 'security_rules_dst' AND user_id = '$user_id';");
                }
            }
        }
    }
    elseif ($type == "remove_usr"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids!=""){
            $lids = explode(",",$ids);
            foreach ($lids as $key => $name){
                $name = addslashes($name);
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN ($rule_lid) AND name = '$name' AND type = 'security_rules_usr' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "remove_categories"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids!=""){
            $lids = explode(",",$ids);
            foreach ($lids as $key => $name){
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN ($rule_lid) AND name = '$name' AND type = 'security_rules_categories' AND user_id = '$user_id';");
            }
        }
        
        
    }
    elseif ($type == "remove_hip"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids != ""){
            $lids = explode(",",$ids);
            foreach ($lids as $key => $member_lid_table){
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN ($rule_lid) AND member_lid = '$member_lid_table' AND type = 'security_rules_hip' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "remove_app"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids != ""){
            $rules = explode(",", $rule_lid);
            $idss = explode(",", $ids);
            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'security_rules_app' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                foreach ($rules as $key => $rule_lid){
                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid = '$rule_lid' AND type = 'security_rules_app' AND user_id = '$user_id';");
                }
            }
        }
    }
    elseif ($type == "remove_srv"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids != ""){
            $rules = explode(",", $rule_lid);
            $idss = explode(",", $ids);
            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                foreach ($rules as $key => $rule_lid){
                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid = '$rule_lid' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                }
            }
        }
    }
    elseif ($type == "remove_tag"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rule_lid = $projectdb->real_escape_string($rule_lid);

        if ($ids!=""){
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$ids' AND table_name_lid = 'tag' AND lid IN ($rule_lid) AND type = 'security_rules_tag' AND user_id = '$user_id';");
        }
    }
    elseif ($type == "set_shared"){

        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $sharedrule = (string) (isset($_POST['sharedrule']) ? $_POST['sharedrule'] : $_GET['sharedrule']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $sharedrule = $projectdb->real_escape_string($sharedrule);

        $vsys_member = "";

        if ($ids != ""){
            take_snapshot_last($project);
            $rule_ids = explode(',', $ids);
            
            $getFile = $projectdb->query("SELECT filename FROM device_mapping LIMIT 1;");
            if ($getFile->num_rows > 0){
                $getFileData = $getFile->fetch_assoc();
                $filename = $getFileData['filename'];
                
                $getShared = $projectdb->query("SELECT id FROM device_mapping WHERE filename = '$filename' AND vsys = 'shared';");
                if ($getShared->num_rows == 0){
                    
                    $getCamps = $projectdb->query("SELECT device, ispanorama, active, version, project, map_devicegroup, map_vsys, baseconfig, vendor, urldb FROM device_mapping WHERE filename = '$filename' AND vsys = '$vsys';");
                    if ($getCamps->num_rows > 0){
                        $getCampsData = $getCamps->fetch_assoc();
                        $device = $getCampsData['device'];
                        $ispanorama = $getCampsData['ispanorama'];
                        $active = $getCampsData['active'];
                        $version = $getCampsData['version'];
                        $project = $getCampsData['project'];
                        $map_devicegroup = $getCampsData['map_devicegroup'];
                        $map_vsys = $getCampsData['map_vsys'];
                        $baseconfig = $getCampsData['baseconfig'];
                        $vendor = $getCampsData['vendor'];
                        $urldb = $getCampsData['urldb'];
                        
                    }
                    $projectdb->query("INSERT INTO device_mapping (device, ispanorama, active, version, project, vsys, map_devicegroup, map_vsys, baseconfig, vendor, urldb) "
                            . " VALUES ('$device', '$ispanorama', '$active', '$version', '$project', 'shared', '$map_devicegroup', '$map_vsys', '$baseconfig', '$vendor', '$urldb');"); 
                }
            }
        
            foreach ($rule_ids as $rule_lid){
                /***********************/   
                // DUPLICATE OBJECTS    /
                /***********************/
                if($sharedrule == "duplicate"){
                    
                    $getSRC = $projectdb->query("SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid = '$rule_lid';");
                    if ($getSRC->num_rows > 0){
                        while ($getSRCData = $getSRC->fetch_assoc()){
                            $members = array();
                            $member_lid = $getSRCData['member_lid'];
                            $table_name = $getSRCData['table_name'];
                            
                            $members[] = $member_lid;

                            if($table_name != "default_regions"){
                                $getVsysMember = $projectdb->query("SELECT vsys FROM $table_name WHERE id='$member_lid';");
                                $dataVsysMember = $getVsysMember->fetch_assoc();
                                $vsys_member = $dataVsysMember['vsys'];
                            }

                            if (preg_match("/address/i", $table_name)) {
                                
                                if ($vsys_member == "shared") {continue;
                                }else{
                                    if(preg_match("/groups/i", $table_name)){
                                        $duplicate_group_member_lid = duplicateAddressGroupsToShared($source, $members);
                                        if($duplicate_group_member_lid != "0") {
                                            $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_src WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_group_member_lid' AND table_name = 'address_group_id';");
                                            if ($getExistMember->num_rows == 0) {
                                                $projectdb->query("UPDATE security_rules_src SET member_lid='$duplicate_group_member_lid', table_name='address_groups_id' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                            } else {
                                                $projectdb->query("DELETE FROM security_rules_src WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                            }
                                        }
                                    }
                                    else{
                                        $duplicate_member_lid = cloneAddress($source, "", "shared", $members);
                                        if($duplicate_member_lid != "0"){
                                            $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_src WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'address';");
                                            if ($getExistMember->num_rows == 0){
                                                $projectdb->query("UPDATE security_rules_src SET member_lid='$duplicate_member_lid', table_name='address' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                            }else{
                                                $projectdb->query("DELETE FROM security_rules_src WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                            }
                                        }
                                    }
                                }
                            }
                            else{
                                if (preg_match("/regions/i", $table_name)) {
                                    
                                    if ($vsys_member == "shared") {continue;
                                    }else{
                                        if (preg_match("/default/i", $table_name)) {continue;
                                        }else{
                                            $duplicate_member_lid = cloneRegions($source, "", "shared", $members);
                                            if($duplicate_member_lid != "0"){
                                                $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_src WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'regions';");
                                                if ($getExistMember->num_rows == 0){
                                                    $projectdb->query("UPDATE security_rules_src SET member_lid = '$duplicate_member_lid', table_name = 'regions' WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';");
                                                }else{
                                                    $projectdb->query("DELETE FROM security_rules_src WHERE rule_lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name = '$table_name'");
                                                }
                                            }
                                        }
                                    }
                                }
                                elseif(preg_match("/external/i", $table_name)){
                                    if ($vsys_member == "shared") {continue;
                                    }else{
                                        $duplicate_member_lid = cloneExternalList($source, "", "shared", $members);
                                        if($duplicate_member_lid != "0"){
                                            $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_src WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'external_list';");
                                            if ($getExistMember->num_rows == 0){
                                                $projectdb->query("UPDATE security_rules_src SET member_lid = '$duplicate_member_lid', table_name = 'external_list' WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';");
                                            }else{
                                                $projectdb->query("DELETE FROM security_rules_src WHERE rule_lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name = '$table_name'");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    $getDST = $projectdb->query("SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid = '$rule_lid';");
                    if ($getDST->num_rows > 0){
                        while ($getDSTData = $getDST->fetch_assoc()){

                            $members = array();
                            $member_lid = $getDSTData['member_lid'];
                            $table_name = $getDSTData['table_name'];

                            $members[] = $member_lid;

                            if($table_name != "default_regions"){
                                $getVsysMember = $projectdb->query("SELECT vsys FROM $table_name WHERE id='$member_lid';");
                                $dataVsysMember = $getVsysMember->fetch_assoc();
                                $vsys_member = $dataVsysMember['vsys'];
                            }

                            if (preg_match("/address/i", $table_name)) {

                                if ($vsys_member == "shared") {continue;
                                }else{
                                    if(preg_match("/groups/i", $table_name)){
                                        $duplicate_group_member_lid = duplicateAddressGroupsToShared($source, $members);
                                        if($duplicate_group_member_lid != "0"){
                                            $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_dst WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_group_member_lid' AND table_name = 'address_group_id';");
                                            if ($getExistMember->num_rows == 0){
                                                $projectdb->query("UPDATE security_rules_dst SET member_lid='$duplicate_group_member_lid', table_name='address_groups_id' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                            }else{
                                                $projectdb->query("DELETE FROM security_rules_dst WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                            }
                                        }
                                    }
                                    else{
                                        $duplicate_member_lid = cloneAddress($source, "", "shared", $members);
                                        if($duplicate_member_lid != "0"){
                                            $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_dst WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'address';");
                                            if ($getExistMember->num_rows == 0){
                                                $projectdb->query("UPDATE security_rules_dst SET member_lid='$duplicate_member_lid', table_name='address' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                            }else{
                                                $projectdb->query("DELETE FROM security_rules_dst WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name';");
                                            }
                                        }
                                    }
                                }
                            }
                            else{
                                if (preg_match("/regions/i", $table_name)) {

                                    if ($vsys_member == "shared") {continue;
                                    }else{
                                        if (preg_match("/default/i", $table_name)) {continue;
                                        }else{
                                            $duplicate_member_lid = cloneRegions($source, "", "shared", $members);
                                            if($duplicate_member_lid != "0"){
                                                $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_dst WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'regions';");
                                                if ($getExistMember->num_rows == 0){
                                                    $projectdb->query("UPDATE security_rules_dst SET member_lid = '$duplicate_member_lid', table_name = 'regions' WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';");
                                                }else{
                                                    $projectdb->query("DELETE FROM security_rules_dst WHERE rule_lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name = '$table_name'");
                                                }
                                            }
                                        }
                                    }
                                }
                                elseif(preg_match("/external/i", $table_name)){
                                    if ($vsys_member == "shared") {continue;
                                    }else{
                                        $duplicate_member_lid = cloneExternalList($source, "", "shared", $members);
                                        if($duplicate_member_lid != "0"){
                                            $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_dst WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'external_list';");
                                            if ($getExistMember->num_rows == 0){
                                                $projectdb->query("UPDATE security_rules_dst SET member_lid = '$duplicate_member_lid', table_name = 'external_list' WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';");
                                            }else{
                                                $projectdb->query("DELETE FROM security_rules_dst WHERE rule_lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name = '$table_name'");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    $getSRV = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$rule_lid';");
                    if ($getSRV->num_rows > 0){
                        while ($getSRVData = $getSRV->fetch_assoc()){

                            $members = array();
                            $member_lid = $getSRVData['member_lid'];
                            $table_name = $getSRVData['table_name'];

                            $members[] = $member_lid;
                            
                            $getVsysMember = $projectdb->query("SELECT vsys FROM $table_name WHERE id='$member_lid';");
                            $dataVsysMember = $getVsysMember->fetch_assoc();
                            $vsys_member = $dataVsysMember['vsys'];
                            
                            if ($vsys_member == "shared") {continue;
                            }else{
                                if(preg_match("/groups/i", $table_name)){
                                    $duplicate_group_member_lid = duplicateServicesGroupsToShared($source, $members);
                                    if($duplicate_group_member_lid != "0"){
                                        $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_srv WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_group_member_lid' AND table_name = 'services_group_id';");
                                        if ($getExistMember->num_rows == 0){
                                            $projectdb->query("UPDATE security_rules_srv SET member_lid='$duplicate_group_member_lid', table_name='services_groups_id' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                        }else{
                                            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                        }
                                    }
                                }
                                else{
                                    $duplicate_member_lid = cloneServices($source, "", "shared", $members);
                                    if($duplicate_member_lid != "0"){
                                        $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_srv WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'services';");
                                        if ($getExistMember->num_rows == 0){
                                            $projectdb->query("UPDATE security_rules_srv SET member_lid='$duplicate_member_lid', table_name='services' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                        }else{
                                            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    $getAPP = $projectdb->query("SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid = '$rule_lid';");
                    if ($getAPP->num_rows > 0){
                        while ($getAPPData = $getAPP->fetch_assoc()){

                            $members = array();
                            $member_lid = $getAPPData['member_lid'];
                            $table_name = $getAPPData['table_name'];

                            $members[] = $member_lid;

                            if($table_name != "default_applications"){
                                $getVsysMember = $projectdb->query("SELECT vsys FROM $table_name WHERE id='$member_lid';");
                                $dataVsysMember = $getVsysMember->fetch_assoc();
                                $vsys_member = $dataVsysMember['vsys'];
                            }

                            if ($vsys_member == "shared") {continue;
                            }else{
                                if(preg_match("/groups/i", $table_name)){
                                    $duplicate_group_member_lid = duplicateApplicationsGroupsToShared($source, $members);
                                    if($duplicate_group_member_lid != "0"){
                                        $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_app WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_group_member_lid' AND table_name = 'applications_group_id';");
                                        if ($getExistMember->num_rows == 0){
                                            $projectdb->query("UPDATE security_rules_app SET member_lid='$duplicate_group_member_lid', table_name='applications_group_id' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                        }else{
                                            $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                        }
                                    }
                                }else{
                                    if (preg_match("/default/i", $table_name)) {continue;
                                    }else{
                                        if (preg_match("/filters/i", $table_name)) {
                                            //$duplicate_member_lid = duplicateApplicationsFiltersToShared($source, $members);
                                            $duplicate_member_lid = cloneApplicationsFilters($source, "", "shared", $members);
                                            if($duplicate_member_lid != "0"){
                                                $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_app WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'applications_filters';");
                                                if ($getExistMember->num_rows == 0){
                                                    $projectdb->query("UPDATE security_rules_app SET member_lid='$duplicate_member_lid', table_name='applications_filters' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                                }else{
                                                    $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                                }
                                            }
                                        }else{
                                            //$duplicate_member_lid = duplicateApplicationsToShared($source, $members);
                                            $duplicate_member_lid = cloneApplications($source, "", "shared", $members);
                                            if($duplicate_member_lid != "0"){
                                                $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_app WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'applications';");
                                                if ($getExistMember->num_rows == 0){
                                                    $projectdb->query("UPDATE security_rules_app SET member_lid='$duplicate_member_lid', table_name='applications' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                                }else{
                                                    $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                                }
                                            }
                                        }  
                                    }
                                }
                            }
                        }
                    }
                    
                    $getTAG = $projectdb->query("SELECT member_lid, table_name FROM security_rules_tag WHERE rule_lid = '$rule_lid';");
                    if ($getTAG->num_rows > 0){
                        while ($getTAGData = $getTAG->fetch_assoc()){

                            $members = array();
                            $member_lid = $getTAGData['member_lid'];
                            $table_name = $getTAGData['table_name'];

                            $members[] = $member_lid;

                            $getVsysMember = $projectdb->query("SELECT vsys FROM $table_name WHERE id='$member_lid';");
                            $dataVsysMember = $getVsysMember->fetch_assoc();
                            $vsys_member = $dataVsysMember['vsys'];
                            
                            if ($vsys_member == "shared") {continue;
                            }else{
                                //$duplicate_member_lid = duplicateTagToShared($source, $members);
                                $duplicate_member_lid = cloneTags($source, "", "shared", $members);
                                if($duplicate_member_lid != "0"){
                                    $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_tag WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'tag';");
                                    if ($getExistMember->num_rows == 0){
                                        $projectdb->query("UPDATE security_rules_tag SET member_lid='$duplicate_member_lid', table_name='tag' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                    }else{
                                        $projectdb->query("DELETE FROM security_rules_tag WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                    }
                                }
                            }
                        }
                    }
                    
                    $getHIP = $projectdb->query("SELECT member_lid, table_name FROM security_rules_hip WHERE rule_lid = '$rule_lid';");
                    if ($getHIP->num_rows > 0){
                        while ($getHIPData = $getHIP->fetch_assoc()){

                            $members = array();
                            $member_lid = $getHIPData['member_lid'];
                            $table_name = $getHIPData['table_name'];

                            $members[] = $member_lid;
                            
                            $getVsysMember = $projectdb->query("SELECT vsys FROM $table_name WHERE id='$member_lid';");
                            $dataVsysMember = $getVsysMember->fetch_assoc();
                            $vsys_member = $dataVsysMember['vsys'];
                            
                            if ($vsys_member == "shared") {continue;
                            }else{
                                if(preg_match("/groups/i", $table_name)){
                                    $duplicate_group_member_lid = duplicateProfilesGroupsToShared($source, $members);
                                    if($duplicate_group_member_lid != "0"){
                                        $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_hip WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_group_member_lid' AND table_name = 'profiles_groups';");
                                        if ($getExistMember->num_rows == 0){
                                            $projectdb->query("UPDATE security_rules_hip SET member_lid='$duplicate_group_member_lid', table_name='profiles_groups' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                        }else{
                                            $projectdb->query("DELETE FROM security_rules_hip WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                        }
                                    }
                                }else{
                                    $duplicate_member_lid = cloneProfiles($source, "", "shared", $members);
                                    if($duplicate_member_lid != "0"){
                                        $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_hip WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'profiles';");
                                        if ($getExistMember->num_rows == 0){
                                            $projectdb->query("UPDATE security_rules_hip SET member_lid='$duplicate_member_lid', table_name='profiles' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                        }else{
                                            $projectdb->query("DELETE FROM security_rules_hip WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    $getPROFILES = $projectdb->query("SELECT member_lid, table_name FROM security_rules_profiles WHERE rule_lid = '$rule_lid';");
                    if ($getPROFILES->num_rows > 0){
                        while ($getPROFILESData = $getPROFILES->fetch_assoc()){

                            $members = array();
                            $member_lid = $getPROFILESData['member_lid'];
                            $table_name = $getPROFILESData['table_name'];

                            $members[] = $member_lid;
                            
                            $getVsysMember = $projectdb->query("SELECT vsys FROM $table_name WHERE id='$member_lid';");
                            $dataVsysMember = $getVsysMember->fetch_assoc();
                            $vsys_member = $dataVsysMember['vsys'];
                            
                            if ($vsys_member == "shared") {continue;
                            }else{
                                if(preg_match("/groups/i", $table_name)){
                                    $duplicate_group_member_lid = duplicateProfilesGroupsToShared($source, $members);
                                    if($duplicate_group_member_lid != "0"){
                                        $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_profiles WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_group_member_lid' AND table_name = 'profiles_groups';");
                                        if ($getExistMember->num_rows == 0){
                                            $projectdb->query("UPDATE security_rules_profiles SET member_lid='$duplicate_group_member_lid', table_name='profiles_groups' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                        }else{
                                            $projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                        }
                                    }
                                }else{
                                    $duplicate_member_lid = cloneProfiles($source, "", "shared", $members);
                                    if($duplicate_member_lid != "0"){
                                        $getExistMember = $projectdb->query("SELECT rule_lid, member_lid, table_name, source FROM security_rules_profiles WHERE rule_lid = '$rule_lid' AND member_lid = '$duplicate_member_lid' AND table_name = 'profiles';");
                                        if ($getExistMember->num_rows == 0){
                                            $projectdb->query("UPDATE security_rules_profiles SET member_lid='$duplicate_member_lid', table_name='profiles' WHERE member_lid='$member_lid' AND table_name='$table_name' AND rule_lid = '$rule_lid';");
                                        }else{
                                            $projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid = '$rule_lid' AND member_lid='$member_lid' AND table_name='$table_name'");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                /***********************/   
                // REPLACE OBJECTS      /
                /***********************/
                }
                elseif($sharedrule == "replace"){

                    $members_Address= array();
                    $members_AddressGroups= array();
                    $members_Regions= array();
                    $members_External= array();

                    $members_Services= array();
                    $members_ServiceGroups= array();
                    $members_Applications= array();
                    $members_ApplicationGroups= array();
                    $members_ApplicationFilters= array();
                    $members_Profiles= array();
                    $members_ProfileGroups= array();
                    $members_Tags= array();
                    // Coger todos los miembros, member_lid y table_name y convertirlos a shared.
                    $getSRC = $projectdb->query("SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid = '$rule_lid';");
                    if ($getSRC->num_rows > 0){
                        while ($getSRCData = $getSRC->fetch_assoc()){
                            $member_lid = $getSRCData['member_lid'];
                            $table_name = $getSRCData['table_name'];

                            if (preg_match("/address/i", $table_name)) {
                                if(preg_match("/groups/i", $table_name)){
                                    $members_AddressGroups[] = $member_lid;
                                }
                                else{
                                    $members_Address[] = $member_lid;
                                }
                            }
                            else{
                                if (preg_match("/regions/i", $table_name)) {
                                    if (preg_match("/default/i", $table_name)) {continue;}
                                    else{
                                        $members_Regions[] = $member_lid;
                                    }
                                }
                                elseif (preg_match("/external/i", $table_name)) {
                                    $members_External[] = $member_lid;
                                }
                            }
                        }
                    }

                    $getDST = $projectdb->query("SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid = '$rule_lid';");
                    if ($getDST->num_rows > 0){
                        while ($getDSTData = $getDST->fetch_assoc()){
                            $member_lid = $getDSTData['member_lid'];
                            $table_name = $getDSTData['table_name'];

                            if (preg_match("/address/i", $table_name)) {
                                if(preg_match("/groups/i", $table_name)){
                                    $members_AddressGroups[] = $member_lid;
                                }
                                else{
                                    $members_Address[] = $member_lid;
                                }
                            }else{
                                if (preg_match("/regions/i", $table_name)) {
                                    if (preg_match("/default/i", $table_name)) {continue;}
                                    else{
                                        $members_Regions[] = $member_lid;
                                    }
                                }
                                elseif (preg_match("/external/i", $table_name)) {
                                    $members_External[] = $member_lid;
                                }
                            }
                        }
                    }

                    $getSRV = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$rule_lid';");
                    if ($getSRV->num_rows > 0){
                        while ($getSRVData = $getSRV->fetch_assoc()){
                            $member_lid = $getSRVData['member_lid'];
                            $table_name = $getSRVData['table_name'];
                            
                            if(preg_match("/groups/i", $table_name)){
                                $members_ServiceGroups[] = $member_lid;
                            }
                            else{
                                $members_Services[] = $member_lid;
                            }
                        }
                    }
                    
                    $getAPP = $projectdb->query("SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid = '$rule_lid';");
                    if ($getAPP->num_rows > 0){
                        while ($getAPPData = $getAPP->fetch_assoc()){
                            $member_lid = $getAPPData['member_lid'];
                            $table_name = $getAPPData['table_name'];

                            if(preg_match("/groups/i", $table_name)){
                                $members_ApplicationGroups[] = $member_lid;
                            }
                            else{
                                if (preg_match("/default/i", $table_name)) {continue;}
                                else{
                                    if (preg_match("/filters/i", $table_name)) {
                                        $members_ApplicationFilters[] = $member_lid;
                                    }
                                    else{
                                        $members_Applications[] = $member_lid;
                                    }
                                }
                            }
                        }
                    }
                    
                    $getTAG = $projectdb->query("SELECT member_lid, table_name FROM security_rules_tag WHERE rule_lid = '$rule_lid';");
                    if ($getTAG->num_rows > 0){
                        while ($getTAGData = $getTAG->fetch_assoc()){
                            $member_lid = $getTAGData['member_lid'];
                            $members_Tags[] = $member_lid;
                        }
                    }
                    
                    $getHIP = $projectdb->query("SELECT member_lid, table_name FROM security_rules_hip WHERE rule_lid = '$rule_lid';");
                    if ($getHIP->num_rows > 0){
                        while ($getHIPData = $getHIP->fetch_assoc()){
                            $member_lid = $getHIPData['member_lid'];
                            $table_name = $getHIPData['table_name'];
                            if(preg_match("/groups/i", $table_name)){
                                $members_ProfileGroups[] = $member_lid;
                            }
                            else{
                                $members_Profiles[] = $member_lid;
                            }
                        }
                    }

                    if(count($members_AddressGroups)>0) {
                        convertAddressGroupsToShared($source, $members_AddressGroups, "notall");
                    }
                    if(count($members_Address)>0) {
                        convertAddressToShared($source, $members_Address, "notall");
                    }
                    if(count($members_Regions)>0) {
                        convertRegionsToShared($source, $members_Regions, "notall");
                    }
                    if(count($members_External)>0) {
                        convertExternalToShared($source, $members_External, "notall");
                    }
                    if(count($members_ServiceGroups)>0) {
                        convertServicesGroupsToShared($source, $members_ServiceGroups, "notall");
                    }
                    if(count($members_Services)>0) {
                        convertServicesToShared($source, $members_Services, "notall");
                    }
                    if(count($members_ApplicationGroups)>0) {
                        convertApplicationsGroupsToShared($source, $members_ApplicationGroups, "notall");
                    }
                    if (count($members_ApplicationFilters)>0) {
                        convertApplicationsFiltersToShared($source, $members_ApplicationFilters, "notall");
                    }
                    if(count($members_Applications)>0) {
                        convertApplicationsToShared($source, $members_Applications, "notall");
                    }
                    if(count($members_Tags)>0) {
                        convertTagToShared($source, $members_Tags, "notall");
                    }
                    if(count($members_ProfileGroups)>0){
                        convertProfilesGroupsToShared($source, $members_ProfileGroups, "notall");
                    }
                    if(count($members_Profiles)>0) {
                        convertProfilesToShared($source, $members_Profiles, "notall");
                    }
                }
                
                $projectdb->query("UPDATE security_rules SET vsys = 'shared' WHERE id = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_src SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_dst SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_srv SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_tag SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_hip SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_app SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_profiles SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_to SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_from SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_categories SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                $projectdb->query("UPDATE security_rules_usr SET vsys = 'shared' WHERE rule_lid = '$rule_lid';");
                
            }
        }
    }
}
elseif ($action=="replace"){

    if ($type=="dm_inline_by_member"){
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $rules = (string) (isset($_POST['rules']) ? $_POST['rules'] : $_GET['rules']);

        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $source = $projectdb->real_escape_string($source);
        $rules = $projectdb->real_escape_string($rules);

        ini_set('max_execution_time', 10000);
        ini_set("memory_limit", "1000M");
        if ($ids!=""){
            take_snapshot_last($project);
            $lids=explode(",",$ids);
            foreach ($lids as $key => $rule_lid){
                replace_dminline_by_members($vsys,$source,$rule_lid,$rules);
            }
        }
        else{
            $getRules=$projectdb->query("SELECT id FROM security_rules WHERE source='$source' AND vsys='$vsys';");
            if ($getRules->num_rows>0){
                while ($getRulesData=$getRules->fetch_assoc()){
                    $rule_lid=$getRulesData['id'];
                    replace_dminline_by_members($vsys,$source,$rule_lid,$rules);
                }
            }

        }
        check_used_objects_new();
	}
}
elseif ($action == "add"){
    $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

    $rule_lid = $projectdb->real_escape_string($rule_lid);

    $rules = explode(",",$rule_lid);
    $msg = addFieldInSecurityRule($projectdb, $source, $vsys, $type, $rules, $user_id);
    if($msg['code']) {
        echo json_encode(array("success" => true));
    }
    else{
        echo json_encode(array("success" => false, "msg" => $msg['msg']));
    }
}
elseif ($action == "update"){
    $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);

    $rule_lid = $projectdb->real_escape_string($rule_lid);

    $rules = explode(",",$rule_lid);
    $msg = updateFieldInSecurityRule($projectdb, $source, $vsys, $type, $rules, $user_id);
    if($msg['code']) {
        echo json_encode(array("success" => true));
    }
    else{
        echo json_encode(array("success" => false, "msg" => $msg['msg']));
    }
}

elseif ($action=="names"){
    $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
    $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
    $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
    $rules = (string) (isset($_POST['rules']) ? $_POST['rules'] : $_GET['rules']);

    $vsys = $projectdb->real_escape_string($vsys);
    $ids = $projectdb->real_escape_string($ids);
    $source = $projectdb->real_escape_string($source);
    $rules = $projectdb->real_escape_string($rules);

    take_snapshot_last($project);

    $msg = updateRuleNames($projectdb, $source, $vsys, $type, "", "security_rules");

    if($msg['code']) {
        echo json_encode(array("success" => true));
    }
    else{
        echo json_encode(array("success" => false, "msg" => $msg['msg']));
    }
}

function addFieldInSecurityRule(mysqli $connection, STRING $source, STRING $vsys, STRING $type, ARRAY $rules, STRING $user_id){
    switch ($type){

        case "from":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);

            $name = $connection->real_escape_string($name);

            foreach ($rules as $key => $rule_lid){
                $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND type = 'security_rules_from' AND user_id = '$user_id';");
                if ($getBridge->num_rows == 0) {
                    $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_from' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                        $getIdData = $getBridgeId->fetch_assoc();
                        $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                        . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_from', '$name', '','$vsys', '$source', '0', '$user_id');");
                }else{
                    $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND type = 'security_rules_from' AND user_id = '$user_id';");
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "to":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);

            $name = $connection->real_escape_string($name);

            foreach ($rules as $key=>$rule_lid){
                $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND type = 'security_rules_to' AND user_id = '$user_id';");
                if ($getBridge->num_rows == 0) {
                    $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_to' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                        $getIdData = $getBridgeId->fetch_assoc();
                        $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                        . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_to', '$name', '','$vsys', '$source', '0', '$user_id');");
                }else{
                    $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND type = 'security_rules_to' AND user_id = '$user_id';");
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "src":

            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);

            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);

            foreach ($rules as $key => $rule_lid){
                if (($member_lid!="") AND ($table_name!="")){
                    list($image, $vsys_member, $name_member, ) = getIcon("address", $table_name, $member_lid, "");
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'security_rules_src' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_src' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }

                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'security_rules_src', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");

                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'security_rules_src' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "dst":

            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);

            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);

            foreach ($rules as $key=>$rule_lid){
                if (($member_lid!="") AND ($table_name!="")){

                    list($image, $vsys_member, $name_member, ) = getIcon("address", $table_name, $member_lid, "");

                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'security_rules_dst' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_dst' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }

                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'security_rules_dst', '$name_member', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'security_rules_dst' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "usr":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $name = $connection->real_escape_string($name);

            $name = addslashes($name);

            foreach ($rules as $key=>$rule_lid){
                if ($name != ""){
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND type = 'security_rules_usr' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_usr' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $isGroup = $connection->query("SELECT name FROM userid_group WHERE name = '$name' OR short_name = '$name';");
                        if ($isGroup->num_rows > 0) {
                            $image = 'user-groups.png';
                        }else{
                            $image = 'userp.png';
                        }

                        if(($name == "pre-logon") || ($name == "known-user") || ($name == "unknown")){
                            $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND type = 'security_rules_usr' AND user_id = '$user_id';");
                        }
                        else{
                            $getSpecials = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name IN ('any', 'pre-logon', 'known-user', 'unknown') AND type = 'security_rules_usr' AND user_id = '$user_id';");
                            if ($getSpecials->num_rows > 0) {
                                while($dataS = $getSpecials->fetch_assoc()){
                                    $id_special = $dataS['id'];
                                    $connection->query("UPDATE edit_table SET remove = '1' WHERE id = '$id_special' AND user_id = '$user_id';");
                                }
                            }
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_usr', '$name', '$image','$vsys', '$source', '0', '$user_id');");

                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND type = 'security_rules_usr' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "categories":
            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $name = $connection->real_escape_string($name);
            foreach ($rules as $key => $rule_lid){
                if ($name != ""){
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND type = 'security_rules_categories' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_categories' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_categories', '$name', '','$vsys', '$source', '0', '$user_id');");
                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND type = 'security_rules_categories' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "hip":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);

            $name = $connection->real_escape_string($name);
            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);

            foreach ($rules as $key => $rule_lid){
                if (($member_lid!="") AND ($table_name!="")){
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'security_rules_hip' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_hip' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $image = getImage("hip", $table_name, $member_lid);
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'security_rules_hip', '$name', '$image','$vsys', '$source', '0', '$user_id');");

                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND name = '$name' AND type = 'security_rules_hip' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "app":
            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);

            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);

            foreach ($rules as $key=>$rule_lid){
                if (($member_lid!="") AND ($table_name!="")){

                    list($image, $vsys_member, $name_member, ) = getIcon("applications", $table_name, $member_lid, "");

                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'security_rules_app' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_app' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }

                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'security_rules_app', '$name_member', '$image','$vsys', '$vsys_member','$source', '0', '$user_id');");
                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'security_rules_app' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "srv":

            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);

            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);

            foreach ($rules as $key=>$rule_lid){

                if (($member_lid!="") AND ($table_name!="")){

                    list($image, $vsys_member, $name_member, ) = getIcon("services", $table_name, $member_lid, "");

                    $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_srv' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                        $getIdData = $getBridgeId->fetch_assoc();
                        $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }

                    if($name_member != "application-default"){
                        $getSpecials = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = 'application-default' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                        if ($getSpecials->num_rows > 0) {
                            while($dataS = $getSpecials->fetch_assoc()){
                                $id_special = $dataS['id'];
                                $connection->query("UPDATE edit_table SET remove = '1' WHERE id = '$id_special' AND user_id = '$user_id';");
                            }
                        }
                        $getExist = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                        if ($getExist->num_rows == 0) {
                            $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                                . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'security_rules_srv', '$name_member', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                        }
                        else{
                            $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                        }

                    }
                    else{
                        // add application-default
                        $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = 'application-default' AND type = 'security_rules_srv' AND remove = '1' AND user_id = '$user_id';");
                        if ($getBridge->num_rows == 0) {
                            $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                                . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'security_rules_srv', '$name_member', '$image','$vsys', '$vsys_member','$source', '0', '$user_id');");
                        }
                        else{
                            $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                        }
                        $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name != 'application-default' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "tag":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);

            $name = $connection->real_escape_string($name);
            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);

            foreach ($rules as $key=>$rule_lid){
                if (($member_lid != "") AND ($table_name != "")){
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'security_rules_tag' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_tag' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $realColor = "";
                        $getTag = $connection->query("SELECT color FROM $table_name WHERE source = '$source' AND id = '$member_lid';");
                        if ($getTag->num_rows == 1){
                            $Ttag = $getTag->fetch_assoc();
                            $realColor = $Ttag['color'];
                        }
                        $image = "tags_$realColor.png";
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'security_rules_tag', '$name', '$image','$vsys', '$source', '0', '$user_id');");
                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND name = '$name' AND type = 'security_rules_tag' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "target":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $device_vsys = (string) (isset($_POST['device_vsys']) ? $_POST['device_vsys'] : $_GET['device_vsys']);
            $id_edit_table = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);
            $where_edit = (string) (isset($_POST['where']) ? $_POST['where'] : $_GET['where']);

            $name = $connection->real_escape_string($name);
            $device_vsys = $connection->real_escape_string($device_vsys);
            $id_edit_table = $connection->real_escape_string($id_edit_table);
            $where_edit = $connection->real_escape_string($where_edit);

            // From security editor
            if($where_edit == "edit"){

                if($id_edit_table == "") {
                    foreach ($rules as $key => $rule_lid){
                        $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND vsys_member = '$device_vsys' AND type = 'security_rules_target' AND user_id = '$user_id';");
                        if ($getBridge->num_rows == 0) {
                            $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_target' AND user_id = '$user_id';");
                            if ($getBridgeId->num_rows == 1) {
                                $getIdData = $getBridgeId->fetch_assoc();
                                $ids = $getIdData['ids'] + 1;
                            } else {
                                $ids = 1;
                            }
                            $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                                . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_target', '$name', '','$vsys', '$device_vsys', '$source', '0', '$user_id');");
                        } else {
                            $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND vsys_member = '$device_vsys' AND type = 'security_rules_target' AND user_id = '$user_id';");
                        }
                    }
                }
                else{

                    $getNameOld = $connection->query("SELECT name, vsys_member FROM edit_table WHERE id = '$id_edit_table' AND type = 'security_rules_target' AND user_id = '$user_id';");
                    if ($getNameOld->num_rows == 1) {
                        $dataNO = $getNameOld->fetch_assoc();
                        $name_old = $dataNO['name'];
                        $vsys_member_old = $dataNO['vsys_member'];
                    }

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE lid IN (".implode(",", $rules).") AND name = '$name_old' AND vsys_member = '$vsys_member_old' AND type = 'security_rules_target' AND user_id = '$user_id';");
                    //echo "UPDATE edit_table SET name = '$name', vsys_member = '$device_vsys' WHERE lid IN (".implode(",", $rules).") AND name = '$name_old' AND vsys_member = '$vsys_member_old' AND source = '$source' AND type = 'security_rules_target' AND user_id = '$user_id';\n";
                    foreach ($rules as $key => $rule_lid){
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '','$rule_lid', '', '', 'security_rules_target', '$name', '','$vsys', '$device_vsys', '$source', '0', '$user_id');");
                    }
                }

            }
            else {
                // From menu

                if(count($rules) == 1){

                    if($rules[0] == ""){
                        // All rules
                        $getAllRules = $connection->query("SELECT id FROM security_rules WHERE source = '$source' ;");

                        if ($getAllRules->num_rows > 0) {
                            $rules = array();
                            while ($dataAR = $getAllRules->fetch_assoc()) {
                                $rules[] = $dataAR['id'];
                            }
                        }
                    }
                }

                foreach ($rules as $key => $rule_lid) {

                    $getExist = $connection->query("SELECT name, device_vsys FROM security_rules_target WHERE rule_lid = '$rule_lid' AND name = '$name' AND device_vsys = '$device_vsys' ;");
                    if ($getExist->num_rows == 0) {
                        $connection->query("INSERT INTO security_rules_target (id, source, vsys, name, device_vsys, rule_lid) "
                            . "VALUES (NULL, '$source', '$vsys', '$name', '$device_vsys', '$rule_lid');");
                    }

                }

            }

            //}
            $message = [
                "code" => true
            ];
            break;

        default:
            $message = [
                "code" => false,
                "msg"  => "Option $type not recognized"
            ];
            break;
    }
    return $message;
}

function updateFieldInSecurityRule(mysqli $connection, STRING $source, STRING $vsys, STRING $type, ARRAY $rules, STRING $user_id){

    switch ($type){
        case "from":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

            $name = $connection->real_escape_string($name);
            $oldname = $connection->real_escape_string($oldname);

            if (($name!="") AND ($oldname!="")){
                //$connection->query("UPDATE edit_table SET remove = '1' WHERE name = '$oldname' AND type = 'security_rules_from' AND source = '$source' AND user_id = '$user_id';");
                foreach ($rules as $key=>$rule_lid){

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name = '$oldname' AND type = 'security_rules_from' AND user_id = '$user_id';");

                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_from' AND name = '$name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_from' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_from', '$name', '','$vsys', '$source', '0', '$user_id');");
                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }

            $message = [
                "code" => true
            ];
            break;

        case "to":
            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

            $name = $connection->real_escape_string($name);
            $oldname = $connection->real_escape_string($oldname);

            if (($name!="") AND ($oldname!="")){
                //$connection->query("UPDATE edit_table SET remove = '1' WHERE name = '$oldname' AND type = 'security_rules_to' AND source = '$source' AND user_id = '$user_id';");
                foreach ($rules as $key=>$rule_lid){
                    $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name = '$oldname' AND type = 'security_rules_to' AND user_id = '$user_id';");

                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_to' AND name = '$name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_to' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_to', '$name', '','$vsys', '$source', '0', '$user_id');");
                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }
            $message = [
                "code" => true
            ];
            break;

        case "src":
//            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
            $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);
            $id = $connection->real_escape_string($id);

            if (($member_lid!="") AND ($table_name!="")){

                $getMemberTable = $connection->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'security_rules_src' AND user_id = '$user_id';");
                if ($getMemberTable->num_rows == 1){
                    $dataMT = $getMemberTable->fetch_assoc();
                    $member_lid_old = $dataMT['member_lid'];
                    $table_name_old = $dataMT['table_name_lid'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'security_rules_src' AND user_id = '$user_id';");
                }

                list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

                foreach ($rules as $key=>$rule_lid){
                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_src' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_src' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'security_rules_src', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }
            $message = [
                "code" => true
            ];
            break;

        case "dst":

            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
            $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);
            $id = $connection->real_escape_string($id);

            if (($member_lid!="") AND ($table_name!="")){
                $getMemberTable = $connection->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'security_rules_dst' AND user_id = '$user_id';");
                if ($getMemberTable->num_rows == 1){
                    $dataMT = $getMemberTable->fetch_assoc();
                    $member_lid_old = $dataMT['member_lid'];
                    $table_name_old = $dataMT['table_name_lid'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'security_rules_dst' AND user_id = '$user_id';");
                }

                list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

                foreach ($rules as $key=>$rule_lid){
                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_dst' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_dst' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'security_rules_dst', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }
            $message = [
                "code" => true
            ];
            break;

        case "usr":
            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

            $name = $connection->real_escape_string($name);
            $oldname = $connection->real_escape_string($oldname);

            if (($name!="") AND ($oldname!="")){
                $name=  addslashes($name);
                $oldname= addslashes($oldname);
                //$connection->query("UPDATE edit_table SET remove = '1' WHERE name = '$oldname' AND type = 'security_rules_usr' AND user_id = '$user_id';");
                foreach ($rules as $key=>$rule_lid){
                    $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name = '$oldname' AND type = 'security_rules_usr' AND user_id = '$user_id';");

                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_usr' AND name = '$name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }
                    else{
                        $isGroup = $connection->query("SELECT name FROM userid_group WHERE name = '$name' OR short_name = '$name';");
                        if ($isGroup->num_rows > 0) {
                            $image = 'user-groups.png';
                        }else{
                            $image = 'userp.png';
                        }

                        if(($name == "pre-logon") || ($name == "known-user") || ($name == "unknown")){
                            $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND user_id = '$user_id';");
                        }

                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_usr' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_usr', '$name', '$image','$vsys', '$source', '0', '$user_id');");

                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }

            $message = [
                "code" => true
            ];
            break;

        case "categories":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

            $name = $connection->real_escape_string($name);
            $oldname = $connection->real_escape_string($oldname);

            if (($name!="") AND ($oldname!="")){
                //$connection->query("UPDATE edit_table SET remove = '1' WHERE name = '$oldname' AND type = 'security_rules_categories' AND source = '$source' AND user_id = '$user_id';");
                foreach ($rules as $key=>$rule_lid){
                    $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name = '$oldname' AND type = 'security_rules_categories' AND user_id = '$user_id';");

                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_categories' AND name = '$name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_categories' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'security_rules_categories', '$name', '','$vsys', '$source', '0', '$user_id');");

                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }

            $message = [
                "code" => true
            ];
            break;

        case "hip":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
            $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            $name = $connection->real_escape_string($name);
            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);
            $id = $connection->real_escape_string($id);

            if (($member_lid!="") AND ($table_name!="")){
                $getMemberTable = $connection->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'security_rules_hip' AND user_id = '$user_id';");
                if ($getMemberTable->num_rows == 1){
                    $dataMT = $getMemberTable->fetch_assoc();
                    $member_lid_old = $dataMT['member_lid'];
                    $table_name_old = $dataMT['table_name_lid'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'security_rules_hip' AND user_id = '$user_id';");
                }
                $image = getImage("hip", $table_name, $member_lid);
                foreach ($rules as $key=>$rule_lid){

                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_hip' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_hip' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'security_rules_hip', '$name', '$image', '$vsys', '$source', '0', '$user_id');");

                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }
            $message = [
                "code" => true
            ];
            break;

        case "app":

//            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
            $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);
            $id = $connection->real_escape_string($id);

            if (($member_lid!="") AND ($table_name!="")){
                $getMemberTable = $connection->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'security_rules_app' AND user_id = '$user_id';");
                if ($getMemberTable->num_rows == 1){
                    $dataMT = $getMemberTable->fetch_assoc();
                    $member_lid_old = $dataMT['member_lid'];
                    $table_name_old = $dataMT['table_name_lid'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'security_rules_app' AND user_id = '$user_id';");
                }
                list($image, $vsys_member, $name_member, $myip) = getIcon("applications", $table_name, $member_lid, "");

                foreach ($rules as $key=>$rule_lid){
                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_app' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_app' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'security_rules_app', '$name_member', '$image', '$vsys', '$vsys_member','$source', '0', '$user_id');");
                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }
            $message = [
                "code" => true
            ];
            break;

        case "srv":

            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
            $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);
            $id = $connection->real_escape_string($id);

            if (($member_lid!="") AND ($table_name!="")){

                list($image, $vsys_member, $name_member, $myip) = getIcon("services", $table_name, $member_lid, "");

                $getMemberTable = $connection->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'security_rules_srv' AND user_id = '$user_id';");

                if ($getMemberTable->num_rows == 1){
                    $dataMT = $getMemberTable->fetch_assoc();
                    $member_lid_old = $dataMT['member_lid'];
                    $table_name_old = $dataMT['table_name_lid'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                }

                foreach ($rules as $key=>$rule_lid){

                    if($name_member != "application-default"){

                        $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_srv' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                        if($getExistRemove->num_rows == 1){
                            $dataExist = $getExistRemove->fetch_assoc();
                            $id_exist = $dataExist['id'];
                            $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                        }
                        else{
                            $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_srv' AND user_id = '$user_id';");
                            if ($getBridgeId->num_rows == 1) {
                                $getIdData = $getBridgeId->fetch_assoc();
                                $ids = $getIdData['ids'] + 1;
                            }else{
                                $ids = 1;
                            }
                            $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                                . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'security_rules_srv', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                        }

                    }
                    else{

                        // add application-default
                        $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = 'application-default' AND type = 'security_rules_srv' AND remove = '1' AND user_id = '$user_id';");
                        if ($getBridge->num_rows == 0) {
                            $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                                . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'security_rules_srv', '$name_member', '$image','$vsys', '$vsys_member','$source', '0', '$user_id');");
                        }
                        else{
                            $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'security_rules_srv' AND user_id = '$user_id';");
                        }
                        $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name != 'application-default' AND type = 'security_rules_srv' AND user_id = '$user_id' ;");

                    }

                }
            }
            else{
                echo json_encode(array("success"=>false));
            }

            $message = [
                "code" => true
            ];
            break;

        case "tag":

            $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
            $member_lid = (string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']);
            $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
            $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            $name = $connection->real_escape_string($name);
            $member_lid = $connection->real_escape_string($member_lid);
            $table_name = $connection->real_escape_string($table_name);
            $id = $connection->real_escape_string($id);

            if (($member_lid!="") AND ($table_name!="")){

                $getNameTag = $connection->query("SELECT name FROM edit_table WHERE ids = '$id' AND type = 'security_rules_tag' AND user_id = '$user_id';");
                if ($getNameTag->num_rows == 1){
                    $dataNT = $getNameTag->fetch_assoc();
                    $name_tag = $dataNT['name'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE name = '$name_tag' AND type = 'security_rules_tag' AND user_id = '$user_id';");
                }

                $getTag = $connection->query("SELECT color FROM $table_name WHERE id = '$member_lid';");
                if ($getTag->num_rows == 1){
                    $Ttag = $getTag->fetch_assoc();
                    $realColor = $Ttag['color'];
                }
                $image = "tags_$realColor.png";
                foreach ($rules as $key=>$rule_lid){
                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'security_rules_tag' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'security_rules_tag' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'security_rules_tag', '$name', '$image', '$vsys', '$source', '0', '$user_id');");
                    }
                }
            }
            else{
                echo json_encode(array("success"=>false));
            }
            $message = [
                "code" => true
            ];
            break;

        case "profiles":

            $profile_type = (string) (isset($_POST['profile_type']) ? $_POST['profile_type'] : $_GET['profile_type']);
            $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);

            $profile_type = $connection->real_escape_string($profile_type);
            $idx = $connection->real_escape_string($idx);

            foreach ($rules as $key=>$value){
                $query = "SELECT id FROM security_rules_profiles WHERE rule_lid='$value' AND type='$profile_type' ";
                $getID=$connection->query($query);
                if ($getID->num_rows==1){
                    while($data=$getID->fetch_assoc()){
                        $profile_id=$data['id'];
                        if ($idx==0){
                            $connection->query("DELETE FROM security_rules_profiles WHERE id='$profile_id';");
                        }
                        else{
                            $mydata=explode(";",$idx);
                            $profileid=$mydata[0];
                            $profiletable=$mydata[1];
                            $query = "UPDATE security_rules_profiles SET table_name='$profiletable', member_lid='$profileid' WHERE id='$profile_id';";
                            $connection->query($query);
                        }
                    }
                }
                else {
                    $mydata=explode(";",$idx);
                    $profileid=$mydata[0];
                    $profiletable=$mydata[1];
                    $query = "INSERT INTO security_rules_profiles (source,vsys,member_lid,table_name,rule_lid,type) VALUES ('$source','$vsys','$profileid','$profiletable','$value','$profile_type');";
                    $connection->query($query);
                }
                #Remove any profile_group from this rule
                $connection->query("DELETE FROM security_rules_profiles WHERE rule_lid='$value' AND table_name='profiles_groups';");
            }
            $message = [
                "code" => true
            ];

            break;

        case "profiles_groups":

            // TODO lid??
            $profile_type = (string) (isset($_POST['profile_type']) ? $_POST['profile_type'] : $_GET['profile_type']);
            $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);

            $profile_type = $connection->real_escape_string($profile_type);
            $idx = $connection->real_escape_string($idx);

            if ($idx==0){
                $connection->query("DELETE FROM security_rules_profiles WHERE rule_lid IN ($idx);");
            }
            else {
                foreach ($rules as $key=>$value){
                    $connection->query("DELETE FROM security_rules_profiles WHERE rule_lid='$value';");
//              $mydata=split(";",$idx);
                    $mydata=explode(";",$idx);
                    $profileid=$mydata[0];
                    $profiletable=$mydata[1];
                    $connection->query("INSERT INTO security_rules_profiles (table_name,vsys,source,rule_lid,member_lid) VALUES ('$profiletable','$vsys','$source','$value','$profileid');");
                }
            }

            $message = [
                "code" => true
            ];

            break;

        default:
            $message = [
                "code" => false,
                "msg"  => "Option $type not recognized"
            ];
            break;
    }

    return $message;
}


?>