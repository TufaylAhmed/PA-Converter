<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/palettes.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

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

if ($action=="get"){
    if($type=="rules" && $short == 'true'){
        $query ="SELECT id, name FROM nat_rules WHERE source ='$source' AND vsys='$vsys' ORDER BY position";
        $result = $projectdb->query($query);
        $rules = array();
        if($result->num_rows >0){
            while($data = $result->fetch_assoc()){
                $rules[] = $data;
            }
        }

        $msg = [
            'total' => count($rules),
            'nat' => $rules,
        ];
        echo json_encode($msg);
    }
    elseif ($type=="rules")	{
        $secRules=array();
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

        $vsyses = getVsyses($projectdb, $vsys, $source);
        $vsyses_filters = getVsyses($projectdb, $vsys, $source, 'quoted');
        $sesysv = array_reverse($vsyses);
        $secRulePacks = array();
        //Albert comment by now
        //calculateAllFiltersNat($vsyses_filters, $source);

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
            $rulesToPresent['pre'][$vsyse]['rules'] = getMatchingNatIds($ruleids, $source, $vsyse, $project, '0', $start, $limit, $filter, $vsys, $id_cons);
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
            $rulesToPresent['post'][$vsyse]['rules'] = getMatchingNatIds($ruleids, $source, $vsyse, $project, '1', $start, $limit, $filter, $vsys, $id_cons);
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
            $inMemory = array();
            // It could be inside a function
            //Step 2. Get the ids ob the objects that will be requested
            /** SRC,DST,TP_DST Address, TRanslated Address and Fallbacks */
            $query = "SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name UNION 
                  SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name UNION 
                  SELECT tp_dat_address_lid as member_lid, tp_dat_address_table as table_name FROM nat_rules WHERE id in (".implode(',',$rules).") AND tp_dat_address_lid!=0 GROUP BY member_lid, table_name UNION 
                  SELECT member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name UNION 
                  SELECT member_lid, table_name FROM nat_rules_translated_address_fallback WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name ;";
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
            $query = "SELECT op_service_lid as member_lid, op_service_table as table_name FROM nat_rules WHERE id in (".implode(',',$rules).") AND op_service_lid!=0 GROUP BY member_lid, table_name";
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

            /** Zones */
            $query = "SELECT name FROM nat_rules_from WHERE rule_lid in (".implode(',',$rules).") GROUP BY name UNION 
                  SELECT op_zone_to as name FROM nat_rules   WHERE id in (".implode(',',$rules).") AND op_zone_to!='' GROUP BY name";
            $result = $projectdb->query($query);
            if($result->num_rows > 0){
                $listZones       = array();
                while ($data = $result->fetch_assoc()) {
                    $listServices[] = $data['name'];
                }

//            $listZones = array_unique($listZones);

                //Zones
                if(count($listZones)>0) {
                    $query = "SELECT * FROM zones WHERE id in (" . implode(',', $listZones) . ")";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['zones'][$row['id']] = $row;
                    }
                }
            }

            /** Tags */
            $query = "SELECT member_lid, table_name FROM nat_rules_tag WHERE rule_lid in (".implode(',',$rules).") GROUP BY member_lid, table_name";
            $result = $projectdb->query($query);
            if($result->num_rows > 0){
                $listTags       = array();
                while ($data = $result->fetch_assoc()) {
                    $table = $data['table_name'];
                    switch ($table) {
                        case "tag":
                            $listTags[] = $data['member_lid'];
                            break;
                        default:
                            break;
                    }
                }

//            $listTags = array_unique($listTags);

                // Tags and Group Tags (PanOS 9.1)
                // Select all tags in memory because if necessary from tags and group tags
                //if(count($listTags)>0) {
                //$query = "SELECT t.*, tc.color AS color_name FROM tag t, tag_colors tc WHERE t.id in (" . implode(',', $listTags) . ") AND t.color = tc.name";
                $query = "SELECT t.*, tc.color AS color_name FROM tag t, tag_colors tc WHERE t.color = tc.name";
                    $result = $projectdb->query($query);
                    while ($row = $result->fetch_assoc()) {
                        $inMemory['tag'][$row['id']] = $row;
                        $color = $row['color'];
                        if ($color=="none"){
                            $inMemory['tag'][$row['id']]['rgb']="";
                        }
                        else{
                            //$inMemory['tag'][$row['id']]['rgb'] = $colorPalette['TagColors'][$color];
                            $inMemory['tag'][$row['id']]['rgb'] = $row['color_name'];
                        }
                    }
                //}
            }

            /** Add Images */
            getIconMemory($inMemory);

            foreach ($rulesToPresent['pre'] as $vsyse => $ruleToPresent) {
//            print_r($ruleToPresent);
                $ruleids = $ruleToPresent['rules'];
                $ruleids = array_slice($ruleids, $ruleToPresent['start'],$ruleToPresent['length']);
                $secRulePacks[] = search_nat_policies_inmemory($ruleids, $source, $vsyse, $project, '0', '', '',$ruleToPresent['color'],$ruleToPresent['group'], $ruleToPresent['label'], $inMemory);
            }

            foreach ($rulesToPresent['post'] as $vsyse => $ruleToPresent) {
                $ruleids = $ruleToPresent['rules'];
                $ruleids = array_slice($ruleids, $ruleToPresent['start'],$ruleToPresent['length']);
                $secRulePacks[] = search_nat_policies_inmemory($ruleids, $source, $vsyse, $project, '1', '', '',$ruleToPresent['color'],$ruleToPresent['group'], $ruleToPresent['label'], $inMemory);
            }
            $secRules = array();
            foreach($secRulePacks as $secRulePack){
                if (count($secRulePack['nat'])>0) {
                    $secRules = array_merge($secRules, $secRulePack['nat']);
                }
            }

        }
        else{
            $total=0;
            $secRules=array();
        }

        $result = [
            'total' => $total,
            'nat' => $secRules,
        ];

        echo json_encode($result);
    }
    elseif ($type=="from_by_rulelid"){
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_from' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
        
            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid FROM nat_rules_from WHERE rule_lid IN ($lid);");
            if ($searchUsers->num_rows > 0) {
                $data = array();
                $howmany = $searchUsers->num_rows;
                while ($row = $searchUsers->fetch_assoc()){
                    //$data [] = $row;
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $source = $row['source'];
                    $vsys = $row['vsys'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'nat_rules_from' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'nat_rules_from', '$name', '','$vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.$howmany.'","rows":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
        else {
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
    elseif ($type=="source_by_rulelid"){
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_src' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
        
            $getSource=$projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM nat_rules_src WHERE rule_lid IN ($lid)");
            if ($getSource->num_rows>0){
                $Source=array();
                while($src=$getSource->fetch_assoc()){
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    $rule_lid = $src['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'nat_rules_src' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$src_member_lid', '$src_table_name', 'nat_rules_src', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                        $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                }
                echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Source).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                        $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                    echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else {
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                    $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                }
                echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type=="destination_by_rulelid"){
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_dst' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
        
            $getSource=$projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM nat_rules_dst WHERE rule_lid IN ($lid);");
            if ($getSource->num_rows>0){
                $Source=array();
                while($src=$getSource->fetch_assoc()){
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    $rule_lid = $src['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'nat_rules_dst' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$src_member_lid', '$src_table_name', 'nat_rules_dst', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                        $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                }
                echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Source).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                        $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                    echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else {
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                    $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                }
                echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type=="tags_by_rulelid"){
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_tag' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
        
            $searchTag=$projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM nat_rules_tag WHERE rule_lid IN ($lid)");
            if ($searchTag->num_rows > 0) {
                $Tag=array();
                while ($Tags=$searchTag->fetch_assoc()){
                    $tag_member_lid = $Tags['member_lid'];
                    $tag_table_name = $Tags['table_name'];
                    $id = $Tags['id'];
                    $rule_lid = $Tags['rule_lid'];
                    $getTag=$projectdb->query("SELECT name,color FROM $tag_table_name WHERE id='$tag_member_lid';");
                    if ($getTag->num_rows==1){
                        $Ttag=$getTag->fetch_assoc();
                        $TagName=$Ttag['name'];
                        $realColor=$Ttag['color'];
                        $thenewtagcolor=$TagName;
                    }
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$tag_member_lid' AND table_name_lid = '$tag_table_name' AND name = '$TagName' AND type = 'nat_rules_tag' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $image = "tags_$realColor.png";
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$tag_member_lid', '$tag_table_name', 'nat_rules_tag', '$TagName', '$image','$vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_tag' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $ids_sql = $getData['member_lid'];
                        $Tag[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'"}';
                    }
                }
                echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Tag).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_tag' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $ids_sql = $getData['member_lid'];
                        $Tag[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'"}';
                    }
                    echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Tag).']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else {
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_tag' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
            if ($getBridgeData->num_rows >= 1) {
                while($getData = $getBridgeData->fetch_assoc()){
                    $image_sql = $getData['image'];
                    $name_sql = $getData['name'];
                    $member_lid_sql = $getData['member_lid'];
                    $table_name_sql = $getData['table_name_lid'];
                    $source_sql = $getData['source'];
                    $vsys_sql = $getData['vsys'];
                    $ids_sql = $getData['member_lid'];
                    $Tag[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'"}';
                }
                echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Tag).']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type=="match_by_rulelid"){
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $rules_match = array();
        $color = "";
        $getNat=$projectdb->query("SELECT tp_sat_type,is_dat,op_zone_to,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE id='$lid';");
        if ($getNat->num_rows>0){
            $getNatData=$getNat->fetch_assoc();
            $isDat=$getNatData['is_dat'];
            $tp_sat_type=$getNatData['tp_sat_type'];
            $op_zone_to=$getNatData['op_zone_to'];
            $tp_dat_address_lid=$getNatData['tp_dat_address_lid'];
            $tp_dat_address_table=$getNatData['tp_dat_address_table'];

            if ($tp_sat_type!=""){
                if ($tp_sat_type=="static-ip" || $tp_sat_type=="dynamic-ip-and-port"){
                    $getTP=$projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid'");
                    if ($getTP->num_rows>0){
                        while ($getTPData=$getTP->fetch_assoc()){
                            $ori_member_lid=$getTPData['member_lid'];
                            $ori_table_name=$getTPData['table_name'];
                            #Exact object Match, future check if its inside
                            $getRulesDst=$projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE member_lid='$ori_member_lid' AND table_name='$ori_table_name';");

                            if ($getRulesDst->num_rows>0){
                                while ($getRulesDstData=$getRulesDst->fetch_assoc()){
                                    $rules_match[]=$getRulesDstData['rule_lid'];
                                    
                                }
                            }
                        }
                    }
                }
            }

            if ($isDat==1 || $isDat==2){
                $getNatDST=$projectdb->query("SELECT table_name,member_lid FROM nat_rules_dst WHERE rule_lid='$lid';");
                if ($getNatDST->num_rows>0){
                    while ($data=$getNatDST->fetch_assoc()){
                        $member=$data['member_lid'];
                        $table=$data['table_name'];
                        $getRules=$projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE member_lid='$member' AND table_name='$table';");
                        if ($getRules->num_rows>0){
                            while ($data2=$getRules->fetch_assoc()){
                                $rules_match[]=$data2['rule_lid'];
                            }
                        }
                    }
                }
            }

            if (count($rules_match)>0){
                $unique=array_unique($rules_match);
                $vsyses = getVsyses($projectdb, $vsys, $source);

                $sesysv = array_reverse($vsyses);
                $secRulePacks = array();
                $group_=0;
                foreach ($sesysv as $vsyse) {
                    //Pre Rules
                    $label = "Pre-rulebase ".$vsyse;
                    $secRulePacks[] = search_security_policies($unique, $source, $vsyse, $project, '0', '', '',$color,$group_, $label);
                    $group_++;
                }

                foreach ($vsyses as $vsyse) {
                    //Post Rules
                    $label = "Pre-rulebase ".$vsyse;
                    $secRulePacks[] = search_security_policies($unique, $source, $vsyse, $project, '1', '', '',$color,$group_, $label);
                    $group_++;
                }
                $total=0;
                $secRules = array();
                foreach($secRulePacks as $secRulePack){
                    $total += $secRulePack['total'];
                    if (count($secRulePack['security'])>0) {
                        $secRules = array_merge($secRules, $secRulePack['security']);
                    }
                }

                $result = [
                    'total' => $total,
                    'security' => $secRules,
                ];

                echo json_encode($result);
//                $narRules = search_security_policies($unique,$source,$vsys,$project,'','');
                unset($rules_match);
            }
            else {
                echo '{"total":0,"security":[]}';
            }
        }
        else {
            echo '{"total":0,"security":[]}';
        }
    }
    elseif ($type=="translated_address_by_rulelid"){
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_translated_address' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
        
            $getSource = $projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM nat_rules_translated_address WHERE rule_lid IN ($lid) ");
            if ($getSource->num_rows>0){
                $Source=array();
                while($src=$getSource->fetch_assoc()){
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    $rule_lid = $src['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'nat_rules_translated_address' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$src_member_lid', '$src_table_name', 'nat_rules_translated_address', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_translated_address' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                        $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                }    
                echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Source).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_translated_address' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                        $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                    echo '{"total":"' . $getSource->num_rows . '","rows":[' . implode(",", $Source) . ']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else {
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_translated_address' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                    $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                }
                echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type=="fallback_translated_address_by_rulelid"){
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_translated_address_fallback' AND user_id = '$user_id' ;");
        if ($getEditTable->num_rows == 0){
        
            $getSource = $projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM nat_rules_translated_address_fallback WHERE rule_lid IN ($lid)");
            if ($getSource->num_rows>0){
                $Source=array();
                while($src=$getSource->fetch_assoc()){
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    $rule_lid = $src['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'nat_rules_translated_address_fallback' AND name = '$name' AND user_id = '$user_id' ;");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$src_member_lid', '$src_table_name', 'nat_rules_translated_address_fallback', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_translated_address_fallback' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                        $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                }    
                echo '{"total":"'.$getBridgeData->num_rows.'","rows":['.implode(",",$Source).']}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_translated_address_fallback' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                        $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                    }
                    echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
                }else{
                    echo '{"total":0,"rows":[]}';
                }
            }
        }
        else {
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_translated_address_fallback' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                    $Source[] = '{"id":"'.$ids_sql.'","img":"'.$image_sql.'","name":"'.$name_sql.'","member_lid":"'.$member_lid_sql.'","table_name":"'.$table_name_sql.'","source":"'.$source_sql.'","vsys":"'.$vsys_sql.'", "vsys_member":"'.$vsys_member.'"}';
                }
                echo '{"total":"' . $getBridgeData->num_rows . '","rows":[' . implode(",", $Source) . ']}';
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
    elseif ($type == "target_by_rulelid") {

        $vsys = $projectdb->real_escape_string((string)(isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string)(isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string)(isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_target' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){

            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid, device_vsys FROM nat_rules_target WHERE rule_lid IN ($lid) ;");
            if ($searchUsers->num_rows > 0) {
                $data = array();
                $howmany = $searchUsers->num_rows;
                while ($row = $searchUsers->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $device_vsys = $row['device_vsys'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'nat_rules_target' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'nat_rules_target', '$name', '$vsys', '$device_vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT name, source, vsys as device_vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_target' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","target":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_target' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'nat_rules_target' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
}
elseif ($action=="set"){
    if ($type=="remove_rule"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        if ($ids!=""){
            take_snapshot_last($project);
            delete_nat_rule($vsys,$source,$ids);
        }
    }
    elseif ($type=="save_position"){
        $ids    = $projectdb->real_escape_string((string)  (isset($_POST['ids'])    ? $_POST['ids']    : $_GET['ids']));
        $needle = $projectdb->real_escape_string((string)  (isset($_POST['id'])     ? $_POST['id']     : $_GET['id']));
        $moveto = $projectdb->real_escape_string((string)  (isset($_POST['moveto']) ? $_POST['moveto'] : $_GET['moveto']));

        require_once INC_ROOT.'/libs/common/rules/rules.php';
        $ids = json_decode($ids);
        $msg = moveRules($projectdb, $project, $source, $vsys, "nat_rules", $ids, $moveto, $needle);
        echo json_encode($msg);
    }
    elseif ($type=="unlock"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        if ($ids!=""){
            take_snapshot_last($project);
            $projectdb->query("UPDATE nat_rules SET blocked='0' WHERE id IN ($ids);");
        }
    }
    elseif ($type=="lock"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        if ($ids!=""){
            take_snapshot_last($project);
            $projectdb->query("UPDATE nat_rules SET blocked='1' WHERE id IN ($ids);");
        }
    }
    elseif ($type == "save_by_rulelid"){

        $vsys = $_POST['vsys'];
        $source = $_POST['source'];
        if (isset($_POST['name'])){$name = $_POST['name'];}else{$name="";}
        $rule_lid = $_POST['rule_lid'];
        if (isset($_POST['description'])){
            $description = addslashes($_POST['description']);}else{$description="";}
        $op_zone_to = $_POST['op_zone_to'];
        $op_to_interface = $_POST['op_to_interface'];
        $op_service = $_POST['op_service'];
        if (isset($_POST['nat_type'])){$nat_type = $_POST['nat_type'];}else{$nat_type="ipv4";}
        $tp_sat_type = $_POST['tp_sat_type'];
        $tp_sat_address_type = $_POST['tp_sat_address_type'];
        $tp_sat_interface = $_POST['tp_sat_interface'];
        $tp_sat_ipaddress = $_POST['tp_sat_ipaddress'];
        $tp_fallback_type = $_POST['tp_fallback_type'];
        $tp_sat_interface_fallback = $_POST['tp_sat_interface_fallback'];
        $tp_sat_ipaddress_fallback = $_POST['tp_sat_ipaddress_fallback'];
        $tp_dat_address = $_POST['tp_dat_address'];
        $dnat_translation_type=$_POST['dnat_translation_type'];
        $tp_dat_port = $_POST['tp_dat_port'];
        $isdat = (isset($_POST['is_dat']) && $_POST['is_dat']=='on')? 1:0;
        $tp_sat_bidirectional = (isset($_POST['tp_sat_bidirectional']) && $_POST['tp_sat_bidirectional']=='on') ? 1 : 0;
        $fallback_interface_type = $_POST['fallback_interface_type'];
        $tags = $_POST['tags'];
        $calc_autozone = $_POST['calc_autozone'];
        $target_negate=$_POST['target_negate'];
        $group_tag_id = $_POST['group_tag_id'];

        take_snapshot_last($project);

        #if (($negate_source=="false") OR ($negate_source=="off")){$negate_source=0;}else{$negate_source=1;}
        if ($tp_dat_port=="any"){$tp_dat_port="";}
        
        if ($tp_sat_bidirectional=="1"){
            $tp_sat_bidirectional_parser = "tp_sat_bidirectional='1', ";
        }
        else{
            $tp_sat_bidirectional_parser = "";
        }

        if ((!isset($target_negate)) OR ($target_negate=="")){$target_negate="no";}

        if ($rule_lid!="") {
            
            $getTypeEdit = $projectdb->query("SELECT DISTINCT(type) FROM edit_table WHERE lid IN ($rule_lid) AND user_id = '$user_id';");
            if ($getTypeEdit->num_rows > 0) {
                while($getTypeData = $getTypeEdit->fetch_assoc()){
                    
                    $type = $getTypeData['type'];
                    $names_edit = array();
                    
                    if($type == "nat_rules_tag"){
                        $tags_explode = explode(",", $tags);
                        foreach ($tags_explode as $value) {
                            $names_edit[] = "'$value'";
                        }
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }
                    
                    if(strcmp($type, 'tp_destination')!=0 && strcmp($type, 'op_service')!=0) {
                        // Add members to type of table to edit in edit
//                        setMembersRules($rule_lid, $type, $vsys, $source, $user_id);
                        setMembersRules($rule_lid, $type, $vsys, $source);
                    }
                }
            }

            $rules = explode(",", $rule_lid);
            foreach ($rules as $key => $rule_lid){
                
                // Add service
                $getSrcBridge = $projectdb->query("SELECT lid, member_lid, table_name_lid FROM edit_table WHERE lid = '$rule_lid' AND type = 'op_service' AND remove = '0' AND user_id = '$user_id';");
                if ($getSrcBridge->num_rows >= 1) {
                    while($getSrcData = $getSrcBridge->fetch_assoc()){
                        $member_lid = $getSrcData['member_lid'];
                        $table_name = $getSrcData['table_name_lid'];
                        $projectdb->query("UPDATE nat_rules SET op_service_lid = '$member_lid', op_service_table = '$table_name' WHERE id = '$rule_lid';");
                    }
                }
                // Add TP Destionation
                $getSrcBridge = $projectdb->query("SELECT lid, member_lid, table_name_lid FROM edit_table WHERE lid = '$rule_lid' AND type = 'tp_destination' AND remove = '0' AND user_id = '$user_id';");
                if ($getSrcBridge->num_rows >= 1) {
                    while($getSrcData = $getSrcBridge->fetch_assoc()){
                        $isdat = 1;
                        $member_lid = $getSrcData['member_lid'];
                        $table_name = $getSrcData['table_name_lid'];
                        $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid = '$member_lid', tp_dat_address_table = '$table_name', is_dat='$isdat' WHERE id = '$rule_lid';");
                        //echo "UPDATE nat_rules SET tp_dat_address_lid = '$member_lid', tp_dat_address_table = '$table_name' WHERE id = '$rule_lid';";
                        if (($table_name != "address_groups_id") AND ($table_name != "shared_address_groups_id")) {
                            $projectdb->query("UPDATE $table_name SET used=1 WHERE id='$member_lid';");
                        }
                    }
                }

                if($tp_sat_type == "static-ip"){
                    $tp_sat_address_type = "";
                    $tp_sat_interface = "";
                    $tp_sat_ipaddress = "";
                    $tp_sat_interface_parser = "tp_sat_interface='', ";
                    $tp_sat_ipaddress_parser = "tp_sat_ipaddress='', ";
                    $tp_sat_address_type_parser = "tp_sat_address_type='', ";
                }

                if ($tp_sat_type=="none"){
                    $projectdb->query("DELETE FROM nat_rules_translated_address WHERE rule_lid='$rule_lid';");
                    $projectdb->query("DELETE FROM nat_rules_translated_address_fallback WHERE rule_lid='$rule_lid';");
                    $tp_sat_interface="";$tp_sat_ipaddress="";$tp_sat_interface_fallback="";$tp_sat_ipaddress_fallback="";$tp_fallback_type="None";$tp_sat_bidirectional=0;$tp_sat_address_type="";
                }

                if ($tp_sat_address_type=="interface-address"){
                     $projectdb->query("DELETE FROM nat_rules_translated_address WHERE rule_lid='$rule_lid';");
                     $projectdb->query("DELETE FROM nat_rules_translated_address_fallback WHERE rule_lid='$rule_lid';");
                     $tp_sat_interface_fallback="";$tp_sat_ipaddress_fallback="";$tp_fallback_type="None";$tp_sat_bidirectional=0;
                }

                if($op_zone_to == "none"){
                    $op_zone_to_parser = "";
                }else{
                    $op_zone_to_parser = "op_zone_to='$op_zone_to', ";
                }
                
                if($op_to_interface == "Any"){
                    $op_to_interface = "any";
                    $op_to_interface_parser = "";
                }else{
                    $op_to_interface_parser = "op_to_interface='$op_to_interface', ";
                }
                  
                if($tp_dat_port == "[1-65535]"){
                    $tp_dat_port_parser = "";    
                }else{
                    $tp_dat_port_parser = "tp_dat_port='$tp_dat_port', ";
                }
                
                if($tp_sat_type == ""){
                    $tp_sat_type_parser = "";
                }else{
                    $tp_sat_type_parser = "tp_sat_type='$tp_sat_type', ";
                }
                
                if($tp_sat_address_type == ""){
                    $tp_sat_address_type_parser = "";
                }else{
                    $tp_sat_address_type_parser = "tp_sat_address_type='$tp_sat_address_type', ";
                }
                
                if($tp_sat_interface == ""){
                    $tp_sat_interface_parser = "";
                    $tp_sat_ipaddress_parser = "";
                    
                }else{
                    if($tp_sat_type == "static-ip"){
                        $tp_sat_interface_parser = "tp_sat_interface='', ";
                        $tp_sat_ipaddress_parser = "tp_sat_ipaddress='', ";
                    }else{
                        $tp_sat_interface_parser = "tp_sat_interface='$tp_sat_interface', ";
                        $tp_sat_ipaddress_parser = "tp_sat_ipaddress='$tp_sat_ipaddress', ";
                    }
                }
                
                if($tp_sat_interface_fallback == ""){
                    $tp_sat_interface_fallback_parser = "";
                    $tp_sat_ipaddress_fallback_parser = "";
                    $tp_fallback_type_parser = "";
                    
                }else{
                    $tp_sat_interface_fallback_parser = "tp_sat_interface_fallback='$tp_sat_interface_fallback', ";
                    $tp_sat_ipaddress_fallback_parser = "tp_sat_ipaddress_fallback='$tp_sat_ipaddress_fallback', ";
                    $tp_fallback_type_parser = "tp_fallback_type='$tp_fallback_type', ";
                }

                if($tp_sat_type != "static-ip"){
                    $tp_sat_bidirectional=0;
                    $tp_sat_bidirectional_parser = "tp_sat_bidirectional='0', ";
                }

                if(($group_tag_id == "") || ($group_tag_id == "None")){
                    $group_tag_id_parser = "";
                }else{
                    $group_tag_id_parser = "group_tag_id='$group_tag_id', ";
                }
                
                if(count($rules) == 1){
                    
                    if($op_to_interface == "Any"){
                        $op_to_interface = "any";
                    }

                    if($isdat == 1){
                        if ($dnat_translation_type=="dynamic"){
                            $tp_dat_port_parser = "tp_dat_port='$tp_dat_port',is_dat='2', ";
                        }
                        else{
                            $tp_dat_port_parser = "tp_dat_port='$tp_dat_port',is_dat='1', ";
                        }
                        $tp_dat_address_parser = "";
                    }
                    else{
                        $tp_dat_port_parser = "";
                        $tp_dat_address_parser = "tp_dat_address_lid = '', tp_dat_address_table = '', tp_dat_port='', is_dat='0', ";
                    }

                    $name = truncate_rulenames($name);

                    $projectdb->query("UPDATE nat_rules SET tp_fallback_type='$tp_fallback_type',tp_sat_ipaddress_fallback='$tp_sat_ipaddress_fallback',tp_sat_interface_fallback='$tp_sat_interface_fallback',tp_sat_interface='$tp_sat_interface',tp_sat_address_type='$tp_sat_address_type',tp_sat_bidirectional='$tp_sat_bidirectional',name='$name',description='$description',op_zone_to='$op_zone_to',op_to_interface='$op_to_interface',tp_sat_type='$tp_sat_type', nat_type='$nat_type', $tp_dat_address_parser $tp_dat_port_parser $group_tag_id_parser tp_sat_ipaddress='$tp_sat_ipaddress' , target_negate='$target_negate', group_tag_id='$group_tag_id' WHERE id='$rule_lid';");
                }
                else{
                    if ($isdat == 1){
                        $tp_dat_port_parser = "tp_dat_port='$tp_dat_port', "; 
                    }else{
                        $tp_dat_port_parser = "";
                    }

                    if($tp_sat_type == ""){
                        $tp_sat_type_parser = "";
                        $tp_sat_address_type_parser = "";
                        $tp_sat_bidirectional_parser = "";
                        $tp_sat_ipaddress_parser = "";
                        $tp_sat_interface_parser = "";
                    }

                    if($description == ""){
                        $description_edit = "";
                    }else{
                        $description_edit = "description='$description', ";
                    }

                    $projectdb->query("UPDATE nat_rules SET $description_edit $tp_fallback_type_parser $tp_sat_interface_fallback_parser $tp_sat_ipaddress_fallback_parser $op_zone_to_parser $op_to_interface_parser $tp_sat_type_parser $tp_sat_address_type_parser $tp_sat_bidirectional_parser $tp_sat_ipaddress_parser $tp_sat_interface_parser $tp_dat_port_parser $group_tag_id_parser source = '$source' WHERE id='$rule_lid';");
                }
                
            }
            
            //Update the Rule Zones
            require_once INC_ROOT.'/libs/common/lib-rules.php';
            $ipMapping = array();
            $vr = 1;
            
            if ($calc_autozone=="on"){
                fix_Nat_Policy(-1, $project, $source, $vsys, $vr, $ipMapping, $rules, true, true);
            }

            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false, "msg"=>"No rule id provided"));
        }
        
        
         
    }
    elseif ($type=="add_rule"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $data = 0;

        $initialPosition=intval($ids);
        $finalPosition=$initialPosition+1;

        if ($data=="0"){$initialPosition=0;$finalPosition=1;}
        if ($vsys==""){$vsys="vsys1";}
        if (($source!=0) AND ($vsys!="all")){
            $projectdb->query("UPDATE nat_rules SET position=position+1 WHERE position >= '$initialPosition';");
            $projectdb->query("INSERT INTO nat_rules (source,vsys,disabled,is_dat,position) values ('$source','$vsys','0','0','$initialPosition');");
            echo json_encode(array("success"=>true));
        }
        else {
            echo json_encode(array("success"=>false));
        }

    }
    elseif ($type=="remove_tag"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        if ($ids!=""){
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$ids' AND table_name_lid = 'tag' AND lid IN ($rule_lid) AND type = 'nat_rules_tag' AND user_id = '$user_id';");
        }
    }
    elseif ($type == "remove_from"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        if ($ids != ""){
            $lids = explode(",", $ids);
            foreach ($lids as $key => $name){
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN ($rule_lid) AND name = '$name' AND type = 'nat_rules_from' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "remove_src"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        
        if ($ids != ""){
            $idss = explode(",", $ids);
            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'nat_rules_src' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid IN ($rule_lid) AND type = 'nat_rules_src' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type=="remove_dst"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        if ($ids != ""){
            $idss = explode(",", $ids);
            foreach ($idss as $key => $ids_table){
                //$projectdb->query("DELETE FROM nat_rules_src WHERE id='$name';");
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'nat_rules_dst' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid IN ($rule_lid) AND type = 'nat_rules_dst' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type=="remove_translated"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        if ($ids!=""){
            $idss = explode(",", $ids);
            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'nat_rules_translated_address' ;");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid IN ($rule_lid) AND type = 'nat_rules_translated_address' ;");
            }
        }
    }
    elseif ($type=="remove_translated_fallback"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        if ($ids!=""){
            $idss = explode(",", $ids);
            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'nat_rules_translated_address_fallback' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid IN ($rule_lid) AND type = 'nat_rules_translated_address_fallback' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "clone") {
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $position = $projectdb->real_escape_string((string) (isset($_POST['position']) ? $_POST['position'] : $_GET['position']));
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
            clone_nat_rule($initialPosition, $finalPosition, $vsys, $source, $value, $message, $project);
        }
        echo json_encode(array("success" => true));
    }
    elseif($type=="remove_target"){

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $where_edit = $projectdb->real_escape_string((string) (isset($_POST['where']) ? $_POST['where'] : $_GET['where']));

        if($where_edit == "edit"){
            if ($ids != ""){

                $ids_explode = explode(",",$ids);

                foreach ($ids_explode AS $id_edit_table){
                    $getNameOld = $projectdb->query("SELECT name, vsys_member FROM edit_table WHERE id = '$id_edit_table' AND type = 'nat_rules_target' AND user_id = '$user_id' AND remove = '0';");
                    if ($getNameOld->num_rows == 1) {
                        $dataNO = $getNameOld->fetch_assoc();
                        $name_old = $dataNO['name'];
                        $vsys_member_old = $dataNO['vsys_member'];
                    }

                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$name_old' AND vsys_member = '$vsys_member_old' AND type = 'nat_rules_target' AND user_id = '$user_id';");
                }
            }
        }
        else{
            take_snapshot_last($project);
            if($ids != ""){
                $projectdb->query("DELETE FROM nat_rules_target WHERE rule_lid IN ($ids);");
            }else{
                $projectdb->query("DELETE FROM nat_rules_target WHERE source = '$source';");
            }
        }
        echo json_encode(array("success"=>true));
    }
}
elseif ($action == "add"){
    if ($type == "from"){
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));

        $rules = explode(",", $rule_lid);
        echo "Source = $source\n";
        foreach ($rules as $key => $rule_lid){
            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND type = 'nat_rules_from' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {
                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_from' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                    . "VALUES (NULL, '$ids','$rule_lid', '', '', 'nat_rules_from', '$name', '','$vsys', '$source', '0', '$user_id');");

            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND type = 'nat_rules_from' AND user_id = '$user_id';");
            }
        }
        
        
        echo json_encode(array("success"=>true));
    }
    elseif ($type == "tag"){
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        $rules = explode(",", $rule_lid);
        foreach ($rules as $key => $rule_lid){
            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'nat_rules_tag' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {
                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_tag' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                $realColor = "";
                $getTag = $projectdb->query("SELECT color FROM $table_name WHERE id = '$member_lid';");
                if ($getTag->num_rows == 1){ 
                    $Ttag = $getTag->fetch_assoc();
                    $realColor = $Ttag['color'];
                }
                $image = "tags_$realColor.png";
                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                    . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'nat_rules_tag', '$name', '$image','$vsys', '$source', '0', '$user_id');");
            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND name = '$name' AND type = 'nat_rules_tag' AND user_id = '$user_id';");
            }
        }
        
        echo json_encode(array("success"=>true));
    }
    elseif ($type == "src"){
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'nat_rules_src' AND user_id = '$user_id';");
        
        $rules = explode(",", $rule_lid);
        
        foreach ($rules as $key => $rule_lid){

            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

            if ($getBridge->num_rows == 0) {

                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_src' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                //$image = getImage("address", $table_name, $member_lid);

                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                    . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'nat_rules_src', '$name_member', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");

            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'nat_rules_src' AND user_id = '$user_id';");
            }
        }
        echo json_encode(array("success"=>true));
    }
    elseif ($type == "dst"){
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'nat_rules_dst' AND user_id = '$user_id';");
        
        $rules = explode(",", $rule_lid);
        
        foreach ($rules as $key => $rule_lid){

            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

            if ($getBridge->num_rows == 0) {

                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_dst' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                //$image = getImage("address", $table_name, $member_lid);

                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                    . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'nat_rules_dst', '$name_member', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");

            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'nat_rules_dst' AND user_id = '$user_id' ;");
            }
        }
        
        echo json_encode(array("success"=>true));
        
    }
    elseif ($type == "translated_address"){
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        $rules = explode(",", $rule_lid);
        
        foreach ($rules as $key => $rule_lid){

            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'nat_rules_translated_address' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {
                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_translated_address' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                //$image = getImage("address", $table_name, $member_lid);

                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                    . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'nat_rules_translated_address', '$name_member', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");

            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'nat_rules_translated_address' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "translated_address_fallback"){
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        $rules = explode(",", $rule_lid);
        
        foreach ($rules as $key => $rule_lid){

            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'nat_rules_translated_address_fallback' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {
                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_translated_address_fallback' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                //$image = getImage("address", $table_name, $member_lid);

                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                    . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'nat_rules_translated_address_fallback', '$name_member', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");

            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'nat_rules_translated_address_fallback' AND user_id = '$user_id';");
            }
        }
        
    }
    elseif ($type == "target"){

        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $device_vsys = $projectdb->real_escape_string((string) (isset($_POST['device_vsys']) ? $_POST['device_vsys'] : $_GET['device_vsys']));
        $id_edit_table = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        $where_edit = $projectdb->real_escape_string((string) (isset($_POST['where']) ? $_POST['where'] : $_GET['where']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        $rules = explode(",",$rule_lid);

        // From security editor
        if($where_edit == "edit"){

            if($id_edit_table == "") {
                foreach ($rules as $key => $rule_lid){
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND vsys_member = '$device_vsys' AND type = 'nat_rules_target' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_target' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        } else {
                            $ids = 1;
                        }
                        $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'nat_rules_target', '$name', '','$vsys', '$device_vsys', '$source', '0', '$user_id');");
                    }
                    else {
                        $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND vsys_member = '$device_vsys' AND type = 'nat_rules_target' AND user_id = '$user_id';");
                    }
                }
            }
            else{

                $getNameOld = $projectdb->query("SELECT name, vsys_member FROM edit_table WHERE id = '$id_edit_table' AND type = 'nat_rules_target' AND user_id = '$user_id';");
                if ($getNameOld->num_rows == 1) {
                    $dataNO = $getNameOld->fetch_assoc();
                    $name_old = $dataNO['name'];
                    $vsys_member_old = $dataNO['vsys_member'];
                }

                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN (".implode(",", $rules).") AND name = '$name_old' AND vsys_member = '$vsys_member_old' AND type = 'nat_rules_target' AND user_id = '$user_id';");
                //echo "UPDATE edit_table SET name = '$name', vsys_member = '$device_vsys' WHERE lid IN (".implode(",", $rules).") AND name = '$name_old' AND vsys_member = '$vsys_member_old' AND source = '$source' AND type = 'nat_rules_target' AND user_id = '$user_id';\n";
                foreach ($rules as $key => $rule_lid){
                    $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                        . "VALUES (NULL, '','$rule_lid', '', '', 'nat_rules_target', '$name', '','$vsys', '$device_vsys', '$source', '0', '$user_id');");
                }
            }

        }
        else{
            // From menu

            if(count($rules) == 1){

                if($rules[0] == ""){
                    // All rules
                    $getAllRules = $projectdb->query("SELECT id FROM nat_rules WHERE source = '$source' ;");

                    if ($getAllRules->num_rows > 0) {
                        $rules = array();
                        while ($dataAR = $getAllRules->fetch_assoc()) {
                            $rules[] = $dataAR['id'];
                        }
                    }
                }
            }

            foreach ($rules as $key => $rule_lid) {

                $getExist = $projectdb->query("SELECT name, device_vsys FROM nat_rules_target WHERE rule_lid = '$rule_lid' AND name = '$name' AND device_vsys = '$device_vsys'  ;");
                if ($getExist->num_rows == 0) {
                    $projectdb->query("INSERT INTO nat_rules_target (id, source, vsys, name, device_vsys, rule_lid) "
                        . "VALUES (NULL, '$source', '$vsys', '$name', '$device_vsys', '$rule_lid');");
                }

            }

        }

    }
}
elseif ($action=="update"){

    if ($type == "from"){

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        
        $rules = explode(",",$rule_lid);
        if (($name!="") AND ($oldname!="")){
            foreach ($rules as $key=>$rule_lid){

                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name = '$oldname' AND type = 'nat_rules_from' AND user_id = '$user_id';");

                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'nat_rules_from' AND name = '$name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 1){
                    $dataExist = $getExistRemove->fetch_assoc();
                    $id_exist = $dataExist['id'];
                    $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                }else{
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_from' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                        . "VALUES (NULL, '$ids','$rule_lid', '', '', 'nat_rules_from', '$name', '','$vsys', '$source', '0', '$user_id');");
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "tag"){

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        $rules = explode(",",$rule_lid);
        
        if (($member_lid!="") AND ($table_name!="")){

            $getNameTag = $projectdb->query("SELECT name FROM edit_table WHERE ids = '$id' AND type = 'nat_rules_tag' AND user_id = '$user_id';");
            if ($getNameTag->num_rows == 1){ 
                $dataNT = $getNameTag->fetch_assoc();
                $name_tag = $dataNT['name'];
                
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$name_tag' AND type = 'nat_rules_tag' AND user_id = '$user_id';");
            }
            
            $getTag = $projectdb->query("SELECT color FROM $table_name WHERE id = '$member_lid';");
            if ($getTag->num_rows == 1){ 
                $Ttag = $getTag->fetch_assoc();
                $realColor = $Ttag['color'];
            }
            $image = "tags_$realColor.png";
            
            foreach ($rules as $key=>$rule_lid){
                
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'nat_rules_tag' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 1){
                    $dataExist = $getExistRemove->fetch_assoc();
                    $id_exist = $dataExist['id'];
                    $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                }else{
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_tag' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'nat_rules_tag', '$name', '$image', '$vsys', '$source', '0', '$user_id');");

                }
            }
            
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "src"){

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        $rules = explode(",",$rule_lid);
        if (($member_lid!="") AND ($table_name!="")){
            $getMemberTable = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'nat_rules_src' AND user_id = '$user_id';");
            if ($getMemberTable->num_rows == 1){ 
                $dataMT = $getMemberTable->fetch_assoc();
                $member_lid_old = $dataMT['member_lid'];
                $table_name_old = $dataMT['table_name_lid'];
                
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'nat_rules_src' AND user_id = '$user_id';");
            }
            //$image = getImage("address", $table_name, $member_lid);
            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

            foreach ($rules as $key=>$rule_lid){
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'nat_rules_src' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 1){
                    $dataExist = $getExistRemove->fetch_assoc();
                    $id_exist = $dataExist['id'];
                    $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist';");
                }else{
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_src' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'nat_rules_src', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "dst"){

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        $rules = explode(",", $rule_lid);
        if (($member_lid!="") AND ($table_name!="")){
            $getMemberTable = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'nat_rules_dst' AND user_id = '$user_id';");
            if ($getMemberTable->num_rows == 1){ 
                $dataMT = $getMemberTable->fetch_assoc();
                $member_lid_old = $dataMT['member_lid'];
                $table_name_old = $dataMT['table_name_lid'];
                
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'nat_rules_dst' AND user_id = '$user_id';");
            }
            //$image = getImage("address", $table_name, $member_lid);
            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

            foreach ($rules as $key=>$rule_lid){
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'nat_rules_dst' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 1){
                    $dataExist = $getExistRemove->fetch_assoc();
                    $id_exist = $dataExist['id'];
                    $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                }else{
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_dst' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'nat_rules_dst', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "op_service"){

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        //$id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        if ($member_lid == "0"){

            $projectdb->query("DELETE FROM edit_table WHERE type = 'op_service' AND source = '$source' AND user_id = '$user_id';");

            $rules = explode(",", $rule_lid);
            foreach ($rules as $key => $rule_lid){
                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                    . "VALUES (NULL, '1','$rule_lid', '$member_lid', '', 'op_service', '', '','$vsys', '$source', '0', '$user_id');");

            }

            echo json_encode(array("success"=>true));
        }
        elseif (($member_lid!="") AND ($table_name!="")){
            $projectdb->query("DELETE FROM edit_table WHERE type = 'op_service' AND source = '$source' AND user_id = '$user_id';");

            $rules = explode(",", $rule_lid);
            foreach ($rules as $key => $rule_lid){
                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                    . "VALUES (NULL, '1','$rule_lid', '$member_lid', '$table_name', 'op_service', '', '','$vsys', '$source', '0', '$user_id');");
            }

            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "tp_destination"){
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        $rules = explode(",", $rule_lid);
        
        foreach ($rules as $key => $rule_lid){
            
            if (($member_lid=="0") AND ($table_name=="0")){
                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                        . "VALUES (NULL, '1','$rule_lid', '$member_lid', '$table_name', 'tp_destination', '', '','$vsys', '$source', '0', '$user_id');");
                echo json_encode(array("success"=>true));
            }
            elseif (($member_lid!="") AND ($table_name!="")){
                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                        . "VALUES (NULL, '1','$rule_lid', '$member_lid', '$table_name', 'tp_destination', '', '','$vsys', '$source', '0', '$user_id');");
                echo json_encode(array("success"=>true));
            }
            else{
                echo json_encode(array("success"=>false));
            }
        
        }
        
    }
    elseif ($type == "translated_address"){
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        $rules = explode(",", $rule_lid);
        
        if (($member_lid!="") AND ($table_name!="")){
            $getMemberTable = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'nat_rules_translated_address' AND user_id = '$user_id';");
            if ($getMemberTable->num_rows == 1){ 
                $dataMT = $getMemberTable->fetch_assoc();
                $member_lid_old = $dataMT['member_lid'];
                $table_name_old = $dataMT['table_name_lid'];
                
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'nat_rules_translated_address' AND user_id = '$user_id';");
            }
            //$image = getImage("address", $table_name, $member_lid);
            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

            foreach ($rules as $key=>$rule_lid){
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'nat_rules_translated_address' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 1){
                    $dataExist = $getExistRemove->fetch_assoc();
                    $id_exist = $dataExist['id'];
                    $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist';");
                }else{
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_translated_address' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'nat_rules_translated_address', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "tp_translated_address"){

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));

        $rules = explode(",", $rule_lid);
        foreach ($rules as $key=>$rule_lid){
            if (($member_lid!="") AND ($table_name!="")){
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND type = 'nat_rules_translated_address' AND user_id = '$user_id';");
                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                    . "VALUES (NULL, '1','$rule_lid', '$member_lid', '$table_name', 'nat_rules_translated_address', '', '','$vsys', '$source', '0', '$user_id');");

            }
        }
        echo json_encode(array("success"=>true));
    }
    elseif ($type=="translated_address_fallback"){

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        if (($member_lid!="") AND ($table_name!="")){
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE ids = '$id' AND type = 'nat_rules_translated_address_fallback' AND user_id = '$user_id';");
            //$image = getImage("address", $table_name, $member_lid);
            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

            $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'nat_rules_translated_address_fallback' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
            if($getExistRemove->num_rows == 1){
                $dataExist = $getExistRemove->fetch_assoc();
                $id_exist = $dataExist['id'];
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist';");
            }else{
                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'nat_rules_translated_address_fallback' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                    . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'nat_rules_translated_address_fallback', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
}


function getMatchingNatIds($ruleids, $source, $vsyse, $project, $preorpost, INT $start, INT $limit, $filter, $vsys, $id_cons){

    global $projectdb;
    $ruleidsInFilters = array();
    $query = generate_query("policies", $vsyse, $preorpost);

    if(($filter != "none") && ($filter != "0")){

        $params['tools_where_columns_id'] = $filter;
        $params['tools_operator_id'] = "contains";
        $params['search'] = "";
        $params['tools_where_id'] = "3";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";
        $params['source'] = $source;
        $params['vsys'] = $vsys;
        $params['case_sensitive'] = "0";

        setFilter($project, $params);
        executeSQL($project, $params);

    }
    elseif(($filter == "none") || ($filter == "0")){
    }

    $query = generateQueryConsolidation($project, "nat_rules", $query, $source, $id_cons);

    list($query, $orderby) = generateQueryFilters($project, "nat_rules", "", $query, $source);

    $order = " ORDER BY source,vsys,preorpost,position ASC ";
    $sec_query = "SELECT id FROM nat_rules $query $order;";

    $result = $projectdb->query($sec_query);
    //echo $sec_query;
    $listOfIds = array();
    if($result->num_rows >0){
        while($data = $result->fetch_assoc()){
            $listOfIds[] = $data['id'];
        }
    }

    return $listOfIds;
}


function search_nat_policies_inmemory($ruleids, $source, $vsys, $project, $preorpost, $start, $limit, $color, $level, $label, $objectsInMemory=null){
    global $projectdb;

    if ($ruleids==NULL){
        $result= [
            "total" => 0,
            "nat" => null
        ];
        return $result;
    }

    $rules = array();
    $rule = array();

    $ruleids2=implode(",",$ruleids);
    $sec_query = "SELECT * FROM nat_rules WHERE id IN ($ruleids2) ORDER BY position;";
    $getLimit = $projectdb->query($sec_query);

    if ($getLimit->num_rows == 0){
        $result= [
            "total" => 0,
            "nat" => null
        ];
    }
    else{

        while ($row = $getLimit->fetch_assoc()) {

            if (($row['op_to_interface'] == "") OR ( $row['op_to_interface'] == NULL)){$row['op_to_interface'] = "any";}
            if (($row['tp_sat_type'] == "") OR ( $row['tp_sat_type'] == NULL)){$row['tp_sat_type'] = "none";}
            if ($row['op_zone_to'] == "") { $row['op_zone_to'] = "none";}

            if (($row['tp_sat_type'] == "") || ($row['tp_sat_type'] == "None") || ($row['tp_sat_type'] == "none") || ($row['tp_sat_type'] == NULL)){
                $row['tp_sat_type_format'] = "None";
            }elseif($row['tp_sat_type'] == "static-ip"){
                $row['tp_sat_type_format'] = "Static";
            }elseif($row['tp_sat_type'] == "dynamic-ip"){
                $row['tp_sat_type_format'] = "Dynamic Ip";
            }elseif($row['tp_sat_type'] == "dynamic-ip-and-port"){
                $row['tp_sat_type_format'] = "Dynamic Ip and Port";
            }

            if ($row['group_tag_id'] == "0") {
                $row['group_tag_id'] = "";
            }

            $row['color'] = $color;
            $row['label'] = $label;
            $row['groupby'] = $level;
            //Default values
            $row["warning"] = 0;

            $row["chk_target"]=$row["target"];
            $row['target']=array();

            if (($row['tp_dat_port']==0) OR ($row['tp_dat_port']=="")){$row['tp_dat_port']="any";}
            $rules[$row['id']] = $row;

            switch ($row["is_dat"]){
                case "1":
                    $rules[$row['id']]['dnat_translation_type']="static";
                    break;
                case "2":
                    $rules[$row['id']]['dnat_translation_type']="dynamic";
                    $rules[$row['id']]['is_dat']="1";
                    break;
                default:
                    $rules[$row['id']]['dnat_translation_type']="static";
            }

            if ( (($row['op_service_lid']==0) AND ($row['op_service_table']==0)) OR ((($row['op_service_lid']=="") AND ($row['op_service_table']=="")))) {
                $rules[$row['id']]["op_service"][] = array('name'=>'any');
            }
            else{
                $serviceObject = $objectsInMemory[$row['op_service_table']][$row['op_service_lid']];
                $rules[$row['id']]["op_service"][]=
                    array('img' => $serviceObject['icon'], 'name' => $serviceObject['name'], 'ip' => $serviceObject['myip'], 'vsys_member' => $serviceObject['vsys']);
            }

            if ( (($row['tp_dat_address_lid']==0) AND ($row['tp_dat_address_table']==0)) OR ((($row['tp_dat_address_lid']=="") AND ($row['tp_dat_address_table']=="")))) {
                $rules[$row['id']]["tp_dat_address"][] = array('name'=>'none');
            }
            else{
                $serviceObject = $objectsInMemory[$row['tp_dat_address_table']][$row['tp_dat_address_lid']];
                $rules[$row['id']]["tp_dat_address"][]=
                    array('img' => $serviceObject['icon'], 'name' => $serviceObject['name'], 'ip' => $serviceObject['myip'], 'vsys_member' => $serviceObject['vsys']);
            }
        }

        # Warnings
        $warn = $projectdb->query("SELECT obj_id FROM logs WHERE fixed=0 AND obj_type='rules' AND obj_id in ($ruleids2) AND obj_table='nat_rules';");
        if ($warn->num_rows>0) {
            while ($data = $warn->fetch_assoc()) {
                $rules[$data['obj_id']]['warning'] = '1';
            }
        }

        # Read the Tags
        $getSource = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM nat_rules_tag WHERE rule_lid IN ($ruleids2);");
        $processed = array();
        if ($getSource->num_rows>0){
            while($src = $getSource->fetch_assoc()) {
                $processed[]=$src['rule_lid'];
//                    $src_table_name = $src['table_name'];
//                    $src_member_lid = $src['member_lid'];
                $tagObject = $objectsInMemory[$src['table_name']][$src['member_lid']];
                $rules[$src['rule_lid']]["tag"][]= [
                    "id"=>$tagObject['id'],
                    "name"=>$tagObject['name'],
                    "color"=>$tagObject['rgb']
                ];
            }
        }
        $notprocessed = array_diff($ruleids, $processed);
        foreach($notprocessed as $ruleid){
            $rules[$ruleid]['tag'] = null;
        }

        # Read the Group Tags PanOS Version 9.1
        $getSource = $projectdb->query("SELECT group_tag_id, 'tag' as table_name, id FROM nat_rules WHERE id IN ($ruleids2) AND group_tag_id != '0';");
        $processed = array();
        if ($getSource->num_rows>0){
            while($src = $getSource->fetch_assoc()) {
                $processed[]=$src['id'];
                $GrouptagObject = $objectsInMemory[$src['table_name']][$src['group_tag_id']];
                $rules[$src['id']]["group_tags"]= [
                    "id"=>$GrouptagObject['id'],
                    "name"=>$GrouptagObject['name']
                ];
            }
        }
        $notprocessed = array_diff($ruleids, $processed);
        foreach($notprocessed as $ruleid){
            $rules[$ruleid]['group_tags'] = null;
        }

        # Read NAT Rules FROM
        $searchZoneSrc = $projectdb->query("SELECT name,rule_lid FROM nat_rules_from WHERE rule_lid IN ($ruleids2);");
        $processed = array();
        if ($searchZoneSrc->num_rows > 0) {
            while ($Tags = $searchZoneSrc->fetch_assoc()) {
                $processed[]=$Tags['rule_lid'];
                $rules[$Tags['rule_lid']]["op_zone_from"][]=$Tags['name'];
            }
        }
        $notprocessed = array_diff($ruleids, $processed);
        foreach($notprocessed as $ruleid){
            $rules[$ruleid]['op_zone_from'] = null;
        }

        # Read Nat Rules SRC
        $getSource = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM nat_rules_src WHERE rule_lid IN ($ruleids2);");
        $processed = array();
        if ($getSource->num_rows>0){
            while($src = $getSource->fetch_assoc()) {
                $processed[]=$src['rule_lid'];
                $addressObject = $objectsInMemory[$src['table_name']][$src['member_lid']];
                $rules[$src['rule_lid']]["src"][]=array('img' => $addressObject['icon'], 'name' => $addressObject['name'], 'ip' => $addressObject['myip'], 'vsys_member' => isset($addressObject['vsys'])?$addressObject['vsys']:'', 'table_name' => $src['table_name']);
            }
        }
        $notprocessed = array_diff($ruleids, $processed);
        foreach($notprocessed as $ruleid){
            $rules[$ruleid]['src'] = null;
        }

        # Read Nat Rules DST
        $getSource = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM nat_rules_dst WHERE rule_lid IN ($ruleids2);");
        $processed = array();
        if ($getSource->num_rows>0){
            while($src = $getSource->fetch_assoc()) {
                $processed[]=$src['rule_lid'];
                $addressObject = $objectsInMemory[$src['table_name']][$src['member_lid']];
                $rules[$src['rule_lid']]["dst"][]=array('img' => $addressObject['icon'], 'name' => $addressObject['name'], 'ip' => $addressObject['myip'], 'vsys_member' => $addressObject['vsys'], 'table_name' => $src['table_name']);
            }
        }
        $notprocessed = array_diff($ruleids, $processed);
        foreach($notprocessed as $ruleid){
            $rules[$ruleid]['dst'] = null;
        }

        # Translated packet
        # Source Translation
        $getSource = $projectdb->query("SELECT table_name,member_lid,rule_lid FROM nat_rules_translated_address WHERE rule_lid IN ($ruleids2);");
        $processed = array();
        if ($getSource->num_rows>0){
            while($src = $getSource->fetch_assoc()) {
                $processed[]=$src['rule_lid'];
                $addressObject = $objectsInMemory[$src['table_name']][$src['member_lid']];
                $rules[$src['rule_lid']]["translated_address"][]=array('img' => $addressObject['icon'], 'name' => $addressObject['name'], 'ip' => $addressObject['myip'], 'vsys_member' => isset($addressObject['vsys'])?$addressObject['vsys']:'', 'table_name' => $src['table_name']);
            }
        }
        $notprocessed = array_diff($ruleids, $processed);
        foreach($notprocessed as $ruleid){
            $rules[$ruleid]['translated_address'][] = array('name' => 'none');
        }

        # Target
        $searchTarget = $projectdb->query("SELECT name,device_vsys,rule_lid FROM nat_rules_target WHERE rule_lid IN ($ruleids2)");
        $processed = array();
        if ($searchTarget->num_rows > 0) {
            $targetArray = array();
            while ($Tags = $searchTarget->fetch_assoc()) {
                $processed[]=$Tags['rule_lid'];
                if ($Tags['device_vsys']!=NULL){
                    $rules[$Tags['rule_lid']]['target'][] = "<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".$Tags['name']."/".$Tags['device_vsys'];
                }
                else{
                    $rules[$Tags['rule_lid']]['target'][] = "<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".$Tags['name'];
                }
            }
        }
        $notprocessed = array_diff($ruleids, $processed);
        foreach($notprocessed as $ruleid){
            $rules[$ruleid]['target'] = 'any';
        }

        $result= [
            "total" => count($rules),
            "nat" => $rules
        ];

    }

    return $result;


}






