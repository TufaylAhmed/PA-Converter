<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/common/palettes.php';
//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';

require_once INC_ROOT.'/libs/common/MemberObject.php';
use PaloaltoNetworks\Policy\Objects\MemberObject;

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename']) ? $_GET['devicename'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $short      = (string)  (isset($_GET['short'])      ? $_GET['short'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        $id_cons    = (string)  (isset($_GET['id_cons'])    ? $_GET['id_cons'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $short      = (string)  (isset($_POST['short'])     ? $_POST['short'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $id_cons    = (string)  (isset($_POST['id_cons'])   ? $_POST['id_cons'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $short      = (string)  (isset($_POST['short'])     ? $_POST['short'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $id_cons    = (string)  (isset($_POST['id_cons'])   ? $_POST['id_cons'] : '');
        break;
}

//require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);
//require_once INC_ROOT.'/libs/common/lib-objects.php';

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

if ($action == "get") {
    if($type=="rules" && $short == 'true'){
        $query ="SELECT id, name FROM appoverride_rules WHERE source ='$source' AND vsys='$vsys' ORDER BY position";
        $result = $projectdb->query($query);
        $rules = array();
        if($result->num_rows >0){
            while($data = $result->fetch_assoc()){
                $rules[] = $data;
            }
        }

        $msg = [
            'total' => count($rules),
            'appoverride' => $rules,
        ];
        echo json_encode($msg);
    }
    elseif ($type == "rules") {

        $vsyses = getVsyses($projectdb, $vsys, $source);

        $sesysv = array_reverse($vsyses);
        $secRulePacks = array();

        $group_ = 0;
        $ruleids = "";
        $colorPos = 900;
        foreach ($sesysv as $vsyse) {
            $color = $colorPalette['DeepOrange'][$colorPos];
            $colorPos -=200;
            //Pre Rules
//            $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '0', $start, $limit);
            $label = ($vsys == $vsyse) ? ("<i class=\"fa fa-map-marker\" style=\"font-size:16px; color:red;\" aria-hidden=\"true\"></i>&nbsp;<font color='#336989'><b>Pre-rulebase ".$vsyse."</b></font></u></b>") : "Pre-rulebase ".$vsyse;
            $secRulePacks[] = search_appOverride_policies($ruleids, $source, $vsyse, $project, '0', '', '',$color, $group_, $label, $filter, $vsys, $id_cons);
            $group_++;
        }

        $colorPos = 900 - (count($vsyses)-1)*200;
        foreach ($vsyses as $vsyse) {
            $color = $colorPalette['Blue'][$colorPos];
            $colorPos += 200;
            //Post Rules
//            $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '1', $start, $limit);
            $label = ($vsys == $vsyse) ? ("<i class=\"fa fa-map-marker\" style=\"font-size:16px; color:red;\" aria-hidden=\"true\"></i>&nbsp;<font color='#336989'><b>Post-rulebase ".$vsyse."</b></font></u></b>") : "Post-rulebase ".$vsyse;
            $secRulePacks[] = search_appOverride_policies($ruleids, $source, $vsyse, $project, '1', '', '',$color, $group_, $label, $filter, $vsys, $id_cons);
            $group_++;
        }
        $total=0;
        $secRules = array();
        foreach($secRulePacks as $secRulePack){
            $total += $secRulePack['total'];
            if (count($secRulePack['appoverride'])>0) {
                $secRules = array_merge($secRules, $secRulePack['appoverride']);
            }
        }

        $result = [
            'total' => $total,
            'appoverride' => $secRules,
        ];

        echo json_encode($result);

    }
    elseif ($type == "source_by_rulelid"){

        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_src' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){

            $getSource = $projectdb->query("SELECT id, table_name, member_lid, rule_lid FROM appoverride_rules_src WHERE rule_lid IN ($lid);");
            if ($getSource->num_rows>0){
                $Source=array();
                while($src=$getSource->fetch_assoc()){
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    $rule_lid = $src['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'appoverride_rules_src' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$src_member_lid', '$src_table_name', 'appoverride_rules_src', '$name', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_src' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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

        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_dst' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            $getSource = $projectdb->query("SELECT id,table_name,member_lid, rule_lid FROM appoverride_rules_dst WHERE rule_lid IN ($lid) ;");
            if ($getSource->num_rows>0){
                $Source=array();
                while($src=$getSource->fetch_assoc()){
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    $rule_lid = $src['rule_lid'];

                    list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");

                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'appoverride_rules_dst' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '$src_member_lid', '$src_table_name', 'appoverride_rules_dst', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_dst' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
    elseif ($type == "apps_by_rulelid"){

        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
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
    elseif ($type == "tags_by_rulelid"){
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_tag' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){
            $searchTag = $projectdb->query("SELECT srt.rule_lid as rule_lid, srt.member_lid as member_lid, tag.name as name, tag.color as color FROM appoverride_rules_tag srt, tag WHERE srt.rule_lid IN ($lid) AND tag.id=srt.member_lid;");
            if ($searchTag->num_rows > 0) {
                $Tag = array();
                while ($Ttag=$searchTag->fetch_assoc()){
                    $tag_member_lid = $Ttag['member_lid'];
                    $tag_table_name='tag';
                    $rule_lid = $Ttag['rule_lid'];
                    $TagName=$Ttag['name'];
                    $TagColor=$Ttag['color'];
                    $realColor=$Ttag['color'];
                    if ($TagColor=="color1"){$TagColor="#CD383F";}
                    elseif ($TagColor=="color2"){$TagColor="#72A392";}
                    elseif ($TagColor=="color3"){$TagColor="#569BBD";}
                    elseif ($TagColor=="color4"){$TagColor="#EBD722";}
                    elseif ($TagColor=="color5"){$TagColor="#C27D2A";}
                    elseif ($TagColor=="color6"){$TagColor="#FF6A00";}
                    elseif ($TagColor=="color7"){$TagColor="#7D3953";}
                    elseif ($TagColor=="color8"){$TagColor="#5B6F7B";}
                    elseif ($TagColor=="color9"){$TagColor="#C9D6A6";}
                    elseif ($TagColor=="color10"){$TagColor="#8AD3DF";}
                    elseif ($TagColor=="color11"){$TagColor="#C2D1D3";}
                    elseif ($TagColor=="color12"){$TagColor="#80A1B6";}
                    elseif ($TagColor=="color13"){$TagColor="#C1D72F";}
                    elseif ($TagColor=="color14"){$TagColor="#000000";}
                    elseif ($TagColor=="color15"){$TagColor="#FFC425";}
                    elseif ($TagColor=="color16"){$TagColor="#918A75";}
                    $thenewtagcolor=$TagName;
                    //}
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$tag_member_lid' AND table_name_lid = '$tag_table_name' AND name = '$TagName' AND type = 'appoverride_rules_tag' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $image = "tags_$realColor.png";
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES ('NULL', '', '$rule_lid', '$tag_member_lid', '$tag_table_name', 'appoverride_rules_tag', '$TagName', '$image','$vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_tag' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_tag' AND remove = '0' AND user_id = '$user_id' GROUP BY member_lid, table_name_lid;");
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
    elseif ($type == "from_by_rulelid"){

        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_from' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){

            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid FROM appoverride_rules_from WHERE rule_lid IN ($lid);");

            if ($searchUsers->num_rows > 0) {
                $data = array();
                $howmany = $searchUsers->num_rows;
                //while ($row = $searchUsers->fetch_object()){
                while ($row = $searchUsers->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'appoverride_rules_from' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'appoverride_rules_from', '$name', '', '0', '$user_id');");
                    }
                }

                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_from' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_to' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){

            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid FROM appoverride_rules_to WHERE rule_lid IN ($lid) ;");
            if ($searchUsers->num_rows > 0) {
                $data = array();
                $howmany = $searchUsers->num_rows;
                while ($row = $searchUsers->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'appoverride_rules_to' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image,  remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'appoverride_rules_to', '$name', '', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_to' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","rows":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_to' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, ids AS id FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_to' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
    elseif ($type == "target_by_rulelid") {

        $vsys = $projectdb->real_escape_string((string)(isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string)(isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $lid = $projectdb->real_escape_string((string)(isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        $getEditTable = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, ids, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_target' AND user_id = '$user_id';");
        if ($getEditTable->num_rows == 0){

            $searchUsers = $projectdb->query("SELECT name, source, vsys, id, rule_lid, device_vsys FROM appoverride_rules_target WHERE rule_lid IN ($lid) ;");
            if ($searchUsers->num_rows > 0) {
                $data = array();
                $howmany = $searchUsers->num_rows;
                while ($row = $searchUsers->fetch_assoc()){
                    $rule_lid = $row['rule_lid'];
                    $name = $row['name'];
                    $device_vsys = $row['device_vsys'];
                    $id = $row['id'];
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND type = 'appoverride_rules_target' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES ('NULL', '$id', '$rule_lid', '', '', 'appoverride_rules_target', '$name', '$vsys', '$device_vsys', '$source', '0', '$user_id');");
                    }
                }
                $getBridgeData = $projectdb->query("SELECT name, source, vsys as device_vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_target' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
                if ($getBridgeData->num_rows >= 1) {
                    while($getData = $getBridgeData->fetch_object()){
                        $data [] = $getData;
                    }
                }
                echo '{"total":"'.count($data).'","target":'.json_encode($data).'}';
            }
            else {
                $getBridgeData = $projectdb->query("SELECT name, source, vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_target' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
            $getBridgeData = $projectdb->query("SELECT name, source, vsys, id, vsys_member AS device_vsys FROM edit_table WHERE lid IN ($lid) AND type = 'appoverride_rules_target' AND remove = '0' AND user_id = '$user_id' GROUP BY name;");
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
elseif ($action == "set") {
    if ($type == "create_from_unknown") {

        $app_id = $projectdb->real_escape_string((string) (isset($_POST['app_id']) ? $_POST['app_id'] : $_GET['app_id']));
        $app_table = $projectdb->real_escape_string((string) (isset($_POST['app_table']) ? $_POST['app_table'] : $_GET['app_table']));
        $rulename = $projectdb->real_escape_string((string) (isset($_POST['rulename']) ? $_POST['rulename'] : $_GET['rulename']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $dst = $projectdb->real_escape_string((string) (isset($_POST['dst']) ? $_POST['dst'] : $_GET['dst']));
        $port = $projectdb->real_escape_string((string) (isset($_POST['port']) ? $_POST['port'] : $_GET['port']));
        $proto = $projectdb->real_escape_string((string) (isset($_POST['proto']) ? $_POST['proto'] : $_GET['proto']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $devicegroup = $projectdb->real_escape_string((string) (isset($_POST['devicegroup']) ? $_POST['devicegroup'] : $_GET['devicegroup']));
        $add_app = $projectdb->real_escape_string((string) (isset($_POST['add_app']) ? $_POST['add_app'] : $_GET['add_app']));

        $Exists = $projectdb->query("SELECT id FROM appoverride_rules WHERE name='$rulename' AND source='$source' AND vsys='$vsys';");
        if ($Exists->num_rows == 0) {
            #Get App name
            $getApp = $projectdb->query("SELECT name FROM $app_table WHERE id='$app_id';");
            $getAppData = $getApp->fetch_assoc();
            $appName = $getAppData['name'];

            if ($add_app == "original_rule") {
                $app_tablename = "";
                $app_memberid = "";
                #Check if App name exists in appvialog # Change to security_rules_app
                $getApp = $projectdb->query("SELECT id FROM default_applications WHERE name='$appName';");
                if ($getApp->num_rows == 0) {
                    $getFromapps = $projectdb->query("SELECT id FROM applications WHERE source='$source' AND vsys='$vsys' AND name='$appName';");
                    if ($getFromapps->num_rows == 0) {
                        #Error i cant find app
                    } else {
                        $getFromappsData = $getFromapps->fetch_assoc();
                        $app_memberid = $getFromappsData['id'];
                        $app_tablename = "applications";
                    }
                } else {
                    $getFromappsData = $getApp->fetch_assoc();
                    $app_memberid = $getFromappsData['id'];
                    $app_tablename = "default_applications";
                }
                $getOldRule = $projectdb->query("SELECT original_rule_lid FROM split_rules_unknown WHERE rule_lid='$rule_lid';");
                $getOldRuleData = $getOldRule->fetch_assoc();
                $oldRule = $getOldRuleData['original_rule_lid'];
                $getDup = $projectdb->query("SELECT id FROM security_rules_app WHERE rule_lid='$rule_lid' AND member_lid='$app_memberid' AND table_name='$app_tablename';");
                if ($getDup->num_rows == 0) {
                    $projectdb->query("INSERT INTO security_rules_app (member_lid,vsys,source,rule_lid,table_name) VALUES ('$app_memberid','$vsys','$source','$oldRule','$app_tablename');");
                }
            }
            elseif ($add_app == "new_rule") {
                $getOldRule = $projectdb->query("SELECT original_rule_lid FROM split_rules_unknown WHERE rule_lid='$rule_lid';");
                $getOldRuleData = $getOldRule->fetch_assoc();
                $oldRule = $getOldRuleData['original_rule_lid'];
                $getPosition = $projectdb->query("SELECT position FROM security_rules WHERE id='$oldRule';");
                $getPosData = $getPosition->fetch_assoc();
                $initialPosition = $getPosData['position'];
                $finalPosition = $initialPosition - 1;
                $message = "App-Ovrr";
                $newlid = clone_security_rule($initialPosition, $finalPosition, $vsys, $source, $oldRule, $message, $project);
                $projectdb->query("DELETE FROM security_rules_dst WHERE rule_lid='$newlid';");
                $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid='$newlid';");
                $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid='$newlid';");
                $projectdb->query("INSERT INTO security_rules_app (source,vsys,member_lid,table_name,rule_lid,devicegroup) VALUES ('$source','$vsys','$app_id','$app_table','$newlid','$devicegroup');");
                #Calcualte the id for application-default
                $getAppdefault=$projectdb->query("SELECT id FROM services WHERE name='application-default' AND source='$source' AND vsys = 'shared' LIMIT 1;");
                if ($getAppdefault->num_rows==1){
                    $getAppdefaultData=$getAppdefault->fetch_assoc();
                    $appid_default=$getAppdefaultData['id'];
                    $projectdb->query("INSERT INTO security_rules_srv (source,vsys,member_lid,table_name,rule_lid,devicegroup) VALUES ('$source','$vsys','$appid_default','services','$newlid','$devicegroup')");
                }
            }

            $getPos = $projectdb->query("SELECT max(position) as max FROM appoverride_rules WHERE source='$source';");
            if (intval($getPos->num_rows) == 0) {
                $position = 1;
            } else {
                $data = $getPos->fetch_assoc();
                $position = intval($data['max']) + 1;
            }
            $projectdb->query("INSERT INTO appoverride_rules (position,name,vsys,source,protocol,port,app_id,app_table,preorpost,devicegroup) VALUES ('$position','$rulename','$vsys','$source','$proto','$port','$app_id','$app_table','pre-rulebase','');");

            $lid = $projectdb->insert_id;

            $getDST = $projectdb->query("SELECT * from security_rules_from where rule_lid='$rule_lid' ;");
            if ($getDST->num_rows > 0) {
                while ($DST = $getDST->fetch_assoc()) {
                    $DST["id"] = "";
                    $DST["rule_lid"] = "$lid";
                    $projectdb->query("INSERT INTO appoverride_rules_from (" . implode(", ", array_keys($DST)) . ") VALUES ('" . implode("', '", array_values($DST)) . "')");
                }
            }

            $getDST = $projectdb->query("SELECT * from security_rules_src where rule_lid='$rule_lid';");
            if ($getDST->num_rows > 0) {
                while ($DST = $getDST->fetch_assoc()) {
                    $DST["id"] = "";
                    $DST["rule_lid"] = "$lid";
                    $projectdb->query("INSERT INTO appoverride_rules_src (" . implode(", ", array_keys($DST)) . ") VALUES ('" . implode("', '", array_values($DST)) . "')");
                }
            }

            $getDST = $projectdb->query("SELECT * from security_rules_to where rule_lid='$rule_lid';");
            if ($getDST->num_rows > 0) {
                while ($DST = $getDST->fetch_assoc()) {
                    $DST["id"] = "";
                    $DST["rule_lid"] = "$lid";
                    $projectdb->query("INSERT INTO appoverride_rules_to (" . implode(", ", array_keys($DST)) . ") VALUES ('" . implode("', '", array_values($DST)) . "')");
                }
            }

            $dest = explode(",", $dst);
            foreach ($dest as $key => $val) {
                $search = $projectdb->query("SELECT id FROM address WHERE ipaddress='$val' AND cidr='32' AND vsys='$vsys' AND source='$source';");
                if ($search->num_rows == 0) {
                    //$search = $projectdb->query("SELECT id FROM shared_address WHERE ipaddress='$val' AND cidr='32';");
                    $search = $projectdb->query("SELECT id FROM address WHERE ipaddress='$val' AND cidr='32' AND vsys = 'shared';");
                    if ($search->num_rows == 0) {
                        $projectdb->query("INSERT INTO address (name_ext,name,used,devicegroup,vsys,source,ipaddress,cidr,type) VALUES ('H-$val-32','H-$val-32',1,'$devicegroup','$vsys','$source','$val','32','ip-netmask');");
                        $getid = $projectdb->insert_id;
                        $projectdb->query("INSERT INTO appoverride_rules_dst (source,vsys,devicegroup,rule_lid,member_lid,table_name) VALUES ('$source','$vsys','$devicegroup','$lid','$getid','address')");
                        if ($add_app == "new_rule") {
                            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,devicegroup,rule_lid,member_lid,table_name) VALUES ('$source','$vsys','$devicegroup','$newlid','$getid','address')");
                        }
                    } else {
                        $data = $search->fetch_assoc();
                        $getid = $data['id'];
                        //$projectdb->query("INSERT INTO appoverride_rules_dst (source,vsys,devicegroup,rule_lid,member_lid,table_name) VALUES ('$source','$vsys','$devicegroup','$lid','$getid','shared_address')");
                        $projectdb->query("INSERT INTO appoverride_rules_dst (source,vsys,devicegroup,rule_lid,member_lid,table_name) VALUES ('$source','$vsys','$devicegroup','$lid','$getid','address')");
                        if ($add_app == "new_rule") {
                            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,devicegroup,rule_lid,member_lid,table_name) VALUES ('$source','$vsys','$devicegroup','$newlid','$getid','address')");
                        }
                    }
                } else {
                    $data = $search->fetch_assoc();
                    $getid = $data['id'];
                    $projectdb->query("INSERT INTO appoverride_rules_dst (source,vsys,devicegroup,rule_lid,member_lid,table_name) VALUES ('$source','$vsys','$devicegroup','$lid','$getid','address')");
                    if ($add_app == "new_rule") {
                        $projectdb->query("INSERT INTO security_rules_dst (source,vsys,devicegroup,rule_lid,member_lid,table_name) VALUES ('$source','$vsys','$devicegroup','$newlid','$getid','address')");
                    }
                }
                $projectdb->query("DELETE FROM unknown_traffic_by_app WHERE dst='$val' AND dport='$port' AND proto='$proto' AND rule_lid='$rule_lid';");
            }

            #Add Tag
            $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='App Override';");
            if ($getTag->num_rows == 1) {
                $data = $getTag->fetch_assoc();
                $tagId = $data['id'];
                $tagTable = "tag";
            } else {
                $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys,devicegroup) VALUES ('App Override','color2','From Phase2. Application Override Rule assoc','$source','$vsys','$project');");
                $tagId = $projectdb->insert_id;
                $tagTable = "tag";
            }
            $projectdb->query("INSERT INTO appoverride_rules_tag (source,vsys,devicegroup,rule_lid,member_lid,table_name) VALUES ('$source','$vsys','$devicegroup','$lid','$tagId','$tagTable')");

            #Clean
            if ($proto == "tcp") {
                $app = "unknown-tcp";
            } elseif ($proto == "udp") {
                $app = "unknown-udp";
            }
            $get = $projectdb->query("SELECT id FROM unknown_traffic_by_app WHERE rule_lid='$rule_lid' AND proto='$proto' AND dport='$port';");
            if ($get->num_rows == 0) {
                $projectdb->query("DELETE FROM applications_from_log WHERE rule_lid='$rule_lid' and app='$app' AND dport='$port';");
                $check = $projectdb->query("SELECT id FROM applications_from_log WHERE rule_lid='$rule_lid'");
                if ($check->num_rows == 0) {
                    delete_security_rule($vsys, $source, $rule_lid);
                }
            }
        } else {
            echo json_encode(array("success" => false, "msg" => "Rule Name Already Exists"));
        }
    }
    elseif ($type == "remove_rule") {
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $changes = $projectdb->real_escape_string((string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']));

        if ($changes!=''){
            delete_appoverride_rule($vsys, $source, $changes);
        }
        echo json_encode(array("success" => true, "msg" => "Rules Removed"));
    }
    elseif ($type == "save_position") {
        $ids    = (string)  (isset($_POST['ids'])    ? $_POST['ids']    : $_GET['ids']);
        $needle = (string)  (isset($_POST['id'])     ? $_POST['id']     : $_GET['id']);
        $moveto = (string)  (isset($_POST['moveto']) ? $_POST['moveto'] : $_GET['moveto']);

        require_once INC_ROOT.'/libs/common/rules/rules.php';
        $ids = json_decode($ids);
        $msg = moveRules($projectdb, $project, $source, $vsys, "appoverride_rules", $ids, $moveto, $needle);
        echo json_encode($msg);
    }
    elseif ($type == "add_rule"){

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $data = 0;

        $initialPosition = intval($ids);
        $finalPosition = $initialPosition+1;

        if ($data=="0"){$initialPosition=0;$finalPosition=1;}
        if ($vsys==""){$vsys="vsys1";}
        if (($source!=0) AND ($vsys!="all")){
            $projectdb->query("UPDATE appoverride_rules SET position=position+1 WHERE position >= '$initialPosition';");
            $projectdb->query("INSERT INTO appoverride_rules (source,vsys,disabled,position) values ('$source','$vsys','0','$initialPosition');");
            echo json_encode(array("success"=>true));
        }
        else {
            echo json_encode(array("success"=>false));
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
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN ($rule_lid) AND name = '$name' AND type = 'appoverride_rules_from' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "remove_to"){

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        if ($ids != ""){
            $lids = explode(",",$ids);
            foreach ($lids as $key => $name){
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid IN ($rule_lid) AND name = '$name' AND type = 'appoverride_rules_to' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "remove_src"){

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        if ($ids != ""){

            $rules = explode(",", $rule_lid);
            $idss = explode(",", $ids);

            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'appoverride_rules_src' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                foreach ($rules as $key => $rule_lid){
                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid = '$rule_lid' AND type = 'appoverride_rules_src' AND user_id = '$user_id';");
                }
            }
        }
    }
    elseif ($type == "remove_dst"){

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        if ($ids!=""){

            $rules = explode(",", $rule_lid);
            $idss = explode(",", $ids);

            foreach ($idss as $key => $ids_table){
                $getMembersDelete = $projectdb->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$ids_table' AND type = 'appoverride_rules_dst' AND user_id = '$user_id';");
                $getMemDelData = $getMembersDelete->fetch_assoc();
                $member_to_delete = $getMemDelData['member_lid'];
                $table_to_delete = $getMemDelData['table_name_lid'];
                foreach ($rules as $key => $rule_lid){
                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_to_delete' AND table_name_lid = '$table_to_delete' AND lid = '$rule_lid' AND type = 'appoverride_rules_dst' AND user_id = '$user_id';");
                }
            }
        }
    }
    elseif ($type == "remove_tag"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        if ($ids!=""){
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$ids' AND table_name_lid = 'tag' AND lid IN ($rule_lid) AND type = 'appoverride_rules_tag' AND user_id = '$user_id';");
        }
    }
    elseif($type == "remove_target"){

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $where_edit = $projectdb->real_escape_string((string) (isset($_POST['where']) ? $_POST['where'] : $_GET['where']));

        if($where_edit == "edit"){
            if ($ids != ""){

                $ids_explode = explode(",",$ids);

                foreach ($ids_explode AS $id_edit_table){
                    $getNameOld = $projectdb->query("SELECT name, vsys_member FROM edit_table WHERE id = '$id_edit_table' AND type = 'appoverride_rules_target' AND user_id = '$user_id' AND remove = '0';");
                    if ($getNameOld->num_rows == 1) {
                        $dataNO = $getNameOld->fetch_assoc();
                        $name_old = $dataNO['name'];
                        $vsys_member_old = $dataNO['vsys_member'];
                    }

                    $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$name_old' AND vsys_member = '$vsys_member_old' AND type = 'appoverride_rules_target' AND user_id = '$user_id';");
                }
            }
        }
        else{
            take_snapshot_last($project);

            if($ids != ""){
                $projectdb->query("DELETE FROM appoverride_rules_target WHERE rule_lid IN ($ids);");
            }else{
                $projectdb->query("DELETE FROM appoverride_rules_target WHERE source = '$source';");
            }
        }
        echo json_encode(array("success"=>true));
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
            clone_appoverride_rule($initialPosition, $finalPosition, $vsys, $source, $value, $message, $project);
        }
        echo json_encode(array("success" => true));
    }
    elseif ($type == "save_by_rulelid"){

        $vsys = $projectdb->real_escape_string($_POST['vsys']);
        $source = $projectdb->real_escape_string($_POST['source']);
        $name = $projectdb->real_escape_string((isset($_POST['name']) ? $_POST['name'] : ''));
        $rule_lid = $projectdb->real_escape_string($_POST['rule_lid']);
        $description = $projectdb->real_escape_string((isset($_POST['description']) ? $_POST['description'] : ''));
        $negate_source = $projectdb->real_escape_string($_POST['negate_source']);
        $negate_destination = $projectdb->real_escape_string($_POST['negate_destination']);
        $zone_from = $projectdb->real_escape_string($_POST['zone_from']);
        $zone_to = $projectdb->real_escape_string($_POST['zone_to']);
        $tags = $projectdb->real_escape_string($_POST['tags']);
        $target_negate = $projectdb->real_escape_string($_POST['target_negate']);
        $protocol = $projectdb->real_escape_string($_POST['protocol']);
        $port = $projectdb->real_escape_string($_POST['port']);
        $app2 = $projectdb->real_escape_string($_POST['app']);
        $group_tag_id = $projectdb->real_escape_string($_POST['group_tag_id']);

        $elements = array();

        take_snapshot_last($project);

        if (($negate_source=="false") OR ($negate_source=="off")){$negate_source=0;}else{$negate_source=1;}
        if (($negate_destination=="false") OR ($negate_destination=="off")){$negate_destination=0;}else{$negate_destination=1;}
        if (isset($description)){$description=addslashes($description);}
        if ((!isset($target_negate)) OR ($target_negate=="")){$target_negate="no";}

        if ($rule_lid != "") {

            $query = "SELECT DISTINCT(type) FROM edit_table WHERE lid IN ($rule_lid) AND user_id = '$user_id' AND type != 'app' ;";
            $getTypeEdit = $projectdb->query($query);
            if ($getTypeEdit->num_rows > 0) {
                while($getTypeData = $getTypeEdit->fetch_assoc()){

                    $type = $getTypeData['type'];
                    $names_edit = array();

                    // Check event key remove from tagfield
                    if($type == "appoverride_rules_from"){
                        $zone_from_explode = explode(",", $zone_from);
                        foreach ($zone_from_explode as $value) {
                            $names_edit[] = "'$value'";
                        }
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }
                    elseif($type == "appoverride_rules_to"){
                        $zone_to_explode = explode(",", $zone_to);
                        foreach ($zone_to_explode as $value) {
                            $names_edit[] = "'$value'";
                        }
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }
                    elseif($type == "appoverride_rules_tag"){
                        $tags_explode = explode(",", $tags);
                        foreach ($tags_explode as $value) {
                            $names_edit[] = "'$value'";
                        }
                        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE type = '$type' AND BINARY name NOT IN (" . implode(",", $names_edit) . ") AND user_id = '$user_id';");
                    }

                    // Add members to type of table to edit in edit
                    setMembersRules($rule_lid, $type, $vsys, $source, $user_id);

                }
            }

            $rules = explode(",", $rule_lid);
            foreach ($rules as $key => $rule_lid2){

                $getAppBridge = $projectdb->query("SELECT lid, member_lid, table_name_lid FROM edit_table WHERE lid = '$rule_lid2' AND type = 'app' AND remove = '0' AND user_id = '$user_id';");
                if ($getAppBridge->num_rows >= 1) {
                    while($dataA = $getAppBridge->fetch_assoc()){
                        $member_lid = $dataA['member_lid'];
                        $table_name = $dataA['table_name_lid'];

                        $projectdb->query("UPDATE appoverride_rules SET app_id = '$member_lid', app_table = '$table_name' WHERE id = '$rule_lid2';");
                    }
                }
            }


            if (preg_match("/,/",$rule_lid)){

                if ($protocol != ""){$elements[] = " protocol = '$protocol' ";}
                if ($port != ""){$elements[] = " port = '$port' ";}

                if ($description != ""){$elements[] = " description = '$description' ";}

                if(($group_tag_id == "") || ($group_tag_id == "None")){
                }else{
                    $elements[]="group_tag_id='$group_tag_id'";
                }

                if (count($elements) > 0){
                    $projectdb->query("UPDATE appoverride_rules SET ".implode(",",$elements)." WHERE id IN ($rule_lid);");

                }
            }
            else{

                $name = truncate_rulenames($name);

                $projectdb->query("UPDATE appoverride_rules 
                                   SET name = '$name', description = '$description', port = '$port', protocol = '$protocol',
                                   negate_destination = '$negate_destination', negate_source = '$negate_source', target_negate = '$target_negate', group_tag_id='$group_tag_id' 
                                   WHERE id = '$rule_lid';");
            }
        }
    }
}
elseif ($action == "replace") {

    if ($type == "transform_app_to_service") {

        $vsys = $projectdb->real_escape_string((string)(isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string)(isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $ids = $projectdb->real_escape_string((string)(isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));

        if(!accessControl("any", ['projectRole.'.$project.'.update'])){
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Your account does not have the rights to see this project contents';
            return $message;
        }

        $result_ids = array();

        take_snapshot_last($project);

        if($vsys == "all"){
            $vsys_query = "";
        }elseif($vsys != "all"){
            $vsys_query = " AND vsys = '$vsys' ";
        }

        // Actualizar las security_rules resultantes con el tag "MATCH APP OVERRIDE"
        $name_tag = "MATCHED APP OVERRIDE";
        $getTags = $projectdb->query("SELECT id FROM tag WHERE vsys = 'shared' AND source = '$source' AND BINARY name = '$name_tag';");
        if ($getTags->num_rows == 0) {
            $query = "INSERT INTO tag (name, vsys, source, color, comments, modified, dummy) 
                           VALUES ('$name_tag', 'shared', '$source', 'color1', 'Transform App to Service Timeout', '1', '0')";
            $projectdb->query($query);
            $id_tag = $projectdb->insert_id;
        }
        else{
            $dataT = $getTags->fetch_assoc();
            $id_tag = $dataT['id'];
        }

        $name_tag_timeout = "ADDED SERVICE TIMEOUT";
        $getTags = $projectdb->query("SELECT id FROM tag WHERE vsys = 'shared' AND source = '$source' AND BINARY name = '$name_tag_timeout';");
        if ($getTags->num_rows == 0) {
            $query = "INSERT INTO tag (name, vsys, source, color, comments, modified, dummy)
                           VALUES ('$name_tag_timeout', 'shared', '$source', 'color1', 'Added Service Timeout', '1', '0')";
            $projectdb->query($query);
            $id_tag_service_timeout = $projectdb->insert_id;
        }
        else{
            $dataT = $getTags->fetch_assoc();
            $id_tag_service_timeout = $dataT['id'];
        }

        $name_tag_timeout_ser = "REPLACED APP TO SERVICE TIMEOUT";
        $getTags = $projectdb->query("SELECT id FROM tag WHERE vsys = 'shared' AND source = '$source' AND BINARY name = '$name_tag_timeout_ser';");
        if ($getTags->num_rows == 0) {
            $query = "INSERT INTO tag (name, vsys, source, color, comments, modified, dummy)
                           VALUES ('$name_tag_timeout_ser', 'shared', '$source', 'color1', 'Added Service Timeout', '1', '0')";
            $projectdb->query($query);
            $id_tag_service_timeout_ser = $projectdb->insert_id;
        }
        else{
            $dataT = $getTags->fetch_assoc();
            $id_tag_service_timeout_ser = $dataT['id'];
        }

        if($ids != ""){

            if($ids == "all"){
                $query = "SELECT member_lid AS id FROM tools_results WHERE source = '$source' AND table_name = 'appoverride_rules';";
            }
            else{
                $query = "SELECT id FROM appoverride_rules WHERE id IN ($ids);";
            }

            $getIds = $projectdb->query($query);

            if ($getIds->num_rows > 0) {
                while($dataI = $getIds->fetch_assoc()){

                    $result_ids = array();

                    $rule_lid_app = $dataI['id'];

                    unset($rule_origins_sources);
                    unset($rule_origins_destinations);

                    $ports_app_explode = array();

                    $getApp = $projectdb->query("SELECT app_id, app_table, vsys, protocol, port FROM appoverride_rules WHERE id = '$rule_lid_app' AND app_table != 'default_applications';");
                    //echo "\n\n\n***************RULE APP OVERRIDE: " .$rule_lid_app. " ************\n";
                    //echo "2. SELECT app_id, app_table FROM appoverride_rules WHERE id = '$rule_lid_app' AND app_table != 'default_applications';\n";
                    //$my = fopen("search.txt","a"); fwrite($my, "SELECT app_id, app_table FROM appoverride_rules WHERE id = '$rule_lid_app' AND app_table != 'default_applications';\n"); fclose($my);

                    if ($getApp->num_rows > 0){
                        $dataA = $getApp->fetch_assoc();

                        $app_id = $dataA['app_id'];
                        $app_table = $dataA['app_table'];
                        $vsys = $dataA['vsys'];
                        $protocol = $dataA['protocol'];
                        $port = $dataA['port'];

                        $getTimeout = $projectdb->query("SELECT name, timeout, tcp_timeout, udp_timeout  FROM applications WHERE id = '$app_id' ;");
                        //echo "1. SELECT name, timeout, tcp_timeout, udp_timeout  FROM applications WHERE id = '$app_id' ;\n";
                        if ($getTimeout->num_rows > 0) {
                            $dataT = $getTimeout->fetch_assoc();
                            $name_app = $dataT['name'];
                            $timeout = $dataT['timeout'];
                            $tcp_timeout = $dataT['tcp_timeout'];
                            $udp_timeout = $dataT['udp_timeout'];

                        }

                        //echo "App id: " .$app_id. " and app table: ".$app_table." AND protocol: ".$protocol." AND ports: ".$port."\n";

                        $result_ids = getFoundRuleIdByMemberAndTableName($app_id, $app_table, "", $source, $vsys);

                        // Primero buscar si la app está dentro de un grupo ya que entonces buscar tb esas reglas q tengan este grupo
                        $getAppG = $projectdb->query("SELECT lid, member_lid, table_name 
                          FROM applications_groups WHERE (member_lid = '$app_id' AND table_name = '$app_table') GROUP BY lid;");

                        if ($getAppG->num_rows > 0) {
                            while($dataA = $getAppG->fetch_assoc()){
                                $app_group_id = $dataA['lid'];
                                $result_ids = getFoundRuleIdByMemberAndTableName($app_group_id, "applications_groups_id", "", $source, $vsys);
                            }
                        }

                        //echo "RESULT_IDS sec mach: \n";
                        //print_r($result_ids);

                        // Get SOURCE Appoverride Rules
                        $rule_origins_sources = getMembersSourceDestination($rule_lid_app, "appoverride_rules_src");
                        //echo "------> Members SOURCE APPOVERRIDE RULES ORIGIN:\n";
                        //print_r($rule_origins_sources);

                        // Get DESTINATION Appoverride Rules
                        $rule_origins_destinations = getMembersSourceDestination($rule_lid_app, "appoverride_rules_dst");
                        //echo "------> Members DESTINATION APPOVERRIDE RULES ORIGIN:\n";
                        //print_r($rule_origins_destinations);

                        foreach ($result_ids as $key => $rule_lid_sec) {

                            //echo "La Security Rule: " .$rule_lid_sec. "\n";
                            $getSecRulesTag = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid = '$rule_lid_sec'
                                        AND member_lid = '$id_tag' AND table_name = 'tag';");

                            if ($getSecRulesTag->num_rows == 0) {
                                $query = "INSERT INTO security_rules_tag (source, member_lid, table_name, rule_lid) 
                                VALUES ('$source', '$id_tag', 'tag', '$rule_lid_sec')";
                                $projectdb->query($query);
                            }

                            $is_match_total = "true";

                            // SOURCE Total Match
                            $getAppoverrideSrc = $projectdb->query("SELECT member_lid, table_name FROM appoverride_rules_src WHERE rule_lid = '$rule_lid_app';");
                            if ($getAppoverrideSrc->num_rows > 0) {
                                while ($dataAS = $getAppoverrideSrc->fetch_assoc()) {
                                    if($is_match_total == "true"){
                                        $member_lid = $dataAS['member_lid'];
                                        $table_name = $dataAS['table_name'];

                                        $is_match_total = getMatchByMemberAndTableNameAndRuleLid($rule_lid_sec, $member_lid, $table_name, "source", $source, $vsys);
                                    }
                                }
                            }
                            else{
                                $is_match_total = "false";
                            }

                            // DESTINATION Total Match
                            if($is_match_total == "true"){
                                $getAppoverrideDst = $projectdb->query("SELECT member_lid, table_name FROM appoverride_rules_dst WHERE rule_lid = '$rule_lid_app';");
                                if ($getAppoverrideDst->num_rows > 0) {
                                    while ($dataAD = $getAppoverrideDst->fetch_assoc()) {
                                        if($is_match_total == "true"){
                                            $member_lid = $dataAD['member_lid'];
                                            $table_name = $dataAD['table_name'];

                                            $is_match_total = getMatchByMemberAndTableNameAndRuleLid($rule_lid_sec, $member_lid, $table_name, "destination", $source, $vsys);
                                        }
                                    }
                                }
                                else{
                                    $is_match_total = "false";
                                }
                            }

                            // PORTS Total Match
                            if($is_match_total == "true"){

                                $is_match_port = "true";
                                $is_only = isOnlyOneApp($rule_lid_sec, $app_id, $app_table);

                                if($is_only == "true"){
                                    $ports_app_explode = explode(",", $port);

                                    $getMemberLid = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$rule_lid_sec';");

                                    if ($getMemberLid->num_rows > 0) {
                                        while ($dataML = $getMemberLid->fetch_assoc()) {

                                            $member_lid = $dataML['member_lid'];
                                            $table_name = $dataML['table_name'];

                                            $is_match_port = checkPortsAreInNewService($is_match_port, $member_lid, $table_name, $ports_app_explode, $app_id, $app_table);

                                        }
                                    }

                                    if($is_match_port == "false"){
                                        $is_match_total = "false";
                                    }
                                }
                                else{
                                    $is_match_total = "false";
                                }
                            }

                            if($is_match_total == "true"){

                                // son totalmente iguales
                                $rule_lid_sec_clone = $rule_lid_sec;
                                //echo "--------------->>>>>>>> TOTAL HA HECHO MATCH LAS REGLAS APP: " .$rule_lid_app. " CON LA REGLA DE SEGURIDAD: " .$rule_lid_sec. " PARA EL VSYS: " .$vsys. "\n";
                                //add_log('ok', 'Transform App-to-Service', 'Match Total Rule Appoverride [' . $rule_lid_app . '] with Security Rule [' . $rule_lid_sec . ']', $source, 'No Action Required');
                                add_log2("ok", 'Transform App-to-Service', 'Match Total Rule Appoverride [' . $rule_lid_app . '] with Security Rule [' . $rule_lid_sec . ']', $source, 'No Action Required','rules', $rule_lid_sec, 'security_rules');

                                if($is_match_port == "true"){
                                    $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$rule_lid_sec_clone';");
                                }

                            }
                            else{

                                $is_match_parcial = "false";
                                //$is_match_port = "false";
                                $is_match_port = "true";

                                // mirar parcialmente etc etc
                                unset($sources_sec_rule);
                                $resulting_source_members = null;
                                unset($destinations_sec_rule);
                                $resulting_destination_members = null;
                                unset($services_sec_rule);
                                $resulting_services_members = null;
                                unset($rule_origins_services_new);

                                $security_rules_src = array();
                                $security_rules_dst = array();
                                $security_rules_srv = array();


                                // Get SOURCE Security Rules
                                $sources_sec_rule = getMembersSourceDestination($rule_lid_sec, "security_rules_src");
                                //echo "-------->>>>>> Members SOURCE SECURITY RULES MATCH APP:\n";
                                //print_r($sources_sec_rule);

                                $resulting_source_members = getCommonMembers($sources_sec_rule, $rule_origins_sources, $projectdb, $source, $vsys);
                                //echo ">>>>>RESULTING SOURCE MEMBERS: app_rule: $rule_lid_app sec_rule: $rule_lid_sec >>>>>>>>>>>>>>>>>>>>\n";
                                //echo "             The matching resulted in ".count($resulting_source_members) ." new Members\n";
                                //print_r($resulting_source_members);

                                // SOURCE Partial Match
                                if(count($resulting_source_members) != 0){

                                    // Get DESTINATION Security Rules
                                    $destinations_sec_rule = getMembersSourceDestination($rule_lid_sec, "security_rules_dst");
                                    //echo "-------->>>>>> Members DESTINATION SECURITY RULES MATCH APP:\n";
                                    //print_r($destinations_sec_rule);

                                    $resulting_destination_members = getCommonMembers($destinations_sec_rule, $rule_origins_destinations, $projectdb, $source, $vsys);
                                    //echo ">>>>>RESULTING DESTINATION MEMBERS: app_rule: $rule_lid_app sec_rule: $rule_lid_sec >>>>>>>>>>>>>>>>>>>>\n";
                                    //echo "             The matching resulted in ".count($resulting_destination_members) ." new Members\n";
                                    //print_r($resulting_destination_members);

                                    // DESTINATIONS Partial Match
                                    if(count($resulting_destination_members) != 0){

                                        $ports_app_explode = explode(",", $port);
                                        //echo "LOS PORTS EXPLODE:\n";
                                        //print_r($ports_app_explode);
                                        // PORTS Match
                                        $getMemberLid = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$rule_lid_sec';");
                                        //echo "SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$rule_lid_sec';\n";

                                        if ($getMemberLid->num_rows > 0) {
                                            while ($dataML = $getMemberLid->fetch_assoc()) {

                                                $member_lid = $dataML['member_lid'];
                                                $table_name = $dataML['table_name'];

                                                //$is_match_port = checkPortsAreInNewServicePartial($is_match_port, $member_lid, $table_name, $ports_app_explode);
                                                $is_match_port = checkPortsAreInNewService($is_match_port, $member_lid, $table_name, $ports_app_explode, $app_id, $app_table);

                                            }
                                        }

                                        if($is_match_port == "true"){

                                            // Significa que ha hecho match los source, destinations and ports, por lo tanto, clonar la regla y crear los servicios con el timeout
                                            // CLONAR si hay más de una aplicación, sino dejarla en la misma
                                            $is_match_parcial = "true";
                                            //echo "--------------->>>>>>>> HA HECHO MATCH LAS REGLAS APP: " .$rule_lid_app. " CON LA REGLA DE SEGURIDAD: " .$rule_lid_sec. " PARA EL VSYS: " .$vsys. "\n";

                                            //add_log('ok', 'Transform App-to-Service', 'Match Partial Rule Appoverride [' . $rule_lid_app . '] with Security Rule [' . $rule_lid_sec . ']', $source, 'No Action Required');
                                            add_log2("ok", 'Transform App-to-Service', 'Match Partial Rule Appoverride [' . $rule_lid_app . '] with Security Rule [' . $rule_lid_sec . ']', $source, 'No Action Required','rules', $rule_lid_sec, 'security_rules');

                                            $position = "above";
                                            if ($rule_lid_sec == 0) {
                                                $initialPosition = 0;
                                                $finalPosition = 1;
                                            }
                                            else {
                                                $initialPosition = "";
                                                $finalPosition = "";
                                            }
                                            if ($position == "above") {
                                                $finalPosition = "-1";
                                            }

                                            //1. Crear reglas por encima de las que hacen match
                                            $rule_lid_sec_clone = clone_security_rule($initialPosition, $finalPosition, $vsys, $source, $rule_lid_sec, "", $project);

                                            //SOURCES: Add resultant match sources on cloned security rule
                                            $query = "DELETE FROM security_rules_src WHERE rule_lid = '$rule_lid_sec_clone';";
                                            $projectdb->query($query);
                                            foreach($resulting_source_members as $source_member){
                                                if(strcmp($source_member->name, "ANY") != 0){
                                                    $security_rules_src[] = "('$source', '$vsys', '$source_member->location', '$source_member->name', '$rule_lid_sec_clone')";
                                                }
                                            }
                                            if (count($security_rules_src) > 0){
                                                $query = "INSERT INTO security_rules_src (source, vsys, table_name, member_lid, rule_lid) VALUES " . implode(",", $security_rules_src) . ";";
                                                $projectdb->query($query);
                                            }

                                            //DESTINATIONS: Add resultant match destinations on cloned security rule
                                            $query = "DELETE FROM security_rules_dst WHERE rule_lid = '$rule_lid_sec_clone';";
                                            $projectdb->query($query);
                                            foreach($resulting_destination_members as $destination_member){
                                                if(strcmp($destination_member->name, "ANY") != 0){
                                                    $security_rules_dst[] = "('$source', '$vsys', '$destination_member->location', '$destination_member->name', '$rule_lid_sec_clone')";
                                                }
                                            }

                                            if (count($security_rules_dst) > 0){
                                                $query = "INSERT INTO security_rules_dst (source, vsys, table_name, member_lid, rule_lid) VALUES " . implode(",", $security_rules_dst) . ";";
                                                $projectdb->query($query);
                                            }

                                            //DELETE Applications to rule clone
                                            $query = "DELETE FROM security_rules_app WHERE rule_lid = '$rule_lid_sec_clone';";
                                            $projectdb->query($query);
                                        }
                                    }
                                }
                            }

                            if(($is_match_parcial == "true") || ($is_match_total == "true")){
                                // COMÚN PARA LOS DOS CASOS

                                //2. Añadir el tag NEW de las que he creado nuevas
                                $getSecRulesTagTimeout = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid = '$rule_lid_sec_clone'
                                        AND member_lid = '$id_tag_service_timeout' AND table_name = 'tag';");

                                if ($getSecRulesTagTimeout->num_rows == 0) {
                                    $query = "INSERT INTO security_rules_tag (source, member_lid, table_name, rule_lid) 
                                          VALUES ('$source', '$id_tag_service_timeout', 'tag', '$rule_lid_sec_clone')";
                                    $projectdb->query($query);
                                }

                                //2. Añadir el tag REPLACED APP TO SERVICE a la appoverride rule origin
                                $getAppRulesTagTimeout = $projectdb->query("SELECT id FROM appoverride_rules_tag WHERE rule_lid = '$rule_lid_app'
                                        AND member_lid = '$id_tag_service_timeout_ser' AND table_name = 'tag';");

                                if ($getAppRulesTagTimeout->num_rows == 0) {
                                    $query = "INSERT INTO appoverride_rules_tag (source, member_lid, table_name, rule_lid) 
                                          VALUES ('$source', '$id_tag_service_timeout_ser', 'tag', '$rule_lid_app')";
                                    $projectdb->query($query);
                                }

                                // Poner en disabled la appoverride rules
                                $query = "UPDATE appoverride_rules SET disabled = '1' WHERE id = '$rule_lid_app';";
                                $projectdb->query($query);

                                $set_default_timeout = 0;

                                if($protocol == "tcp"){
                                    if($timeout == ""){
                                        $timeout = $tcp_timeout;
                                    }
                                    if(($timeout == "0") || ($timeout == "")){
                                        $timeout = "3600";
                                        $set_default_timeout = 1;
                                    }
                                }
                                else if($protocol == "udp"){
                                    $timeout = $udp_timeout;
                                    if(($timeout == "0") || ($timeout == "")){
                                        $timeout = "30";
                                        $set_default_timeout = 1;
                                    }
                                }

                                //3. Crear los servicios con los nuevos puertos y timeout que se han encontrado en las reglas de appoverride_rules
                                //4. Añadirles tag a los news servicios creados
                                $new_service_timeout = truncate_names($name_app."_".$timeout);

                                $i = 0;
                                $id_service = checkNameServices($new_service_timeout, $source, $vsys, $protocol, $port, $timeout, $name_tag_timeout, $i, $new_service_timeout, $set_default_timeout);

                                // Actualizar la tabla security_rules_srv
                                if($id_service != ""){

                                    // Check if are application-default
                                    $getIdAppDefault = $projectdb->query("SELECT id FROM services WHERE name = 'application-default' AND vsys = 'shared' AND source = '$source';");

                                    if ($getIdAppDefault->num_rows == 1) {
                                        $dataIAD = $getIdAppDefault->fetch_assoc();
                                        $id_app_default = $dataIAD['id'];

                                        $projectdb->query("DELETE FROM security_rules_srv WHERE member_lid = '$id_app_default' AND table_name = 'services' AND rule_lid = '$rule_lid_sec_clone';");
                                    }

                                    // Delete application
                                    $projectdb->query("DELETE FROM security_rules_app WHERE member_lid = '$app_id' AND table_name = '$app_table' AND rule_lid = '$rule_lid_sec_clone';");

                                    $ports_app_explode = explode(",", $port);
                                    // hacer búsqueda por rangos con la nueva función versionada de la del Didac para recorrer por comas
                                    $getMemberLidSRV = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$rule_lid_sec_clone';");

                                    if ($getMemberLidSRV->num_rows > 0) {
                                        while ($dataML = $getMemberLidSRV->fetch_assoc()) {

                                            $member_lid = $dataML['member_lid'];
                                            $table_name = $dataML['table_name'];

                                            checkPortsAreInNewServiceClean($rule_lid_sec_clone, $member_lid, $table_name, $ports_app_explode);

                                        }
                                    }

                                    $query = "INSERT INTO security_rules_srv (source, member_lid, table_name, rule_lid)
                                          VALUES ('$source', '$id_service', 'services', '$rule_lid_sec_clone')";
                                    //echo "QUERY INSERT: " .$query. "\n";
                                    $projectdb->query($query);

                                }
                            }
                        }// Fin foreach rules
                    }
                }
                //check_used_objects_new();
            }
        }
        echo json_encode(array("success" => true));
    }
}
elseif ($action == "add"){
    $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
    $rules = explode(",",$rule_lid);

    $msg = addFieldInAppoverrideRule($projectdb, $source, $vsys, $type, $rules, $user_id);

    if($msg['code']) {
        echo json_encode(array("success" => true));
    }
    else{
        echo json_encode(array("success" => false, "msg" => $msg['msg']));
    }
}
elseif ($action == "update"){
    $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
    $rules = explode(",",$rule_lid);

    $msg = updateFieldInAppoverrideRule($projectdb, $source, $vsys, $type, $rules, $user_id);

    if($msg['code']) {
        echo json_encode(array("success" => true));
    }
    else{
        echo json_encode(array("success" => false, "msg" => $msg['msg']));
    }
}


function addFieldInAppoverrideRule(mysqli $connection, STRING $source, STRING $vsys, STRING $type, ARRAY $rules, STRING $user_id){

    switch ($type){

        case "from":

            $name = $connection->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
            foreach ($rules as $key => $rule_lid){
                if(($name != "Any") && ($name != "any")){
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND type = 'appoverride_rules_from' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_from' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'appoverride_rules_from', '$name', '','$vsys', '$source', '0', '$user_id');");
                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND type = 'appoverride_rules_from' AND user_id = '$user_id';");
                    }
                }

            }
            $message = [
                "code" => true
            ];
            break;

        case "to":

            $name = $connection->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
            foreach ($rules as $key=>$rule_lid){
                if(($name != "Any") && ($name != "any")){
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND type = 'appoverride_rules_to' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_to' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'appoverride_rules_to', '$name', '','$vsys', '$source', '0', '$user_id');");
                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND type = 'appoverride_rules_to' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "src":

            $member_lid = $connection->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
            $table_name = $connection->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
            foreach ($rules as $key => $rule_lid){
                if (($member_lid!="") AND ($table_name!="")){
                    list($image, $vsys_member, $name_member, ) = getIcon("address", $table_name, $member_lid, "");
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'appoverride_rules_src' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_src' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }

                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'appoverride_rules_src', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");

                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'appoverride_rules_src' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "dst":

            $member_lid = $connection->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
            $table_name = $connection->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
            foreach ($rules as $key=>$rule_lid){
                if (($member_lid!="") AND ($table_name!="")){

                    list($image, $vsys_member, $name_member, ) = getIcon("address", $table_name, $member_lid, "");

                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'appoverride_rules_dst' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_dst' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }

                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'appoverride_rules_dst', '$name_member', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND BINARY name = '$name_member' AND type = 'appoverride_rules_dst' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "tag":

            $name = $connection->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
            $member_lid = $connection->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
            $table_name = $connection->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
            foreach ($rules as $key=>$rule_lid){
                if (($member_lid != "") AND ($table_name != "")){
                    $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND type = 'appoverride_rules_tag' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_tag' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $getTag = $connection->query("SELECT color FROM $table_name WHERE id = '$member_lid';");
                        if ($getTag->num_rows == 1){
                            $Ttag = $getTag->fetch_assoc();
                            $realColor = $Ttag['color'];
                        }
                        $image = "tags_$realColor.png";
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '$member_lid', '$table_name', 'appoverride_rules_tag', '$name', '$image','$vsys', '$source', '0', '$user_id');");
                    }else{
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND name = '$name' AND type = 'appoverride_rules_tag' AND user_id = '$user_id';");
                    }
                }
            }
            $message = [
                "code" => true
            ];
            break;

        case "target":

            $name = $connection->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
            $device_vsys = $connection->real_escape_string((string) (isset($_POST['device_vsys']) ? $_POST['device_vsys'] : $_GET['device_vsys']));
            $id_edit_table = $connection->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
            $where_edit = $connection->real_escape_string((string) (isset($_POST['where']) ? $_POST['where'] : $_GET['where']));

            // From security editor
            if($where_edit == "edit"){

                if($id_edit_table == "") {
                    foreach ($rules as $key => $rule_lid){
                        $getBridge = $connection->query("SELECT id FROM edit_table WHERE lid = '$rule_lid' AND name = '$name' AND vsys_member = '$device_vsys' AND type = 'appoverride_rules_target' AND user_id = '$user_id';");
                        if ($getBridge->num_rows == 0) {
                            $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_target' AND user_id = '$user_id';");
                            if ($getBridgeId->num_rows == 1) {
                                $getIdData = $getBridgeId->fetch_assoc();
                                $ids = $getIdData['ids'] + 1;
                            } else {
                                $ids = 1;
                            }
                            $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                                . "VALUES (NULL, '$ids','$rule_lid', '', '', 'appoverride_rules_target', '$name', '','$vsys', '$device_vsys', '$source', '0', '$user_id');");
                        } else {
                            $connection->query("UPDATE edit_table SET remove = '0' WHERE lid = '$rule_lid' AND name = '$name' AND vsys_member = '$device_vsys' AND type = 'appoverride_rules_target' AND user_id = '$user_id';");
                        }
                    }
                }
                else{

                    $getNameOld = $connection->query("SELECT name, vsys_member FROM edit_table WHERE id = '$id_edit_table' AND type = 'appoverride_rules_target' AND user_id = '$user_id';");
                    if ($getNameOld->num_rows == 1) {
                        $dataNO = $getNameOld->fetch_assoc();
                        $name_old = $dataNO['name'];
                        $vsys_member_old = $dataNO['vsys_member'];
                    }

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE lid IN (".implode(",", $rules).") AND name = '$name_old' AND vsys_member = '$vsys_member_old' AND type = 'appoverride_rules_target' AND user_id = '$user_id';");
                    //echo "UPDATE edit_table SET name = '$name', vsys_member = '$device_vsys' WHERE lid IN (".implode(",", $rules).") AND name = '$name_old' AND vsys_member = '$vsys_member_old' AND source = '$source' AND type = 'security_rules_target' AND user_id = '$user_id';\n";
                    foreach ($rules as $key => $rule_lid){
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '','$rule_lid', '', '', 'appoverride_rules_target', '$name', '','$vsys', '$device_vsys', '$source', '0', '$user_id');");
                    }
                }

            }
            else{
                // From menu
                if(count($rules) == 1){

                    if($rules[0] == ""){
                        // All rules
                        $getAllRules = $connection->query("SELECT id FROM appoverride_rules WHERE source = '$source' ;");

                        if ($getAllRules->num_rows > 0) {
                            $rules = array();
                            while ($dataAR = $getAllRules->fetch_assoc()) {
                                $rules[] = $dataAR['id'];
                            }
                        }
                    }
                }

                foreach ($rules as $key => $rule_lid) {

                    $getExist = $connection->query("SELECT name, device_vsys FROM appoverride_rules_target WHERE rule_lid = '$rule_lid' AND name = '$name' AND device_vsys = '$device_vsys' ;");

                    if ($getExist->num_rows == 0) {
                        $connection->query("INSERT INTO appoverride_rules_target (id, source, vsys, name, device_vsys, rule_lid) "
                            . "VALUES (NULL, '$source', '$vsys', '$name', '$device_vsys', '$rule_lid');");
                    }
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


function updateFieldInAppoverrideRule(mysqli $connection, STRING $source, STRING $vsys, STRING $type, ARRAY $rules, STRING $user_id){

    switch ($type){

        case "from":

            $name = $connection->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
            $oldname = $connection->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
            if (($name!="") AND ($oldname!="")){
                foreach ($rules as $key=>$rule_lid){
                    $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name = '$oldname' AND type = 'appoverride_rules_from' AND user_id = '$user_id';");

                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'appoverride_rules_from' AND name = '$name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_from' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'appoverride_rules_from', '$name', '','$vsys', '$source', '0', '$user_id');");
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

            $name = $connection->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
            $oldname = $connection->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
            if (($name!="") AND ($oldname!="")){
                foreach ($rules as $key=>$rule_lid){
                    $connection->query("UPDATE edit_table SET remove = '1' WHERE lid = '$rule_lid' AND name = '$oldname' AND type = 'appoverride_rules_to' AND user_id = '$user_id';");

                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'appoverride_rules_to' AND name = '$name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_to' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids','$rule_lid', '', '', 'appoverride_rules_to', '$name', '','$vsys', '$source', '0', '$user_id');");
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

            $member_lid = $connection->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
            $table_name = $connection->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
            $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            if (($member_lid!="") AND ($table_name!="")){

                $getMemberTable = $connection->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'appoverride_rules_src' AND user_id = '$user_id';");
                if ($getMemberTable->num_rows == 1){
                    $dataMT = $getMemberTable->fetch_assoc();
                    $member_lid_old = $dataMT['member_lid'];
                    $table_name_old = $dataMT['table_name_lid'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'appoverride_rules_src' AND user_id = '$user_id';");
                }

                list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

                foreach ($rules as $key=>$rule_lid){
                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'appoverride_rules_src' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_src' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'appoverride_rules_src', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
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

            $member_lid = $connection->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
            $table_name = $connection->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
            $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            if (($member_lid!="") AND ($table_name!="")){
                $getMemberTable = $connection->query("SELECT member_lid, table_name_lid FROM edit_table WHERE ids = '$id' AND type = 'appoverride_rules_dst' AND user_id = '$user_id';");
                if ($getMemberTable->num_rows == 1){
                    $dataMT = $getMemberTable->fetch_assoc();
                    $member_lid_old = $dataMT['member_lid'];
                    $table_name_old = $dataMT['table_name_lid'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE member_lid = '$member_lid_old' AND table_name_lid = '$table_name_old' AND type = 'appoverride_rules_dst' AND user_id = '$user_id';");
                }

                list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "");

                foreach ($rules as $key=>$rule_lid){
                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'appoverride_rules_dst' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_dst' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'appoverride_rules_dst', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
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

            $name = $connection->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
            $member_lid = $connection->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
            $table_name = $connection->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
            $id = $connection->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));

            if (($member_lid!="") AND ($table_name!="")){

                $getNameTag = $connection->query("SELECT name FROM edit_table WHERE ids = '$id' AND type = 'appoverride_rules_tag' AND user_id = '$user_id';");
                if ($getNameTag->num_rows == 1){
                    $dataNT = $getNameTag->fetch_assoc();
                    $name_tag = $dataNT['name'];

                    $connection->query("UPDATE edit_table SET remove = '1' WHERE name = '$name_tag' AND type = 'appoverride_rules_tag' AND user_id = '$user_id';");
                }

                $getTag = $connection->query("SELECT color FROM $table_name WHERE id = '$member_lid';");
                if ($getTag->num_rows == 1){
                    $Ttag = $getTag->fetch_assoc();
                    $realColor = $Ttag['color'];
                }
                $image = "tags_$realColor.png";
                foreach ($rules as $key=>$rule_lid){
                    $getExistRemove = $connection->query("SELECT id FROM edit_table WHERE type = 'appoverride_rules_tag' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$rule_lid' AND remove = '1' AND user_id = '$user_id';");
                    if($getExistRemove->num_rows == 1){
                        $dataExist = $getExistRemove->fetch_assoc();
                        $id_exist = $dataExist['id'];
                        $connection->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                    }else{
                        $getBridgeId = $connection->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'appoverride_rules_tag' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }
                        $connection->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$rule_lid', '$member_lid', '$table_name', 'appoverride_rules_tag', '$name', '$image', '$vsys', '$source', '0', '$user_id');");
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

            $member_lid = $connection->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
            $table_name = $connection->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
            //$id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);

            if ($member_lid == "0"){

                $connection->query("DELETE FROM edit_table WHERE type = 'app' AND source = '$source' AND user_id = '$user_id';");

                foreach ($rules as $key=>$rule_lid){
                    $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                        . "VALUES (NULL, '1','$rule_lid', '$member_lid', '', 'app', '', '','$vsys', '$source', '0', '$user_id');");

                }

                echo json_encode(array("success"=>true));
            }
            elseif (($member_lid!="") AND ($table_name!="")) {
                $connection->query("DELETE FROM edit_table WHERE type = 'app' AND source = '$source' AND user_id = '$user_id';");

                foreach ($rules as $key => $rule_lid) {
                    $connection->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, source, remove, user_id) "
                        . "VALUES (NULL, '1','$rule_lid', '$member_lid', '$table_name', 'app', '', '','$vsys', '$source', '0', '$user_id');");
                }

            }
            else{
                echo json_encode(array("success"=>false));
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


function getMembersSourceDestination($rule_lid, $table_name){

    global $projectdb;

    unset($members);

    // Get Members security rules origin
    $getSec = $projectdb->query("SELECT member_lid, table_name FROM $table_name WHERE rule_lid = '$rule_lid';");
    if ($getSec->num_rows > 0) {
        while ($dataSS = $getSec->fetch_assoc()) {

            $member_lid = $dataSS['member_lid'];
            $table_name = $dataSS['table_name'];

            if($table_name == "address"){
                $getAddress = $projectdb->query("SELECT id, ipaddress, cidr FROM address WHERE id = '$member_lid';");
                if ($getAddress->num_rows > 0) {
                    $myData = $getAddress->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member_ip = $myData['ipaddress'];
                    $member_cidr = $myData['cidr'];
                    $member = new MemberObject($member_lid, 'address', $member_ip, $member_cidr);
                    $members[] = $member;
                }
            }
            elseif($table_name == "address_groups_id"){
                $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'address_groups_id');
                    $members[] = $member;
                }
            }
            elseif($table_name == "default_regions"){
                $getGRP = $projectdb->query("SELECT id FROM default_regions WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'default_regions');
                    $members[] = $member;
                }
            }
            elseif($table_name == "regions"){
                $getGRP = $projectdb->query("SELECT id FROM regions WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'regions');
                    $members[] = $member;
                }
            }
            elseif($table_name == "external_list"){
                $getGRP = $projectdb->query("SELECT id FROM external_list WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'external_list');
                    $members[] = $member;
                }
            }
        }
    }
    else{
        $member = new MemberObject("ANY", '', '0.0.0.0', '0');
        $members[] = $member;
    }

    return $members;

}


function getMembersServices($rule_lid, $table_name){

    global $projectdb;

    unset($members);

    // Get Members security rules origin
    $getSrv = $projectdb->query("SELECT member_lid, table_name FROM $table_name WHERE rule_lid = '$rule_lid';");
    if ($getSrv->num_rows > 0) {
        while ($dataSS = $getSrv->fetch_assoc()) {

            $member_lid = $dataSS['member_lid'];
            $table_name = $dataSS['table_name'];

            if($table_name == "services"){
                $getService = $projectdb->query("SELECT id, dport, protocol FROM services WHERE id = '$member_lid';");
                if ($getService->num_rows > 0) {
                    $myData = $getService->fetch_assoc();
                    $service_lid = $myData['id'];
                    $service_port = $myData['dport'];
                    $protocol = $myData['protocol'];
                    $member = new MemberObject($service_lid, "services", $service_port, $protocol);
                    $members[] = $member;
                }
            }
            elseif($table_name == "services_groups_id"){
                $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'services_groups_id');
                    $members[] = $member;
                }
            }
        }
    }
    else{
        $member = new MemberObject("ANY",'','','');
        $members[] = $member;
    }

    return $members;

}


function getCommonMembers($childMembers, $parentMembers, $projectdb, $source, $vsys){
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //No parent of children sources were defined, so they are ANY
    $tmp_Members = null;

    if((!isset($parentMembers) || count($parentMembers) == 0) &&
        (!isset($childMembers) || count($childMembers) == 0)     ){
        $member = new MemberObject('ANY', '', '0.0.0.0', '0');
        $tmp_Members = $member;
    }
    //The Parent policy has an ANY. We use the Child's Sources's members
    elseif(!isset($parentMembers) || count($parentMembers) == 0 || strcmp($parentMembers[0]->name, "ANY") == 0){
        $tmp_Members = $childMembers;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif(!isset($childMembers) || count($childMembers) == 0 || strcmp($childMembers[0]->name, "ANY") == 0){  //The policy has ANY as a source. We use the Parents source
        $tmp_Members = $parentMembers;
    }
    //Parent and Child are equal. Therefore, these are the common members.
    elseif($parentMembers == $childMembers){  //TODO: test with array_diff instead, because order of the members could be different
        $tmp_Members = $parentMembers;
    }
    /*elseif(count($parentMembers) == count($childMembers)){  //TODO: test with array_diff instead, because order of the members could be different
        echo "ENTRA!!!!!";
        $tmp_Members = $parentMembers;
        $array_diff_members = array_diff($parentMembers, $childMembers);
        print_r($array_diff_members);
    }*/



    //Both the parent policy and the child have members that are not equal. We need to calculate matchings
    else{
        //To make it simple, we will explode all groups into its Members.
        $exploded_childMembers = explodeGroups2Members($childMembers, $projectdb, $source, $vsys, 0);
        //echo "Hijos";
        //print_r($childMembers);
        //print_r($exploded_childMembers);
        $exploded_parentMembers = explodeGroups2Members($parentMembers, $projectdb, $source, $vsys, 0);
        //echo "Parents";
        //print_r(        $parentMembers        );
        //print_r($exploded_parentMembers);

        foreach ($exploded_childMembers as $childNode){
            foreach ($exploded_parentMembers as $parentMember){
                $way = -1;
                $result = netMatchObjects2Ways($childNode, $parentMember, $way);
                if(isset($result)){
//                    echo "               We found that $result->value/$result->cidr satisfies both. We can stop for this childNode\n";
                    $tmp_Members[] = $result;
                    if($way == 1){
                        break 1;
                    }
                }
            }
        }

        //In case $childMembers was a group and all its members were selected, substitute the members by the group
        //In case $parentMembers was a group and all its members were selected, substitute the members by the group
        if(isset($tmp_Members)){
            $replace_childGroup = true;
            $replace_parentGroup = true;
            foreach ($exploded_childMembers as $child){
                if(!in_array($child, $tmp_Members)){
                    $replace_childGroup = false;
                    break;
                }
            }
            foreach ($exploded_parentMembers as $parent){
                if(!in_array($parent, $tmp_Members)){
                    $replace_parentGroup = false;
                    break;
                }
            }

            if($replace_childGroup){
                foreach($exploded_childMembers as $child){
                    $key = array_search($child,$tmp_Members);
                    if($key !== false){
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members = $childMembers;
            }
            if($replace_parentGroup){
                foreach($exploded_parentMembers as $parent){
                    $key = array_search($parent, $tmp_Members);
                    if($key !== false){
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members = $parentMembers;
            }
            //All clean now with the common Members
        }
    }

    return $tmp_Members;
}


function getCommonServices($childServices, $parentServices, $projectdb, $source, $vsys){
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //The Parent policy has an ANY. We use the Child's Sources's members
    if((!isset($parentServices) || count($parentServices)==0) &&
        (!isset($childServices) || count($childServices)==0)     ){
        $member = new MemberObject('ANY', '', '', '');
        $tmp_Services=$member;
    }
    elseif(!isset($parentServices) || count($parentServices)==0 || strcmp($parentServices[0]->name, "ANY")==0){
        $tmp_Services=$childServices;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif(!isset($childServices) || count($childServices)==0 || strcmp($childServices[0]->name, "ANY")==0){  //The subpolicy has ANY as a source. We use the Parents source
        $tmp_Services=$parentServices;
    }
    //Parent and Child are equal. Therefore, these are the common members.
    elseif($parentServices == $childServices){
        $tmp_Services = $parentServices;
    }

    //Both the parent policy and the child have members that are not equal. We need to calculate matchings
    else{

        //To make it simple, we will explode all groups into its Members.
        $exploded_childServices = explodeGroups2Services($childServices,$projectdb, $source, $vsys, 0);
        $exploded_parentServices = explodeGroups2Services($parentServices,$projectdb, $source, $vsys, 0);
        //echo "DENTRO DE LA FUNCIÓN: exploded_childServices\n";
        //print_r($exploded_childServices);
        //echo "DENTRO DE LA FUNCIÓN: exploded_parentServices\n";
        //print_r($exploded_parentServices);

        foreach ($exploded_childServices as $childService){
            foreach ($exploded_parentServices as $parentService){
                $way=-1;
                //echo "ChildService\n";
                //print_r($childService);
                //echo "ParentService\n";
                //print_r($parentService);
                $result = serviceMatchObjects2Ways($childService, $parentService, $way);
                //echo "RESULT GLOBAL\n";
                //print_r($result);
                if(isset($result)){
                    $tmp_Services[]=$result;
                    if($way==1){
                        break 1;
                    }
                }
            }

        }

        //In case $childMembers was a group and all its members were selected, substitute the members by the group
        //In case $parentMembers was a group and all its members were selected, substitute the members by the group
        if(isset($tmp_Services)){
            $replace_childGroup = true;
            $replace_parentGroup = true;
            foreach ($exploded_childServices as $child){
                if(!in_array($child, $tmp_Services)){
                    $replace_childGroup = false;
                    break;
                }
            }
            foreach ($exploded_parentServices as $parent){
                if(!in_array($parent, $tmp_Services)){
                    $replace_parentGroup = false;
                    break;
                }
            }

            if($replace_childGroup){
                foreach($exploded_childServices as $child){
                    $key = array_search($child,$tmp_Services);
                    if($key!==false){
                        unset($tmp_Services[$key]);
                    }
                }
                $tmp_Services=$childServices;
            }
            if($replace_parentGroup){
                foreach($exploded_parentServices as $parent){
                    $key = array_search($parent, $tmp_Services);
                    if($key!==false){
                        unset($tmp_Services[$key]);
                    }
                }
                $tmp_Services=$parentServices;
            }
            //All clean now with the common Services
        }

    }

    return $tmp_Services;
}


function checkNameServices($new_service_timeout, $source, $vsys, $protocol, $port, $timeout, $name_tag_timeout, $i, $new_service_timeout_initial, $set_default_timeout){

    global $projectdb;

    $exist_service = existNameServiceTimeout($new_service_timeout, $source, $vsys);

    if($exist_service == 0){
        $projectdb->query("INSERT INTO services (source, vsys, name, protocol, dport, sport, tag, timeout, override)  
                                    VALUES ('$source', '$vsys', '$new_service_timeout', '$protocol', '$port', '', '$name_tag_timeout', '$timeout', 'yes');");

        $id_service = $projectdb->insert_id;

        // Add log if set timeout on 3600 from TCP or 30 from UDP
        if($set_default_timeout == 1){
            add_log('warning', 'Transform App-to-Service', 'Service ['.$id_service.'] timeout has been set to the default of 3600 (for TCP) 30 (for UDP)', $source, 'No Action Required', '2');
        }

    }
    else{

        $id_service = existNameValueServiceTimeout($new_service_timeout, $source, $vsys, $protocol, $port, $timeout);

        if($id_service == 0){
            // No coinciden los valores!
            $i++;
            $new_service_timeout_final = $new_service_timeout_initial."_".$i;

            $id_service = checkNameServices($new_service_timeout_final, $source, $vsys, $protocol, $port, $timeout, $name_tag_timeout, $i, $new_service_timeout_initial, $set_default_timeout);
        }
    }

    return $id_service;
}


function existNameServiceTimeout($new_service_timeout, $source, $vsys)
{

    global $projectdb;

    $exist = 0;

    $getExistName = $projectdb->query("SELECT id FROM services WHERE BINARY name = '$new_service_timeout' AND source = '$source' AND vsys = '$vsys';");

    if ($getExistName->num_rows == 1) {
        $exist = 1;
    }

    return $exist;
}


function existNameValueServiceTimeout($new_service_timeout_final, $source, $vsys, $protocol, $port, $timeout){

    global $projectdb;

    $id_service = 0;

    // Si existe, comprobar que tienen los mismos puertos y tiemout, sino, crearlo de nuevo con _x
    $getExistName = $projectdb->query("SELECT id FROM services WHERE BINARY name = '$new_service_timeout_final' AND source = '$source' AND vsys = '$vsys' "
        . " AND protocol = '$protocol' AND dport = '$port' AND timeout = '$timeout';");

    if ($getExistName->num_rows == 1){
        $dataEN = $getExistName->fetch_assoc();
        $id_service = $dataEN['id'];
    }

    return $id_service;
}


function isOnlyOneApp($rule_lid, $member_lid, $table_name){

    global $projectdb;

    $is_only = "false";

    $getOnlyOneApp = $projectdb->query("SELECT id FROM security_rules_app WHERE rule_lid = '$rule_lid';");

    if ($getOnlyOneApp->num_rows == 1){

        $getCheckIsApp = $projectdb->query("SELECT id FROM security_rules_app WHERE rule_lid = '$rule_lid' 
            AND member_lid = '$member_lid' AND table_name = '$table_name';");

        if ($getCheckIsApp->num_rows == 1){

            $is_only = "true";

        }
    }

    return $is_only;

}


function checkPortsAreInNewService($is_match_port, $member_lid, $table_name, $parent_ports, $app_id, $app_table){

    global $projectdb;

    if($is_match_port == "true"){

        if($table_name == "services"){

            $getServicesPorts = $projectdb->query("SELECT name, dport FROM services WHERE id = '$member_lid' ;");
            //echo "SELECT name, dport FROM services WHERE id = '$member_lid' ;\n";
            if ($getServicesPorts->num_rows > 0) {
                while ($dataSP = $getServicesPorts->fetch_assoc()) {

                    $dports = $dataSP['dport'];
                    $name = $dataSP['name'];

                    if($name == "application-default"){
                        //$is_match_port = "true";

                        //Check if the app's ports have the same ports from appoverride rules
                        $getPortsFromApp = $projectdb->query("SELECT id, value FROM $app_table WHERE id = '$app_id' ;");
                        //echo "SELECT id, value FROM $app_table WHERE id = '$app_id' ;\n";

                        if ($getPortsFromApp->num_rows == 1){
                            $dataPFA = $getPortsFromApp->fetch_assoc();
                            $value_ports = $dataPFA['value'];
                            //echo "Los value ports ".$app_id." de la app: " .$value_ports. "\n";
                            if($value_ports != ""){

                                $value_ports_explode = explode(",", $value_ports);

                                foreach ($value_ports_explode as $value_ports_item){

                                    $valueArr = explode("/", $value_ports_item);
                                    $portsArr = explode("-",$valueArr[1]);
                                    $start_child = $portsArr[0];
                                    $end_child = isset($portsArr[1])?$portsArr[1]:$portsArr[0];
                                    $protocol = $valueArr[0];

                                    $is_match_port_partial = "false";

                                    foreach ($parent_ports as $parent_ports_item){
                                        $portsArr2 = explode("-",$parent_ports_item);
                                        $start_parent = $portsArr2[0];
                                        $end_parent = isset($portsArr2[1])?$portsArr2[1]:$portsArr2[0];

                                        if($is_match_port_partial != "true"){
                                            $is_match_port_partial = matchPortsRang($start_child, $end_child, $start_parent, $end_parent);

                                            if($is_match_port_partial == "true"){
                                                $is_match_port = "true";
                                                break;
                                            }elseif($is_match_port_partial == "false"){
                                                $is_match_port = "false";
                                            }
                                        }

                                        //echo "Is match port partial: " .$is_match_port_partial. "\n";
                                        //echo "Start Child: " .$start_child. "\n";
                                        //echo "End Child: " .$end_child. "\n";
                                        //echo "Start Parent: " .$start_parent. "\n";
                                        //echo "End Parent: " .$end_parent. "\n";

                                    }
                                }
                            }
                        }
                    }
                    else{
                        $dport_explode = explode(",", $dports);

                        foreach($dport_explode as $dport){
                            if (in_array($dport, $parent_ports)) {
                            }else{
                                $is_match_port = "false";
                            }
                        }
                    }
                }
            }
        }
        elseif($table_name == "services_groups_id"){

            $getMemeberLid = $projectdb->query("SELECT member_lid, table_name FROM services_groups WHERE lid = '$member_lid';");
            if ($getMemeberLid->num_rows > 0) {
                while ($dataML = $getMemeberLid->fetch_assoc()) {

                    $member_lid_group = $dataML['member_lid'];
                    $table_name_group = $dataML['table_name'];

                    $is_match_port = checkPortsAreInNewService($is_match_port, $member_lid_group, $table_name_group, $parent_ports, $app_id, $app_table);

                }
            }
        }
    }

    return $is_match_port;

}


function checkPortsAreInNewServiceClean($rule_lid_sec, $member_lid, $table_name, $parent_ports){

    global $projectdb;

    if($table_name == "services"){

        $getServicesPorts = $projectdb->query("SELECT dport FROM services WHERE id = '$member_lid' ;");
        if ($getServicesPorts->num_rows > 0) {
            while ($dataSP = $getServicesPorts->fetch_assoc()) {

                $dport = $dataSP['dport'];
                $portsArr = explode("-",$dport);
                $start_child = $portsArr[0];
                $end_child = isset($portsArr[1])?$portsArr[1]:$portsArr[0];

                foreach ($parent_ports as $parent_ports_item){
                    $portsArr2 = explode("-",$parent_ports_item);
                    $start_parent = $portsArr2[0];
                    $end_parent = isset($portsArr2[1])?$portsArr2[1]:$portsArr2[0];

                    $is_match_port_partial = matchPortsRang($start_child, $end_child, $start_parent, $end_parent);

                    if($is_match_port_partial == "true"){
                        $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$rule_lid_sec' AND member_lid = '$member_lid' AND table_name = '$table_name';");
                    }
                }
            }
        }
    }
    elseif($table_name == "services_groups_id"){

        $getMemeberLid = $projectdb->query("SELECT member_lid, table_name FROM services_groups WHERE lid = '$member_lid';");
        if ($getMemeberLid->num_rows > 0) {
            while ($dataML = $getMemeberLid->fetch_assoc()) {

                $member_lid_group = $dataML['member_lid'];
                $table_name_group = $dataML['table_name'];

                checkPortsAreInNewServiceClean($rule_lid_sec, $member_lid_group, $table_name_group, $parent_ports);

            }
        }
    }

}


function matchPortsRang($childStart, $childEnd, $parentStart, $parentEnd){

    if (($childStart >= $parentStart) && ($childEnd <= $parentEnd)) {
        return "true";
    }
    else{
        return "false";
    }
}

?>