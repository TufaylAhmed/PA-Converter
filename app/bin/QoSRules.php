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
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        $short      = (string)  (isset($_POST['short'])     ? $_POST['short'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        $short      = (string)  (isset($_POST['short'])     ? $_POST['short'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
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

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if($type=="rules" && $short == 'true'){
        $query ="SELECT id, name FROM qos_rules WHERE source ='$source' AND vsys='$vsys' ORDER BY position";
        $result = $projectdb->query($query);
        $rules = array();
        if($result->num_rows >0){
            while($data = $result->fetch_assoc()){
                $rules[] = $data;
            }
        }

        $msg = [
            'total' => count($rules),
            'qos' => $rules,
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
            $secRulePacks[] = search_qos_policies($ruleids, $source, $vsyse, $project, '0', '', '',$color, $group_, $label, $filter, $vsys);
            $group_++;
        }

        $colorPos = 900 - (count($vsyses)-1)*200;
        foreach ($vsyses as $vsyse) {
            $color = $colorPalette['Blue'][$colorPos];
            $colorPos += 200;
            //Post Rules
//            $secRulePacks[] = search_security_policies($ruleids, $source, $vsyse, $project, '1', $start, $limit);
            $label = ($vsys == $vsyse) ? ("<i class=\"fa fa-map-marker\" style=\"font-size:16px; color:red;\" aria-hidden=\"true\"></i>&nbsp;<font color='#336989'><b>Post-rulebase ".$vsyse."</b></font></u></b>") : "Post-rulebase ".$vsyse;
            $secRulePacks[] = search_qos_policies($ruleids, $source, $vsyse, $project, '1', '', '',$color, $group_, $label, $filter, $vsys);
            $group_++;
        }
        $total=0;
        $secRules = array();
        foreach($secRulePacks as $secRulePack){
            $total += $secRulePack['total'];
            if (count($secRulePack['qos'])>0) {
                $secRules = array_merge($secRules, $secRulePack['qos']);
            }
        }

        $result = [
            'total' => $total,
            'qos' => $secRules,
        ];

        echo json_encode($result);

    }
}

?>