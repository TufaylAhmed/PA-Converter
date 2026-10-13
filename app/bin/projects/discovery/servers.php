<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 31/05/17 - 10:56
 ******************************************************************************/

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/settings/ML_Settings.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD']) {
    case 'GET':
        $project = $pandb->real_escape_string((string)(isset($_GET['project']) ? $_GET['project'] : ''));
        $mode = $pandb->real_escape_string((string)(isset($_GET['mode']) ? $_GET['mode'] : ''));
        $start = $pandb->real_escape_string((string)(isset($_GET['start']) ? $_GET['start']: '0'));
        $limit = $pandb->real_escape_string((string)(isset($_GET['limit']) ? $_GET['limit']: '50'));
        $data = array("project" => $project, "mode" => $mode, "start"=>$start, "limit"=>$limit);
        $message = findServers($data);
        if ($message['code']) {
            $totalTags = $message['total'];
            echo json_encode(array('total' => $totalTags, 'servers' => $message['msg']));
        } else {
            echo '{"total":"0","regions":[]}';
        }
        break;
}

function findServers($params){
    global $projectdb;
    $MODE    = (isset($params['mode']))? $params['mode']: "pre-analysis";
    $project = (isset($params['project']))? $params['project']: "";
    $start=$params['start'];
    $limit=$params['limit'];

    $projectdb = selectDatabase($project);
    $Data=array();

//    $query =
//        "SELECT DISTINCT ml.serverAddress, INET_ATON(serverAddress) as serverAddressLong, ml.application, applicationList.categories, applicationList.subcategories , applicationList.type
//          FROM ML_Servers ml, (SELECT container as application,
//             GROUP_CONCAT(category separator ', ') as categories, GROUP_CONCAT(subcategory separator ', ') as subcategories, 'cont' as type
//             FROM default_applications
//             WHERE container!=''
//             GROUP BY container
//                UNION
//             SELECT name as application, category as categories, subcategory as subcategories, 'app' as type
//             FROM default_applications
//             WHERE category !='') applicationList
//          WHERE ml.timestamp in (SELECT MAX(timestamp) from ML_Servers ) AND
//	            ml.application = applicationList.application
//          ORDER BY ml.application";

        $getCount=$projectdb->query("SELECT count(*) as counter FROM ML_Servers ml WHERE ml.timestamp in (SELECT MAX(timestamp) from ML_Servers );");
        $totalCounter=0;
        if ($getCount->num_rows==1){
            $getCountData=$getCount->fetch_assoc();
            $totalCounter=$getCountData['counter'];
        }

        if ($totalCounter>5000){
            $query =
                "SELECT DISTINCT ml.serverAddress, INET_ATON(serverAddress) as serverAddressLong, ml.application, app.category as categories, app.subcategory as subcategories
          FROM ML_Servers ml, default_applications app
          WHERE	            ml.application = app.name and
                ml.timestamp in (SELECT MAX(timestamp) from ML_Servers )
          LIMIT $start,$limit;";
        }
        else{
            $query =
                "SELECT DISTINCT ml.serverAddress, INET_ATON(serverAddress) as serverAddressLong, ml.application, app.category as categories, app.subcategory as subcategories
          FROM ML_Servers ml, default_applications app
          WHERE	            ml.application = app.name and
                ml.timestamp in (SELECT MAX(timestamp) from ML_Servers )
          ORDER BY ml.application LIMIT $start,$limit;";
        }



//    $gettimestamp=$projectdb->query("SELECT MAX(timestamp) as max FROM ML_Servers;");
//    if ($gettimestamp->num_rows==1){
//        $gettimestampData=$gettimestamp->fetch_assoc();
//        $timestamp=$gettimestampData['max'];
//
//        //$readApps=$projectdb->query("SELECT ")
//        $query="SELECT serverAddress, INET_ATON(serverAddress) as serverAddressLong, application FROM ML_Servers WHERE timestamp='$timestamp' ORDER BY application LIMIT $start,$limit; ";
//
//    }


    $potential=$projectdb->query($query);
    if ($potential->num_rows>0){
        while($potentialData=$potential->fetch_assoc()){
            $Data[]=$potentialData;
        }
    }

    $message = array();
    $message['code'] = true;
    $message['total'] = $totalCounter;
    $message['msg'] = $Data;
    return $message;

}