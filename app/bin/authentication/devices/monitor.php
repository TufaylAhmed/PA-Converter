<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/5/16 - 15:28
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

//include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        if (isset($_GET['statistics'])){
            switch ($_GET['statistics']){
                case "model":
                    $message = stats_model();
                    break;

                case "panos":
                    $message = stats_panos();
                    break;

                case "expired_licenses":
                    $message = stats_expired_licenses();
                    break;

                case "old_apps":
                    $message = stats_old_apps();
                    break;
                default:

            }

            if($message['code']) {
                $total = count($message['msg']);
                echo json_encode(array('total' => $total, 'stats' => $message['msg']));
            }
            else{
                echo '{"total":"0","stats":[]}';
            }
        }

    case 'POST':
//        $message = register_Device($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
//        $message = update_Device($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
//        $message = delete_Device($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function stats_expired_licenses(){
    global $pandbRBAC;

    $message['code']=false;
    $message['msg']="";
    $data=[];

    $getlic=$pandbRBAC->query("SELECT licenses.serial,licenses.expires,licenses.feature,devices.devicename FROM licenses, devices WHERE licenses.expired='yes' AND licenses.serial=devices.serial AND devices.connected='yes';");
    if ($getlic->num_rows>0){
        $message['code']=true;
        while($getlicData=$getlic->fetch_assoc()){
            $data[]=$getlicData;
        }
    }
    $message['msg'] = $data;
    return $message;
}

function stats_old_apps(){
    global $pandbRBAC;

    $message['code']=false;
    $message['msg']="";
    $data=[];

    $getlic=$pandbRBAC->query("SELECT devicename,serial,appversion,appreleasedate FROM devices WHERE (appreleasedate < NOW() - INTERVAL 30 DAY) AND ( (appversion!=0) AND (appversion!='') ) AND connected='yes';");
    if ($getlic->num_rows>0){
        $message['code']=true;
        while($getlicData=$getlic->fetch_assoc()){
            $data[]=$getlicData;
        }
    }
    $message['msg'] = $data;
    return $message;
}

function stats_panos($serial=NULL){
    global $pandbRBAC;

    $message['code']=false;
    $message['msg']="";
    $data=[];
    $addQuery="";

    if ($serial!=NULL){
        $addQuery=" AND (management='$serial' OR serial='$serial') ";
        $query = "SELECT type AS name, count(type) AS name_count FROM devices WHERE connected='yes' $addQuery GROUP BY type;";
    }
    else{
        $query = "SELECT type AS name, count(type) AS name_count FROM devices GROUP BY type;";
    }

    $getlic=$pandbRBAC->query($query);
    if ($getlic->num_rows>0){
        $message['code']=true;
        while($getlicData=$getlic->fetch_assoc()){
            if ($getlicData['name']==""){$getlicData['name']="Unknown";}
            $data[]=$getlicData;
        }
    }
    $message['msg'] = $data;
    return $message;
}

function stats_model($serial=NULL){
    global $pandbRBAC;

    $message['code']=false;
    $message['msg']="";
    $data=[];
    $addQuery="";

    if ($serial!=NULL){
        $addQuery=" AND (management='$serial'  OR serial='$serial') ";
        $query = "SELECT panos AS name, count(panos) AS name_count FROM devices WHERE connected='yes' $addQuery GROUP BY panos;";
    }
    else{
        $query = "SELECT panos AS name, count(panos) AS name_count FROM devices GROUP BY panos;";
    }

    $getlic=$pandbRBAC->query($query);
    if ($getlic->num_rows>0){
        $message['code']=true;
        while($getlicData=$getlic->fetch_assoc()){
            if ($getlicData['name']==""){$getlicData['name']="Unknown";}
            $data[]=$getlicData;
        }
    }
    $message['msg'] = $data;
    return $message;
}
