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

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_Paks();
        if($message['code']) {
            $totalDevices = count($message['msg']);
            echo json_encode(array('total' => $totalDevices, 'packs' => $message['msg']));
        }
        else{
            echo '{"total":"0","packs":[]}';
        }
        break;

    case 'POST':
        $message = register_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_Pack($data);

        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function delete_Pack($data){
    global $app;
    global $bestPracticesdb;
    $message=array();
    if(!accessControl("any", ['project.admin'])){
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to remove this contents';
        return $message;
    }

    if(isset($data['action']) && $data['action'] == "delete_all"){
        $bestPracticesdb->query("TRUNCATE TABLE bestpractices_packs;");
        $message['code'] = true;
        $message['msg'] = "All the Best Practices Packs have been deleted.";
        return $message;
    }
    else {
        if ((isset($data['id'])) AND ($data['id']!="")){
            $bestPracticesdb->query("DELETE FROM bestpractices_packs WHERE id ='".$data['id']."';");
            $message['code'] = true;
            $message['msg'] = "Best Practice Pack ".$data['name']." removed.";
        }

        return $message;
    }
}

function update_Device($data){
    require_once INC_ROOT.'/userManager/API/devices/update.php';

    $data2 = array();
    $data2['devicename']    = $data['devicename'];
    $data2['hostname']      = $data['hostname'];
    $data2['type']          = $data['type'];
    $data2['id']            = $data['id'];
    $data2['description']   = $data['description'];
    $data2['serial']        = $data['serial'];
    $message = updateDevice($data2);
    return $message;
}

function register_Device($data){
    require_once INC_ROOT.'/userManager/API/devices/register.php';
    $message = registerDevice($data);

    return $message;
}

function list_Paks(){
    global $bestPracticesdb;
    $query ="SELECT * FROM bestpractices_packs;";
    $result= $bestPracticesdb->query($query);
    $myData=array();
    $message = array();
    if ($result->num_rows>0){
        while($row = $result->fetch_object()){
            $myData[]= $row;
        }
    }
    else{
        require_once INC_ROOT.'/libs/common/bestpractices/loadXML.php';
        $message=load_bestpractices();
        if ($message['code']==false){
            return $message;
        }
        else{
            $result= $bestPracticesdb->query($query);
            if($result->num_rows>0){
                while($row = $result->fetch_object()){
                    $myData[]= $row;
                }
            }
        }
    }
    $message['code'] = true;
    $message['count'] = count($myData);
    $message['msg'] = $myData;

    return $message;
}