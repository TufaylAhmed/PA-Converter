<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/minemeld/minemeld.php';
require_once INC_ROOT.'/libs/database.php';
$request_body   = file_get_contents('php://input');
$params           = json_decode($request_body, true);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project=$pandb->real_escape_string(isset($_GET['project']) ? $_GET['project']:'');
        if ((isset($project)) AND ($project!='')){
            $message = list_nodes($project);
            if($message['code']) {
                echo json_encode(array('total' => $message['count'], 'minemeld' => $message['msg']));
            }
            else{
                echo '{"total":"0","minemeld":[]}';
            }
        }
        else{
            echo '{"total":"0","minemeld":[]}';
        }

        break;

    case 'POST':
        $message = register_node($params);
        echo json_encode(array('success' => $message['code']));
        break;

    case 'PUT':

        break;

    case 'DELETE':
        $message = delete_node($params);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_nodes(STRING $project){
    $message=array();
    $message['code']=false;
    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);
    $getMM=$projectdb->query("SELECT * FROM minemeld;");
    if ($getMM->num_rows>0){
        $mm=array();
        while($data=$getMM->fetch_assoc()){
            $mm[]=$data;
        }
        $message['code']=true;
        $message['msg']=$mm;
        $message['count']=count($mm);
    }


    return $message;
}

function register_node(ARRAY $params){
    global $app;
    global $projectdb;

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }
    $projectdb = selectDatabase($project);
    $name = htmlspecialchars($params['name']);
    $username = htmlspecialchars($params['username']);
    $password = $params['password'];
    $url = $params['url'];
    $ssl_verify_peer=$params['ssl_verify_peer'];
    $ssl_verify_host=$params['ssl_verify_host'];
    $check_dup=$projectdb->query("SELECT id FROM minemeld WHERE name ='$name';");
    if ($check_dup->num_rows==0){
        $hash=base64_encode($username.":".$password);
        $result=$projectdb->query("INSERT INTO minemeld (name,hash,url,ssl_verify_peer,ssl_verify_host) VALUES ('$name','$hash','$url','$ssl_verify_peer','$ssl_verify_host')");
        if ($result){
            $nodeID=$projectdb->insert_id;
            retrieve_output_nodes($nodeID,$ssl_verify_peer,$ssl_verify_host);
            $message['code']=true;
            return $message;
        }
    }
    $message['code']=false;
    return $message;
}

function delete_node(ARRAY $data){
    $project = $data['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);
    $nodeID=$data['id'];
    $query = "DELETE FROM minemeld WHERE id='$nodeID';";
    $projectdb->query($query);
    $query = "DELETE FROM minemeld_feeds WHERE node_id='$nodeID';";
    $projectdb->query($query);
    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Minemeld Object Removed';
    return $message;

}
