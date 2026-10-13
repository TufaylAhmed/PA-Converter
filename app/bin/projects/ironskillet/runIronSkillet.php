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
require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

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

        break;

    case 'POST':
        $message = run_ironSkillet($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message['code']=true;
        $message['msg']="Invalid Method";
        break;

    case 'DELETE':
        $message['code']=true;
        $message['msg']="Invalid Method";
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function run_ironSkillet($data){
    global $app;
    $project=$data['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    $message=array();
    $message['code']=false;
    $message['count']=0;
    $message['msg']='Error creating the BaseConfig at the time to apply the variables.';

    $panos_type=$data['panos_type'];
    $panos_version=$data['panos_version'];

    # Check Permissions

    $ironSkilletTemplates= INC_ROOT."/OS/IronSkillet/";
    $loader = new Twig_Loader_Filesystem($ironSkilletTemplates);
    $twig = new Twig_Environment($loader);
    $filter = new Twig_Filter('md5_hash', function ($string) {

        $str='openssl passwd -1 '.$string;
        return exec($str);
        #return md5($string);
    });
    $twig->addFilter($filter);


    if ($panos_type=="panorama"){
        $filename="panorama_".$panos_version.".xml";
    }
    else{
        $filename="panos_".$panos_version.".xml";
    }

    # Set predefined Vars
    $data['STACK'] = "iron-skillet-stack";
    $data['API_KEY_LIFETIME'] = 0;
    $data['INCLUDE_PAN_EDL'] = "yes";

    if ($filename!=""){
        //echo "Data del Iron: \n";
        //print_r($data);

        $myconfig=$twig->render($filename,$data);
        $projectObj = $app->project->where("name", $project)->first();
        $keyObj = $app->accessKey->where("type","project")->where("lid", $projectObj->id)->first();
        $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

        $projectPath=USERSPACE_PATH."/projects/" . $project . "/toImport/".$filename;
        $encryptor->encryptToFile($myconfig,"$projectPath.dat");

        $message['code']=true;
        $message['count']=0;
        $message['msg']='IronSkillet created Base Config successfuly';

    }







    return $message;

}