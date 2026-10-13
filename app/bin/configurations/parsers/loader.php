<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 21/9/16 - 18:07
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';
//require_once INC_ROOT.'/libs/shared.php';


$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

parse_str(file_get_contents("php://input"),$post_vars);
if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = $pandb->real_escape_string((string)(isset($_GET['type']) ? $_GET['type'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        break;

    case 'POST':
        $message = loadParser($data);
        echo json_encode(array('success' => $message['code'], 'jobid' => $message['msg']));
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}

function loadParser(ARRAY $data)
{

    $vendor = $data['vendor'];
    $project = $data['project'];
    global $projectdb;
    global $app;

    $projectdb = selectDatabase($project);
    $user = $app->container->sentinel->getUser();

    if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the loader rights in this project';
        return $message;
    }

    $folder = INC_ROOT."/bin/configurations/parsers";

    switch ($vendor) {
        case "CHECKPOINT":
            $correct = true;
            $path = $folder."/Checkpoint/CHECKPOINT.php";
            break;
        case "CHECKPOINTR80":
            $correct = true;
            $path = $folder."/Checkpoint/CHECKPOINTR80.php";
            break;
        case "CHECKPOINTR81":
            $correct = true;
            $path = $folder."/Checkpoint/CHECKPOINTR81.php";
            break;
        case "CISCO":
            $correct = true;
            $path = $folder."/Cisco/CISCO.php";
            break;
        case "FORTINET":
            $correct = true;
            $path = $folder."/Fortinet/FORTINET.php";
            break;
        case "ALGOSEC":
            $correct = true;
            $path = $folder."/Algosec/ALGOSEC.php";
            break;
        case "PALOALTO":
            $correct = true;
            $path = $folder."/PaloAltoNetworks/PALOALTO.php";
            break;
        case "SCREENOS":
            $correct = true;
            $path = $folder."/Screenos/SCREENOS.php";
            break;
        case "SRX":
            $correct = true;
            $path = $folder."/Srx/SRX.php";
            break;
        case "SIDEWINDER":
            $correct = true;
            $path = $folder."/Sidewinder/SIDEWINDER.php";
            break;
        case "STONESOFT":
            $correct = true;
            $path = $folder."/Stonesoft/STONESOFT.php";
            break;
        case "XGS":
            $correct = true;
            $path = $folder."/ibm/XGS.php";
            break;
        default:
            $correct = false;
            break;
    }

    if($correct){
        $message = array();

        $query = "INSERT INTO project_status (datetime,project,percentage,message) values (NOW(),'$project','0.00','Initializing')";
        $projectdb->query($query);
        $loaderPID = $projectdb->insert_id;

        $signatureId = str_replace(',',';',$data['signatureid']); //There may be the case that the signatureId has commas, such as in Stonesoft to identify the different policies to load. Change the , by ; so the readVars does not split by those internal lists
        $string="{".
            "sender:".$user->email.",".
            "api_key:".getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id")).",".
            "action:import,".
            "project:".$data['project'].",".
            "vendor:".$data['vendor'].",".
            "signatureid:".$signatureId.",".
            "pasword:".$data['password'].",".
            //"afa_hostname:".$data['afa_hostname'].",".
            "jobid:".$loaderPID.",".
            "checkpoint_name:".$data['checkpoint_name'].",".
            "noDNAT:".(boolean)$data['noDNAT'].",".
            "groupbydescription:".(boolean)$data['groupbydescription'].",".
            "asPanorama:".(boolean)$data['asPanorama'].",".
            "}";

        $encodedString = base64_encode($string);
//        exec("export PHP_IDE_CONFIG=\"serverName=Expedition1\"; php -dxdebug.remote_enable=1 -dxdebug.remote_mode=req -dxdebug.remote_port=9001 -dxdebug.remote_host=".DEBUG_SERVER." -dxdebug.remote_connect_back=0 $path \"".$string."\"  > /tmp/error 2>/tmp/error &");
          if (XDEBUG===true){
              exec("export PHP_IDE_CONFIG=\"serverName=Expedition1\"; php $path \"".$encodedString."\"  > /tmp/error 2>/tmp/error &");
          }else{
              exec("php $path \"".$encodedString."\"  > /tmp/error 2>/tmp/error &");
          }

//        exec("php $path \"".$string."\"  > /tmp/error 2>&1");
//        global $app;
//        $key = $app->accessKey->where("type", "project")->where("lid",$project)->first();
//        $encodedParams = openssl_encrypt($string,"aes-256-cbc", $key->key, 0, $key->iv);
//        exec("php $path \"".$project . $encodedParams."\" > /tmp/error 2>/tmp/error2 &");
        $message['code'] = true;
        $message['msg'] = $loaderPID;
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = '';
    }
    return $message;
}