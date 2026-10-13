<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 13:19
 */


//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
    case 'POST':
        $project    = check_sanitize((string)(isset($_POST['project'])      ? $_POST['project'] : ''));
        $message = downloadFile($project);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function downloadFile($project, $mode="zip"){
    global $app;
    global $pandbRBAC;

    $project = check_sanitize($project);

    if(!accessControl("any", ['expedition.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'You do not have rights to download this file';
        return $message;
    }

    $projectdb=selectDatabase($project);
    $projectObj = $app->project->where("name", $project)->first();
    $keyObj = $app->accessKey->where("type", "project")->where("lid", $projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);


    if ($mode=="zip"){
        $configfile="";
        $searchBC=$projectdb->query("SELECT filename FROM device_mapping WHERE baseconfig =1 LIMIT 1;");
        if ($searchBC->num_rows==1){
            $searchBCData=$searchBC->fetch_assoc();
            $configfile=$searchBCData['filename'];
        }

        # Dump Project Database to exportedProject.sql
        $projectDump = USERSPACE_PATH."/projects/$project/exportedProject.sql";

        $mysql_dump_file= create_mysql_dump_file();

        // execute the command
        //$Command = "mysqldump -u ".DBUser." -p".DBPass." $project > ".$projectDump;
        $Command = "mysqldump --defaults-extra-file=$mysql_dump_file $project > $projectDump";
        exec($Command);

        delete_mysql_dump_file($mysql_dump_file);

        if($configfile!="") {
            $encryptedPath = USERSPACE_PATH.'/projects/'.$project.'/'.$configfile.".dat";
            error_reporting(0 | E_PARSE);
            if (file_exists($encryptedPath)){
                $decryptedPath = USERSPACE_PATH.'/projects/'.$project.'/'.$configfile;
                $contents = $encryptor->decryptFromFile($encryptedPath);
                file_put_contents($decryptedPath,$contents);
            }
        }

        # Create a info file with the vendors imported into the project
        $getVendors=$pandbRBAC->query("SELECT vendors FROM projects WHERE name='$project' LIMIT 1;");
        if ($getVendors->num_rows==1){
            $getVendorsData=$getVendors->fetch_assoc();
            $vendors=$getVendorsData['vendors'];
            file_put_contents(USERSPACE_PATH.'/projects/'.$project.'/info.txt', $vendors);
        }

        $zip = new ZipArchive;
        if ($zip->open(USERSPACE_PATH."/projects/".$project."/EX-".$project.".zip",ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {

            if (file_exists(USERSPACE_PATH."/projects/$project/exportedProject.sql")){
                $zip->addFile(USERSPACE_PATH."/projects/$project/exportedProject.sql", 'exportedProject.sql');

            }
            if ($configfile!=""){
                if (file_exists(USERSPACE_PATH."/projects/".$project."/".$configfile)){
                    $zip->addFile(USERSPACE_PATH."/projects/".$project."/".$configfile, $configfile);
                }
            }

            if (file_exists(USERSPACE_PATH.'/projects/'.$project.'/info.txt')){
                $zip->addFile(USERSPACE_PATH."/projects/".$project."/info.txt", 'info.txt');
            }
            $zip->close();

            if (file_exists(USERSPACE_PATH."/projects/$project/exportedProject.sql")){
                unlink(USERSPACE_PATH."/projects/$project/exportedProject.sql");
            }
            if ($configfile!=""){
                if (file_exists(USERSPACE_PATH."/projects/".$project."/".$configfile)){
                    unlink(USERSPACE_PATH."/projects/".$project."/".$configfile);
                }
            }
            if (file_exists(USERSPACE_PATH.'/projects/'.$project.'/info.txt')){
                unlink(USERSPACE_PATH.'/projects/'.$project.'/info.txt');
            }

        }
    }

    //echo json_encode(array("success"=>true));
    $message = array();
    $message['code']=true;
    $message['msg']='Project has been Exported correctly.';
    return $message;

    error_reporting(E_ALL ^ E_WARNING | E_PARSE);
}