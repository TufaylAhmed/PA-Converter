<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';

//Dependencies
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

//include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';
include INC_ROOT.'/bin/middleware_sanitizer.php';
//Capture request paramenters
switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project            = $pandb->real_escape_string(isset($_GET['project'])      ? $_GET['project'] : '');
        break;
    case 'POST':
        include INC_ROOT . '/libs/PaloAltoNetworks/Middleware/loadCSRFControl_fromPOST.php';
        checkCSRF($_POST);
        $project            = $pandb->real_escape_string(isset($_POST['project'])      ? $_POST['project'] : '');
        if($project == ''){
            $post_max_size = ini_get("post_max_size");
            $message = array();
            $message['code'] = false;
            $message['msg'] = "Data could not be submitted correctly. Current maximum size is $post_max_size. <br>".
                " Check potential causes:<br>\n".
            " php.ini post_max_size and upload_max_filesize too small. <br>\n";
            $message['url'] = "https://live.paloaltonetworks.com/t5/Expedition-Discussions/How-to-Upload-configuration-files-bigger-than-2MB/m-p/215689#M14";
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg'], 'url'=>$message['url']));
            return $message;
        }else{
            // validation to check the project exists
            if (!is_dir("/home/userSpace/projects/" . $project)){
                echo json_encode(array('success'=>false,'message'=>'Invalid Project Selected'));
                exit;
            }
        }
        $message = import_project($project);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;
    default:
        $project            = isset($_POST['project'])      ? $_POST['project'] : '';
        break;
}


function import_project($project){
    global $app;
    $message=array();
    if(!accessControl("any", ['expedition.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this project';
        return $message;
    }
    require_once INC_ROOT.'/libs/database.php';
    global $pandbRBAC;

    $projectObj = $app->project->where("name", $project)->first();
    $keyObj = $app->accessKey->where("type","project")->where("lid", $projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    if (isset($_FILES['projectzip']) && $_FILES['projectzip']['name'] != "") {
        checkValidConfigFileName($_FILES['projectzip']['name']);
        checkFolderExists(USERSPACE_PATH."/projects/".$project);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . $_FILES['projectzip']['name'];
        $path = USERSPACE_PATH."/projects/" . $project . "/";
        if (move_uploaded_file($_FILES['projectzip']['tmp_name'], $target_path)) {
            $result = unzip2($target_path, $path);

            if ($result===TRUE){

                if (file_exists( USERSPACE_PATH."/projects/$project/info.txt")){
                    $vendors=file_get_contents(USERSPACE_PATH."/projects/".$project."/info.txt");
                    $pandbRBAC->query("UPDATE projects SET vendors='$vendors' WHERE name='$project';");
                    //echo "UPDATE projects SET vendors='$vendors' WHERE name='$project';";
                    unlink(USERSPACE_PATH."/projects/".$project."/info.txt");
                }

                $file = USERSPACE_PATH."/projects/$project/";
                $filesInPath = glob($file."exportedProject.sql");
                $numberOfFiles = count($filesInPath);
                if($numberOfFiles==1){
                    $mysql_file= create_mysql_file();

                    //$Command = "mysql -u ".DBUser." -p".DBPass." $project < ".$fileInPath;
                    $Command = "mysql --defaults-extra-file=".$mysql_file." ". $project. " < " . $file . "exportedProject.sql";
                    exec($Command);
                    $Command = "mysql --defaults-extra-file=$mysql_file $project -e 'truncate table connectors'";
                    exec($Command);
                    unlink($file . "exportedProject.sql");

                    delete_mysql_dump_file($mysql_file);

                    $dirrule = opendir($file);
                    while ($rule = readdir($dirrule)) {
                        if ((($rule != ".") && ($rule != "..") && ($rule != "Backups") && ($rule != "Pcaps") && (!preg_match("/.zip/i", $rule) && ($rule != "Reports")))) {

                            if (!is_dir($rule)) {
                                $encryptor->encryptFiletoFile($file.$rule, "$file$rule.dat");
                                unlink($file.$rule);
                            }
                        }
                    }

                    $message['code']=true;
                    $message['msg']='Project has been Imported correctly.';

                }else{

                    $message['code']=false;
                    $message['msg']= 'Error ocurred while unzip the file';

                }
            }
            else{

                $message['code']=false;
                $message['msg']= 'Error ocurred while unzip the file';

            }
            unlink($target_path);
            # Todo: Needs to update the SQL UPDATE with the Project ....
            require_once INC_ROOT."/bin/updates/updateSQLProject.php";
            updateProject($project);
        }
    }
    return $message;
}

function checkValidConfigFileName(STRING $name){
    if(preg_match('/^(MT-)(.)*$/', $name)) {
        echo json_encode(array('success' => false, 'msg' => "Please, rename your '$name' configuration file.<br> Make sure the configuration file is not named as \"MT-*\""));
        exit;
    }
}

function checkFolderExists(STRING $folder){

    if (!file_exists($folder)) {
        if (!mkdir($folder, 0777, true) && !is_dir($folder)) {
            throw new \RuntimeException(sprintf('Directory "%s" was not created', $folder));
        }
    }
}

function unzip2($target_path, $path) {
//$path = pathinfo(realpath($file), PATHINFO_DIRNAME);
    $zip = new ZipArchive;
    $res = $zip->open($target_path);
    if ($res === TRUE) {
        // extract it to the path we determined above
        $zip->extractTo($path);
        $zip->close();

        $dirrule = opendir($path);
        while ($rule = readdir($dirrule)) {
            if ((($rule != ".") && ($rule != "..") && ($rule != "Backups") && ($rule != "Pcaps") && (!preg_match("/.zip/i", $rule) && ($rule != "Reports") && (!preg_match("/^__/i", $rule) )))) {
                $rulepath = $path . $rule;
                if (is_dir($rulepath)) {
                    //echo "rulepath: " .$rulepath. "\n";
                    //echo "path: " .$path. "\n";

                    move_to_folder($rulepath . "/", $path);
                    rmdir($rulepath);
                    unlink($target_path);
                }
            }
        }

        return TRUE;
    } else {
        return FALSE;
    }
}