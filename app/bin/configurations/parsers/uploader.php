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

global $app;

include INC_ROOT.'/bin/middleware_sanitizer.php';

//Capture request paramenters
switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project            = $pandb->real_escape_string(isset($_GET['project'])      ? $_GET['project'] : '');
        $configclipboard    = $pandb->real_escape_string(isset($_GET['clipboard'])    ? $_GET['clipboard'] : '');
        $vendor             = $pandb->real_escape_string(isset($_GET['vendor'])       ? $_GET['vendor'] : '');
        $deviceSerial       = $pandb->real_escape_string(isset($_GET['serial'])       ? $_GET['serial'] : '');
        $baseconfig         = $pandb->real_escape_string(isset($_GET['baseconfig'])   ? $_GET['baseconfig'] : '');
        $configclipboard    = $pandb->real_escape_string(isset($_GET['configclipboard'])?$_GET['configclipboard']:'');
        $fix_R7540          = $pandb->real_escape_string((string) (isset($_GET['fixr7540']) ? $_GET['fixr7540'] : ''));
        $fix_R75402         = $pandb->real_escape_string((string) (isset($_GET['fixr75402']) ? $_GET['fixr75402'] : ''));
        $vsx         = $pandb->real_escape_string((string) (isset($_GET['vsx']) ? $_GET['vsx'] : ''));
        break;
    case 'POST':
        $project            = $pandb->real_escape_string(isset($_POST['project'])      ? $_POST['project'] : '');
        $configclipboard    = $pandb->real_escape_string(isset($_POST['clipboard'])    ? $_POST['clipboard'] : '');
        $vendor             = $pandb->real_escape_string(isset($_POST['vendor'])       ? $_POST['vendor'] : '');
        $deviceSerial       = $pandb->real_escape_string(isset($_POST['serial'])       ? $_POST['serial'] : '');
        $baseconfig         = $pandb->real_escape_string(isset($_POST['baseconfig'])   ? $_POST['baseconfig'] : '');
        $configclipboard    = $pandb->real_escape_string(isset($_POST['configclipboard'])?$_POST['configclipboard']:'');
        $fix_R7540          = $pandb->real_escape_string((string) (isset($_POST['fixr7540']) ? $_POST['fixr7540'] : ''));
        $fix_R75402         = $pandb->real_escape_string((string) (isset($_POST['fixr75402']) ? $_POST['fixr75402'] : ''));
        $vsx                = $pandb->real_escape_string((string) (isset($_POST['vsx']) ? $_POST['vsx'] : ''));
        break;

    default:
        $project            = $pandb->real_escape_string(isset($_POST['project'])      ? $_POST['project'] : '');
        $configclipboard    = $pandb->real_escape_string(isset($_POST['clipboard'])    ? $_POST['clipboard'] : '');
        $vendor             = $pandb->real_escape_string(isset($_POST['vendor'])       ? $_POST['vendor'] : '');
        $deviceSerial       = $pandb->real_escape_string(isset($_POST['serial'])       ? $_POST['serial'] : '');
        $baseconfig         = $pandb->real_escape_string(isset($_POST['baseconfig'])   ? $_POST['baseconfig'] : '');
        $configclipboard    = $pandb->real_escape_string(isset($_POST['configclipboard'])?$_POST['configclipboard']:'');
        $fix_R7540          = $pandb->real_escape_string((string) (isset($_POST['fixr7540']) ? $_POST['fixr7540'] : ''));
        $fix_R75402         = $pandb->real_escape_string((string) (isset($_POST['fixr75402']) ? $_POST['fixr75402'] : ''));
        $vsx                = $pandb->real_escape_string((string) (isset($_POST['vsx']) ? $_POST['vsx'] : ''));
        break;
}

//check the name of the uploaded Config file
function checkValidConfigFileName(STRING $name){
    if(preg_match('/^(MT-)(.)*$/', $name)) {
        echo json_encode(array('success' => false, 'msg' => "Please, rename your '$name' configuration file.<br> Make sure the configuration file is not named as \"MT-*\""));
        exit;
    }
}

function return_bytes($val)
{
    $val  = trim($val);

    $last = strtolower($val[strlen($val)-1]);
    $val  = substr($val, 0, -1); // necessary since PHP 7.1; otherwise optional

    switch($last) {
        // The 'G' modifier is available since PHP 5.1.0
        case 'g':
            $val *= 1024;
        case 'm':
            $val *= 1024;
        case 'k':
            $val *= 1024;
    }

    return $val;
}

function checkSize(STRING $field):array{
    $post_max_size = return_bytes(ini_get('post_max_size'));
    $upload_max_filesize = return_bytes(ini_get('upload_max_filesize'));

    $max = min([$post_max_size, $upload_max_filesize]);

    if (isset($_FILES[$field])) {
        if ($_FILES[$field]['size'] > $post_max_size) { //10 MB (size is also in bytes)
            // File too big
            $message =  array('success' => false, 'msg' => "This file is bigger than $max. Please update your php.ini settings (in /etc/php/7.0/apache2/php.ini)  and restart apache2 service\n");
        }
        else {
            // File within size restrictions
            $message =  array('success' => true, 'msg' => "");
        }
    }
    else{
        $message = array('success' => false, 'msg' => "There was an error. Probably the set of files is bigger than $max. Please update your post_max_size and upload_max_filesize variables php.ini settings (in /etc/php/7.0/apache2/php.ini) and restart apache2 service (sudo service apache2 restart)");
    }

    return $message;
}

if($project == ''){
    $post_max_size = ini_get("post_max_size");
    $message = array();
    $message['code'] = false;
    $message['msg'] = "Data could not be submitted correctly. Current maximum size is $post_max_size"." Check potential causes:<br>\n".
        " php.ini post_max_size and upload_max_filesize too small. <br>\n";
    $message['url'] = "https://live.paloaltonetworks.com/t5/Expedition-Discussions/How-to-Upload-configuration-files-bigger-than-2MB/m-p/215689#M14";
    echo json_encode(array('success' => $message['code'], 'msg' => $message['msg'], 'url'=>$message['url']));
    return $message;
}

if(!checkProjectRights($project,'update')){
    $message = array();
    $message['code'] = false;
    $message['msg'] = 'You do not have rights in this project';
    echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
    return $message;
}

if (!file_exists(USERSPACE_PATH."/projects/$project/toImport/")) {
    mkdir(USERSPACE_PATH."/projects/$project/toImport/", 0777, true);
}

if ($vendor == "PALOALTO") {
    $projectObj = $app->project->where("name", $project)->first();
    $keyObj = $app->accessKey->where("type","project")->where("lid", $projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    if (isset($_FILES['paloaltozip']) && $_FILES['paloaltozip']['name'] != "") {
        $sizeCheck = checkSize('paloaltozip');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['paloaltozip']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/toImport/" . normalizeNames($_FILES['paloaltozip']['name']);
        $path = USERSPACE_PATH."/projects/" . $project . "/toImport/";

        //echo "El archivo es: " .$_FILES['paloaltozip']['tmp_name']. "\n";
        $size = getZipOriginalSize($_FILES['paloaltozip']['tmp_name']);
        //echo "original size: $size bytes\n";

        if($size <= "1073741824") {
            if (move_uploaded_file($_FILES['paloaltozip']['tmp_name'], $target_path)) {
                $result = unzip($target_path, $path);

                $file = USERSPACE_PATH."/projects/$project/toImport/";
                $filesInPath = glob($file."*.xml");
                $numberOfFiles = count($filesInPath);
                if($numberOfFiles>0){
                    //For each file encrypt it
                    foreach ($filesInPath as $fileInPath){
                        $encryptor->encryptFiletoFile($fileInPath, "$fileInPath.dat");
                        unlink($fileInPath);
                    }
                }

                if ($result === TRUE) {
                    echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
                }
                else {
                    echo json_encode(array('success' => false, 'msg' => 'Error ocurred while unzip the file'));
                }
                #unlink($target_path);
            }
        }
        else{
            echo json_encode(array('success' => false, 'msg' => 'This file is bigger than 1GB.'));
        }

    }
    if (isset($_FILES['paloaltoxml']) && $_FILES['paloaltoxml']['name'] != "") {
        $sizeCheck = checkSize('paloaltoxml');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['paloaltoxml']['name']);

        $target_path = USERSPACE_PATH."/projects/$project/toImport/" . $_FILES['paloaltoxml']['name'];
        if (move_uploaded_file($_FILES['paloaltoxml']['tmp_name'], $target_path)) {
            $encryptor->encryptFiletoFile($target_path,"$target_path.dat");
            unlink($target_path);
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        }
        else {
            $post_max_size = return_bytes(ini_get('post_max_size'));
            $upload_max_filesize = return_bytes(ini_get('upload_max_filesize'));

            $max = min([$post_max_size, $upload_max_filesize])/1024/1024;

            echo json_encode(array('success' => false,
                'msg' => "Error ocurred while uploading the file. \n".PHP_EOL.
                         "Check potential causes:<br>\n".
                         " php.ini post_max_size and upload_max_filesize too small. Current max value: $max MB<br>\n")
            );
        }
    }
    if (isset($_FILES['paloaltobc']) && $_FILES['paloaltobc']['name'] != "") {
        $sizeCheck = checkSize('paloaltobc');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['paloaltobc']['name']);
        $target_path = USERSPACE_PATH."/Templates/" . $_FILES['paloaltobc']['name'];
        if (move_uploaded_file($_FILES['paloaltobc']['tmp_name'], $target_path)) {
            $encryptor->encryptFiletoFile($target_path,"$target_path.dat");
            unlink($target_path);
            echo json_encode(array('success' => true, 'msg' => 'The file has been uploaded correctly.'));
        } else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
        }
    }


    if ($baseconfig != "") {
        if (copy_baseconfig($baseconfig, $project)) {
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        } else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while loading the file'));
        }
    }
    if ($deviceSerial != "") {
        if (copy_device($deviceSerial, $project)) {
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        } else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while loading the file'));
        }
    }
} 
elseif ($vendor == "CHECKPOINT") {
    if (!file_exists(USERSPACE_PATH."/projects/$project/checkPointR77/")) {
        mkdir(USERSPACE_PATH."/projects/$project/checkPointR77/", 0777, true);
    }

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);
    #Checkpoint
    if (isset($_FILES['objects']) && $_FILES['objects']['name'] != "") {
        $sizeCheck = checkSize('objects');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['objects']['name']);
        $target_path = USERSPACE_PATH."/projects/$project/checkPointR77/objects_5_0.C";
        if (move_uploaded_file($_FILES['objects']['tmp_name'], $target_path)) {
            $objects = true;
        }
    }

    if (isset($_FILES['policy']) && $_FILES['policy']['name'] != "") {
        $sizeCheck = checkSize('policy');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['policy']['name']);

        $target_path = USERSPACE_PATH."/projects/$project/checkPointR77/PolicyName.W";
        if (move_uploaded_file($_FILES['policy']['tmp_name'], $target_path)) {
            $policy = true;
        }
    }

    if (isset($_FILES['rulebases']) && $_FILES['rulebases']['name'] != "") {
        $sizeCheck = checkSize('rulebases');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['rulebases']['name']);

        $target_path = USERSPACE_PATH."/projects/$project/checkPointR77/rulebases_5_0.fws";
        if (move_uploaded_file($_FILES['rulebases']['tmp_name'], $target_path)) {
            
        }
    }

    if (isset($_FILES['routes']) && $_FILES['routes']['name'] != "") {
        $target_path = USERSPACE_PATH."/projects/$project/checkPointR77/".$_FILES['routes']['name'];
        preg_match("/^(.*).(gz|zip|gzip)$/", $_FILES['routes']['name'], $output_array);
        if(count($output_array)>0) {  //This is a Zip file
            $size = getZipOriginalSize($_FILES['routes']['tmp_name']);
            //echo "original size: $size bytes\n";

            if ($size <= "1073741824") {
                if (move_uploaded_file($_FILES['routes']['tmp_name'], $target_path)) {
                    $path = USERSPACE_PATH."/projects/" . $project . "/checkPointR77/";
                    $result = unzip($target_path, $path);
                    if ($result === TRUE) {
                        $routes = true;
                    } else {
                        return json_encode(array('success' => false, 'msg' => 'Error ocurred while unzipping the routes file'));
                    }
                }
            } else {
                return json_encode(array('success' => false, 'msg' => 'This zip routes file is larger than 1GB.'));
            }
        }
        else {
            $sizeCheck = checkSize('routes');
            if ($sizeCheck['success'] == false) {
                return json_encode($sizeCheck);
            }
            checkValidConfigFileName($_FILES['routes']['name']);


            if (move_uploaded_file($_FILES['routes']['tmp_name'], $target_path)) {
                $routes = true;
            }
        }
    }

    if (isset($fix_R7540) && $fix_R7540 == "on") {
        #Support for file came from rulebases. Delete first tab and replace the table uid by the name
        $policyR7540file = USERSPACE_PATH."/projects/" . $project . "/checkPointR77/PolicyName.W";
        $ckpt_config_file = file($policyR7540file);
        $my_file = USERSPACE_PATH.'/projects/' . $project . '/checkPointR77/PolicyFINAL.txt';
        $handle = fopen($my_file, 'a') or die('Cannot open file:  ' . $my_file);

        foreach ($ckpt_config_file as $line => $names_line) {
            $string = preg_replace("/^\t/", "", $names_line);
            fwrite($handle, $string);
        }

        $cadena = file_get_contents($my_file, TRUE);
        if (preg_match('/: \(ReferenceObject\s\n\t\t\t\t:Name\s\((.*)\)\s\n.*:Table\s(.*)\s\n.*:Uid (.*)\s\n.*\)/', $cadena)) {

            $patron = '/: \(ReferenceObject\s\n\t\t\t\t:Name\s\((.*)\)\s\n.*:Table\s(.*)\s\n.*:Uid (.*)\s\n.*\)/';
            $sustitucion = ': ${1}';
            $cadena = preg_replace($patron, $sustitucion, $cadena);
            #$handle = fopen($policyR7540file, 'w') or die('Cannot open file:  '.$policyR7540file);
            #fwrite($handle, $out);
        }
        if (preg_match('/: \(ReferenceObject\n\t\t\t\t:Name\s\((.*)\)\n.*:Table\s(.*)\n.*:Uid (.*)\n.*\)/', $cadena)) {

            #$cadena=file_get_contents($my_file,TRUE);
            $patron = '/: \(ReferenceObject\n\t\t\t\t:Name\s\((.*)\)\n.*:Table\s(.*)\n.*:Uid (.*)\n.*\)/';
            $sustitucion = ': ${1}';
            $cadena = preg_replace($patron, $sustitucion, $cadena);

            #$handle = fopen($policyR7540file, 'w') or die('Cannot open file:  '.$policyR7540file);
            #fwrite($handle, $out);
        }
        if (preg_match('/: \(ReferenceObject\n\t\t\t\t:Table\s(.*)\n.*:Name\s\((.*)\)\n.*:Uid (.*)\n.*\)/', $cadena)) {

            #$cadena=file_get_contents($my_file,TRUE);
            $patron = '/: \(ReferenceObject\n\t\t\t\t:Table\s(.*)\n.*:Name\s\((.*)\)\n.*:Uid (.*)\n.*\)/';
            $sustitucion = ': ${2}';
            $cadena = preg_replace($patron, $sustitucion, $cadena);

            #$handle = fopen($policyR7540file, 'w') or die('Cannot open file:  '.$policyR7540file);
            #fwrite($handle, $out);
        }
        #R77
        if (preg_match('/: \(ReferenceObject\n\t\t\t\t:Name\s\((.*)\)\n.*:Table\s(.*)\n.*/', $cadena)) {

            #$cadena=file_get_contents($my_file,TRUE);
            $patron = '/: \(ReferenceObject\n\t\t\t\t:Name\s\((.*)\)\n.*:Table\s(.*)\n.*/';
            $sustitucion = ': ${1}';
            $cadena = preg_replace($patron, $sustitucion, $cadena);

            #$handle = fopen($policyR7540file, 'w') or die('Cannot open file:  '.$policyR7540file);
            #fwrite($handle, $out);
        }
        if ($cadena != "") {
            $handle = fopen($policyR7540file, 'w') or die('Cannot open file:  ' . $policyR7540file);
            fwrite($handle, $cadena);
        }

        unlink($my_file);
    }

    if (isset($fix_R75402) && $fix_R75402 == "on") {
        $objects_file = USERSPACE_PATH . "/projects/" . $project . "/checkPointR77/objects_5_0.C";
        $rules_file = USERSPACE_PATH . "/projects/" . $project . "/checkPointR77/PolicyName.W";
        $objects = file($objects_file);
        $rules = file($rules_file);

        $my_file = USERSPACE_PATH . '/projects/' . $project . '/checkPointR77/PolicyFINAL.txt';
        $handle = fopen($my_file, 'a') or die('Cannot open file:  ' . $my_file);

        if ((file_exists($objects_file)) AND (file_exists($rules_file))) {

            $entering_rules = FALSE;
            $entering_natrules = FALSE;

            foreach ($rules as $num => $rule) {
                if (preg_match("/^\t:rules \(/i", $rule)) {
                    $entering_rules = TRUE;
                } elseif (preg_match("/^\t\)/i", $rule)) {
                    $entering_rules = FALSE;
                }

                if ($entering_rules == TRUE) {
                    if (preg_match("/\t\t\: \(rule/i", $rule)) {
                        $string = "\t:rule (\n";
                    } else {
                        $string = preg_replace("/^\t\t/", "\t", $rule);
                    }
                    fwrite($handle, $string);

                } else {
                    $string = $rule;
                    fwrite($handle, $string);
                }

                if (preg_match("/^\t:rules-adtr \(/i", $rule)) {
                    $entering_natrules = TRUE;
                }

                if ((preg_match("/^\t\)/i", $rule)) AND ($entering_natrules==TRUE)) {
                    $entering_natrules = FALSE;
                }

                if ($entering_natrules==TRUE){
                    if (preg_match("/\t\t\: \(rule/i", $rule)) {
                        $string = "\t:rule_adtr (\n";
                    } else {
                        $string = preg_replace("/^\t\t/", "\t", $rule);
                    }
                    fwrite($handle, $string);
                }

            }

            $cmd = "mv ". escapeshellarg(USERSPACE_PATH."/projects/" . $project . "/checkPointR77/PolicyFINAL.txt ".USERSPACE_PATH."/projects/" . $project . "/checkPointR77/PolicyName.W");
            shell_exec($cmd);
        }
    }

    if (($policy) AND ( $objects)) {
        echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
    }
    else {
        echo json_encode(array('success' => false, 'msg' => 'We need Objects and Policy files. Please upload them again.'));
    }
}
elseif ($vendor == "CHECKPOINTR80"){
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);

    if (isset($_FILES['security']) && $_FILES['security']['name'] != "") {
        $sizeCheck = checkSize('security');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['security']['name']);

        $filename = $_FILES['security']['name'];
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        if($ext=="zip") {
            if (is_dir(USERSPACE_PATH."/projects/$project/security")){
                rrmdir(USERSPACE_PATH."/projects/$project/security");
            }
            mkdir(USERSPACE_PATH."/projects/$project/security",0744);
            $target_path = USERSPACE_PATH."/projects/" . $project . "/security/" . $_FILES['security']['name'];
            if (move_uploaded_file($_FILES['security']['tmp_name'], $target_path)) {
                $security = true;
                $path = USERSPACE_PATH."/projects/" . $project . "/security";
                $result = unzip($target_path, $path);
                if ($result === TRUE) {
                    unlink($target_path);
                    join_json_files($path,$project,"security");
                }
            }
        }
        else{
            $target_path = USERSPACE_PATH."/projects/$project/rulebases.txt";
            if (move_uploaded_file($_FILES['security']['tmp_name'], $target_path)) {
                $security = true;
            }
        }
    }

    if (isset($_FILES['nat']) && $_FILES['nat']['name'] != "") {
        $sizeCheck = checkSize('nat');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['nat']['name']);

        $filename = $_FILES['nat']['name'];
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        if($ext=="zip") {
            if (is_dir(USERSPACE_PATH."/projects/$project/nat")){
                rrmdir(USERSPACE_PATH."/projects/$project/nat");
            }
            mkdir(USERSPACE_PATH."/projects/$project/nat",0744);
            $target_path = USERSPACE_PATH."/projects/" . $project . "/nat/" . $_FILES['nat']['name'];
            if (move_uploaded_file($_FILES['nat']['tmp_name'], $target_path)) {
                $security = true;
                $path = USERSPACE_PATH."/projects/" . $project . "/nat";
                $result = unzip($target_path, $path);
                if ($result === TRUE) {
                    unlink($target_path);
                    join_json_files($path,$project,"nat");
                }
            }
        }
        else{
            $target_path = USERSPACE_PATH."/projects/$project/nat.txt";
            if (move_uploaded_file($_FILES['nat']['tmp_name'], $target_path)) {
                $nat = true;
            }
        }
    }

    if (isset($_FILES['routes']) && $_FILES['routes']['name'] != "") {
        checkValidConfigFileName($_FILES['routes']['name']);

        $target_path = USERSPACE_PATH."/projects/$project/routes.txt";
        if (move_uploaded_file($_FILES['routes']['tmp_name'], $target_path)) {
            $routes = true;
        }
    }

    echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
}
elseif ($vendor == "CHECKPOINTR81"){
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);

    if (isset($_FILES['security']) && $_FILES['security']['name'] != "") {
        $sizeCheck = checkSize('security');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['security']['name']);

        $filename = $_FILES['security']['name'];
        $ext = pathinfo($filename, PATHINFO_EXTENSION);

        if($ext=="zip") {
            if (is_dir(USERSPACE_PATH."/projects/$project/security")){
                rrmdir(USERSPACE_PATH."/projects/$project/security");
            }
            mkdir(USERSPACE_PATH."/projects/$project/security",0744);
            $target_path = USERSPACE_PATH."/projects/" . $project . "/security/" . $_FILES['security']['name'];
            if (move_uploaded_file($_FILES['security']['tmp_name'], $target_path)) {
                $security = true;
                $path = USERSPACE_PATH."/projects/" . $project . "/security";
                $result = unzip($target_path, $path);
                if ($result === TRUE) {
                    unlink($target_path);
                    //join_json_files($path,$project,"security");
                }
            }
        }
        elseif (($ext=="tgz") Or ($ext=="gz")){
            if (is_dir(USERSPACE_PATH."/projects/$project/security")){
                rrmdir(USERSPACE_PATH."/projects/$project/security");
            }
            mkdir(USERSPACE_PATH."/projects/$project/security",0744);
            $target_path = USERSPACE_PATH."/projects/" . $project . "/security/package.tgz";
            if (move_uploaded_file($_FILES['security']['tmp_name'], $target_path)) {
                $security = true;
                $path = USERSPACE_PATH."/projects/" . $project . "/security";
                $p = new PharData($target_path);
                $p->decompress(); // creates files.tar

                // unarchive from the tar
                $tarfile=
                $phar = new PharData(USERSPACE_PATH."/projects/" . $project . "/security/package.tar");
                $phar->extractTo(USERSPACE_PATH."/projects/" . $project . "/security");
                unlink(USERSPACE_PATH."/projects/" . $project . "/security/package.tar");
                unlink(USERSPACE_PATH."/projects/" . $project . "/security/package.tgz");
            }
            // decompress from gz

        }
        else{
//            $target_path = USERSPACE_PATH."/projects/$project/rulebases.txt";
//            if (move_uploaded_file($_FILES['security']['tmp_name'], $target_path)) {
//                $security = true;
//            }
        }
    }

    if (isset($_FILES['routes']) && $_FILES['routes']['name'] != "") {
        checkValidConfigFileName($_FILES['routes']['name']);

        $target_path = USERSPACE_PATH."/projects/$project/routes.txt";
        if (move_uploaded_file($_FILES['routes']['tmp_name'], $target_path)) {
            $routes = true;
        }
    }

    echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
}
elseif ($vendor == "SRX") {
    if (isset($_FILES['srxzip']) && $_FILES['srxzip']['name'] != "") {
        $sizeCheck = checkSize('srxzip');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['srxzip']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . $_FILES['srxzip']['name'];
        $path = USERSPACE_PATH."/projects/" . $project . "/";

        $size = getZipOriginalSize($_FILES['srxzip']['tmp_name']);
        //echo "original size: $size bytes\n";

        if($size <= "1073741824") {
            if (move_uploaded_file($_FILES['srxzip']['tmp_name'], $target_path)) {
                $result = unzip($target_path, $path);
                if ($result === TRUE) {
                    echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
                }
                else {
                    echo json_encode(array('success' => false, 'msg' => 'Error ocurred while unzipping the file'));
                }
                #unlink($target_path);
            }

        }
        else{
            echo json_encode(array('success' => false, 'msg' => 'This file is larger than 1GB.'));
        }

    }
    if (isset($_FILES['configsrx']) && $_FILES['configsrx']['name'] != "") {
        $sizeCheck = checkSize('configsrx');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['configsrx']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . normalizeNames($_FILES['configsrx']['name']);
        if (move_uploaded_file($_FILES['configsrx']['tmp_name'], $target_path)) {
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        } else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
        }
    }
    if (isset($configclipboard) && $configclipboard != "") {
        //date_default_timezone_set('America/Los_Angeles');
        $filename_config = "srx_" . date('m-d-Y-His') . ".txt";
        $trans = array("^M" => "\n");
        $configclipboard2 = stripslashes($configclipboard);
        $data = strtr($configclipboard2, $trans);
        $target_path = USERSPACE_PATH."/projects/$project/" . $filename_config;
        $file = fopen($target_path, "w");
        $data = preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $data);
        fwrite($file, $data);
        fclose($file);
        echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
    }
} 
elseif ($vendor == "SCREENOS") {
    if (isset($_FILES['screenoszip']) && $_FILES['screenoszip']['name'] != "") {
        $sizeCheck = checkSize('screenoszip');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['screenoszip']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . $_FILES['screenoszip']['name'];
        $path = USERSPACE_PATH."/projects/" . $project . "/";

        $size = getZipOriginalSize($_FILES['screenoszip']['tmp_name']);
        //echo "original size: $size bytes\n";

        if($size <= "1073741824") {
            if (move_uploaded_file($_FILES['screenoszip']['tmp_name'], $target_path)) {
                $result = unzip($target_path, $path);
                if ($result === TRUE) {
                    echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
                }
                else {
                    echo json_encode(array('success' => false, 'msg' => 'Error ocurred while unzip the file'));
                }
                #unlink($target_path);
            }
        }
        else{
            echo json_encode(array('success' => false, 'msg' => 'This file is bigger than 1GB.'));
        }

    }
    if (isset($_FILES['configscreenos']) && $_FILES['configscreenos']['name'] != "") {
        $sizeCheck = checkSize('configscreenos');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['configscreenos']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . normalizeNames($_FILES['configscreenos']['name']);
        if (move_uploaded_file($_FILES['configscreenos']['tmp_name'], $target_path)) {
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        } else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
        }
    }
    if (isset($configclipboard) && $configclipboard != "") {
        //date_default_timezone_set('America/Los_Angeles');
        $filename_config = "srx_" . date('m-d-Y-His') . ".txt";
        $trans = array("^M" => "\n");
        $configclipboard2 = stripslashes($configclipboard);
        $data = strtr($configclipboard2, $trans);
        $target_path = USERSPACE_PATH."/projects/$project/" . $filename_config;
        $file = fopen($target_path, "w");
        $data = preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $data);
        fwrite($file, $data);
        fclose($file);
        echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
    }
} 
elseif ($vendor == "FORTINET") {
    if (isset($_FILES['fortinetzip']) && $_FILES['fortinetzip']['name'] != "") {
        $sizeCheck = checkSize('fortinetzip');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['fortinetzip']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . $_FILES['fortinetzip']['name'];
        $path = USERSPACE_PATH."/projects/" . $project . "/";

        $size = getZipOriginalSize($_FILES['fortinetzip']['tmp_name']);
        //echo "original size: $size bytes\n";

        if($size <= "1073741824") {
            if (move_uploaded_file($_FILES['fortinetzip']['tmp_name'], $target_path)) {
                $result = unzip($target_path, $path);
                if ($result === TRUE) {
                    echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
                }
                else {
                    echo json_encode(array('success' => false, 'msg' => 'Error ocurred while unzip the file'));
                }
                #unlink($target_path);
            }
        }
        else{
            echo json_encode(array('success' => false, 'msg' => 'This file is bigger than 1GB.'));
        }

    }
    if (isset($_FILES['configfortinet']) && $_FILES['configfortinet']['name'] != "") {
        $sizeCheck = checkSize('configfortinet');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['configfortinet']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . normalizeNames($_FILES['configfortinet']['name']);
        if (move_uploaded_file($_FILES['configfortinet']['tmp_name'], $target_path)) {
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        } else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
        }
    }
    if (isset($configclipboard) && $configclipboard != "") {
        //date_default_timezone_set('America/Los_Angeles');
        $filename_config = "forti_" . date('m-d-Y-His') . ".txt";
        $trans = array("^M" => "\n");
        $configclipboard2 = stripslashes($configclipboard);
        $data = strtr($configclipboard2, $trans);
        $target_path = USERSPACE_PATH."/projects/$project/" . $filename_config;
        $file = fopen($target_path, "w");
        $data = preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $data);
        fwrite($file, $data);
        fclose($file);
        echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
    }
} 
elseif ($vendor == "CISCO") {
    if (isset($_FILES['ciscozip']) && $_FILES['ciscozip']['name'] != "") {
        $sizeCheck = checkSize('ciscozip');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['ciscozip']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . $_FILES['ciscozip']['name'];
        $path = USERSPACE_PATH."/projects/" . $project . "/";

        $size = getZipOriginalSize($_FILES['ciscozip']['tmp_name']);
        //echo "original size: $size bytes\n";

        if($size <= "1073741824") {

            if (move_uploaded_file($_FILES['ciscozip']['tmp_name'], $target_path)) {
                $result = unzip($target_path, $path);
                if ($result === TRUE) {
                    echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
                }
                else {
                    echo json_encode(array('success' => false, 'msg' => 'Error ocurred while unzip the file'));
                }
                #unlink($target_path);
            }
        }
        else{
            echo json_encode(array('success' => false, 'msg' => 'This file is bigger than 1GB.'));
        }


    }
    if (isset($_FILES['configcisco']) && $_FILES['configcisco']['name'] != "") {
        $sizeCheck = checkSize('configcisco');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['configcisco']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . normalizeNames($_FILES['configcisco']['name']);
        if (move_uploaded_file($_FILES['configcisco']['tmp_name'], $target_path)) {
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        } else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
        }
    }
    if (isset($configclipboard) && $configclipboard != "") {
        //date_default_timezone_set('America/Los_Angeles');
        $filename_config = "cisco_" . date('m-d-Y-His') . ".txt";
        $trans = array("^M" => "\n");
        $configclipboard2 = stripslashes($configclipboard);
        $data = strtr($configclipboard2, $trans);
        $target_path = USERSPACE_PATH."/projects/$project/" . $filename_config;
        $file = fopen($target_path, "w");
        $data = preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $data);
        fwrite($file, $data);
        fclose($file);
        echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
    }
}
elseif ($vendor == "iron-skillet"){
    if (isset($configclipboard) && $configclipboard != "") {
        //date_default_timezone_set('America/Los_Angeles');
        $filename_config = "iron-skillet_vars.txt";
        $trans = array("^M" => "\n");
        $configclipboard2 = stripslashes($configclipboard);
        $data = strtr($configclipboard2, $trans);
        $target_path = USERSPACE_PATH."/projects/$project/toImport/" . $filename_config;
        $file = fopen($target_path, "w");
        //$data = preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $data);
        $data = read_jinja_params($data);
        fwrite($file, $data);
        fclose($file);
        echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
    }
}
elseif ($vendor == "SIDEWINDER") {
    //TODO: No zip method for sidewinder?
    if (isset($_FILES['configsidewinder']) && $_FILES['configsidewinder']['name'] != "") {
        $sizeCheck = checkSize('configsidewinder');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['configsidewinder']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . normalizeNames($_FILES['configsidewinder']['name']);
        if (move_uploaded_file($_FILES['configsidewinder']['tmp_name'], $target_path)) {
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        }
        else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
        }
    }
    if (isset($configclipboard) && $configclipboard != "") {
        //date_default_timezone_set('America/Los_Angeles');
        $filename_config = "sidewinder_" . date('m-d-Y-His') . ".txt";
        $trans = array("^M" => "\n");
        $configclipboard2 = stripslashes($configclipboard);
        $data = strtr($configclipboard2, $trans);
        $target_path = USERSPACE_PATH."/projects/$project/" . $filename_config;
        $file = fopen($target_path, "w");
        $data = preg_replace("/(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+/", "\n", $data);
        fwrite($file, $data);
        fclose($file);
        echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
    }
} 
elseif ($vendor == "CSV") {
    $objtype = $_POST['objtype'];
    require_once INC_ROOT.'/libs/projectdb.php'; //TODO: Check that libs are correctly loaded now, and that the project name is known
    $projectdb = selectDatabase($project);
    if (isset($_FILES['csvfile']) && $_FILES['csvfile']['name'] != "") {
        $sizeCheck = checkSize('csvfile');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['csvfile']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/MT-" . $_FILES['csvfile']['name'];
        $path = USERSPACE_PATH."/projects/" . $project . "/";
        if (move_uploaded_file($_FILES['csvfile']['tmp_name'], $target_path)) {
            ini_set('auto_detect_line_endings', TRUE);
            $handle = fopen($target_path, 'r');
            while (($data = fgetcsv($handle, '', ';') ) !== FALSE) {
                if (array(null) !== $data) {
                    $mydata = array();
                    $counter = count($data);

                    foreach ($data as $key => $value) {
                        $valueTrans = addslashes(str_replace("\"", "", $value));
                        $mydata[] = "'$valueTrans'";
                    }
                    if (count($mydata) > 0) {
                        $lines[] = "(" . implode(",", $mydata) . ")";
                    }
                }
            }

            for ($x = 0; $x < $counter; $x++) {
                $column[] = "col$x";
                $column2[] = "('col$x')";
            }
            $projectdb->query("TRUNCATE csv_columns;");
            $projectdb->query("INSERT INTO csv_columns (" . implode(",", $column) . ") VALUES " . implode(",", $lines) . ";");
            $projectdb->query("UPDATE csv_columns SET objtype='$objtype';");
            $projectdb->query("TRUNCATE csv_mapping");
            $projectdb->query("INSERT INTO csv_mapping (columns) VALUES " . implode(",", $column2) . ";");
            $projectdb->query("UPDATE csv_mapping SET objtype='$objtype';");
            unset($column);
            unset($column2);
            unset($lines);
            unset($data);
            fclose($handle);
            unlink($target_path);

            # TRy to read first line and find if there is a Header who matches the column mapping to create the mapping automatically
            $getHeader=$projectdb->query("SELECT * FROM csv_columns LIMIT 1;");
            if ($getHeader->num_rows>0){

                while($getHeaderData=$getHeader->fetch_assoc()){
                    $Options=array();
                    $id_delete = "";

                    switch ($objtype){
                        case "address":
                            $Options=array("name","ipaddress","netmask","type","cidr","ipaddress_cidr","ipaddress_netmask","ipaddress_range","ipaddress_start","ipaddress_end","tag","description");
                            break;
                        case "regions":
                            $Options=array("name","latitude","longitude","address");
                            break;
                        case "address_groups":
                            $Options=array("name","description","tag","members");
                            break;
                        case "services_groups":
                            $Options=array("name","description","tag","members");
                            break;
                        case "services":
                            $Options=array("name","description","tag","port","protocol","protocol_port","dport","sport");
                            break;
                        case "security":
                            $Options=array("name","from","to","src","dst","user","service","app","action","description","isdisabled","tag","negate_src","negate_dst","log_start","log_end","protocol","sport","dport");
                            break;
                        case "interfaces":
                            $Options=array("name","ipaddress","netmask","cidr","ipaddress_cidr","ipaddress_netmask","secondaryip","zone","tag","media");
                            break;
                        case "routes_static":
                            $Options=array("name","ipaddress","netmask","cidr","ipaddress_cidr","ipaddress_netmask","gateway","metric","tointerface");
                            break;
                        case "zones":
                            $Options=array("name","type","interfaces","profile","log","include","exclude","enable_user");
                            break;
                        case "nat":
                            $Options=array("name","description","tag","from","src","to","dst","service","interface","tp_source","tp_destination","tp_port","isdisabled");

                    }
                    if (count($Options)>0){

                        for ($x = 0; $x <= 29; $x++){
                            $colName="col".$x;
                            if (in_array($getHeaderData[$colName],$Options)){
                                $id_delete = $getHeaderData['id'];
                                $projectdb->query("update csv_mapping set mapping='$getHeaderData[$colName]' where columns='$colName';");

                            }
                        }
                        if($id_delete != ""){
                            // Delete the first line if are mapping columns because are inserted to project database
                            $projectdb->query("DELETE FROM csv_columns WHERE id = '$id_delete';");
                        }
                    }
                }
            }

            ini_set('auto_detect_line_endings', FALSE);
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        }
        else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
        }
    }
}
elseif ($vendor == "STONESOFT") {
    if (isset($_FILES['stonesoftzip']) && $_FILES['stonesoftzip']['name'] != "") {
        $sizeCheck = checkSize('stonesoftzip');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['stonesoftzip']['name']);

        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . normalizeNames($_FILES['stonesoftzip']['name']);
        $path = USERSPACE_PATH."/projects/" . $project . "/";
        if (move_uploaded_file($_FILES['stonesoftzip']['tmp_name'], $target_path)) {
            $result = unzip($target_path, $path);
            if ($result === TRUE) {
                //Check all the files to sanitize them
                echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
            }
            else {
                echo json_encode(array('success' => false, 'msg' => 'Error ocurred while unzip the file'));
            }
            #unlink($target_path);
        }
    }
    if (isset($_FILES['stonesoftxml']) && $_FILES['stonesoftxml']['name'] != "") {
        $sizeCheck = checkSize('stonesoftxml');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['stonesoftxml']['name']);

        $target_path = USERSPACE_PATH."/projects/$project/" . $_FILES['stonesoftxml']['name'];
        if (move_uploaded_file($_FILES['stonesoftxml']['tmp_name'], $target_path)) {
            sanitizeFile($target_path);
            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
        }
        else {
            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
        }
    }
}
elseif ($vendor == "XGS") {

    if ($_FILES['xgszip']['name'] != "") {
        $sizeCheck = checkSize('xgszip');
        if($sizeCheck['success']==false){
            return json_encode($sizeCheck);
        }
        checkValidConfigFileName($_FILES['xgszip']['name']);
        $target_path = USERSPACE_PATH."/projects/" . $project . "/" . normalizeNames($_FILES['xgszip']['name']);
        $path = USERSPACE_PATH."/projects/" . $project . "/";
        $file_parts = pathinfo($_FILES['xgszip']['name']);

        if (file_exists($path."/XGS")){
            rrmdir($path."/XGS");
        }

        switch($file_parts['extension'])
        {
            case "tgz":

                if (move_uploaded_file($_FILES['xgszip']['tmp_name'], $target_path)) {
                    $p = new PharData($target_path);
                    $p->decompress(); // creates files.tar

                    // unarchive from the tar
                    $phar = new PharData($path."/".$file_parts['filename'].".tar");
                    $phar->extractTo($path);
                }
                else {
                    echo json_encode(array('success' => false, 'msg' => 'Error ocurred while loading the file'));
                }
                if (file_exists($path."/".$file_parts['filename'].".tar")){
                    unlink($path."/".$file_parts['filename'].".tar");
                }
                unlink($target_path);

                $old = $path."".$file_parts['filename'];

                $new = $path."XGS";

                //$command="mv $old $new";
                //shell_exec($command);
                //shell_exec(escapeshellarg($command));
                rename($old, $new);

                echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
                break;

            case "zip":

                $size = getZipOriginalSize($_FILES['xgszip']['tmp_name']);
                //echo "original size: $size bytes\n";

                if($size <= "1073741824"){
                    if (move_uploaded_file($_FILES['xgszip']['tmp_name'], $target_path)) {

                        $result = unzip($target_path, $path."/XGS");
                        if ($result === TRUE) {
                            echo json_encode(array('success' => true, 'msg' => 'All the minimum files have been uploaded correctly.'));
                        } else {
                            echo json_encode(array('success' => false, 'msg' => 'Error ocurred while unzip the file.'));
                        }
                        unlink($target_path);
                    }
                }
                else{
                    echo json_encode(array('success' => false, 'msg' => 'This file is bigger than 1GB.'));
                }


                break;

            case "": // Handle file extension for files ending in '.'
            case NULL: // Handle no file extension
                break;
        }

    }

}

function read_jinja_params($vars_config_file){
    $vars_config_file_array = explode("\n", $vars_config_file);
    $allVars=array();
    foreach ($vars_config_file_array as $line => $names_line){
        $activeParams=explode("#",$names_line);
        $vars=explode(":",$activeParams[0],2);
        if (count($vars)==2){
            if (preg_match('/"([^"]+)"/', $vars[0], $m)) {
                if (preg_match('/"([^"]+)"/', $vars[1], $j)) {
                    $allVars[$m[1]]=$j[1];
                }
            }
        }
    }
    return json_encode($allVars);
}

function getZipOriginalSize($filename) {
    $size = 0;
    $resource = zip_open($filename);
    while ($dir_resource = zip_read($resource)) {
        $size += zip_entry_filesize($dir_resource);
    }
    zip_close($resource);

    return $size;
}

function rrmdir($dir) {
    if (is_dir($dir)) {
        $objects = scandir($dir);
        foreach ($objects as $object) {
            if ($object != "." && $object != "..") {
                if (is_dir($dir."/".$object))
                    rrmdir($dir."/".$object);
                else
                    unlink($dir."/".$object);
            }
        }
        rmdir($dir);
    }
}

function join_json_files($path,$project,$policy){
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);
    $allobjects=array();
    if (file_exists($path."/order")){
        $handle = fopen($path."/order", "r");
        $files=array();
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $files[]=$line;
            }
            fclose($handle);
        } else {
            return $message["msg"]="Order file has not been found!.";
        }

        $objects=array();
        $total=array();
        $rulebase_sec=array();
        foreach ($files as $rulebases){
            $rulebase=trim($rulebases);
            $myRules = file_get_contents($path."/".$rulebase);
            for ($i = 0; $i <= 31; ++$i) {
                $myRules = str_replace(chr($i), "", $myRules);
            }
            $myRules = str_replace(chr(127), "", $myRules);
            if (0 === strpos(bin2hex($myRules), 'efbbbf')) {
                $myRules = substr($myRules, 3);
            }
            $myRules = json_decode( $myRules ,true);

            foreach($myRules["rulebase"] as $ruleSection) {
                if (isset($ruleSection['name'])) {
                    $name = $ruleSection['name'];
                } else {
                    $name = $ruleSection['rule-number'];
                }
                $type = $ruleSection['type'];
                switch($type) {
                    case "access-section":
                        if ((isset($ruleSection['rulebase'])) AND (count($ruleSection['rulebase'])>0)){
                            foreach ($ruleSection['rulebase'] as $rule) {
                                if ($rule['type'] == "access-rule") {
                                    //$total['rulebase'][$name][]=$rule;
                                    $ruleNumber=intval($rule['rule-number']);
                                    $rule['header']=$name;
                                    $total['rulebase'][$ruleNumber]=$rule;
                                }
                            }
                        }
                        break;
                    case "access-rule":
                        //$total['rulebase']['rules'][]=$ruleSection;
                        $ruleNumber=intval($ruleSection['rule-number']);
                        $ruleSelection['header']="";
                        $total['rulebase'][$ruleNumber]=$ruleSection;
                        break;
                    case "nat-section":
                        if ((isset($ruleSection['rulebase'])) AND (count($ruleSection['rulebase'])>0)){
                            foreach ($ruleSection['rulebase'] as $rule) {
                                if ($rule['type'] == "nat-rule") {
                                    $total['rulebase'][$name][]=$rule;
                                }
                            }
                        }
                        break;
                    case "nat-rule":
                        $total['rulebase']['rules'][]=$ruleSection;
                        break;
                    default:
                        file_put_contents('/tmp/error.r80', print_r($ruleSection, true));
                }
            }

            $objects=$myRules['objects-dictionary'];

            foreach ($objects as $object){
                $uid=$object['uid'];
                $newObjects[$uid]=$object;
            }
        }

        foreach ($newObjects as $object){
            $allobjects[]=$object;
        }
        //$myRules['objects-dictionary']=$allobjects;
        $total['objects-dictionary']=$allobjects;

        if ($policy=="security"){
            $total['rulebase']=array_values($total['rulebase']);
            file_put_contents(USERSPACE_PATH."/projects/$project/rulebases.txt", json_encode($total,true));
            rrmdir(USERSPACE_PATH."/projects/$project/security");
        }
        else{
            if (count($total)>0){
                if (isset($total['rulebase']['rules'])){
                    $newRules['rulebase']=$total['rulebase']['rules'];
                }
                foreach($myRules["rulebase"] as $internalID=>$ruleSection) {
                    if (isset($ruleSection['name'])) {
                        $name = $ruleSection['name'];
                    }

                    $type = $ruleSection['type'];
                    switch($type) {
                        case "nat-section":
                            if (isset($total['rulebase'][$name])){
                                $ruleSection['rulebase']=$total['rulebase'][$name];
                                $newRules['rulebase'][]=$ruleSection;
                            }
                            //$myRules["rulebase"][$internalID]['rulebase']=$ruleSection['rulebase'];
                            break;
                    }

                }
                $myRules['rulebase']=$newRules['rulebase'];
                unset($newRules);
            }
            file_put_contents(USERSPACE_PATH."/projects/$project/nat.txt", json_encode($myRules));
            rrmdir(USERSPACE_PATH."/projects/$project/nat");
        }


    }
}

function sanitizeFile(STRING $config_path){
//    echo "Going to sanitize the file";
    $str = file($config_path);
    $test = preg_replace("/\^#/i", "", $str);
    file_put_contents($config_path, $test);
    $str = file($config_path);
    $test = preg_replace("/@¨/i", "- ", $str);
    file_put_contents($config_path, $test);
}