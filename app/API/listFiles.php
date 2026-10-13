<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2017-07-07 11:35
 ******************************************************************************/

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once "DirnameFilter.php";
require_once "FilenameFilter.php";
require_once "FilesystemRegexFilter.php";
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';

if(isset($_SERVER['REQUEST_METHOD'])) {
    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
            //$message = listFiles($params);
            //echo json_encode(array('success' => $message['code'], 'files' => $message['msg'], 'errorMessage' => $message['errorMessage']));
            $message = json_encode(array('success' => false, 'msg' => "Feature not available", 'errorMessage' => "Feature not available"));
            return $message;

        default:
            $message = json_encode(array('success' => false, 'files' => ""));
            return $message;
    }
}

function listFiles(ARRAY $params=null){
    include_once INC_ROOT.'/libs/file_functions.php';
    $paths = (isset($params['path']))   ?explode(',',$params['path']): null;

    $conn = get_pdo("pandbRBAC");

    $errorMessage = '';
    $code = true;

    $files = array();
    if(!is_null($paths)){
        foreach ($paths as $path) {
            if ($path != "") {
                $path = check_sanitize($path);

                // Validate the path is defined in a device
                $stmt = $conn->prepare("SELECT id FROM devices WHERE csv_path= :csv_path");
                $stmt->bindParam(":csv_path", $path);
                $stmt->execute();
                $getPath = $stmt->fetchAll(PDO::FETCH_ASSOC);

                if (count($getPath) == 0) {
                    break; //continue with the next path
                }

                $pathArr = explode(DIRECTORY_SEPARATOR, $path);

                $fileExpr = array_pop($pathArr);
    //            echo "$fileExpr-";
                $fileExpr = str_replace("*", ".*", $fileExpr);
                $fileExpr = str_replace("?", ".{1}", $fileExpr);
    //            $fileExpr = substr($fileExpr, strlen($fileExpr)-1,1)=="*" ? substr($fileExpr, 0,strlen($fileExpr)-1) : $fileExpr;
    //            echo "$fileExpr<br>";
                $dir = implode(DIRECTORY_SEPARATOR, $pathArr) . "/";

                if (file_exists($dir) && $dir!="/") {
                    $directory = new RecursiveDirectoryIterator($dir);

                    $filter = new DirnameFilter($directory, '/^(?!\.Trash|\.|\.\.)/');  //Remove the . .. and .Trash folders so they are not considered for Recursive listing

                    try {
                        $filter = new FilenameFilter($filter, '/' . $fileExpr . '\.(?:log|csv|csv\.gz)+$/'); //Looking for files that start with the fileExpr, and end with .csv or .gz
                        foreach (new RecursiveIteratorIterator($filter) as $file) {
                            if (is_file($file)) {
                                try {
                                    $files[] = [
                                        'name' => check_sanitize($file) . "",
                                        'date' => date("Y-m-d", filemtime($file))
                                    ];
                                } catch (Exception $e1) {
                                    $files[] = [
                                        'name' => check_sanitize($file) . "",
                                        'date' => ""
                                    ];
                                }
                            }
                        }
                        $code = true;
                        $errorMessage = "";
                    } catch (Exception $e) {
                        $code = false;
                        $errorMessage = "The given path cannot be scanned. '";
                    }
                } else {
                    $code = false;
                    $errorMessage = "The given path does not exist or cannot be accessed. '";
                }
            }
        }
    }

    // validate the returned files are log files and remove any other log
    $count_files = count($files);
    for($i=0;$i<$count_files;$i++){
        $file = &$files[$i];
        if( isset($file['name']) && filesize($file['name']) != 0 ){
            $file['size'] = FileSizeConvert(filesize($file['name']));
            $file['version'] = FileLogVersion($file['name']);
            if(isset($file['version']) && $file['version']!= 'unkwown') {
                $file['serial'] = FileLogSerial($file['name'], $file['version']);
                if($file['serial']=="unknown"){
                    unset($file[$i]); // it's not a NGFW log file do not return as it can not be processed
                }
            }else{
                unset($file[$i]); // it's not a NGFW log file do not return as it can not be processed
            }
        }
        else{
            unset($files[$i]); // it's an empty file do not return as it can not be processed
        }
    }

    return [
        'code'          => $code,
        'msg'           => $files,
        'errorMessage'  => $errorMessage
    ];
}