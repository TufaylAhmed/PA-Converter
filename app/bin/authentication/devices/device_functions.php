<?php

function getContents(STRING $deviceSerial){
    global $app;

    include_once INC_ROOT.'/libs/file_functions.php';

    if(!$device = $app->device->where('serial', $deviceSerial)->get()->first()){
        $message = array();
        $message['code'] = true;
        $message['msg'] = '';
        return $message;
    }

    $message = array();

    $downloadings = array();
    //Check if there are any pending tasks for this device
    if($jobs = $app->job->where('parentType','devices')->where('description','not like','Spark: %')->where('parentId',$device->id)->whereColumn('completed','<','tasks')->get()){
        foreach ($jobs as $job){
            $tasks = $job->tasks()->get();
            foreach ($tasks as $task){
                $type = $task->taskName;

//                echo "$task->taskName should be Downloading...<br>";
                $downloadings[$task->taskName]['processed'] = false;
            }
        }
    }

    $fileList = array();
    if(is_dir(USERSPACE_PATH.'/devices/'.$device->serial)) {
        $files = scandir(USERSPACE_PATH . '/devices/' . $device->serial);
    }
    else{
        $files = array();
    }

    foreach ($files as $file){
        if($file == '.' || $file == '..') {
        }
        else {
            switch($file){
                case "ConfigBackup.xml":
                    $fileItem['type'] = 'Download Configuration';
                    break;

                case "applications-container.xml":
                    $fileItem['type'] = 'Download Application Container';
                    break;

                case (preg_match('/SharedPushedPolicy.*/', $file) ? true : false):
                    $fileItem['type'] = 'Download Configuration';
                    break;

                case "applications.xml":
                    $fileItem['type'] = 'Download Applications';
                    break;

                case "region.xml":
                    $fileItem['type'] = 'Download Regions';
                    break;

                default:
                    $fileItem['type'] ='custom';
                    break;
            }
            $fileItem['filename'] = $file;
            $fileItem['date'] = date("F d Y H:i:s", filemtime(USERSPACE_PATH . '/devices/' . $device->serial . '/' . $file));
            $fileItem['size'] = FileSizeConvert(filesize(USERSPACE_PATH . '/devices/' . $device->serial . '/' . $file));
            if(isset($downloadings[$fileItem['type']])){
                $fileItem['state'] = 'Updating...';
                $downloadings[$fileItem['type']]['processed'] = true;
            }
            else {
                $fileItem['state'] = 'downloaded';
            }
            $fileItem['available'] = true;
            $fileList[] = $fileItem;
        }
    }

    $message['code'] = 1;

    foreach ($downloadings as $key=>$downloading){
        if(!$downloading['processed']){
            $fileItem['type'] = $key;
            $fileItem['filename'] = 'unknown';
            $fileItem['date'] = 'n/a';
            $fileItem['size'] = 'n/a';
            $fileItem['state'] = 'Downloading...';
            $fileItem['available'] = false;
            $fileList[] = $fileItem;
            $message['code'] = 2;
        }
    }

    $message['msg'] = $fileList;
    return $message;
}
