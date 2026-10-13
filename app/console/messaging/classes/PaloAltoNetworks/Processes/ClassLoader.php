<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 3/6/16 - 14:40
 */

namespace PaloAltoNetworks\Processes;

class ClassLoader{
    private $localPath;

    function getDirContents($dir, &$results = array()){
        $files = scandir($dir);

        foreach($files as $key => $value){
            $path = realpath($dir.DIRECTORY_SEPARATOR.$value);
            if(!is_dir($path)) {
            } else if($value != "." && $value != "..") {
                self::getDirContents($path, $results);
                $results[] = $path.'/';
            }
        }

        return $results;
    }

    function myAutoloader($className){
        echo "Checking: $className\n";
        $classPath = INC_ROOT. '/console/messaging/classes/PaloAltoNetworks/Processes/';
//        require $classPath . str_replace("\\", "/", $className) . '.php';

//        $sources = array(
//            "",
//            "BestPractices/",
//            "BestPractices/Check/",
//            "BestPractices/Remediate/"
//        );

        $sources = self::getDirContents($classPath);
        $sources[] = $classPath;
        foreach ($sources as $source){
            if (file_exists($source . str_replace("\\", "/", $className) . '.php')){
//                echo $source . str_replace("\\", "/", $className) . ".php\n";
                require_once $source . str_replace("\\", "/", $className) . '.php';
            }
        }

    }

    public function __construct($message)
    {

        spl_autoload_register('self::myAutoloader');

        $process        = $message->proccessCode;
        $params         = $message->params;
        $params->sender = $message->sender;
        $params->loggable = (isset($message->loggable))  ? $message->loggable   : false;
        $params->logPath  = (isset($message->logPath))   ? $message->logPath    : '';

        $className=$process;

        // BestPractices\\Check\\GeneralSettings1
        if (class_exists($className)) {
            $obj=new $className((ARRAY) $params);
            $obj->start();
        }
        else{
            // print_r($message);
        }

    }
}