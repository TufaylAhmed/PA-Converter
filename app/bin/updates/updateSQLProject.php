<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';

function updateProject(String $projectName){
    $DB = selectDatabase($projectName);
    $extension="common";
    $first=true;
    foreach (glob(INC_ROOT."/OS/SQL/updates/*.".$extension) as $filename) {
        $file=basename($filename);
        if ($first==true){
            $return=table_updates($DB);
            $first=false;
        }
        if (!in_array($file,$return)){
            $command = "/usr/bin/mysql -u".DBUser." -p".DBPass." $projectName < $filename";
            shell_exec($command);
            $DB->query("INSERT INTO updates (datetime,filename) VALUES (NOW(),'$file');");
            // echo "Updating Database: ".$projectName." Applying Patch:".$file.PHP_EOL;
        }
    }
}

function table_updates($database){
    $return=array();
    $updateDB="CREATE TABLE  `updates` (`id` int(11) NOT NULL AUTO_INCREMENT,`datetime` datetime DEFAULT NULL,`filename` varchar(255) DEFAULT NULL,PRIMARY KEY (`id`)) ENGINE=MyISAM DEFAULT CHARSET=utf8;";
    $result=$database->query($updateDB);
    if($result){
        return $return;
    }
    else{
        $files=$database->query("SELECT filename FROM updates;");
        if ($files->num_rows>0){
            while($filesData=$files->fetch_assoc()){
                $return[]=$filesData['filename'];
            }
        }
        return $return;
    }
}