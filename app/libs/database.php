<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

require_once INC_ROOT.'/libs/common/definitions.php';
ini_set ( 'mysqli.default_socket' , '/var/run/mysqld/mysqld.sock' );

$DBName='pandb';
$DBName2='pandbRBAC';
$DBName3='BestPractices';
$DBName3='RealTimeUpdates';

global $pandb;
global $pandbRBAC;
global $bestPracticesdb;
global $realTimeUpdates;

if(defined('DBSERVER') && DBServer == 'localhost'){
    define('DBServer','127.0.0.1');
}

$pandb = new mysqli("p:" . DBServer, DBUser, DBPass, $DBName);
if ($pandb->connect_error) {
    trigger_error('Database connection failed: ' . $pandb->connect_error, E_USER_ERROR);
}

$pandbRBAC = new mysqli("p:" . DBServer, DBUser, DBPass, $DBName2);
if ($pandbRBAC->connect_error) {
    trigger_error('Database connection failed: ' . $pandbRBAC->connect_error, E_USER_ERROR);
}

$bestPracticesdb = new mysqli("p:" . DBServer, DBUser, DBPass, $DBName3);
if ($bestPracticesdb->connect_error) {
    trigger_error('Database connection failed: ' . $bestPracticesdb->connect_error, E_USER_ERROR);
}

$realTimeUpdates = new mysqli("p:" . DBServer, DBUser, DBPass, $DBName3);
if ($realTimeUpdates->connect_error) {
    trigger_error('Database connection failed: ' . $realTimeUpdates->connect_error, E_USER_ERROR);
}

function create_mysql_dump_file():string{
    // create mysqldump file and set file permissions to rw-r--r--
    $content = "[mysqldump]\nhost = ".DBServer."\nuser = ".DBUser."\npassword = \"".DBPass."\"";
    $file_path = "/home/userSpace/mysqldump.cnf";
    $file = fopen($file_path, "w");
    fwrite($file, $content);
    fclose($file);
    chmod($file_path, 0640);
    return $file_path;
}

function create_mysql_file($file_name=""):string{
    // create mysqldump file and set file permissions to rw-r--r--
    $content = "[mysql]\nhost = ".DBServer."\nuser = ".DBUser."\npassword = \"".DBPass."\"";
    if($file_name=="") {
        $file_path = "/home/userSpace/" . floor(microtime(true) * 1000) . "_mysql.cnf";
    }else{
        $file_path=$file_name;
    }
    $file = fopen($file_path, "w");
    fwrite($file, $content);
    fclose($file);
    chmod($file_path, 0640);
    return $file_path;
}

function delete_mysql_dump_file($file_path){
    // Remove the mysqldump file. Check if the file exists before attempting to delete it
    if (file_exists($file_path)) {
        // Attempt to delete the file
        unlink($file_path);
    }
}

// Create a callback function to apply htmlspecialchars() to each value
function escapeHtmlSpecialChars($value) {

    if (is_array($value)) {
        // If the request parameter is an array then apply the mysql escape for each stored attribute
        foreach ($value as $key => $innerArray) {
            if (is_array($innerArray)) {
                foreach ($innerArray as $innerKey => $value2) {
                    $value[$key][$innerKey] = htmlspecialchars($value2, ENT_XML1);
                }
            }else{
                $value[$key] = htmlspecialchars($innerArray);
            }
        }

        return $value;

    } else {
        // Apply htmlspecialchars() to each value
        return htmlspecialchars($value);
    }
}

// Create a callback function to apply real_escape_string() to each value
function escapeStringMiddleWareSanitizer ($value) {
    global $pandb;

    if (is_array($value)) {
        // If the request parameter is an array then apply the mysql escape for each stored attribute
        foreach ($value as $key => $innerArray) {
            if (is_array($innerArray)) {
                foreach ($innerArray as $innerKey => $value2) {
                    $value[$key][$innerKey] = mysqli_real_escape_string($pandb, $value2);
                }
            }else{
                $value[$key] = mysqli_real_escape_string($pandb, $innerArray);
            }
        }

        return $value;

    } else {
        // Apply real_escape_string() to each value
        return mysqli_real_escape_string($pandb, $value);
    }
}

function check_sanitize($str)
{
    $str = preg_replace('#\'#','&apos;',$str);    // Replace [ ' ] with [ &apos; ]
    $str = preg_replace("#\\\\#",'',$str);   // Remove [ \ ]
    $str = htmlspecialchars($str); // or $str = htmlentities($str);
    return $str;
}
?>