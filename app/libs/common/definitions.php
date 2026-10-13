<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 8/4/16 - 20:04
 */

//if(!isset($_SERVER['DOCUMENT_ROOT'])){
$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
//}

const DEBUG_SERVER = '192.168.10.171';
define ('INC_ROOT', $_SERVER['DOCUMENT_ROOT']);
define ('USERSPACE_PATH', '/home/userSpace');
define ('SYSLOGPATH', '/data');
define ('ValidFileName','/^[a-zA-Z0-9-_\.]*$/');

$userDefinitionsPath = "/home/userSpace/userDefinitions.php";

if(file_exists($userDefinitionsPath)) {
    include_once $userDefinitionsPath;
}
else{
    copy(INC_ROOT.'/libs/common/userDefinitions.php', $userDefinitionsPath);
    include_once $userDefinitionsPath;
}

include_once INC_ROOT."/libs/common/errorCodes.php";

if(!isset ($curlConnections)) {
    global $curlConnections;
    $curlConnections = array();
}

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

$debug_environment = "/home/userSpace/debug_enabled";
if(file_exists($debug_environment)) {
    define ('XDEBUG', true);
} else {
    define ('XDEBUG', false);
}

if(!defined ('DEVICE_CONNECTION_TIMEOUT')){
    define ('DEVICE_CONNECTION_TIMEOUT', 900);
}
if(!defined('DEVICE_DEBUG_CONNECTION_ENABLED')){
    define('DEVICE_DEBUG_CONNECTION_ENABLED',0);
}
