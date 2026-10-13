<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

$response = array();

$response['alive'] = true;

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

if(isset($post_vars['java_version'])){
    $response['java_version'] = shell_exec("java -version 2>&1");
}


echo json_encode($response);