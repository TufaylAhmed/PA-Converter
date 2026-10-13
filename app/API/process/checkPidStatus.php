<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';
require_once INC_ROOT . '/libs/definitions/sparkVersions.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

if(!isset($post_vars['pid'])){
    echo json_encode(['status' => false]);
}
else{
    # Cleaning
    $basepath = '/proc/';
    $realBase = realpath($basepath);

    $userpath = $basepath . $post_vars['pid'];
    $realUserPath = realpath($userpath);

    $isRunning = false;

    if ($realUserPath === false || strpos($realUserPath, $realBase) !== 0) {
        echo json_encode(['pid'=> $post_vars['pid'], 'isRunning' => $isRunning]);
    } else {
        if (file_exists( "/proc/".$post_vars['pid'] )){
            $isRunning = true;
        }
        else{
            $isRunning = false;
        }
        echo json_encode(['pid'=> $post_vars['pid'], 'isRunning' => $isRunning]);
    }
}





