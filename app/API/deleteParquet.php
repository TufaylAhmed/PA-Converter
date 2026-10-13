<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

//$myFile= fopen('file', 'a');
//fwrite($myFile, "post_vars");
//fwrite($myFile, print_r($post_vars, true));
//fwrite($myFile, "data");
//fwrite($myFile, print_r($data, true));
//fclose($myFile);

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = json_encode(array('success' => false, 'msg' => "Feature not available", 'errorMessage' => "Feature not available"));
        return $message;

    case 'DELETE':
        $message = json_encode(array('success' => false, 'msg' => "Feature not available", 'errorMessage' => "Feature not available"));
        return $message;

    default:
        echo json_encode(array('success' => false, 'files' => ""));
        break;
}

