<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';
//Dependencies
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/bestpractices/bpat.php';
require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project    = $pandb->real_escape_string((string)  (isset($_GET['project'])    ? $_GET['project'] : ''));
        $template   = $pandb->real_escape_string((string)  (isset($_GET['template'])   ? $_GET['template'] : ''));
        $vsys       = $pandb->real_escape_string((string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : ''));
        $subtype    = $pandb->real_escape_string((string)  (isset($_GET['subtype'])   ? $_GET['subtype'] : ''));
        $topic      = $pandb->real_escape_string((string)  (isset($_GET['topic'])    ? $_GET['topic'] : ''));
        $message = list_bpat_bpchecks($project,$vsys,$template,$subtype,$topic);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'bpchecks' => $message['msg']));
        }
        else{
            echo '{"total":"0","bpchecks":[]}';
        }
        break;
    case 'POST':
    default:
        break;
}