<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/libs/database.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $project = $pandb->real_escape_string($post_vars['project']);
}
else {
    $project = $pandb->real_escape_string((string)(isset($_GET['project']) ? $_GET['project'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $roles = getMyRole($project);
        echo json_encode($roles, true);
        break;

    default:
        break;
}

function getMyRole(STRING $projectName):array{
    global $app;
    /** @var  $generalRole string */
    /** @var  $projectRole string */
    $me = $app->sentinel->getUser();
    return $app->user->where('id',$me['id'])->get()->first()->getMyRole($projectName);
}

