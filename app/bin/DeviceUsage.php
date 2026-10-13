<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once '../libs/database.php';
require_once '../libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $dusage_platform    = (string) (isset($_GET['dusage_platform']) ? $_GET['dusage_platform'] : '');
        $dusage_version     = (string) (isset($_GET['dusage_version'])  ? $_GET['dusage_version'] : '');
        $vsys               = (string) (isset($_GET['dusage_vsys'])     ? $_GET['dusage_vsys'] : '');
        $source             = (string) (isset($_GET['dusage_source'])   ? $_GET['dusage_source'] : '');
        $dusage_template    = (string) (isset($_GET['dusage_template']) ? $_GET['dusage_template'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $dusage_platform    = (string) (isset($_POST['dusage_platform']) ? $_POST['dusage_platform'] : '');
        $dusage_version     = (string) (isset($_POST['dusage_version'])  ? $_POST['dusage_version'] : '');
        $vsys               = (string) (isset($_POST['dusage_vsys'])     ? $_POST['dusage_vsys'] : '');
        $source             = (string) (isset($_POST['dusage_source'])   ? $_POST['dusage_source'] : '');
        $dusage_template    = (string) (isset($_POST['dusage_template']) ? $_POST['dusage_template'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $dusage_platform    = (string) (isset($_POST['dusage_platform']) ? $_POST['dusage_platform'] : '');
        $dusage_version     = (string) (isset($_POST['dusage_version'])  ? $_POST['dusage_version'] : '');
        $vsys               = (string) (isset($_POST['dusage_vsys'])     ? $_POST['dusage_vsys'] : '');
        $source             = (string) (isset($_POST['dusage_source'])   ? $_POST['dusage_source'] : '');
        $dusage_template    = (string) (isset($_POST['dusage_template']) ? $_POST['dusage_template'] : '');
        break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//
//$dusage_platform = (string) (isset($_POST['dusage_platform']) ? $_POST['dusage_platform'] : $_GET['dusage_platform']);
//$dusage_version = (string) (isset($_POST['dusage_version']) ? $_POST['dusage_version'] : $_GET['dusage_version']);
//$vsys = (string) (isset($_POST['dusage_vsys']) ? $_POST['dusage_vsys'] : $_GET['dusage_vsys']);
//$source = (string) (isset($_POST['dusage_source']) ? $_POST['dusage_source'] : $_GET['dusage_source']);
//$dusage_template = (string) (isset($_POST['dusage_template']) ? $_POST['dusage_template'] : $_GET['dusage_template']);

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$dusage_platform = (integer) $projectdb->real_escape_string($dusage_platform);
$dusage_version = $projectdb->real_escape_string($dusage_version);
$vsys = $projectdb->real_escape_string($vsys);
$source = (integer) $projectdb->real_escape_string($source);
$dusage_template = $projectdb->real_escape_string($dusage_template);

if($dusage_version!="") {
    $pattern = '/^\d+(\.\d+)*(\.h\d+(\.\d+)*)?$/';
    if (!preg_match($pattern, $dusage_version)) {
        echo '{"total":"","statistics":""}';
        exit();
    }
}
deviceUsage($action, $type, $project, $dusage_platform, $dusage_version, $vsys, $source, $dusage_template);



?>