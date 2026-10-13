<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/


//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

use PaloAltoNetworks\HealthCheck\DeviceDebugConnection;
use \PaloAltoNetworks\HealthCheck\ProjectRolesCheck;
use \PaloAltoNetworks\HealthCheck\DeviceRolesCheck;
use \PaloAltoNetworks\HealthCheck\DependenciesPackageCheck;
use \PaloAltoNetworks\HealthCheck\DependenciesPIPPackageCheck;
//use \PaloAltoNetworks\HealthCheck\HoldPackagesCheck;
use \PaloAltoNetworks\HealthCheck\PanOrdersAgentCheck;
use \PaloAltoNetworks\HealthCheck\MLSettingsCheck;
use \PaloAltoNetworks\HealthCheck\HostNameCheck;
use \PaloAltoNetworks\HealthCheck\MLCheckAlive;
use \PaloAltoNetworks\HealthCheck\DiskUserSpaceCheck;
use \PaloAltoNetworks\HealthCheck\DiskBootSpaceCheck;
use \PaloAltoNetworks\HealthCheck\DiskSparkTempSpaceCheck;
use \PaloAltoNetworks\HealthCheck\DiskParquetCheck;
use \PaloAltoNetworks\HealthCheck\MysqlLogBin;
use \PaloAltoNetworks\HealthCheck\MysqlReconnect;
use \PaloAltoNetworks\HealthCheck\MysqlSQLLogBin;
use \PaloAltoNetworks\HealthCheck\OrphanDeviceRolesCheck;
use \PaloAltoNetworks\HealthCheck\OrphanProjectRolesCheck;
use \PaloAltoNetworks\HealthCheck\SuperUsersCheck;
use \PaloAltoNetworks\HealthCheck\UnusedAccountsCheck;
use \PaloAltoNetworks\HealthCheck\EnvironmentParameters;
use \PaloAltoNetworks\HealthCheck\MisreportedCompletedTasksCheck;
use \PaloAltoNetworks\HealthCheck\ExpeditionGroup;
use \PaloAltoNetworks\HealthCheck\MariaDBSettings;

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

require_once INC_ROOT.'/libs/database.php';

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $param       = $pandb->real_escape_string((string)(isset($_GET['param'])         ? $_GET['param'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = checkHealth();
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg'], 'total'=>$message['total'], 'failed'=>$message['failed']));
        break;

    case 'POST':
        $message = repairHealth();
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg'], 'total'=>$message['total'], 'failed'=>$message['failed']));
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}

function checkHealth():array{
    $checkProjects = new ProjectRolesCheck();
    $checkDevices = new DeviceRolesCheck();
    $checkDependencies = new DependenciesPackageCheck([
        "expedition-beta"                   => "expedition-beta 1.1.48.2",
        "expeditionml-dependencies-beta"    => "expeditionml-dependencies-beta 0.1.3-h2",
    ]);
    $checkPIPDependencies = new DependenciesPIPPackageCheck([
        "BPA"    => "BPA;3.33.0;sh /var/www/html/OS/BPA/updateBPA306.sh",
    ]);
    /*$checkHoldPackages = new HoldPackagesCheck([
        "libmariadbclient18",
        "libmysqlclient18",
    ]);*/
    $checkAgent= new PanOrdersAgentCheck();
    $deviceDebugConnection = new DeviceDebugConnection();
    $checkMLSettings= new MLSettingsCheck();
    $checkHostName= new HostNameCheck();
    $checkMLCheckAlive= new MLCheckAlive();
    $checkDiskUserSpace= new DiskUserSpaceCheck();
    $checkBootSpace= new DiskBootSpaceCheck();
    $checkSparkTempSpace= new DiskSparkTempSpaceCheck();
    $checkParquetSpace= new DiskParquetCheck();
    $checkMysqlLogBin= new MysqlLogBin();
    $checkMysqlReconnect= new MysqlReconnect();
    $checkMysqlSQLLogBin= new MysqlSQLLogBin();
    $checkOrphanDeviceRoles= new OrphanDeviceRolesCheck();
    $checkOrphanProjectRoles= new OrphanProjectRolesCheck();
    $checkSuperUsers = new SuperUsersCheck();
    $checkUnusedAccounts = new UnusedAccountsCheck();
    $checkEnvironmentParameters = new EnvironmentParameters();
    $checkMisreportedCompletedTasksCheck = new MisreportedCompletedTasksCheck();
    $expeditionGroup = new ExpeditionGroup();
    $expeditionMariaDBSettings = new MariaDBSettings();

    $checkResponses = array();
    $checkResponses[] = $checkProjects->check()->toArray();
    $checkResponses[] = $checkDevices->check()->toArray();
    $checkResponses[] = $checkDependencies->check()->toArray();
    $checkResponses[] = $checkPIPDependencies->check()->toArray();
    //$checkResponses[] = $checkHoldPackages->check()->toArray();
    $checkResponses[] = $checkAgent->check()->toArray();
    $checkResponses[] = $deviceDebugConnection->check()->toArray();
    $checkResponses[] = $checkMLSettings->check()->toArray();
    $checkResponses[] = $checkHostName->check()->toArray();
    $checkResponses[] = $checkMLCheckAlive->check()->toArray();
    $checkResponses[] = $checkDiskUserSpace->check()->toArray();
    $checkResponses[] = $checkBootSpace->check()->toArray();
    $checkResponses[] = $checkSparkTempSpace->check()->toArray();
    $checkResponses[] = $checkParquetSpace->check()->toArray();
    $checkResponses[] = $checkMysqlLogBin->check()->toArray();
    $checkResponses[] = $checkMysqlReconnect->check()->toArray();
    $checkResponses[] = $checkMysqlSQLLogBin->check()->toArray();
    $checkResponses[] = $checkOrphanDeviceRoles->check()->toArray();
    $checkResponses[] = $checkOrphanProjectRoles->check()->toArray();
    $checkResponses[] = $checkSuperUsers->check()->toArray();
    $checkResponses[] = $checkUnusedAccounts->check()->toArray();
    $checkResponses[] = $checkEnvironmentParameters->check()->toArray();
    $checkResponses[] = $checkMisreportedCompletedTasksCheck->check()->toArray();
    $checkResponses[] = $expeditionGroup->check()->toArray();
    $checkResponses[] = $expeditionMariaDBSettings->check()->toArray();

    $failed=0;
    foreach ($checkResponses as $checkResponse){
        if(!$checkResponse['success'] ) {
            $failed++;
        }
    }

    if($failed>0){
        $checkResponses[] = [
            'category' => " Summary",
            'check'=> "N/A",
            'code' => -1,
            'description'=> "Number of failed checks",
            'msg'=> "$failed check(s) FAILED",
            'remediation'=> "Check remediations to be applied",
            'success'=> false
        ];
    }

    $response = [
        'code'  => true,
        'msg'   => $checkResponses,
        'total' => count($checkResponses),
        'failed'=> $failed
    ];

    return $response;
}


function repairHealth():array{

    if(!accessControl("any", ['expedition.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to modify Expedition settings';
        return $message;
    }
    
    $checkProjects = new ProjectRolesCheck();
    $checkDevices = new DeviceRolesCheck();
    $checkDependencies = new DependenciesPackageCheck([
        "expedition-beta"                   => "expedition-beta",
        "expeditionml-dependencies-beta"    => "expeditionml-dependencies-beta",
    ]);
    $checkPIPDependencies = new DependenciesPIPPackageCheck([
        "BPA"    => "BPA;3.33.0;sh /var/www/html/OS/BPA/updateBPA306.sh",
    ]);
    /*$checkHoldPackages = new HoldPackagesCheck([
        "libmariadbclient18",
        "libmysqlclient18",
    ]);*/
    $checkAgent= new PanOrdersAgentCheck();
    $checkMLSettings= new MLSettingsCheck();
    $deviceDebugConnection = new DeviceDebugConnection();
    $checkHostname= new HostNameCheck();
    $checkMLCheckAlive= new MLCheckAlive();
    $checkDiskUserSpace= new DiskUserSpaceCheck();
    $checkBootSpace= new DiskBootSpaceCheck();
    $checkSparkTempSpace= new DiskSparkTempSpaceCheck();
    $checkParquetSpace= new DiskParquetCheck();
    $checkMysqlLogBin= new MysqlLogBin();
    $checkMysqlReconnect= new MysqlReconnect();
    $checkMysqlSQLLogBin= new MysqlSQLLogBin();
    $checkOrphanDeviceRoles= new OrphanDeviceRolesCheck();
    $checkOrphanProjectRoles= new OrphanProjectRolesCheck();
    $checkSuperUsers = new SuperUsersCheck();
    $checkUnusedAccounts = new UnusedAccountsCheck();
    $checkEnvironmentParameters = new EnvironmentParameters();
    $checkMisreportedCompletedTasksCheck = new MisreportedCompletedTasksCheck();
    $expeditionGroup = new ExpeditionGroup();
    $expeditionMariaDBSettings = new MariaDBSettings();


    $checkResponses = array();

    $checkResponses[] = $checkProjects->repair();
    $checkResponses[] = $checkDevices->repair();
    $checkResponses[] = $checkDependencies->repair();
    $checkResponses[] = $checkPIPDependencies->repair();
    //$checkResponses[] = $checkHoldPackages->repair();
    $checkResponses[] = $checkAgent->repair();
    $checkResponses[] = $deviceDebugConnection->repair();
    $checkResponses[] = $checkMLSettings->repair();
    $checkResponses[] = $checkHostname->repair();
    $checkResponses[] = $checkMLCheckAlive->repair();
    $checkResponses[] = $checkDiskUserSpace->repair();
    $checkResponses[] = $checkBootSpace->repair();
    $checkResponses[] = $checkSparkTempSpace->repair();
    $checkResponses[] = $checkParquetSpace->check();
    $checkResponses[] = $checkMysqlLogBin->repair();
    $checkResponses[] = $checkMysqlReconnect->repair();
    $checkResponses[] = $checkMysqlSQLLogBin->repair();
    $checkResponses[] = $checkOrphanDeviceRoles->repair();
    $checkResponses[] = $checkOrphanProjectRoles->repair();
    $checkResponses[] = $checkSuperUsers->repair();
    $checkResponses[] = $checkUnusedAccounts->repair();
    $checkResponses[] = $checkEnvironmentParameters->repair();
    $checkResponses[] = $checkMisreportedCompletedTasksCheck->repair();
    $checkResponses[] = $expeditionGroup->repair();
    $checkResponses[] = $expeditionMariaDBSettings->repair();

    $failed=0;
    foreach ($checkResponses as $checkResponse){
        if(!$checkResponse->success()) $failed++;
    }

    if($failed>0){
        $checkResponses[] = [
            'category' => " Summary",
            'check'=> "N/A",
            'code' => -1,
            'description'=> "Number of failed checks",
            'msg'=> "$failed check(s) FAILED",
            'remediation'=> "Check remediations to be applied",
            'success'=> false
        ];
    }

    $response = [
        'code'  => true,
        'msg'   => $checkResponses,
        'total' => count($checkResponses),
        'failed'=> $failed
    ];

    return $response;
}