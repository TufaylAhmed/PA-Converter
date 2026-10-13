<?php

use PaloAltoNetworks\HealthCheck\DependenciesPackageCheck;
use PaloAltoNetworks\HealthCheck\DependenciesPIPPackageCheck;
use PaloAltoNetworks\HealthCheck\DeviceDebugConnection;
use PaloAltoNetworks\HealthCheck\DeviceRolesCheck;
use PaloAltoNetworks\HealthCheck\EnvironmentParameters;
use PaloAltoNetworks\HealthCheck\HostNameCheck;
use PaloAltoNetworks\HealthCheck\MisreportedCompletedTasksCheck;
use PaloAltoNetworks\HealthCheck\MLCheckAlive;
use PaloAltoNetworks\HealthCheck\MLSettingsCheck;
use PaloAltoNetworks\HealthCheck\MysqlLogBin;
use PaloAltoNetworks\HealthCheck\MysqlReconnect;
use PaloAltoNetworks\HealthCheck\MysqlSQLLogBin;
use PaloAltoNetworks\HealthCheck\OrphanDeviceRolesCheck;
use PaloAltoNetworks\HealthCheck\OrphanProjectRolesCheck;
use PaloAltoNetworks\HealthCheck\PanOrdersAgentCheck;
use PaloAltoNetworks\HealthCheck\ProjectRolesCheck;
use PaloAltoNetworks\HealthCheck\SuperUsersCheck;
use PaloAltoNetworks\HealthCheck\UnusedAccountsCheck;

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';


require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/userManager/API/devices/list.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

global $app;

if($user = $app->user->where('email',"admin")->get()->first()) {
    $app->sentinel->login($user);
}


$getSettings = $pandbRBAC->query("SELECT * FROM pandbRBAC.ml_settings;");
$setting = $getSettings->fetch_assoc();
$_SERVER['SERVER_ADDR'] = $setting['server'];
echo("\nDevices & Log processor checks:\n");
print_r(listDevices('direct', '', false));
echo("\nSystem checks:\n");
print_r(checkHealth());

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
    //$checkAgent= new PanOrdersAgentCheck();
    $deviceDebugConnection = new DeviceDebugConnection();
    $checkMLSettings= new MLSettingsCheck();
    $checkHostName= new HostNameCheck();
    $checkMLCheckAlive= new MLCheckAlive();
    //$checkDiskUserSpace= new DiskUserSpaceCheck();
    //$checkBootSpace= new DiskBootSpaceCheck();
    //$checkSparkTempSpace= new DiskSparkTempSpaceCheck();
    //$checkParquetSpace= new DiskParquetCheck();
    $checkMysqlLogBin= new MysqlLogBin();
    $checkMysqlReconnect= new MysqlReconnect();
    $checkMysqlSQLLogBin= new MysqlSQLLogBin();
    $checkOrphanDeviceRoles= new OrphanDeviceRolesCheck();
    $checkOrphanProjectRoles= new OrphanProjectRolesCheck();
    $checkSuperUsers = new SuperUsersCheck();
    $checkUnusedAccounts = new UnusedAccountsCheck();
    $checkEnvironmentParameters = new EnvironmentParameters();
    $checkMisreportedCompletedTasksCheck = new MisreportedCompletedTasksCheck();
    //$expeditionGroup = new ExpeditionGroup();
    //$expeditionMariaDBSettings = new MariaDBSettings();

    $checkResponses = array();
    $checkResponses[] = $checkProjects->check()->toArray();
    $checkResponses[] = $checkDevices->check()->toArray();
    $checkResponses[] = $checkDependencies->check()->toArray();
    $checkResponses[] = $checkPIPDependencies->check()->toArray();
    //$checkResponses[] = $checkHoldPackages->check()->toArray();
    //$checkResponses[] = $checkAgent->check()->toArray();
    $checkResponses[] = $deviceDebugConnection->check()->toArray();
    $checkResponses[] = $checkMLSettings->check()->toArray();
    $checkResponses[] = $checkHostName->check()->toArray();
    $checkResponses[] = $checkMLCheckAlive->check()->toArray();
    //$checkResponses[] = $checkDiskUserSpace->check()->toArray();
    //$checkResponses[] = $checkBootSpace->check()->toArray();
    //$checkResponses[] = $checkSparkTempSpace->check()->toArray();
    //$checkResponses[] = $checkParquetSpace->check()->toArray();
    $checkResponses[] = $checkMysqlLogBin->check()->toArray();
    $checkResponses[] = $checkMysqlReconnect->check()->toArray();
    $checkResponses[] = $checkMysqlSQLLogBin->check()->toArray();
    $checkResponses[] = $checkOrphanDeviceRoles->check()->toArray();
    $checkResponses[] = $checkOrphanProjectRoles->check()->toArray();
    $checkResponses[] = $checkSuperUsers->check()->toArray();
    $checkResponses[] = $checkUnusedAccounts->check()->toArray();
    $checkResponses[] = $checkEnvironmentParameters->check()->toArray();
    $checkResponses[] = $checkMisreportedCompletedTasksCheck->check()->toArray();
    //$checkResponses[] = $expeditionGroup->check()->toArray();
    //$checkResponses[] = $expeditionMariaDBSettings->check()->toArray();

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