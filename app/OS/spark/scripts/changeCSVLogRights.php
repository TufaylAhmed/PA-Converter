<?php

/***
 * Looks for CSV log files for the existing firewalls and modifies their settings to be writeable (deleteable) by www-data
 */


require_once '/var/www/html/libs/common/definitions.php';
require_once INC_ROOT.'/libs/vendor/autoload.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/userManager/API/accessControl.php';

require_once INC_ROOT.'/userManager/API/devices/list.php';

require_once INC_ROOT.'/libs/common/device/CsvFilesLister.php';
use PaloAltoNetworks\Sentinel\Devices\CsvFilesLister;


global $app;

$userId='admin';

if(!isset($userId)){
    $userId='';
}
$credentials = [
    'email' => $userId,
];

if($user = $app->container->sentinel->findByCredentials($credentials)) {
    $app->sentinel->login($user);
}
else{
    echo "User not found";
}

$scope = '';
$projectName = '';


if(!accessControl("any", ['device.*', 'device.create'])){
    $message = array();
    $message['code'] = false;
    print 'Your account does not have the rights to view logs from this device\n';
    return $message;
}

if(!$devices = $app->container->device->where('active', '=', '1')->where('autoProcessCSV',1)->orderBy('devicename')->get(['serial','csv_path'])){
    print 'No devices to check for changing its CSV log files rights. Maybe autoProcess CSV has not been set\n';
    return;
}

if(count($devices)==0){
    print 'No devices to check for changing its CSV log files rights. Maybe autoProcess CSV has not been set\n';
    return;
}

foreach ($devices as $device){
    //Change the file ownership and rights
    $fileLister = new CsvFilesLister($device->serial, $device->csv_path);

    $message= $fileLister->list_LogFiles();  //Use this method to validate that the file that is going to be changed rights is a CSV file from this device! Avoid changing file rights from other paths, such as /opt, /root, /boot, etc, which won't be CSV files from this firewall
    foreach ($message['news'] as $newFile){
        if(file_exists($newFile)) {
            $command = "chown expedition:www-data " . $newFile . "; chmod 660 " . $newFile . ";";
            exec($command);
            print "Executing: $command\n";
        }
    }

    print "Check Completed\n";

}
