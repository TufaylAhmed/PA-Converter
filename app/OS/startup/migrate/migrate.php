<?php

use function cli\line;
use function cli\menu;

require_once './options/common.php';

$userDefinitionsPath = "/tmp/migrationSettings.php";

if(file_exists($userDefinitionsPath)) {
    $variables = json_decode(file_get_contents($userDefinitionsPath), true);
}
else{
    $variables = [
        'ip' => "192.168.10.2",
        'sshPort' => "22",
        'sshUser' => "root",
//    'sshPass' => "paloalto",
        'mysqlPort' => "3306",
        'mysqlUser' => "root",
        'mysqlPass' => "paloalto",
        'CSVlogsPath' => "/PALogs",
        'connections_parquet' => "/data",
        ];
    $userSettingsFile = fopen($userDefinitionsPath, 'wb');
    fwrite($userSettingsFile, json_encode($variables));
    fclose($userSettingsFile);
}




$menu = array(
    //'instructions'   => 'See Preparation Instructions',
    'targetSettings' => 'Enter Destination settings                   (Required) ',
    'seeSettings'    => ' See Destination settings',
    //'checkSettings'   => 'Check Destination settings',
    'migrateData'    => 'Migrate Users, Devices and Projects          (Required) ',
    'migrateLogs'    => 'Migrate Device Logs (Traffic Logs)           (Optional)',
    'migrateParquet' => 'Migrate Pre-Processed Data (Traffic Logs)    (Optional)',
    'userParameters' => 'Review User and Environment Parameters       (Required)',

    'quit' => 'Quit',
);

introduction();

while (true) {
    $choice = menu($menu, null, 'Choose an option');
    line();

    if ($choice === 'quit') {
        break;
    }

    include "./options/${choice}.php";
    line();
}

function introduction(){
    echo \cli\Colors::colorize('  %C%9--------------------------------------------------------------------------------------------------------------------%n', true) . "\n";
    echo \cli\Colors::colorize('  %C%9|%n                                WELCOME TO THE EXPEDITION TRANSFER ASSISTANT                                      %C%9|%n',true)."\n";
    echo \cli\Colors::colorize('  %C%9|%n                                               %B%9ver. 1.0                                                           %C%9|%n', true)."\n";
    echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
    echo \cli\Colors::colorize('  %C%9|%n   This tool will help you transferring your current projects and data between two Expedition instances,          %C%9|%n', true)."\n";
    echo \cli\Colors::colorize('  %C%9|%n   being this one the Source (%B%9Machine_A%n) to a new Expedition (%C%9Machine_B%n).                                         %C%9|%n', true)."\n";
    echo \cli\Colors::colorize('  %C%9|%n                                                                                                                  %C%9|%n', true)."\n";
    echo \cli\Colors::colorize('  %C%9--------------------------------------------------------------------------------------------------------------------%n', true) . "\n";
}

