<?php

use function cli\line;

require_once './options/common.php';

line('Enter the destination Expedition IP:');
$variables['ip'] = \cli\Streams::input();

$userSettingsFile = fopen($userDefinitionsPath, 'wb');
fwrite($userSettingsFile, json_encode($variables));
fclose($userSettingsFile);