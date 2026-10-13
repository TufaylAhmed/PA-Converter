<?php

use function cli\line;
use function cli\menu;

require_once './options/common.php';

$menuGeneralSettings = array(
    'targetSettingsIP'   => 'Enter Destination IP',
    'targetSettingsSSH' => 'Enter Destination SSH Settings',
    'targetSettingsDB' => 'Enter Destination DB Settings',

    'quit' => 'Done',
);

while (true) {
    $choice = menu($menuGeneralSettings, null, 'Choose an option');
    line();

    if ($choice === 'quit') {
        break;
    }

    include "./options/settings/${choice}.php";
    line();
}
