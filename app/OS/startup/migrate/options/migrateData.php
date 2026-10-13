<?php



require_once 'common.php';

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';
require_once INC_ROOT . '/userManager/start_CLI.php';
require_once INC_ROOT . '/libs/Security/SecureProject.php';
require_once INC_ROOT . '/libs/Security/SecureDevice.php';
require_once 'migrate_functions.php';

transfer_pandbRBAC($variables);
migrateProjects($variables);
migrateDevices($variables);


