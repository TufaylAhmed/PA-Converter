<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT . '/bin/Authentication.php';

require_once INC_ROOT . '/libs/DiskStatus.class.php';
require_once INC_ROOT . '/libs/settings/ML_Settings.php';
require_once INC_ROOT . '/libs/projectdb.php';
require_once INC_ROOT . '/libs/cpu_status_functions.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

$scope = isset($_GET['scope'])? $_GET['scope']:'system';

switch (strtolower($scope)){
    case 'ml':
        $output = getMLStatus();
        break;

    case 'system':
    default:
        $output = getSystemStatus();
        break;
}
echo json_encode($output);
