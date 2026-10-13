<?php
require_once '/var/www/html/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';
require_once INC_ROOT.'/libs/common/tools/tools-rules.php';
require_once './AddressAnalysis.php';
require_once './AddressGroupAnalysis.php';
require_once './ServiceGroupAnalysis.php';
require_once './ServiceAnalysis.php';
require_once './SecRulesAnalysis.php';

error_reporting(E_ERROR | E_PARSE);

$projects = [
    "PROJECT_NAME",
];



$sec_analyzer = new SecRulesAnalysis() ;
foreach ($projects as $project) {
    if ($projectdb = selectDatabase($project)){
        $sec_analyzer->name_quality($projectdb);
    }
}







