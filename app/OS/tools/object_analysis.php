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

//
$projects = [
    "PROJECT_NAME",
];

$current_time = date("ymd-G.i.s");

$address_analyzer = new AddressAnalysis();
$log_file_name = "./address_analysis.v.".$current_time.".json";
$my_file = fopen($log_file_name, "w+");
echo "Address\n";
foreach ($projects as $project){
    $log_line = $address_analyzer->print_entry($project, "CHG");
    echo $log_line;
    fwrite($my_file, $log_line);
}
fclose($my_file);

$address_group_analyzer = new AddressGroupAnalysis();
$log_file_name = "./address_group_analysis.v.".$current_time.".json";
$my_file = fopen($log_file_name, "w+");
echo "Address Group\n";
foreach ($projects as $project){
    $log_line = $address_group_analyzer->print_entry($project);
    echo $log_line;
    fwrite($my_file, $log_line);
}
fclose($my_file);


$service_analyzer = new ServiceAnalysis();
$log_file_name = "./service_analysis.v.".$current_time.".json";
$my_file = fopen($log_file_name, "w+");
echo "Service\n";
foreach ($projects as $project){
    $log_line =     $service_analyzer->print_entry($project);
    echo $log_line;
    fwrite($my_file, $log_line);
}
fclose($my_file);

$service_group_analyzer = new ServiceGroupAnalysis();
$log_file_name = "./service_group_analysis.v.".$current_time.".json";
$my_file = fopen($log_file_name, "w+");
echo "Service Group\n";
foreach ($projects as $project){
    $log_line =     $service_group_analyzer->print_entry($project);
    echo $log_line;
    fwrite($my_file, $log_line);
}
fclose($my_file);

$sec_analyzer = new SecRulesAnalysis() ;
$log_file_name = "./sec_rules_analysis.v.".$current_time.".json";
$my_file = fopen($log_file_name, "w+");
echo "Security\n";
foreach ($projects as $project){
    $log_line = $sec_analyzer->print_entry($project, "Change");
    echo $log_line;
    fwrite($my_file, $log_line);
}
fclose($my_file);







