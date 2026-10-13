<?php
require_once '/var/www/html/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';
require_once INC_ROOT.'/libs/common/tools/tools-rules.php';

error_reporting(E_ERROR | E_PARSE);

$projects = [
    "PROJECT_NAME",
];

foreach ($projects as $project){
    $projectdb = selectDatabase($project);

    $query = "SELECT vsys 
                FROM devicegroups, device_mapping
                WHERE devicegroups.device_mapping_id = device_mapping.id ";
    $results = $projectdb->query($query);

    $current_time = date("ymd-G.i.s");
    $log_file_name = "./".$project."-merge.v.".$current_time.".json";
    if($results->num_rows>0){
        $my_file = fopen($log_file_name, "w+");
        while($data = $results->fetch_assoc()){
            $dg = $data['vsys'];
            $mergeable = [];

            $fields = ['duplicated','service', 'source', 'destination', 'application'];
            foreach ($fields as $field){
                $analysis_results = count_mergeable_cases($project, $dg, $field);
                if($analysis_results['count']>0) {
                    $mergeable[$field] = [
                        'cases' => $analysis_results['count'],
                        'max' => $analysis_results['max'],
                        'min' => $analysis_results['min'],
                        'avg' => $analysis_results['avg'],
                        'std' => $analysis_results['std']
                    ];
                }else{
                    $mergeable[$field] = [
                        'cases' => $analysis_results['count'],
                        'max' => '0',
                        'min' => '0',
                        'avg' => '0',
                        'std' => '0'
                    ];
                }

            }

            $total_rules = get_count_rules($projectdb, $dg);

            $line = print_entry($project, $dg, $total_rules, $mergeable);
            echo $line;
            fwrite($my_file, $line);
        }
        fclose($my_file);
    }
}


exit(0);

function get_count_rules(mysqli $projectdb, string $dg):int{
    $query = "SELECT count(*) as amount FROM security_rules where vsys = '$dg'";

    $results = $projectdb->query($query);
    if($results->num_rows>0){
        $data = $results->fetch_assoc();
        return $data['amount'];
    }
    return 0;
}

function stats_standard_deviation(array $a, $sample = false) {
    $n = count($a);
    if ($n === 0) {
        trigger_error("The array has zero elements", E_USER_WARNING);
        return false;
    }
    if ($sample && $n === 1) {
        trigger_error("The array has only 1 element", E_USER_WARNING);
        return false;
    }
    $mean = array_sum($a) / $n;
    $carry = 0.0;
    foreach ($a as $val) {
        $d = ((double) $val) - $mean;
        $carry += $d * $d;
    };
    if ($sample) {
        --$n;
    }
    return sqrt($carry / $n);
}

function count_mergeable_cases(string $project, string $dg, string $field):array {

    $params = [
        "project"=> $project,
        "mode"=> "get_consolidation_rules",
        "vsys"=> $dg,
        "source"=> 1,
        "check_from_sec"=> true,
        "check_to_sec"=> true,
        "check_source_sec"=> true,
        "check_dst_sec"=> true,
        "check_srv_sec"=> true,
        "check_app_sec"=> true,
        "check_name_sec"=> false,
        "check_action_sec"=> true,
        "check_target_sec"=> true,
        "check_from_nat"=> "",
        "check_to_nat"=> "",
        "check_source_nat"=> "",
        "check_dst_nat"=> "",
        "check_srv_nat"=> "",
        "check_name_nat"=> "",
        "check_target_nat"=> "",
        "check_from_app"=> "",
        "check_to_app"=> "",
        "check_source_app"=> "",
        "check_dst_app"=> "",
        "check_app_app"=> "",
        "check_protocol_app"=> "",
        "check_port_app"=> "",
        "check_name_app"=> "",
        "check_target_app"=> "",
        "table_name"=> "security_rules"
    ];

    switch ($field){
        case 'none':
        case 'duplicated':
            $params['']=false;
            break;
        case 'destination':
            $params["check_dst_sec"]= false;
            break;
        case 'source':
            $params["check_source_sec"]= false;
            break;
        case 'application':
            $params["check_app_sec"]= false;
            break;
        case 'from':
            $params["check_from_sec"]= false;
            break;
        case 'to':
            $params["check_to_sec"]= false;
            break;
        case 'service':
        default:
            $params['check_srv_sec']=false;
            break;
    }
    register_tools($params);

    $get_params = [
        "project"=>$project,
        "action"=>"get",
        "mode"=>"get_consolidation",
        "table_name"=>"security_rules"
    ];
    $message = list_tools($get_params);

    $rules_in_case = [];
    foreach ($message['msg'] as $case){
        $rules_in_case[] = count(explode(",",$case->rules_lid));
    }

    $average = array_sum($rules_in_case) / count($rules_in_case);
    $standardDeviation = stats_standard_deviation($rules_in_case);
    $min = min($rules_in_case);
    $max = max($rules_in_case);

    return [
        'count'=> $message['count'],
        'max' => $max,
        'min' => $min,
        'avg' => $average,
        'std' => $standardDeviation
    ];
}

function print_entry(string $project, string $dg, int $total_rules, array $cases):string{
    return json_encode([
        'Project'=> $project,
        'DG'=> $dg,
        'total' => $total_rules,

        'duplicated_cases' => $cases['duplicated']['cases'],
        'duplicated_max_rules_in_cases' => $cases['duplicated']['max'],
        'duplicated_min_rules_in_cases' => $cases['duplicated']['min'],
        'duplicated_avg_rules_in_cases' => $cases['duplicated']['avg'],
        'duplicated_std_rules_in_cases' => $cases['duplicated']['std'],


        'dist_source_cases' => $cases['source']['cases'],
        'dist_source_max_rules_in_cases' => $cases['source']['max'],
        'dist_source_min_rules_in_cases' => $cases['source']['min'],
        'dist_source_avg_rules_in_cases' => $cases['source']['avg'],
        'dist_source_std_rules_in_cases' => $cases['source']['std'],

        'dist_destination_cases' => $cases['destination']['cases'],
        'dist_destination_max_rules_in_cases' => $cases['destination']['max'],
        'dist_destination_min_rules_in_cases' => $cases['destination']['min'],
        'dist_destination_avg_rules_in_cases' => $cases['destination']['avg'],
        'dist_destination_std_rules_in_cases' => $cases['destination']['std'],

        'dist_service_cases' => $cases['service']['cases'],
        'dist_service_max_rules_in_cases' => $cases['service']['max'],
        'dist_service_min_rules_in_cases' => $cases['service']['min'],
        'dist_service_avg_rules_in_cases' => $cases['service']['avg'],
        'dist_service_std_rules_in_cases' => $cases['service']['std'],

        'dist_application_cases' => $cases['application']['cases'],
        'dist_application_max_rules_in_cases' => $cases['application']['max'],
        'dist_application_min_rules_in_cases' => $cases['application']['min'],
        'dist_application_avg_rules_in_cases' => $cases['application']['avg'],
        'dist_application_std_rules_in_cases' => $cases['application']['std']
    ]).PHP_EOL;
}

function list_tools(ARRAY $params){

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view', 'project.create'], 1)){
        $message =[
            'code'  => false,
            'msg'   => 'Your account does not have the rights to view this project contents'
        ];
        return $message;
    }
    switch ($params['mode']){

        case 'get_consolidation':
            $message = getConsolidationHash($project, $params);
            break;

        default:
            $message = [
                'code'  => true,
                'count' => 0,
                'msg'   => ''
            ];
            break;
    }

    return $message;

}

function register_tools(ARRAY $params){

    $project = $params['project'];
    $message = "";

    if(!accessControl("any", ['projectRole.'.$project.'.update'], 1)){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }
//    take_snapshot_last($project);
    switch ($params['mode']){

        case 'get_consolidation_rules':
            getConsolidationRules($project, $params);
            $message = [];
            break;

        case 'set_merge_security_rules':
            $message = setMergeSecurityRules($project, $params,'yes');
            break;

        default:
            break;
    }

    return $message;


}