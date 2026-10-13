<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by alejandradevegamir
 * Date: 23/1/17 - 11:00
 */
require_once INC_ROOT.'/libs/common/tools/filters.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}


function get_applications(ARRAY $params){
    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($params['project']);

    $filter = mysqli_real_escape_string($projectdb, $params['objfilter']);
    $custom_only = mysqli_real_escape_string($projectdb, $params['custom_only']);
    $hide_shared = mysqli_real_escape_string($projectdb, $params['hide_shared']);
    $start = mysqli_real_escape_string($projectdb, $params['start']);
    $limit = mysqli_real_escape_string($projectdb, $params['limit']);
    $source = mysqli_real_escape_string($projectdb, $params['source']);

    $count2 = 0;
    $id = 1;

    if($hide_shared == "true"){
        $conditions = generate_query_multitable("objects");
    }
    else{
        $conditions = generate_query_multitable("objects_vsyses");
    }

    if(($filter != "none") && ($filter != "0")){

        if(($filter == "74") || ($filter == "75") || ($filter == "111")){
            $params['case_sensitive'] = "1";
        }else{
            $params['case_sensitive'] = "0";
        }

        $params['tools_where_columns_id'] = $filter;
        $params['tools_operator_id'] = "contains";
        $params['search'] = "";
        $params['tools_where_id'] = "9";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";

        setFilter($params['project'], $params);
        executeSQL($params['project'], $params);

    }
    elseif(($filter == "none") || ($filter == "0")){
    }

    list($conditions, $orderby) = generateQueryFilters($params['project'], "applications", "", $conditions, $source);

    list($conditions_default, $orderby_default) = generateQueryFilters($params['project'], "default_applications", "", "", $source);

    if($custom_only == "false"){
        $sql_custom_only = " UNION SELECT '' as parent_app,id as idx, id, '$source' as source, '' as devicegroup, 'all' as vsys, name, category, subcategory, 
        risk, technology, evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,
        category AS tunnel_applications,prone_to_misuse,pervasive_use,category AS file_type_ident,category AS virus_ident,category AS data_ident,
        category AS default_type,category AS value,category AS type,category AS code,category AS timeout,category AS tcp_timeout,category AS udp_timeout,
        category AS spyware_ident, category AS tcp_half_closed_timeout, name AS description, category AS tcp_time_wait_timeout, 
        'default_applications' as table_name, 0 AS merge_as_primary, used FROM default_applications a $conditions_default ";

        $sql_custom_only_count = " UNION SELECT count(*) FROM default_applications a $conditions_default ";
    }
    elseif($custom_only == "true"){$sql_custom_only = ""; $sql_custom_only_count = "";}

    $getAll = $projectdb->query("SELECT count(*) as total FROM applications a $conditions;");
    //$getAll = $projectdb->query("SELECT count(*) as total FROM applications a $conditions $sql_custom_only_count;");
    //echo "SELECT count(*) as total FROM applications a $conditions $sql_custom_only_count;";
    $row = $getAll->fetch_assoc();
    $count = $row['total'];

    if($sql_custom_only_count != ""){
        $getAll2 = $projectdb->query("SELECT count(*) as total FROM default_applications a $conditions_default;");
        $row2 = $getAll2->fetch_assoc();
        $count2 = $row2['total'];
    }

    $count = $count + $count2;

    if ($count > 0) {
        $getLimit = $projectdb->query("SELECT parent_app,id as idx, id, source, devicegroup, vsys, name, category, subcategory, risk, technology, evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,spyware_ident,tcp_half_closed_timeout, description,tcp_time_wait_timeout,'applications' as table_name, merge_as_primary, used 
            FROM applications a $conditions  $sql_custom_only ;");

        //echo "1. SELECT parent_app,id as idx, id, source, devicegroup, vsys, name, category, subcategory, risk, technology, evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,spyware_ident,tcp_half_closed_timeout, description,tcp_time_wait_timeout,'applications' as table_name, merge_as_primary, used
        //    FROM applications a $conditions  $sql_custom_only ;\n";
        if ($getLimit->num_rows > 0){

            while ($data = $getLimit->fetch_object()) {

                //list($data->img, $data->vsys, $name_member, $myip) = getIcon("applications", "applications", $data->idx, "");

                $query = "SELECT tag.name as name FROM tag, tag_relations WHERE tag_relations.member_lid='".$data->idx."' AND tag_relations.table_name='applications' AND tag.id = tag_relations.tag_id";
                $result = $projectdb->query($query);
                $tags = array();
                $signatures = array();
                while($row = $result->fetch_assoc()){
                    $tags[]= $row['name'];
                }
                $data->tag = $tags;

                $getSig = $projectdb->query("SELECT signature FROM applications_signatures WHERE table_name='$data->table_name' AND member_lid='$data->idx';");
                //echo "2. SELECT signature FROM applications_signatures WHERE table_name='$data->table_name' AND member_lid='$data->idx';\n";
                if ($getSig->num_rows > 0) {
                    while($getSigData = $getSig->fetch_object()){
                        $signatures[] = addslashes($getSigData->signature);

                    }
                    $data->xml = $signatures;

                } else {
                    $data->xml = "";
                }

                $data->filter = $filter;
                $data->id = $id;
                $myData[] = $data;
                $id ++;
            }
        }

    }

    if ($count == 0) {
        $myData = array();
    }
    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;
    //print_r($myData);
    return $message;
}

function get_applications_signatures(ARRAY $params){
    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($params['project']);

    $id_app = mysqli_real_escape_string($projectdb, $params['id_app']);
    $table_name = mysqli_real_escape_string($projectdb, $params['table_name']);

    if($id_app == ""){
        $id_app = '0';
    }
    $getSig = $projectdb->query("SELECT id, id as app_sign_id, name AS name_sig, signature FROM applications_signatures WHERE table_name='applications' AND member_lid='$id_app';");
    //echo "SELECT id, id as app_sign_id, name AS name_sig, signature FROM applications_signatures WHERE table_name='applications' AND member_lid='$id_app';";
    //echo "SELECT id, signature FROM applications_signatures WHERE table_name='$table_name' AND member_lid='$id_app';";
    $count = $getSig->num_rows;

    if ($getSig->num_rows > 0) {
        while($getSigData = $getSig->fetch_object()){
            //$getSigData->signature = addslashes($getSigData->signature);
            $getSigData->signature = $getSigData->signature;
            $myData[] = $getSigData;
        }
        //$data->xml = $signatures;


    }



    if ($count == 0) {
        $myData = array();
    }
    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;

    //print_r($myData);
    return $message;
}



function register_applications(ARRAY $data){

    global $projectdb;
    global $app;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $data['able_to_transfer_file'] = (string) (isset($data['able_to_transfer_file']) ? $data['able_to_transfer_file'] : "");
    $data['used_by_malware'] = (string) (isset($data['used_by_malware']) ? $data['used_by_malware'] : "");
    $data['has_known_vulnerability'] = (string) (isset($data['has_known_vulnerability']) ? $data['has_known_vulnerability'] : "");
    $data['pervasive_use'] = (string) (isset($data['pervasive_use']) ? $data['pervasive_use'] : "");
    $data['consume_big_bandwidth'] = (string) (isset($data['consume_big_bandwidth']) ? $data['consume_big_bandwidth'] : "");
    $data['prone_to_misuse'] = (string) (isset($data['prone_to_misuse']) ? $data['prone_to_misuse'] : "");
    $data['tunnel_other_application'] = (string) (isset($data['tunnel_other_application']) ? $data['tunnel_other_application'] : "");
    $data['evasive_behavior'] = (string) (isset($data['evasive_behavior']) ? $data['evasive_behavior'] : "");
    $data['tunnel_applications'] = (string) (isset($data['tunnel_applications']) ? $data['tunnel_applications'] : "");
    $data['file_type_ident'] = (string) (isset($data['file_type_ident']) ? $data['file_type_ident'] : "");
    $data['virus_ident'] = (string) (isset($data['virus_ident']) ? $data['virus_ident'] : "");
    $data['spyware_ident'] = (string) (isset($data['spyware_ident']) ? $data['spyware_ident'] : "");
    $data['data_ident'] = (string) (isset($data['data_ident']) ? $data['data_ident'] : "");
    $data['shared'] = (string) (isset($data['shared']) ? $data['shared'] : "");
    $data['port'] = (string) (isset($data['port']) ? $data['port'] : "");

    $v = $app->applicationsValidation;

    $v->validate([
        'name'                      => [$data['name'], 'required|regexnamewithbar'],
        'parent_app'                => [$data['parent_app'], 'regexnamewithbar'],
        'category'                  => [$data['category'], 'required|regexnamewithbar'],
        'subcategory'               => [$data['subcategory'], 'required|regexnamewithbar'],
        'technology'                => [$data['technology'], 'required|regexnamewithbar'],
        'timeout'                   => [$data['timeout'], 'number'],
        'tcp_timeout'               => [$data['tcp_timeout'], 'number'],
        'udp_timeout'               => [$data['udp_timeout'], 'number'],
        'tcp_half_closed_timeout'   => [$data['tcp_half_closed_timeout'], 'number'],
        'tcp_time_wait_timeout'     => [$data['tcp_time_wait_timeout'], 'number'],
        'ip_protocol_value'         => [$data['ip_protocol_value'], 'number'],
        'icmp_type'                 => [$data['icmp_type'], 'number'],
        'icmp_code'                 => [$data['icmp_code'], 'number'],
        'icmp6_type'                => [$data['icmp6_type'], 'number'],
        'icmp6_code'                => [$data['icmp6_code'], 'number'],
        'risk'                      => [$data['risk'], 'number'],
        'able_to_transfer_file'     => [$data['able_to_transfer_file'], 'alpha'],
        'used_by_malware'           => [$data['used_by_malware'], 'alpha'],
        'has_known_vulnerability'   => [$data['has_known_vulnerability'], 'alpha'],
        'pervasive_use'             => [$data['pervasive_use'], 'alpha'],
        'consume_big_bandwidth'     => [$data['consume_big_bandwidth'], 'alpha'],
        'prone_to_misuse'           => [$data['prone_to_misuse'], 'alpha'],
        'tunnel_other_application'  => [$data['tunnel_other_application'], 'alpha'],
        'evasive_behavior'          => [$data['evasive_behavior'], 'alpha'],
        'tunnel_applications'       => [$data['tunnel_applications'], 'alpha'],
        'file_type_ident'           => [$data['file_type_ident'], 'alpha'],
        'virus_ident'               => [$data['virus_ident'], 'alpha'],
        'spyware_ident'             => [$data['spyware_ident'], 'alpha'],
        'data_ident'                => [$data['data_ident'], 'alpha'],
    ]);

    if (!$v->passes()) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }

    $name = $data['name'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    $category = $data['category'];
    $subcategory = $data['subcategory'];
    $technology = $data['technology'];
    $parent_app = $data['parent_app'];
    $timeout = $data['timeout'];
    $tcp_timeout = $data['tcp_timeout'];
    $udp_timeout = $data['udp_timeout'];
    $tcp_half_closed_timeout = $data['tcp_half_closed_timeout'];
    $tcp_time_wait_timeout = $data['tcp_time_wait_timeout'];

    $ip_protocol_value = $data['ip_protocol_value'];
    $icmp_type = $data['icmp_type'];
    $icmp_code = $data['icmp_code'];
    $icmp6_type = $data['icmp6_type'];
    $icmp6_code = $data['icmp6_code'];
    $risk = $data['risk'];
    $able_to_transfer_file = $data['able_to_transfer_file'];
    $has_known_vulnerability = $data['has_known_vulnerability'];

    $pervasive_use = $data['pervasive_use'];
    $consume_big_bandwidth = $data['consume_big_bandwidth'];
    $prone_to_misuse = $data['prone_to_misuse'];
    $tunnel_other_application = $data['tunnel_other_application'];
    $evasive_behavior = $data['evasive_behavior'];
    $tunnel_applications = $data['tunnel_applications'];
    $file_type_ident = $data['file_type_ident'];
    $virus_ident = $data['virus_ident'];
    $spyware_ident = $data['spyware_ident'];
    $data_ident = $data['data_ident'];
    $used_by_malware = $data['used_by_malware'];

    $names_tags = sanitizeInput($projectdb, $data['names_tags']);
    $description = sanitizeInput($projectdb, $data['description']);
    $shared = sanitizeInput($projectdb, $data['shared']);
    $default_type = sanitizeInput($projectdb, $data['default_type']);

    $type = "";
    $code = "";

    $port = $data['port'];

    $port = json_decode($port);

    if($source <= 0 || $vsys == ''){
        $message = array();
        $message['code'] = false;
        $message['msg'] = "The specified target is not correct";
        return $message;
    }

    if ($shared == "on") {
        $vsys = 'shared';
    }

    $getExistName = $projectdb->query("SELECT id FROM applications WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' "
        . "UNION SELECT id FROM applications_groups_id WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' UNION SELECT id FROM applications_filters WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");

    if ($getExistName->num_rows == 0){

        if ($default_type == "None") {
            $default_type = "None";
            $value = "";
        }
        elseif ($default_type == "port") {
            $default_type = "port";
            $value = "";
        }
        elseif ($default_type == "ip_protocol") {
            $default_type = "ident-by-ip-protocol";
            $value = $ip_protocol_value;
        }
        elseif ($default_type == "icmp_type") {
            $default_type = "ident-by-icmp-type";
            $value = $icmp_type;
            $type = $icmp_type;
            $code = $icmp_code;
        }
        elseif ($default_type == "icmp6_type") {
            $default_type = "ident-by-icmp6-type";
            $value = "";
            $type = $icmp6_type;
            $code = $icmp6_code;
        }

        if ($parent_app == "None") {$parent_app = "";}
        if ($risk == ""){ $risk = "1";}

        $projectdb->query("INSERT INTO applications (source, vsys, category, name, subcategory, parent_app, description, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse, pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, spyware_ident, tcp_half_closed_timeout, tcp_time_wait_timeout)  
                           VALUES ('$source', '$vsys', '$category', '$name', '$subcategory', '$parent_app', '$description', '$risk', '$technology', '$evasive_behavior', '$consume_big_bandwidth', '$used_by_malware', '$able_to_transfer_file', '$has_known_vulnerability', '$tunnel_other_application', '$tunnel_applications', '$prone_to_misuse', '$pervasive_use', '$file_type_ident', '$virus_ident', '$data_ident', '$default_type', '$value', '$type', '$code', '$timeout', '$tcp_timeout', '$udp_timeout', '$spyware_ident', '$tcp_half_closed_timeout', '$tcp_time_wait_timeout');");

        $id = $projectdb->insert_id;

        // Update signatures if they have been added
        $projectdb->query("UPDATE applications_signatures SET member_lid = '$id' WHERE member_lid = '0';");

        if($default_type == "port"){
            if (count($port) > 0) {

                foreach ($port as $port_value) {
                    $projectdb->query("INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$id','applications','$port_value','$vsys','','$source');");
                    //  echo "INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$id','applications','$port_value','$vsys','','$source');\n";
                }
            }
        }

        $names_tags_exp = explode(",", $names_tags);
        $tagPartialQuery = array();
        foreach ($names_tags_exp as $tag_id){
            $tagPartialQuery [] = "('applications', $id, $tag_id)";
        }
        if(count($tagPartialQuery)>0){
            $projectdb->query("DELETE FROM tag_relations WHERE table_name = 'applications' AND member_lid = '$id' ;");
            $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",", $tagPartialQuery);
            $projectdb->query($query);
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = '';
        return $message;
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Applications, Applications Filters or Applications Groups already exists with the same name.';
        return $message;
    }

}


function register_applications_signature(ARRAY $data){

    global $projectdb;
    global $app;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $source = $data['source'];
    $vsys = $data['vsys'];

    $data['name_sig'] = (string) (isset($data['name_sig']) ? $data['name_sig'] : "");
    $data['member_lid'] = (string) (isset($data['member_lid']) ? $data['member_lid'] : "");
    $data['signature'] = (string) (isset($data['signature']) ? $data['signature'] : "");
    $data['app_sign_id'] = (string) (isset($data['app_sign_id']) ? $data['app_sign_id'] : "");

    $v = $app->applicationsValidation;

    $v->validate([
        'name_sig'                      => [$data['name_sig'], 'required|regexnamewithbar']
    ]);

    if (!$v->passes()) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }

    $signature = $data['signature'];
    $name = $data['name_sig'];
    $member_lid = $data['member_lid'];
    $app_sign_id = $data['app_sign_id'];

    $signature = preg_replace('/<entry name="(.*?)">/', '<entry name="'.$name.'">', $signature);
    $signature = addslashes($signature);


    if($app_sign_id != ""){

        $projectdb->query("UPDATE applications_signatures SET name = '$name', signature = '$signature' WHERE id = '$app_sign_id';");

        $message = array();
        $message['code'] = true;
        $message['msg'] = '';
        return $message;
    }
    else{

        $getExistName = $projectdb->query("SELECT id FROM applications_signatures WHERE BINARY name = '$name' AND member_lid = '$member_lid';");

        if ($getExistName->num_rows == 0){

            $projectdb->query("INSERT INTO applications_signatures (source, vsys, member_lid, table_name, name, signature)  
                           VALUES ('$source', '$vsys', '$member_lid', 'applications', '$name', '$signature');");

            $message = array();
            $message['code'] = true;
            $message['msg'] = '';
            return $message;
        }
        else{
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Applications Signatures already exists with the same name.';
            return $message;
        }

    }


}

function update_applications(ARRAY $data){

    global $projectdb;
    global $app;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $data['able_to_transfer_file'] = (string) (isset($data['able_to_transfer_file']) ? $data['able_to_transfer_file'] : "");
    $data['used_by_malware'] = (string) (isset($data['used_by_malware']) ? $data['used_by_malware'] : "");
    $data['has_known_vulnerability'] = (string) (isset($data['has_known_vulnerability']) ? $data['has_known_vulnerability'] : "");
    $data['pervasive_use'] = (string) (isset($data['pervasive_use']) ? $data['pervasive_use'] : "");
    $data['consume_big_bandwidth'] = (string) (isset($data['consume_big_bandwidth']) ? $data['consume_big_bandwidth'] : "");
    $data['prone_to_misuse'] = (string) (isset($data['prone_to_misuse']) ? $data['prone_to_misuse'] : "");
    $data['tunnel_other_application'] = (string) (isset($data['tunnel_other_application']) ? $data['tunnel_other_application'] : "");
    $data['evasive_behavior'] = (string) (isset($data['evasive_behavior']) ? $data['evasive_behavior'] : "");
    $data['tunnel_applications'] = (string) (isset($data['tunnel_applications']) ? $data['tunnel_applications'] : "");
    $data['file_type_ident'] = (string) (isset($data['file_type_ident']) ? $data['file_type_ident'] : "");
    $data['virus_ident'] = (string) (isset($data['virus_ident']) ? $data['virus_ident'] : "");
    $data['spyware_ident'] = (string) (isset($data['spyware_ident']) ? $data['spyware_ident'] : "");
    $data['data_ident'] = (string) (isset($data['data_ident']) ? $data['data_ident'] : "");
    $data['shared'] = (string) (isset($data['shared']) ? $data['shared'] : "");
    $data['port'] = (string) (isset($data['port']) ? $data['port'] : "");

    $v = $app->applicationsValidation;

    $v->validate([
        'name'                      => [$data['name'], 'required|regexnamewithbar'],
        'parent_app'                => [$data['parent_app'], 'regexnamewithbar'],
        'category'                  => [$data['category'], 'required|regexnamewithbar'],
        'subcategory'               => [$data['subcategory'], 'required|regexnamewithbar'],
        'technology'                => [$data['technology'], 'required|regexnamewithbar'],
        'timeout'                   => [$data['timeout'], 'number'],
        'tcp_timeout'               => [$data['tcp_timeout'], 'number'],
        'udp_timeout'               => [$data['udp_timeout'], 'number'],
        'tcp_half_closed_timeout'   => [$data['tcp_half_closed_timeout'], 'number'],
        'tcp_time_wait_timeout'     => [$data['tcp_time_wait_timeout'], 'number'],
        'ip_protocol_value'         => [$data['ip_protocol_value'], 'number'],
        'icmp_type'                 => [$data['icmp_type'], 'number'],
        'icmp_code'                 => [$data['icmp_code'], 'number'],
        'icmp6_type'                => [$data['icmp6_type'], 'number'],
        'icmp6_code'                => [$data['icmp6_code'], 'number'],
        'risk'                      => [$data['risk'], 'number'],
        'able_to_transfer_file'     => [$data['able_to_transfer_file'], 'alpha'],
        'used_by_malware'           => [$data['used_by_malware'], 'alpha'],
        'has_known_vulnerability'   => [$data['has_known_vulnerability'], 'alpha'],
        'pervasive_use'             => [$data['pervasive_use'], 'alpha'],
        'consume_big_bandwidth'     => [$data['consume_big_bandwidth'], 'alpha'],
        'prone_to_misuse'           => [$data['prone_to_misuse'], 'alpha'],
        'tunnel_other_application'  => [$data['tunnel_other_application'], 'alpha'],
        'evasive_behavior'          => [$data['evasive_behavior'], 'alpha'],
        'tunnel_applications'       => [$data['tunnel_applications'], 'alpha'],
        'file_type_ident'           => [$data['file_type_ident'], 'alpha'],
        'virus_ident'               => [$data['virus_ident'], 'alpha'],
        'spyware_ident'             => [$data['spyware_ident'], 'alpha'],
        'data_ident'                => [$data['data_ident'], 'alpha'],
    ]);

    if (!$v->passes()) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }

    $name = $data['name'];
    $id = $data['idx'];
    $source = $data['source'];
    $vsys_selected = $data['vsys'];

    $category = $data['category'];
    $subcategory = $data['subcategory'];
    $technology = $data['technology'];
    $parent_app = $data['parent_app'];
    $timeout = $data['timeout'];
    $tcp_timeout = $data['tcp_timeout'];
    $udp_timeout = $data['udp_timeout'];
    $tcp_half_closed_timeout = $data['tcp_half_closed_timeout'];
    $tcp_time_wait_timeout = $data['tcp_time_wait_timeout'];

    $ip_protocol_value = $data['ip_protocol_value'];
    $icmp_type = $data['icmp_type'];
    $icmp_code = $data['icmp_code'];
    $icmp6_type = $data['icmp6_type'];
    $icmp6_code = $data['icmp6_code'];
    $risk = $data['risk'];
    $able_to_transfer_file = $data['able_to_transfer_file'];
    $has_known_vulnerability = $data['has_known_vulnerability'];

    $pervasive_use = $data['pervasive_use'];
    $consume_big_bandwidth = $data['consume_big_bandwidth'];
    $prone_to_misuse = $data['prone_to_misuse'];
    $tunnel_other_application = $data['tunnel_other_application'];
    $evasive_behavior = $data['evasive_behavior'];
    $tunnel_applications = $data['tunnel_applications'];
    $file_type_ident = $data['file_type_ident'];
    $virus_ident = $data['virus_ident'];
    $spyware_ident = $data['spyware_ident'];
    $data_ident = $data['data_ident'];
    $used_by_malware = $data['used_by_malware'];
    $port = $data['port'];

    $type = "";
    $code = "";

    $port = json_decode($port);

    $names_tags = sanitizeInput($projectdb, $data['names_tags']);
    $description = sanitizeInput($projectdb, $data['description']);
    $shared = sanitizeInput($projectdb, $data['shared']);
    $default_type = sanitizeInput($projectdb, $data['default_type']);
    //$xml = addslashes($data['xml']);

    $entryInfo = $projectdb->query("SELECT vsys, source FROM applications WHERE id='$id'");
    if($entryInfo->num_rows>0){
        $queryData = $entryInfo->fetch_assoc();
        $vsys = $queryData['vsys'];
        $source = $queryData['source'];
    }

    $getExistName = $projectdb->query("SELECT id FROM applications WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' "
        . "UNION SELECT id FROM applications_groups_id WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' UNION SELECT id FROM applications_filters WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");

    if ($getExistName->num_rows == 0){

        if ($default_type == "None") {
            $default_type = "None";
            $value = "";
        }
        elseif ($default_type == "port") {
            $default_type = "port";
            $value = "";

        }
        elseif ($default_type == "ip_protocol") {
            $default_type = "ident-by-ip-protocol";
            $value = $ip_protocol_value;
        }
        elseif ($default_type == "icmp_type") {
            $default_type = "ident-by-icmp-type";
            $value = $icmp_type;
            $type = $icmp_type;
            $code = $icmp_code;
        }
        elseif ($default_type == "icmp6_type") {
            $default_type = "ident-by-icmp6-type";
            $value = "";
            $type = $icmp6_type;
            $code = $icmp6_code;
        }

        if ($parent_app == "None") {$parent_app = "";}
        if ($risk == ""){ $risk = "1";}

        $projectdb->query("UPDATE applications SET name='$name',description='$description',category='$category',subcategory='$subcategory',parent_app='$parent_app',risk='$risk',technology='$technology',evasive_behavior='$evasive_behavior',consume_big_bandwidth='$consume_big_bandwidth',used_by_malware='$used_by_malware',able_to_transfer_file='$able_to_transfer_file',has_known_vulnerability='$has_known_vulnerability',tunnel_other_application='$tunnel_other_application',tunnel_applications='$tunnel_applications',prone_to_misuse='$prone_to_misuse',pervasive_use='$pervasive_use',file_type_ident='$file_type_ident',virus_ident='$virus_ident',data_ident='$data_ident',default_type='$default_type',value='$value',type='$type',code='$code',timeout='$timeout',tcp_timeout='$tcp_timeout',udp_timeout='$udp_timeout',spyware_ident='$spyware_ident',tcp_half_closed_timeout='$tcp_half_closed_timeout',tcp_time_wait_timeout='$tcp_time_wait_timeout' WHERE id='$id';");

        if ($shared == "on") {
            $projectdb->query("UPDATE applications SET source = '$source', vsys = 'shared' WHERE id='$id';");
        }
        else{
            if($vsys_selected != "all"){
                $projectdb->query("UPDATE applications SET source = '$source', vsys = '$vsys_selected' WHERE id='$id';");
            }
        }

        if($default_type == "port"){
            if (count($port) > 0) {

                $projectdb->query("DELETE FROM applications_ports WHERE member_lid = '$id';");

                foreach ($port as $port_value) {
                    $projectdb->query("INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$id','applications','$port_value','$vsys','','$source');");
                }
            }
        }

        $names_tags_exp = explode(",", $names_tags);
        $tagPartialQuery = array();
        foreach ($names_tags_exp as $tag_id){
            $tagPartialQuery [] = "('applications', $id, $tag_id)";
        }
        if(count($tagPartialQuery)>0){
            $projectdb->query("DELETE FROM tag_relations WHERE table_name = 'applications' AND member_lid = '$id' ;");

            $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",", $tagPartialQuery);
            $projectdb->query($query);
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = '';
        return $message;
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Applications, Applications Filters or Applications Groups already exists with the same name.';
        return $message;
    }

}


function delete_applications(ARRAY $data){

    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $ids = mysqli_real_escape_string($projectdb, $data['ids']);


    $remove_references = $data['remove_references'];


    $used_in_groups = "no";
    $array_name_on_groups = array();
    $array_ids_on_groups = array();

    $getUsed = $projectdb->query("SELECT id, name, used FROM applications WHERE id IN (".$ids.") AND used = '0' ;");
    if ($getUsed->num_rows > 0) {
        while($getData = $getUsed->fetch_assoc()){

            $id = $getData['id'];
            $name = $getData['name'];

            $is_used = check_used_objects_in_groups($projectdb, $id, "applications", "applications_groups");

            if($is_used == 0){
                $projectdb->query("DELETE FROM applications WHERE id = '$id' AND dummy = 0;");
                $projectdb->query("DELETE FROM applications_ports WHERE member_lid = '$id' ;");
                $projectdb->query("DELETE FROM applications_signatures WHERE member_lid = '$id' ;");
            }
            else{
                // is used on group
                $used_in_groups = "yes";
                $array_name_on_groups[] = $name;
                $array_ids_on_groups[] = $id;
            }
        }
    }

    if($used_in_groups == "yes"){
        if($remove_references == "no"){
            $message = array();
            $message['code'] = false;
            $message['msg'] = "These Applications '".implode(", ",$array_name_on_groups)."' used on Applications Groups. Are you sure you want to Delete?";
            return $message;
        }
        elseif($remove_references == "yes"){
            $projectdb->query("DELETE FROM applications WHERE id IN (".implode(",", $array_ids_on_groups).") AND dummy = 0;");
            $projectdb->query("DELETE FROM applications_ports WHERE member_lid IN (".implode(",", $array_ids_on_groups).") ;");
            $projectdb->query("DELETE FROM applications_signatures WHERE member_lid IN (".implode(",", $array_ids_on_groups).") ;");

            $projectdb->query("DELETE FROM applications_groups WHERE (member_lid IN (".implode(",", $array_ids_on_groups).") AND table_name = 'applications');");
        }
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';

    return $message;

}

function delete_applications_signatures(ARRAY $data)
{

    $project = $data['project'];

    take_snapshot_last($project);

    if (!accessControl("any", ['projectRole.' . $project . '.update'])) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $ids = mysqli_real_escape_string($projectdb, $data['ids']);

    if($ids != ""){
        $projectdb->query("DELETE FROM applications_signatures WHERE id IN ($ids) ;");
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';

    return $message;

}