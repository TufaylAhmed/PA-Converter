<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 15/7/16 - 14:44
 */
require_once INC_ROOT.'/libs/common/address/AddressGroupsQueryBuilder.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

use PaloAltoNetworks\Address\AddressGroupsQueryBuilder;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}


function get_address(ARRAY $params){
    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($params['project']);
//    $conditions = generate_query_multitable("objects_vsyses");

    $myData = array();

    $filter = mysqli_real_escape_string($projectdb, $params['objfilter']);
    $hide_shared = mysqli_real_escape_string($projectdb, $params['hide_shared']);
    $start = mysqli_real_escape_string($projectdb, $params['start']);
    $limit = mysqli_real_escape_string($projectdb, $params['limit']);
    $source = mysqli_real_escape_string($projectdb, $params['source']);

    if($hide_shared == "true"){
//        if (preg_match("/WHERE/", $conditions)) {
//            $conditions .= " AND a.vsys != 'shared' ";
            $conditions = generate_query_multitable("objects");
    }
    else{
//            $conditions .= " WHERE a.vsys != 'shared' ";
            $conditions = generate_query_multitable("objects_vsyses");
//        }
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
        $params['tools_where_id'] = "5";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";


        //checkExistFilterAndRemove($params['project'], 'address');
        setFilter($params['project'], $params);
        executeSQL($params['project'], $params);

    }

    list($conditions, $orderby) = generateQueryFilters($params['project'], "address", "", $conditions, $source);

    $getAll = $projectdb->query("SELECT count(*) as total FROM address a $conditions;");
    $row = $getAll->fetch_assoc();
    $count = $row['total'];
    if ($count > 0) {
        $getLimit = $projectdb->query(
            "SELECT *, 
                    if (type=\"ip-netmask\",
		              INET_ATON(ipaddress),
		                      if (type=\"ip-range\",INET_ATON(SUBSTRING_INDEX(ipaddress, '-', 1)),ipaddress)
                    ) as ipaddressLong
                    FROM address a $conditions $orderby LIMIT $start, $limit;");

    }

    if (isset($getLimit)) {
        if ($getAll->num_rows > 0){

            while ($data = $getLimit->fetch_assoc()) {
                $objectsInMemory['address'][$data['id']] = $data;
                list($data['img'], $data['vsys'], $name_member, $myip) = getIcon("address", "address", $data['id'], "", $objectsInMemory);

                $query = "SELECT tag.name as name FROM tag, tag_relations WHERE tag_relations.member_lid='".$data['id']."' AND tag_relations.table_name='address' AND tag.id = tag_relations.tag_id";
                $result = $projectdb->query($query);
                $tags = array();
                if ($result->num_rows > 0) {
                    while($row = $result->fetch_assoc()){
                        $tags[] = $row['name'];
                    }
                }
                $data['tag'] = $tags;
                $data['filter'] = $filter;
                $myData[] = $data;
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


function get_addressStatic(STRING $projectName, STRING $scope){
    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($projectName);

    $conditions = generate_query("objects");

    if (preg_match("/ WHERE /", $conditions)) {
        $query = $conditions . " AND type='ip-netmask' OR type='ip-range' AND dummy=0 ";
    } else {
        $query = " WHERE type='ip-netmask' OR type='ip-range' AND dummy=0 ";
    }
    $getAll = $projectdb->query(
        "SELECT id as idx,name_ext,name,used,id,checkit,devicegroup,vsys,type,ipaddress,
                  if (type=\"ip-netmask\",
		            INET_ATON(ipaddress),
		                      if (type=\"ip-range\",INET_ATON(SUBSTRING_INDEX(ipaddress, '-', 1)),ipaddress)
                  ) as ipaddressLong, 
                  cidr,description,fqdn,v4,v6,vtype,source,tag,'address' as table_name  FROM address $query;");
    $count = $getAll->num_rows;
    $getLimit = $projectdb->query(
        "SELECT id as idx,name_ext,name,used,id,checkit,devicegroup,vsys,type,ipaddress,
                  if (type=\"ip-netmask\",
		            INET_ATON(ipaddress),
		                      if (type=\"ip-range\",INET_ATON(SUBSTRING_INDEX(ipaddress, '-', 1)),ipaddress)
                  ) as ipaddressLong,  
                  cidr,description,fqdn,v4,v6,vtype,source,tag,'address' as table_name,  (CASE type WHEN 'fqdn' THEN 'fa fa-book' WHEN 'ip-range' THEN 'fa fa-sitemap' ELSE 'fa fa-desktop' END) AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM address $query ORDER BY name ASC;");
    $x = 0;
    while ($data = $getLimit->fetch_assoc()) {
        $data['id'] = $x++;
        $myData[] = $data;
    }
    if ($count == 0) {
        $myData = "";
    }
    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;
    return $message;
}


function get_addressAll(STRING $projectName, STRING $scope, $params){
    global $projectdb;

    $vsysesMap = array();

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($projectName);

    $conditions = generate_query_multitable("objects_vsyses");
    $conditions2="";
    $source = $params["source"];
    $params_query=isset($params["query"])?$params["query"]:'';
    if ($params_query!=""){
        if (preg_match("/WHERE/", $conditions)) {
            $conditions = $conditions . " AND name LIKE '%$params_query%' ";
        } else {
            $conditions = $conditions . " WHERE name LIKE '%$params_query%' ";
        }
        $conditions2 = " WHERE name LIKE '%$params_query%' ";
    }

    $query_all_addresses =
        "SELECT 'shared' as vsys, $source AS source, '0' as disable_override, id as idx, name, name_ext, id, 'regions.png' AS type,           'default_regions' AS table_name,   'fa fa-globe' AS icon, '#235585' AS color                                                                                                                            FROM default_regions $conditions2 ".
        "UNION SELECT vsys, source,             disable_override, id as idx, name, name_ext, id, 'regions.png' AS type,           'regions' AS table_name,           'fa fa-globe' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color                                                                                           FROM regions  a $conditions ".
        "UNION SELECT vsys, source,             disable_override, id as idx, name, name_ext, id, 'external_list.png' AS type,     'external_list' AS table_name,     'fa fa-list' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color                                                                                            FROM external_list  a $conditions ".
        "UNION SELECT vsys, source,             disable_override, id as idx, name, name_ext, id, 'address.gif' AS type,           'address' AS table_name,           (CASE type WHEN 'fqdn' THEN 'fa fa-book' WHEN 'ip-range' THEN 'fa fa-sitemap' ELSE 'fa fa-desktop' END) AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM address  a $conditions ".
        "UNION SELECT vsys, source,             disable_override, id as idx, name, name_ext, id, 'address_groups_id.gif' AS type, 'address_groups_id' AS table_name, if (type = 'static', 'fa fa-object-ungroup', 'fa fa-object-group') AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color                                      FROM address_groups_id a $conditions ;";

    //echo $query_all_addresses;
    $getLimit = $projectdb->query($query_all_addresses);
    $count = $getLimit->num_rows;
    $x = 0;
    //We want to list only the actionable objects. Therefore only the final value after overrides
    if($scope == 'override') {
        while ($data = $getLimit->fetch_assoc()) {
            $data['id'] = $x++;
            $myData[$data['name']][] = $data;
        }

        $myDataOverriden = array();
        foreach ($myData as $entries) {
            if (count($entries) == 1) {
                $myDataOverriden[] = $entries[0];
            }
            else{
                //Get the vsyses and flag if we get any with override
                $highestPrecendencelevel=INF;
                $precedenceVsys = '';
                $deepestVsys = '';
                $deepestLevel = 0;

                foreach ($entries as &$entry){
                    if(!isset($vsysesMap[$entry['vsys']])){
                        $vsysesMap[$entry['vsys']]=getVsyses($projectdb, $entry['vsys'], $entry['source']);
                    }
                    $entry['vsyses'] = $vsysesMap[$entry['vsys']];
                    $entry['level'] = count($entry['vsyses']);
                    if($entry['disable_override']=='yes'){
                        if($entry['level']<$highestPrecendencelevel){
                            $highestPrecendencelevel = $entry['level'];
                            $precedenceVsys = $entry['vsys'];
                        }
                    }

                    if($entry['level'] > $deepestLevel){
                        $deepestLevel = $entry['level'];
                        $deepestVsys = $entry['vsys'];
                    }

                }


                //Identify if we need to take the deepest vsys (not overrides forbiden) or the highest vsys in which there is a disable_override object
                $target_vsys = ($precedenceVsys != '')?$precedenceVsys:$deepestVsys;

                //Take all the object types found in that vsys level
                $candidate = array();
                foreach ($entries as $entryMember){
                    if($entryMember['vsys']==$target_vsys){
                        $candidate[$entryMember['table_name']] = $entryMember;
                    }
                }

                //Select the object based on the object type priority
                if(isset($candidate['default_regions'])){
                    $myDataOverriden[] = $candidate['default_regions'];
                    continue;
                }
                elseif(isset($candidate['regions'])){
                    $myDataOverriden[] = $candidate['regions'];
                    continue;
                }
                elseif(isset($candidate['external_list'])){
                    $myDataOverriden[] = $candidate['external_list'];
                    continue;
                }
                elseif(isset($candidate['address_groups_id'])){
                    $myDataOverriden[] = $candidate['address_groups_id'];
                    continue;
                }
                elseif(isset($candidate['address'])){
                    $myDataOverriden[] = $candidate['address'];
                    continue;
                }
            }
        }
    }

    //We want to list all the elements, including overriden
    else{
        while ($data = $getLimit->fetch_assoc()) {
            $data['id'] = $x++;
            $myDataOverriden[] = $data;
        }
    }

    $message = [
        'code'  => true,
        'count' => $count,
        'msg'   => $myDataOverriden,
        ];
    return $message;
}

function get_addressGroupsOverride(STRING $projectName, STRING $scope, $params){
    global $projectdb;

    $vsysesMap = array();

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($projectName);

    $conditions = generate_query_multitable("objects_vsyses");
    $conditions2="";
    $source = $params["source"];
    $params_query=$params["query"];
    if ($params_query!=""){
        if (preg_match("/WHERE/", $conditions)) {
            $conditions = $conditions . " AND name LIKE '%$params_query%' ";
        } else {
            $conditions = $conditions . " WHERE name LIKE '%$params_query%' ";
        }
        $conditions2 = " WHERE name LIKE '%$params_query%' ";
    }

    $query_all_addresses =
        "SELECT vsys, source,             disable_override, id as idx, name, name_ext, id, 'address.gif' AS type,           'address' AS table_name,           (CASE type WHEN 'fqdn' THEN 'fa fa-book' WHEN 'ip-range' THEN 'fa fa-sitemap' ELSE 'fa fa-desktop' END) AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM address  a $conditions ".
        "UNION SELECT vsys, source,             disable_override, id as idx, name, name_ext, id, 'address_groups_id.gif' AS type, 'address_groups_id' AS table_name, if (type = 'static', 'fa fa-object-ungroup', 'fa fa-object-group') AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color                                      FROM address_groups_id a $conditions ;";

    //echo $query_all_addresses;
    $getLimit = $projectdb->query($query_all_addresses);
    $count = $getLimit->num_rows;
    $x = 0;
    //We want to list only the actionable objects. Therefore only the final value after overrides
    if($scope == 'override') {
        while ($data = $getLimit->fetch_assoc()) {
            $data['id'] = $x++;
            $myData[$data['name']][] = $data;
        }

        $myDataOverriden = array();
        foreach ($myData as $entries) {
            if (count($entries) == 1) {
                $myDataOverriden[] = $entries[0];
            }
            else{
                //Get the vsyses and flag if we get any with override
                $highestPrecendencelevel=INF;
                $precedenceVsys = '';
                $deepestVsys = '';
                $deepestLevel = 0;

                foreach ($entries as &$entry){
                    if(!isset($vsysesMap[$entry['vsys']])){
                        $vsysesMap[$entry['vsys']]=getVsyses($projectdb, $entry['vsys'], $entry['source']);
                    }
                    $entry['vsyses'] = $vsysesMap[$entry['vsys']];
                    $entry['level'] = count($entry['vsyses']);
                    if($entry['disable_override']=='yes'){
                        if($entry['level']<$highestPrecendencelevel){
                            $highestPrecendencelevel = $entry['level'];
                            $precedenceVsys = $entry['vsys'];
                        }
                    }

                    if($entry['level'] > $deepestLevel){
                        $deepestLevel = $entry['level'];
                        $deepestVsys = $entry['vsys'];
                    }

                }


                //Identify if we need to take the deepest vsys (not overrides forbiden) or the highest vsys in which there is a disable_override object
                $target_vsys = ($precedenceVsys != '')?$precedenceVsys:$deepestVsys;

                //Take all the object types found in that vsys level
                $candidate = array();
                foreach ($entries as $entryMember){
                    if($entryMember['vsys']==$target_vsys){
                        $candidate[$entryMember['table_name']] = $entryMember;
                    }
                }

                //Select the object based on the object type priority
                if(isset($candidate['default_regions'])){
                    $myDataOverriden[] = $candidate['default_regions'];
                    continue;
                }
                elseif(isset($candidate['regions'])){
                    $myDataOverriden[] = $candidate['regions'];
                    continue;
                }
                elseif(isset($candidate['external_list'])){
                    $myDataOverriden[] = $candidate['external_list'];
                    continue;
                }
                elseif(isset($candidate['address_groups_id'])){
                    $myDataOverriden[] = $candidate['address_groups_id'];
                    continue;
                }
                elseif(isset($candidate['address'])){
                    $myDataOverriden[] = $candidate['address'];
                    continue;
                }
            }
        }
    }

    //We want to list all the elements, including overriden
    else{
        while ($data = $getLimit->fetch_assoc()) {
            $data['id'] = $x++;
            $myDataOverriden[] = $data;
        }
    }

    $message = [
        'code'  => true,
        'count' => $count,
        'msg'   => $myDataOverriden,];
    return $message;
}

function get_addressNotGroups(STRING $projectName, STRING $scope){

}


function get_addressAndGroupsAndExternal(STRING $projectName, STRING $scope){
    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($projectName);

    $conditions = generate_query_multitable("objects");

    $getLimit = $projectdb->query("SELECT id as idx, name, name_ext, id, 'external_list.png' as type,'external_list' as table_name, 'fa fa-list' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM external_list a $conditions ".
                                  "UNION SELECT id as idx, name, name_ext, id,'address.gif' as type,'address' as table_name, (CASE type WHEN 'fqdn' THEN 'fa fa-book' WHEN 'ip-range' THEN 'fa fa-sitemap' ELSE 'fa fa-desktop' END) AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM address a $conditions ".
                                  "UNION SELECT id as idx, name, name_ext, id, 'address_groups_id.gif' as type,'address_groups_id' as table_name, if (type = 'static', 'fa fa-object-ungroup', 'fa fa-object-group') AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM address_groups_id a $conditions;");

    $count = $getLimit->num_rows;
    $x = 0;
    while ($data = $getLimit->fetch_assoc()) {
        $data['id'] = $x++;
        $myData[] = $data;
    }
    if ($count == 0) {
        $myData = "";
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;
    return $message;
}


function get_addressAndGroupsOnly(STRING $projectName, STRING $scope){
    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);
    $projectdb = selectDatabase($projectName);

    $conditions = generate_query_multitable("objects");

    $getLimit = $projectdb->query("SELECT id as idx,name,id, type, vtype, vsys, 'address' as table_name, (CASE type WHEN 'fqdn' THEN 'fa fa-book' WHEN 'ip-range' THEN 'fa fa-sitemap' ELSE 'fa fa-desktop' END) AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM address a $conditions ".
                                  "UNION SELECT id as idx, name, id, type, type as vtype, vsys, 'address_groups_id' as table_name, if (type = 'static', 'fa fa-object-ungroup', 'fa fa-object-group') AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM address_groups_id a $conditions;");

    $count = $getLimit->num_rows;
    $x = 0;
    while ($data = $getLimit->fetch_assoc()) {
        //$data->img = getObjectImage($data->vsys, $data->type, $data->table_name, $data->vtype);
        $data['id'] = $x++;
        $myData[] = $data;
    }
    if ($count == 0) {
        $myData = "";
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;
    return $message;
}


function register_address(ARRAY $data){

    global $projectdb;
    global $app;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $project = $data['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $v = $app->addressValidation;

    $v->validate([
        'name' => [$data['name'], 'required|regexnamewithbar'],
        'type' => [$data['type'], 'required|ipType'],
        'ipaddress' => [$data['ipaddress'], "required|regexipaddressv4v6(".$data['type'].")"],
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
    $type = $data['type'];
    $ipaddress = $data['ipaddress'];
    $names_tags = sanitizeInput($projectdb, $data['names_tags']);
    $description = sanitizeInput($projectdb, $data['description']);

    switch($type){
        case 'ip-range':
            $fqdn = '';
            $cidr='32';
            $ip = explode('-',$ipaddress);
            $ipVersion = ip_version($ip[0]);
            $ipVersion2 = ip_version($ip[1]);
            if($ipVersion != $ipVersion2 || $ipVersion == 'noip'){
                $v4 = 0;
                $v6 = 0;
                $invalid = 1;
            }
            else {
                switch ($ipVersion) {
                    case 'v4':
                        $v4 = 1;
                        $v6 = 0;
                        $invalid = 0;
                        break;
                    case 'v6':
                        $v4 = 1;
                        $v6 = 0;
                        $invalid = 0;
                        break;
                    default:
                        $v4 = 0;
                        $v6 = 0;
                        $invalid = 1;
                }
            }

            break;

        case 'fqdn':
            $fqdn = $ipaddress;
            $cidr='';
            $v4=0;
            $v6=0;
            $invalid=0;
            break;

        case 'dynamic':
            $fqdn = $ipaddress;
            //$cidr = mysqli_real_escape_string($projectdb, $data['cidr']);
            $cidr = sanitizeInput($projectdb, $data['cidr']);
            $v4=0;
            $v6=0;
            $invalid=0;
            break;

        case 'ip-wildcard':
            $fqdn = '';
            $cidr = '';
            $v4 = 0;
            $v6 = 0;
            $invalid = 0;
            break;

        case 'ip-netmask':

        default:
            $ip = explode('-',$ipaddress);
            $ipVersion = ip_version($ip[0]);
            switch($ipVersion){
                case 'v4':
                    $v4=1;
                    $v6=0;
                    $invalid=0;
                    break;
                case 'v6':
                    $v4=1;
                    $v6=0;
                    $invalid=0;
                    break;
                default:
                    $v4=0;
                    $v6=0;
                    $invalid=1;
            }
            $fqdn = '';
            //$cidr = mysqli_real_escape_string($projectdb, $data['cidr']);
            $cidr = sanitizeInput($projectdb, $data['cidr']);
            break;
    }

    $modified = 1;
    $dummy = 0;
    $vtype = '';
    //$devicegroup = 'default';

    if($source <=0 || $vsys==''){
        $message = array();
        $message['code'] = false;
        $message['msg'] = "The specified target is not correct";
        return $message;
    }
    else{

        $getExistName = $projectdb->query("SELECT id FROM address WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' "
            . "UNION SELECT id FROM address_groups_id WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");
        if ($getExistName->num_rows == 0) {
            $invalid_name = 0;
            $query = "INSERT INTO address (name_ext, name, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, tag, source, invalid, modified, dummy) 
                           VALUES ('$name', '$name', 'default', '$vsys', '$type', '$ipaddress', '$cidr', '$description', '$fqdn', '$v4', '$v6', '$vtype', '$names_tags', '$source', '$invalid', '$modified', '$dummy')";
            $projectdb->query($query);
//            echo "$query";
            $id = $projectdb->insert_id;

            $query = "DELETE FROM tag_relations WHERE table_name='address' AND member_lid='$id' ";
            $projectdb->query($query);

            $names_tags_exp = explode(",", $names_tags);

            // Type ip-wildcard don't have tags.
            if($type != "ip-wildcard"){
                foreach ($names_tags_exp as $tag){
                    $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('address', $id, $tag)";
                    $projectdb->query($query);
                }
            }

        }
        else{
            $invalid_name = 1;
        }

    }

    $message = array();
    $message['code'] = true;
    if($invalid == 1) {
        $message['msg'] = 'The specified address seems to be invalid';
    }
    elseif($invalid_name == 1){
        $message['code'] = false;
        $message['msg'] = 'Address or Address Groups already exists with the same name.';
    }
    else{
        $message['msg'] = '';
    }

    return $message;
}


function update_address(ARRAY $data){

    global $projectdb;
    global $app;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $project = $data['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    take_snapshot_last($project);

    $projectdb = selectDatabase($project);

    $v = $app->addressValidation;

    $v->validate([
        'id'   => [$data['id'], "required|number"],
        'name' => [$data['name'], "required|regexnamewithbar"],
        'type' => [$data['type'], 'required|ipType'],
        'ipaddress' => [$data['ipaddress'], "required|regexipaddressv4v6(".$data['type'].")"],
        //'ipaddress' => [$data['ipaddress'], "required|regexipaddressv4v6"],
    ]);

    if (!$v->passes()) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }

    $id = $data['id'];
    $name = $data['name'];
    $source = $data['source'];
    $vsys = $data['vsys'];
    $type = $data['type'];
    $ip = $data['ipaddress'];
    $names_tags = sanitizeInput($projectdb, $data['names_tags']);
    $description = sanitizeInput($projectdb, $data['description']);

    switch($type){

        case 'ip-range':
            $ipaddress = $ip;
            $fqdn = '';
            $cidr='32';
            $ip = explode('-',$ipaddress);
            $ipVersion = ip_version($ip[0]);
            $ipVersion2 = ip_version($ip[1]);
            if($ipVersion != $ipVersion2 || $ipVersion == 'noip'){
                $v4 = 0;
                $v6 = 0;
                $invalid = 1;
            }
            else {
                switch ($ipVersion) {
                    case 'v4':
                        $v4 = 1;
                        $v6 = 0;
                        $invalid = 0;
                        break;
                    case 'v6':
                        $v4 = 1;
                        $v6 = 0;
                        $invalid = 0;
                        break;
                    default:
                        $v4 = 0;
                        $v6 = 0;
                        $invalid = 1;
                }
            }

            break;

        case 'fqdn':
            $ipaddress = $ip;
            $fqdn = $ip;
            $cidr='32';
            $v4=0;
            $v6=0;
            $invalid=0;
            break;

        case 'dynamic':
            $ipaddress = $ip;
            $fqdn = $ipaddress;
            //$cidr = mysqli_real_escape_string($projectdb, $data['cidr']);
            $cidr = sanitizeInput($projectdb, $data['cidr']);
            $v4=0;
            $v6=0;
            $invalid=0;
            break;

        case 'ip-wildcard':
            $ipaddress = $ip;
            $fqdn = '';
            $cidr = '';
            $v4 = 0;
            $v6 = 0;
            $invalid = 0;
            break;

        case 'ip-netmask':

        default:
            $ipaddress = $ip;
            $ipVersion = ip_version($ipaddress);
            switch($ipVersion){
                case 'v4':
                    $v4=1;
                    $v6=0;
                    $invalid=0;
                    break;
                case 'v6':
                    $v4=1;
                    $v6=0;
                    $invalid=0;
                    break;
                default:
                    $v4=0;
                    $v6=0;
                    $invalid=1;
            }
            $fqdn = '';
            //$cidr = mysqli_real_escape_string($projectdb, $data['cidr']);
            $cidr = sanitizeInput($projectdb, $data['cidr']);
            break;
    }

    //$zone = '';
    $modified = 1;

    $entryInfo = $projectdb->query("SELECT vsys, source FROM address WHERE id='$id'");
    if($entryInfo->num_rows>0){
        $queryData = $entryInfo->fetch_assoc();
        $vsys = $queryData['vsys'];
        $source = $queryData['source'];
    }

    if($vsys == "all"){
        $queryVsys = "SELECT vsys FROM address WHERE id = '$id';";
        $resultVsys = $projectdb->query($queryVsys);
        $row = $resultVsys->fetch_assoc();
        $vsys = $row['vsys'];
    }

    $getExistName = $projectdb->query("SELECT id FROM address WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' "
        . "UNION SELECT id FROM address_groups_id WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");
    if ($getExistName->num_rows == 0) {
        $invalid_name = 0;
        if(!$invalid) {
            $query = "UPDATE address SET name='$name', type='$type', ipaddress='$ipaddress', cidr='$cidr', tag = '$names_tags',
              description='$description', fqdn='$fqdn', v4='$v4', v6='$v6', source='$source', invalid='$invalid', modified='$modified'
              WHERE id=$id";
            $projectdb->query($query);

            //Remove old tags
            $query = "DELETE FROM tag_relations WHERE table_name='address' AND member_lid='$id' ";
            $projectdb->query($query);

            $names_tags_exp = explode(",", $names_tags);
            $tagPartialQuery = array();
            foreach ($names_tags_exp as $tag_id){
                $tagPartialQuery [] = "('address', $id, $tag_id)";
            }

            // Type ip-wildcard don't have tags.
            if($type != "ip-wildcard"){
                if(count($tagPartialQuery)>0){
                    $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",", $tagPartialQuery);
                    $projectdb->query($query);
                }
            }

            // Update nexthop value and destination from static routes:
            $projectdb->query("UPDATE routes_static SET nexthop_value = '$name' WHERE nexthop_value_member_lid = '$id' ;");
            $projectdb->query("UPDATE routes_static SET destination = '$name' WHERE destination_member_lid = '$id' ;");
        }
    }
    else{
        $invalid_name = 1;
    }

    $message = [
        'msg'   => ''
    ];
    //$message['code'] = true;
    if($invalid == 1) {
        $message['code'] = false;
        $message['msg'] .= 'The specified address seems to be invalid';
    }
    elseif($invalid_name == 1){
        $message['code'] = false;
        $message['msg'] .= 'Address or Address Groups already exists with the same name.';
    }
    else{
        $message['code'] = true;
        $message['msg'] = '';
    }

    return $message;
}


function delete_address(ARRAY $data){

    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $remove_references = $data['remove_references'];
    $ids = mysqli_real_escape_string($projectdb, $data['ids']);

    $used_in_groups = "no";
    $array_name_on_groups = array();
    $array_ids_on_groups = array();

    $getUsed = $projectdb->query("SELECT id, name, used FROM address WHERE id in (".$ids.") AND used = '0' ;");
    if ($getUsed->num_rows > 0) {
        while($getData = $getUsed->fetch_assoc()){

            $id = $getData['id'];
            $name = $getData['name'];

            $is_used = check_used_objects_in_groups($projectdb, $id, "address", "address_groups");

            if($is_used == 0){
                $projectdb->query("DELETE FROM address WHERE id = '$id' AND dummy = 0;");
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
            $message['msg'] = "These Address '".implode(", ",$array_name_on_groups)."' used on Address Groups. Are you sure you want to Delete?";
            return $message;
        }
        elseif($remove_references == "yes"){
            $projectdb->query("DELETE FROM address WHERE id IN (".implode(",", $array_ids_on_groups).") AND dummy = 0;");

            $projectdb->query("DELETE FROM address_groups WHERE (member_lid IN (".implode(",", $array_ids_on_groups).") AND table_name = 'address');");
        }
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    return $message;

}


function getObjectImage(STRING $vsys, STRING $type, STRING $table_name, STRING $vtype){
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);
    $member_shared_prefix = ($vsys == 'shared')? 'shared_': '';
    if ($table_name == "address") {
        switch ($type) {
            case "ip-range":
                $image = $member_shared_prefix . 'ip_range.gif';
                break;
            case "domain":
                $image = $member_shared_prefix . 'domain.png';
                break;
            case "fqdn":
                $image = $member_shared_prefix . 'domain.png';
                break;
            case "group_with_exclusion":
                $image = $member_shared_prefix . 'groupwithexclusion.png';
                break;
            case "gateway_cluster":
            case "cluster_member":
            case "gateway_fw":
                $image = $member_shared_prefix . 'checkpointp.png';
                break;
            default:
                if ($vtype != 'dummy') {
                    $image = $member_shared_prefix . "$table_name.gif";
                } else {
                    $image = $member_shared_prefix . 'pan16.gif';
                }
        }
    }
    else {
        switch ($type) {
            case "dynamic":
                $image = "dynamic_group.png";
                break;
            default:
                $image = $member_shared_prefix.'address_groups.gif';
            
        }
    }
    return $image;
}