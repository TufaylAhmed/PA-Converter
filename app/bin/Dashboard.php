<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/common/panosGlobalReq.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/libs/database.php';
//Dependencies
require_once INC_ROOT.'/libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

//Get request paramenters
switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
//$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$source = $projectdb->real_escape_string($source);

if(!checkProjectRights($project,'view')){
    $message = array();
    $message['code'] = false;
    $message['msg'] = 'You do not have rights in this project';
    return $message;
}

if ($action == "get") {
    if ($type == "global_summary") {
        $getAddr = $projectdb->query("SELECT count(id) as total FROM address WHERE dummy=0;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $address = $data[0]['total'];
        }

        else{
            $address = 0;
        }

        $getSrv = $projectdb->query("SELECT count(id) FROM services WHERE dummy=0;");
        if($getSrv->num_rows>0){
            $data = $getSrv->fetch_assoc();
            $services = $data[0]['total'];
        }
        else{
            $services = 0;
        }
//        $services = $getSrv->num_rows;
        //$getSAddr = $projectdb->query("SELECT id FROM shared_address WHERE dummy=0;");
        //$shared_address = $getSAddr->num_rows;
        //$getSSrv = $projectdb->query("SELECT id FROM shared_services WHERE dummy=0;");
        //$shared_services = $getSSrv->num_rows;
        $total_address =$address;
        $total_services = $services;

        $getAddr = $projectdb->query("SELECT count(id) as total FROM address_groups_id;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $address = $data[0]['total'];
        }
        else{
            $address = 0;
        }
//        $address = $getAddr->num_rows;

        $getSrv = $projectdb->query("SELECT count(id) as total FROM services_groups_id;");
        if($getSrv->num_rows>0){
            $data = $getSrv->fetch_assoc();
            $services = $data[0]['total'];
        }
        else{
            $services = 0;
        }
//        $services = $getSrv->num_rows;
        //$getSAddr = $projectdb->query("SELECT id FROM shared_address_groups_id;");
        //$shared_address = $getSAddr->num_rows;
        //$getSSrv = $projectdb->query("SELECT id FROM shared_services_groups_id;");
        //$shared_services = $getSSrv->num_rows;
        $total_address_groups = $address;
        $total_services_groups = $services;

        $getAddr = $projectdb->query("SELECT count(id) as total FROM security_rules;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $security = $data[0]['total'];
        }
        else{
            $security = 0;
        }
//        $security = $getAddr->num_rows;
        $getSrv = $projectdb->query("SELECT count(id) as total FROM nat_rules;");
        if($getSrv->num_rows>0){
            $data = $getSrv->fetch_assoc();
            $nat = $data[0]['total'];
        }
        else{
            $nat = 0;
        }
//        $nat = $getSrv->num_rows;

        echo '{"dashboard":[{"address":"' . $total_address . '","services":"' . $total_services . '","address_groups":"' . $total_address_groups . '","services_groups":"' . $total_services_groups . '","address":"' . $total_address . '","services":"' . $total_services . '","address_groups":"' . $total_address_groups . '","services_groups":"' . $total_services_groups . '","security":"' . $security . '","nat":"' . $nat . '"}]}';
    } 
    elseif ($type == "global_summary_objects") {

        if (($source == "0") || ($source == "")) {
            $where = "";
            $whereAddress = "WHERE dummy=0";
            $whereDummy = "WHERE dummy=1";
        }
        else {
            $where = "WHERE source='$source'";
            $whereAddress = "WHERE source='$source' AND dummy=0";
            $whereDummy = "WHERE source='$source' AND dummy=1";
        }
        $version=calcVersion($source);
        $getAddr = $projectdb->query("SELECT used, count(id) as total FROM address $whereAddress GROUP BY used;");
        $total_address = 0;
        $total_address_unused = 0;
        if($getAddr->num_rows>0){
            while($data = $getAddr->fetch_assoc()) {
                if($data['used']=='0'){
                    $total_address_unused = $data['total'];
                }
                $total_address += $data['total'];
            }
        }

        $getAddr = $projectdb->query("SELECT used, count(id) as total FROM address $whereDummy GROUP BY used;");
        $total_address_ghost = 0;
        if($getAddr->num_rows>0){
            while($data = $getAddr->fetch_assoc()) {
                $total_address_ghost += $data['total'];
            }
        }

        $getSrv = $projectdb->query("SELECT used, count(id) as total FROM services $whereAddress GROUP BY used;");
        $total_services = 0;
        $total_services_unused = 0;
        if($getSrv->num_rows>0){
            while($data = $getSrv->fetch_assoc()) {
                if($data['used']==0){
                    $total_services_unused = $data['total'];
                }
                $total_services += $data['total'];
            }
        }

        $getSrv = $projectdb->query("SELECT used, count(id) as total FROM services $whereDummy GROUP BY used;");
        $total_services_ghost = 0;
        if($getSrv->num_rows>0){
            while($data = $getSrv->fetch_assoc()) {
                $total_services_ghost += $data['total'];
            }
        }

        $getRegions = $projectdb->query("SELECT used, count(id) as total FROM regions $where GROUP BY used;");
        $total_regions = 0;
        $total_regions_unused = 0;
        if($getRegions->num_rows>0){
            while($data = $getRegions->fetch_assoc()) {
                if($data['used']==0){
                    $total_regions_unused = $data['total'];
                }
                $total_regions += $data['total'];
            }
        }

        $getRegions = $projectdb->query("SELECT used, count(id) as total FROM regions $whereDummy GROUP BY used;");
        $total_regions_ghost = 0;
        if($getRegions->num_rows>0){
            while($data = $getRegions->fetch_assoc()) {
                $total_regions_ghost += $data['total'];
            }
        }

        $getAddr = $projectdb->query("SELECT used, count(id) as total FROM address_groups_id $where GROUP BY used;");
        $total_address_groups = 0;
        $total_address_groups_unused = 0;
        if($getAddr->num_rows>0){
            while($data = $getAddr->fetch_assoc()) {
                if($data['used']==0){
                    $total_address_groups_unused = $data['total'];
                }
                $total_address_groups += $data['total'];
            }
        }

        $getAddr = $projectdb->query("SELECT used, count(id) as total FROM address_groups_id $whereDummy GROUP BY used;");
        $total_address_groups_ghost = 0;
        if($getAddr->num_rows>0){
            while($data = $getAddr->fetch_assoc()) {
                $total_address_groups_ghost += $data['total'];
            }
        }

        $getSrv = $projectdb->query("SELECT used, count(id) as total FROM services_groups_id $where GROUP BY used;");
        $total_services_groups = 0;
        $total_services_groups_unused = 0;
        if($getSrv->num_rows>0){
            while($data = $getSrv->fetch_assoc()) {
                if($data['used']==0){
                    $total_services_groups_unused = $data['total'];
                }
                $total_services_groups += $data['total'];
            }
        }

        $getSrv = $projectdb->query("SELECT used, count(id) as total FROM services_groups_id $whereDummy GROUP BY used;");
        $total_services_groups_ghost = 0;
        if($getSrv->num_rows>0){
            while($data = $getSrv->fetch_assoc()) {
                $total_services_groups_ghost += $data['total'];
            }
        }

        $getTags = $projectdb->query("SELECT id FROM tag $whereAddress AND devicegroup!='predefined' ;");
        $total_tag = $getTags->num_rows;

        $getTag = $projectdb->query("SELECT used, count(id) as total FROM tag $whereAddress AND devicegroup!='predefined' GROUP BY used;");
        $total_tag = 0;
        $total_tag_unused = 0;
        if($getTag->num_rows>0){
            while($data = $getTag->fetch_assoc()) {
                if($data['used']=='0'){
                    $total_tag_unused = $data['total'];
                }
                $total_tag += $data['total'];
            }
        }

        $getAddr = $projectdb->query("SELECT count(id) as total FROM security_rules $where;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $security = $data['total'];
        }
        else{
            $security = 0;
        }

        $getSrv = $projectdb->query("SELECT count(id) as total FROM nat_rules $where;");
        if($getSrv->num_rows>0){
            $data = $getSrv->fetch_assoc();
            $nat = $data['total'];
        }
        else{
            $nat = 0;
        }

        $getAddr = $projectdb->query("SELECT count(id) as total FROM zones $where;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $zones = $data['total'];
        }
        else{
            $zones = 0;
        }

        $getAddr = $projectdb->query("SELECT count(id) as total FROM zones $whereDummy;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $zones_ghost = $data['total'];
        }
        else{
            $zones_ghost = 0;
        }

        $getAddr = $projectdb->query("SELECT count(id) as total FROM interfaces $where;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $interfaces = $data['total'];
        }
        else{
            $interfaces = 0;
        }

        $getAddr = $projectdb->query("SELECT count(id) as total FROM ipsec_tunnel $where;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $ipsec_tunnel = $data['total'];
        }
        else{
            $ipsec_tunnel = 0;
        }

        $getSrv = $projectdb->query("SELECT count(id) as total FROM appoverride_rules $where;");
        if($getSrv->num_rows>0){
            $data = $getSrv->fetch_assoc();
            $appoverride = $data['total'];
        }
        else{
            $appoverride = 0;
        }

        //$getAddr = $projectdb->query("SELECT count(id) as t FROM address $whereAddress GROUP BY BINARY name HAVING t > 1 ;");
        //$dup_total_address = $getAddr->num_rows;
        $getAddr = $projectdb->query("SELECT sum(subquery.duplicate_count) as duplicates FROM ( SELECT BINARY name, COUNT(*) AS duplicate_count FROM address $whereAddress GROUP BY BINARY name HAVING COUNT(*) > 1) AS subquery;");
        $data = $getAddr->fetch_assoc();
        $dup_total_address = $data['duplicates'];

        //$getAddr = $projectdb->query("SELECT count(id) as t FROM services $whereAddress GROUP BY BINARY name HAVING t > 1 ;");
        //$dup_total_services = $getAddr->num_rows;
        $getAddr = $projectdb->query("SELECT sum(subquery.duplicate_count) as duplicates FROM ( SELECT BINARY name, COUNT(*) AS duplicate_count FROM services $whereAddress GROUP BY BINARY name HAVING COUNT(*) > 1) AS subquery;");
        $data = $getAddr->fetch_assoc();
        $dup_total_services = $data['duplicates'];

        //$getAddr = $projectdb->query("SELECT count(id) as t FROM regions $where GROUP BY BINARY name HAVING t > 1 ;");
        //$dup_total_regions = $getAddr->num_rows;
        $getAddr = $projectdb->query("SELECT sum(subquery.duplicate_count) as duplicates FROM ( SELECT BINARY name, COUNT(*) AS duplicate_count FROM regions $whereAddress GROUP BY BINARY name HAVING COUNT(*) > 1) AS subquery;");
        $data = $getAddr->fetch_assoc();
        $dup_total_regions = $data['duplicates'];

        //$getAddr = $projectdb->query("SELECT count(id) as t FROM services_groups_id $where GROUP BY BINARY name HAVING t > 1 ;");
        //$dup_total_services_groups = $getAddr->num_rows;
        $getAddr = $projectdb->query("SELECT sum(subquery.duplicate_count) as duplicates FROM ( SELECT BINARY name, COUNT(*) AS duplicate_count FROM services_groups_id $whereAddress GROUP BY BINARY name HAVING COUNT(*) > 1) AS subquery;");
        $data = $getAddr->fetch_assoc();
        $dup_total_services_groups = $data['duplicates'];

        //$getAddr = $projectdb->query("SELECT count(id) as t FROM address_groups_id $where GROUP BY BINARY name HAVING t > 1 ;");
        //$dup_total_address_groups = $getAddr->num_rows;
        $getAddr = $projectdb->query("SELECT sum(subquery.duplicate_count) as duplicates FROM ( SELECT BINARY name, COUNT(*) AS duplicate_count FROM address_groups_id $whereAddress GROUP BY BINARY name HAVING COUNT(*) > 1) AS subquery;");
        $data = $getAddr->fetch_assoc();
        $dup_total_address_groups = $data['duplicates'];

        $getTags = $projectdb->query("SELECT count(id) as t FROM tag $whereAddress GROUP BY BINARY name HAVING t > 1 ;");
        $dup_total_tag = $getTags->num_rows;

        $getAddr = $projectdb->query("SELECT count(id) as t FROM security_rules $where GROUP BY BINARY name HAVING t > 1 ;");
        $dup_security = $getAddr->num_rows;

        $getAddr = $projectdb->query("SELECT count(id) as t FROM nat_rules $where GROUP BY BINARY name HAVING t > 1 ;");
        $dup_nat = $getAddr->num_rows;

        $getAddr = $projectdb->query("SELECT count(id) as t FROM appoverride_rules $where GROUP BY BINARY name HAVING t > 1 ;");
        $dup_appoverride = $getAddr->num_rows;

        $getAddr = $projectdb->query("SELECT count(id) as t FROM zones $where GROUP BY BINARY name HAVING t > 1 ;");
        $dup_zones = $getAddr->num_rows;
        
        $getAddr = $projectdb->query("SELECT count(id) as t FROM interfaces $where GROUP BY BINARY unitname HAVING t > 1 ;");
        $dup_interfaces = $getAddr->num_rows;
        
        $getAddr = $projectdb->query("SELECT count(id) as t FROM ipsec_tunnel $where GROUP BY BINARY name HAVING t > 1 ;");
        $dup_ipsec_tunnel = $getAddr->num_rows;

        if ($where == "") {
            $where = " WHERE disabled=1 ";
        } else {
            $where = $where . " AND disabled=1 ";
        }
        $getAddr = $projectdb->query("SELECT count(id) as total FROM security_rules $where  ;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $disabled_security = $data['total'];
        }
        else{
            $disabled_security = 0;
        }

        $getAddr = $projectdb->query("SELECT count(id) as total FROM nat_rules $where ;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $disabled_nat = $data['total'];
        }
        else{
            $disabled_nat = 0;
        }

        $getAddr = $projectdb->query("SELECT count(id) as total FROM appoverride_rules $where ;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $disabled_appoverride = $data['total'];
        }
        else{
            $disabled_appoverride = 0;
        }

        #Invalid Services
        if ($source == "0") {
            $where3 = " AND dummy = 0 ";
        } else {
            $where3 = " AND dummy = 0 AND source='$source'";
        }
        //$getInvalid = $projectdb->query("SELECT count(id) as total FROM services WHERE (protocol!='tcp' AND protocol!='udp' OR (dport>65535) OR dport='') $where3;");
        $getInvalid = $projectdb->query("SELECT count(id) as total FROM services WHERE (((protocol != 'tcp' AND protocol != 'udp') OR dport = '' OR dport = '0' OR (dport >= 65535) OR (LENGTH(name) > 63)  OR invalid=1 ) AND name NOT IN ('application-default', 'service-http', 'service-https') ) $where3;");

        if($getInvalid->num_rows>0){
            $data = $getInvalid->fetch_assoc();
            $total_invalid_services = $data['total'];
        }
        else{
            $total_invalid_services = 0;
        }

        #Invalid AddressGroups
        $maxMembersPerGroup = getLimitationsPanos($project, 'maxMembersPerGroup');


        $getAG500 = $projectdb->query("SELECT id,count(id) as t FROM address_groups GROUP BY lid HAVING t > $maxMembersPerGroup;");
        $getAG500Invalid = $getAG500->num_rows;

        $getAGInvalid = $projectdb->query("SELECT id FROM address_groups_id WHERE type = 'static' AND id NOT IN (SELECT lid FROM address_groups);");
        $total_invalid_address_groups = $getAGInvalid->num_rows;

        $total_invalid_address_groups = $total_invalid_address_groups + $getAG500Invalid;

        #Invalid Address
        if (($source == "0") || ($source == "")){
            $where4 = "";
            $where4And = "";
        } else {
            $where4 = " WHERE source='$source'";
            $where4And = " AND source='$source'";
        }
        $queryInvalidAddressGroups = "SELECT DISTINCT id FROM
                        (
                            SELECT id FROM address_groups $where4 GROUP BY lid HAVING count(id) > $maxMembersPerGroup
                            UNION
                            SELECT id FROM address_groups_id WHERE type = 'static' AND id NOT IN (SELECT lid FROM address_groups) $where4And OR LENGTH(name) > 63
                            UNION
                            SELECT id FROM address_groups_id WHERE id IN (SELECT lid FROM address_groups WHERE table_name NOT IN ('address','address_groups_id','default_regions','regions','external_list') $where4And)
                        ) t;";
        $total_invalid_address_groups = $projectdb->query($queryInvalidAddressGroups)->num_rows;

        #Invalid ServicesGroups
        $queryInvalidServGroups = "SELECT distinct id FROM
                      (
                          SELECT id FROM services_groups_id WHERE id NOT IN (SELECT lid FROM services_groups) $where3
                          UNION
                          SELECT id FROM services_groups_id WHERE id IN (SELECT lid FROM services_groups WHERE table_name NOT IN ('services', 'services_groups_id') $where3)
                          UNION
                          SELECT id FROM services_groups_id  WHERE invalid = '1'
                      ) t;";
        $getSGInvalid = $projectdb->query($queryInvalidServGroups);
        $total_invalid_services_groups = $getSGInvalid->num_rows;

        #Invalid Address
        if (($source == "0") || ($source == "")){
            $where = "";
            $whereMulti = "";
        } else {
            $whereMulti = " AND a.source='$source'";
            $where = " AND source='$source'";
        }
        $getInvalidAddr = $projectdb->query("SELECT count(id) as total FROM address $whereAddress  AND ( (invalid=1) OR (type = '') OR (ipaddress='') OR (type = 'ip-netmask' AND cidr = '0') OR (type = 'ip-netmask' AND ipaddress = '0') 
        OR (type = 'ip-netmask' AND ipaddress = '') OR (LENGTH(name) > 63) OR (ipaddress REGEXP '^[0-9]' AND type NOT IN ('ip-netmask', 'ip-range', 'fqdn', 'ip-wildcard')) 
        OR (type IN ('ip-netmask') AND (!IS_IPv4(ipaddress) AND !IS_IPV6(ipaddress))) OR (type IN ('ip-range') AND 
		        NOT (
		            IS_IPv4(SUBSTRING_INDEX(ipaddress,'-',1)) AND IS_IPv4(SUBSTRING_INDEX(ipaddress,'-',-1)) 
		            OR
		            IS_IPv6(SUBSTRING_INDEX(ipaddress,'-',1)) AND IS_IPv6(SUBSTRING_INDEX(ipaddress,'-',-1))
		        )
              ) OR 
        (name NOT REGEXP '^[a-zA-Z0-9][a-zA-Z0-9-_. ]*$') ) ;");

        if($getInvalidAddr->num_rows>0){
            $data = $getInvalidAddr->fetch_assoc();
            $countInvalidAddr = $data['total'];
        }
        else{
            $countInvalidAddr = 0;
        }

        //TODO. Calculate Warnings for Address
//        $warningsQuery = "SELECT count(*) as total FROM logs WHERE obj_id $whereAddress AND obj_type='objects' AND obj_table='address' AND level >0;";
//        $getWarningAddr = $projectdb->query($warningsQuery);
//        if($getWarningAddr->num_rows>0){
//            $data = $getInvalidAddr->fetch_assoc();
//            $total_warning_address = $data['total'];
//        }
//        else{
//            $total_warning_address = 0;
//        }

//        $countInvalidAddr = $getInvalidAddr->num_rows;

        #Zones Invalid
        $getZonesInvalid = $projectdb->query("SELECT id, name FROM zones WHERE invalid=0 $where;");
        if($getZonesInvalid->num_rows > 0){
            while($dataZI = $getZonesInvalid->fetch_assoc()){
                $id_zone = $dataZI['id'];
                $name_zone = $dataZI['name'];
                // echo "Version: " .$version. "\n";
                // Normally, the source is empty in the dashboard, so the version is empty
                // MT-1039 Zone names - max characters is 31 - expedition recognizes only up to 15
                if($version == ""){
                    $version = 8;
                }
                if ($version < 7){
                    if(strlen($name_zone) > 15){
                        $projectdb->query("UPDATE zones SET invalid=1 WHERE id = '$id_zone';");
                    }
                }
                else{
                    if(strlen($name_zone) > 31){
                        $projectdb->query("UPDATE zones SET invalid=1 WHERE id = '$id_zone';");
                    }
                }

            }       
        }
        
        $getZonesInvalid = $projectdb->query("SELECT count(id) as total FROM zones WHERE invalid=1 $where;");
        if($getZonesInvalid->num_rows>0){
            $data = $getZonesInvalid->fetch_assoc();
            $zones_invalid = $data['total'];
        }
        else{
            $zones_invalid = 0;
        }

        #Invalid NAT Rules
        # Check zone FROM if its empty and name is empty
        $getNatInvalid = $projectdb->query("SELECT count(id) as total FROM nat_rules WHERE op_zone_to='' OR op_zone_to = 'none' OR name = '' $where ;");
        if($getNatInvalid->num_rows>0){
            $data = $getNatInvalid->fetch_assoc();
            $invalidNat1 = $data['total'];
        }
        else{
            $invalidNat1 = 0;
        }

        $warningsQuery = "SELECT count(*) as total FROM logs WHERE obj_type='rules' AND obj_table='nat_rules' AND level >0 $where;";
        $getWarningNat = $projectdb->query($warningsQuery);
        if($getWarningNat->num_rows>0){
            $data = $getWarningNat->fetch_assoc();
            $total_warning_nat = $data['total'];
        }
        else{
            $total_warning_nat = 0;
        }

        $warningsQuery = "SELECT count(*) as total FROM logs WHERE obj_type='rules' AND obj_table='app_override_rules' AND level >0 $where;";
        $getWarningAppOverride = $projectdb->query($warningsQuery);
        if($getWarningAppOverride->num_rows>0){
            $data = $getWarningAppOverride->fetch_assoc();
            $total_warning_appoverride = $data['total'];
        }
        else{
            $total_warning_appoverride = 0;
        }


        #Invalid Security Rules
        # Check name if its empty
        $getSecInvalid = $projectdb->query("SELECT count(id) as total FROM security_rules WHERE name = '' $where ;");
        if($getSecInvalid->num_rows>0){
            $data = $getSecInvalid->fetch_assoc();
            $invalidSec1 = $data['total'];
        }
        else{
            $invalidSec1 = 0;
        }

        //Look for those rules that use an app incomplete or insufficient-data
        $query = "SELECT distinct(a.rule_lid) FROM applications app, security_rules_app a 
                    WHERE app.name in ('insufficient-data', 'incomplete') AND
                          a.member_lid = app.id AND a.table_name='applications' $whereMulti
                    ";
//        echo $query;
        $getSecInvalid = $projectdb->query($query);
        $invalidSec1 += $getSecInvalid->num_rows;

        $warningsQuery = "SELECT count(*) as total FROM logs WHERE obj_type='rules' AND obj_table='security_rules' AND level >0 AND UPPER(action) NOT LIKE '%NO ACTION REQUIRED%' $where;";
        $getWarningSec = $projectdb->query($warningsQuery);
        if($getWarningSec->num_rows>0){
            $data = $getWarningSec->fetch_assoc();
            $total_warning_security = $data['total'];
        }
        else{
            $total_warning_security = 0;
        }
        
        #Invalid IPSEC TUNNELS
        $ikev1=$projectdb->query("select count(id) as total from ike_gateways_profiles WHERE ike_crypto_profile_ikev1='' AND version='ikev1' $where;");
        if($ikev1->num_rows>0){
            $data = $ikev1->fetch_assoc();
            $ikev = $data['total'];
        }
        else{
            $ikev = 0;
        }

        $ikev1=$projectdb->query("select count(id) as total from ike_gateways_profiles WHERE ike_crypto_profile_ikev2='' AND version='ikev2' $where;");
        if($ikev1->num_rows>0){
            $data = $ikev1->fetch_assoc();
            $ikev2 = $data['total'];
        }
        else{
            $ikev2 = 0;
        }

        $ikev1=$projectdb->query("select count(id) as total from ike_gateways_profiles WHERE ike_crypto_profile_ikev2='' AND ike_crypto_profile_ikev1='' AND version='ikev2-preferred' $where;");
        if($ikev1->num_rows>0){
            $data = $ikev1->fetch_assoc();
            $ikev3 = $data['total'];
        }
        else{
            $ikev3 = 0;
        }

        $inv_ipsec_tunnel=$ikev+$ikev2+$ikev3;
        
        echo '{"dashboard":'.
            '[{"object":"address",'.
                '"number":"' . $total_address . '",'.
                '"duplicated":"' . $dup_total_address . '",'.
                '"unused":"' . $total_address_unused . '",'.
                '"invalid":"' . $countInvalidAddr . '",'.
                '"warning":"N/A",'.
                '"ghost":"' . $total_address_ghost . '"'.
            '},{"object":"services",'.
                '"number":"' . $total_services . '",'.
                '"duplicated":"' . $dup_total_services . '",'.
                '"unused":"' . $total_services_unused . '",'.
                '"invalid":"' . $total_invalid_services . '",'.
                '"warning":"N/A",'.
                '"ghost":"' . $total_services_ghost . '"'.
            '},{"object":"address_groups",'.
                '"number":"' . $total_address_groups . '",'.
                '"duplicated":"' . $dup_total_address_groups . '",'.
                '"unused":"' . $total_address_groups_unused . '",'.
                '"invalid":"' . $total_invalid_address_groups . '",'.
                '"warning":"N/A",'.
                '"ghost":"' . $total_address_groups_ghost . '"'.
            '},{"object":"services_groups",'.
                '"number":"' . $total_services_groups . '",'.
                '"duplicated":"' . $dup_total_services_groups . '",'.
                '"unused":"' . $total_services_groups_unused . '",'.
                '"invalid":"' . $total_invalid_services_groups . '",'.
                '"warning":"N/A",'.
                '"ghost":"' . $total_services_groups_ghost . '"'.
            '},{"object":"tag",'.
                '"number":"' . $total_tag . '",'.
                '"duplicated":"' . $dup_total_tag . '",'.
                '"unused":"'.$total_tag_unused.'",'.
                '"invalid":0,'.
                '"warning":"N/A",'.
                '"ghost":0'.
            '},{"object":"regions",'.
                '"number":"' . $total_regions . '",'.
                '"duplicated":"' . $dup_total_regions . '",'.
                '"unused":"' . $total_regions_unused . '",'.
                '"invalid":"0",'.
                '"warning":"N/A",'.
                '"ghost":"' . $total_regions_ghost . '"'.
            '},{"object":"security",'.
                '"number":"' . $security . '",'.
                '"duplicated":"' . $dup_security . '",'.
                '"disabled":"' . $disabled_security . '", '.
                '"invalid":"' . $invalidSec1 . '",'.
                '"warning":"' . $total_warning_security . '",'.
                '"ghost":"0"'.
            '},{"object":"nat",'.
                '"number":"' . $nat . '",'.
                '"duplicated":"' . $dup_nat . '",'.
                '"disabled":"' . $disabled_nat . '",'.
                '"invalid":"' . $invalidNat1 . '",'.
                '"warning":"' . $total_warning_nat . '",'.
                '"ghost":"0"'.
            '},{"object":"appoverride",'.
                '"number":"' . $appoverride . '",'.
                '"duplicated":"' . $dup_appoverride . '",'.
                '"disabled":"' . $disabled_appoverride . '",'.
                '"warning":"' . $total_warning_appoverride . '",'.
                '"ghost":"0"'.
            '},{"object":"zones",'.
                '"number":"' . $zones . '",'.
                '"duplicated":"' . $dup_zones . '",'.
                '"disabled":0,'.
                '"invalid":"' . $zones_invalid . '",'.
                '"warning":"N/A",'.
                '"ghost":"' . $zones_ghost . '"'.
            '},{"object":"interfaces",'.
                '"number":"' . $interfaces . '",'.
                '"duplicated":"' . $dup_interfaces . '",'.
                '"disabled":0,'.
                '"invalid":0,'.
                '"warning":"N/A",'.
                '"ghost":"0"'.
            '},{"object":"ipsec_tunnel",'.
                '"number":"' . $ipsec_tunnel . '",'.
                '"duplicated":"' . $dup_ipsec_tunnel . '",'.
                '"disabled":0,'.
                '"invalid":"'.$inv_ipsec_tunnel.'",'.
                '"warning":"N/A",'.
                '"ghost":"0"'.
            '}]}';
    } 
    elseif ($type == "appid_statistics") {
        
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        
        if (($source == "0") || ($source == "")){
            $where = "";
            $where_and = "";
            $where_and2 = "";
        } else {
            $where = " WHERE source='$source'";
            $where_and = " AND source='$source'";
            $where_and2 = " AND s.source='$source'";
        }

        //Check if this is a too large policy and we should avoid calculating some statistics
        $getDisabled = $projectdb->query("SELECT count(id) as total FROM security_rules $where;");
        if($getDisabled->num_rows>0){
            $data = $getDisabled->fetch_assoc();
            $number_of_rules = $data['total'];
        }
        else{
            $number_of_rules = 0;
        }
        $skip_checks = false;
        if(defined('MAX_RULES_TO_ANALYZE')){
            $maxRulesToAnalyze = MAX_RULES_TO_ANALYZE;
        }else{
            $maxRulesToAnalyze=600;
        }
        if($number_of_rules>$maxRulesToAnalyze){
            $skip_checks=true;
        }

        //$getRuleswithapp = $projectdb->query("SELECT id FROM security_rules_app $where GROUP BY rule_lid;");
        $getRuleswithapp = $projectdb->query("SELECT count(*) as total FROM (SELECT sa.rule_lid FROM security_rules_app sa, security_rules s WHERE sa.rule_lid = s.id AND s.action = 'allow' AND disabled = '0' $where_and2 GROUP BY sa.rule_lid) as subtable; ");
        if($getRuleswithapp->num_rows>0){
            $data = $getRuleswithapp->fetch_assoc();
            $appid = $data['total'];
        }
        else{
            $appid = 0;
        }
//        $appid = $getRuleswithapp->num_rows;

        $getAddr = $projectdb->query("SELECT count(id) as total FROM security_rules WHERE action = 'allow' AND disabled = '0' $where_and;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $security = $data['total'];
        }
        else{
            $security = 0;
        }
//        $security = $getAddr->num_rows;

        $getSrv = $projectdb->query("SELECT count(id) as total FROM nat_rules;");
        if($getSrv->num_rows>0){
            $data = $getSrv->fetch_assoc();
            $nat = $data['total'];
        }
        else{
            $nat = 0;
        }
//        $nat = $getSrv->num_rows;

        //$getUnknown = $projectdb->query("SELECT id FROM applications_from_log WHERE app LIKE 'unknown-%' $where_and GROUP BY rule_lid;");
//        $getUnknown = $projectdb->query("SELECT af.id, af.rule_lid FROM applications_from_log af, security_rules s WHERE af.rule_lid = s.id AND s.action = 'allow' AND disabled = '0'  AND af.app LIKE 'unknown-%' $where_and2 GROUP BY rule_lid;");
        $getUnknown = $projectdb->query("SELECT count(*) as total FROM (SELECT af.rule_lid as total FROM applications_from_log af, security_rules s WHERE af.rule_lid = s.id AND s.action = 'allow' AND disabled = '0'  AND af.app LIKE 'unknown-%' $where_and2 GROUP BY rule_lid) as subtable;");
        if($getUnknown->num_rows>0){
            $data = $getUnknown->fetch_assoc();
            $unknown = $data['total'];
        }
        else{
            $unknown = 0;
        }
//        $unknown = $getUnknown->num_rows;

        //$getPlusten = $projectdb->query("SELECT id,count(id) as t FROM security_rules_app $where GROUP BY rule_lid HAVING t>10;");
//        $getPlusten = $projectdb->query("SELECT sa.id,count(sa.id) as t FROM security_rules_app sa, security_rules s WHERE sa.rule_lid = s.id AND s.action = 'allow' AND disabled = '0' $where_and2 GROUP BY rule_lid HAVING t>10;");
        $getPlusten = $projectdb->query("SELECT count(*) as total FROM (SELECT count(sa.id) as t FROM security_rules_app sa, security_rules s WHERE sa.rule_lid = s.id AND s.action = 'allow' AND disabled = '0' $where_and2 GROUP BY rule_lid HAVING t>10) as subtable;");
        if($getPlusten->num_rows>0){
            $data = $getPlusten->fetch_assoc();
            $plusten = $data['total'];
        }
        else{
            $plusten = 0;
        }
//        $plusten = $getPlusten->num_rows;

        $getAddr = $projectdb->query("SELECT count(id) as total FROM zones $where;");
        if($getAddr->num_rows>0){
            $data = $getAddr->fetch_assoc();
            $zones = $data['total'];
        }
        else{
            $zones = 0;
        }
//        $zones = $getAddr->num_rows;

        $getSrv = $projectdb->query("SELECT count(id) as total FROM appoverride_rules $where;");
        if($getSrv->num_rows>0){
            $data = $getSrv->fetch_assoc();
            $appoverride = $data['total'];
        }
        else{
            $appoverride = 0;
        }
//        $appoverride = $getSrv->num_rows;

        if(!$skip_checks) {
            //$getAppsServiceAny = $projectdb->query("SELECT rule_lid FROM security_rules_app GROUP BY rule_lid;");
            $getAppsServiceAny = $projectdb->query("SELECT sa.rule_lid FROM security_rules_app sa, security_rules s WHERE sa.rule_lid = s.id AND s.action = 'allow' AND disabled = '0' $where_and2 GROUP BY sa.rule_lid;");
            $apps_service_any = 0;
            if ($getAppsServiceAny->num_rows > 0) {
                while ($getAppsServiceAnyData = $getAppsServiceAny->fetch_assoc()) {
                    $rule_lid = $getAppsServiceAnyData['rule_lid'];
                    $getServices = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid='$rule_lid' GROUP BY rule_lid;");
                    if ($getServices->num_rows == 0) {
                        $apps_service_any++;
                    }
                }
            }
        }
        else{
            $apps_service_any = 'Skipped';
        }

        //$getAppsAny = $projectdb->query("SELECT id FROM security_rules_app GROUP BY rule_lid;");
        $getAppsAny = $projectdb->query("SELECT count(*) as total FROM (SELECT sa.rule_lid FROM security_rules_app sa, security_rules s WHERE sa.rule_lid = s.id AND s.action = 'allow' AND disabled = '0' $where_and2 GROUP BY rule_lid) as subtable;");
        if($getAppsAny->num_rows>0){
            $data = $getAppsAny->fetch_assoc();
            $apps_any = $security - $data['total'];
        }
        else{
            $apps_any = $security - 0;
        }
//        $apps_any = $security - $getAppsAny->num_rows;

        if(!$skip_checks) {
            $getAppDefault = $projectdb->query("SELECT id, 'services' AS table_name FROM services WHERE name = 'application-default' $where_and ;");
            //echo "1. SELECT id, 'shared_services' AS table_name FROM shared_services WHERE name = 'application-default' $where_and ;\n";
            if ($getAppDefault->num_rows == 1) {
                $dataAD = $getAppDefault->fetch_assoc();
                $member_lid = $dataAD['id'];
                $member_lid_default = $member_lid;
                $table_name = $dataAD['table_name'];
                $table_name_default = $table_name;

                $getAppsServiceAny = $projectdb->query("SELECT sa.rule_lid FROM security_rules_app sa, security_rules s WHERE sa.rule_lid = s.id AND s.action = 'allow' AND disabled = '0' $where_and2 GROUP BY sa.rule_lid;");
                //echo "2. SELECT sa.rule_lid FROM security_rules_app sa, security_rules s WHERE sa.rule_lid = s.id AND s.action = 'allow' AND disabled = '0' $where_and2 GROUP BY sa.rule_lid;\n";
                $apps_service_no_app_default = 0;
                if ($getAppsServiceAny->num_rows > 0) {
                    while ($getAppsServiceAnyData = $getAppsServiceAny->fetch_assoc()) {
                        $rule_lid = $getAppsServiceAnyData['rule_lid'];

                        $getNotAnyServices = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid' GROUP BY rule_lid;");
                        //echo "3. SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid' GROUP BY rule_lid;\n";
                        if ($getNotAnyServices->num_rows > 0) {
                            $getServices = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name = '$table_name' GROUP BY rule_lid;");
                            //echo "4. SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name = '$table_name' GROUP BY rule_lid;\n";
                            if ($getServices->num_rows == 0) {
                                $apps_service_no_app_default++;
                            }
                        }
                    }
                }
            } else {
                //Defined blank values to avoid undefined variables
                $apps_service_no_app_default = 0;
                $member_lid_default = '';
                $table_name_default = '';
            }
        }
        else{
            $apps_service_no_app_default = 'Skipped';
        }
        
        $getActionDeny = $projectdb->query("SELECT count(id) as total FROM security_rules WHERE action != 'allow' AND disabled = '0' $where_and;");
        if($getActionDeny->num_rows>0){
            $data = $getActionDeny->fetch_assoc();
            $security_deny = $data['total'];
        }
        else{
            $security_deny = 0;
        }
//        $security_deny = $getActionDeny->num_rows;

        if(!$skip_checks) {
            $deny_service_app_default = 0;
//        if($getActionDeny->num_rows > 0){
            if ($security_deny > 0) {
                while ($dataAD = $getActionDeny->fetch_assoc()) {
                    $rule_lid = $dataAD['id'];

                    $getServices = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid' AND member_lid = '$member_lid_default' AND table_name = '$table_name_default' GROUP BY rule_lid;");
                    //echo "4. SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid' AND member_lid = '$member_lid' AND table_name = '$table_name' GROUP BY rule_lid;\n";
                    if ($getServices->num_rows > 0) {
                        $deny_service_app_default++;
                    }
                }

            }
        }
        else{
            $deny_service_app_default = 'Skipped';
        }
        
        $getDisabled = $projectdb->query("SELECT count(id) as total FROM security_rules WHERE disabled = '1' $where_and;");
        if($getDisabled->num_rows>0){
            $data = $getDisabled->fetch_assoc();
            $security_disabled = $data['total'];
        }
        else{
            $security_disabled = 0;
        }
//        $security_disabled = $getDisabled->num_rows;

        echo '{"statistics":['.
                '{"risk":"",'.
                    '"check":"Rules enabled and allowed with App-id",'.
                    '"number":"' . $appid . '"'.
                '},{"risk":"",'.
                    '"check":"Rules enabled and allowed with Unknown Traffic",'.
                    '"number":"' . $unknown . '"'.
                '},{"risk":"",'.
                    '"check":"Rules enabled and allowed with +10 Apps found",'.
                    '"number":"' . $plusten . '"'.
                '},{"risk":"",'.
                    '"check":"Rules enabled and allowed with Application = Any",'.
                    '"number":"' . $apps_any . '"'.
                '},{"risk":"",'.
                    '"check":"Rules enabled and allowed with Application but Service = Any",'.
                    '"number":"' . $apps_service_any . '"'.
                '},{"risk":"",'.
                    '"check":"Rules enabled and allowed with Application but Service Not (application-default)",'.
                    '"number":"' . $apps_service_no_app_default . '"'.
                '},{"risk":"",'.
                    '"check":"Rules enabled with action deny, drop, reset client, reset server or reset both with Service = application-default",'.
                    '"number":"' . $deny_service_app_default . '"'.
                '},{"risk":"",'.
                    '"check":"Rules enabled with action deny, drop, reset client, reset server or reset both",'.
                    '"number":"' . $security_deny . '"'.
                '},{"risk":"",'.
                    '"check":"Rules disabled",'.
                    '"number":"' . $security_disabled . '"'.
                '}]}';
    }
    elseif ($type == "appid_statistics2") {
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        if (($source == "0") || ($source == "")){
            $where = "";
        } else {
            $where = "WHERE source='$source'";
        }

        $getRules = $projectdb->query("SELECT count(id) as total FROM security_rules $where;");
        if($getRules->num_rows>0){
            $data = $getRules->fetch_assoc();
            $total_rules = $data['total'];
        }
        else{
            $total_rules = 0;
        }
//        $total_rules = $getRules->num_rows;

        $getRuleswithapp = $projectdb->query("SELECT count(*) as total FROM (SELECT id as total FROM security_rules_app $where GROUP BY rule_lid) as subtable;");
        if($getRuleswithapp->num_rows>0){
            $data = $getRuleswithapp->fetch_assoc();
            $total_app_rules = $data['total'];
        }
        else{
            $total_app_rules = 0;
        }
//        $total_app_rules = $getRuleswithapp->num_rows;

        if ($total_rules==0){
            $pct=0;
            $appid_rules = 0;
            $appid_norules = 0;
        }
        else{
            $pct=round(((intval($total_app_rules)*100)/$total_rules),0);
            $appid_rules = $total_app_rules;
            $appid_norules = $total_rules - $appid_rules;
        }
        
        if ($total_app_rules == 0) {
            echo '{"statistics":[{"rules":"0","label":"Rules with App-id","total":"0","pct":"0"},
            {"rules":"1","label":"Rules with Services","total":"0","pct":"0"}]}';
        } else {
            echo '{"statistics":[{"rules":"' . $appid_rules . '","label":"Rules with App-id","total":"'.$total_rules.'","pct":"'.$pct.'"},{"rules":"' . $appid_norules . '","label":"Rules with Services","total":"'.$total_rules.'","pct":"'.$pct.'"}]}';
        }
    }
    elseif ($type == "userid_statistics2") {
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $total_app_rules=0;
        if (($source == "0") || ($source == "")){
            $where = "";
        } else {
            $where = "WHERE source='$source'";
        }
        $getRules = $projectdb->query("SELECT count(id) as total FROM security_rules $where;");
        if($getRules->num_rows>0){
            $data = $getRules->fetch_assoc();
            $total_rules = $data['total'];
        }
        else{
            $total_rules = 0;
        }
//        $total_rules = $getRules->num_rows;

        $getRuleswithapp = $projectdb->query("SELECT count(*) as total FROM (SELECT id FROM security_rules_usr $where GROUP BY rule_lid) as subtable;");
        if($getRuleswithapp->num_rows>0){
            $data = $getRuleswithapp->fetch_assoc();
            $total_app_rules = $data['total'];
        }
        else{
            $total_app_rules = 0;
        }
//        $total_app_rules = $getRuleswithapp->num_rows;
        if ($total_rules==0){
            $pct=0;
            $appid_rules = 0;
            $appid_norules = 0;
        }
        else{
            $pct=round(((intval($total_app_rules)*100)/$total_rules),0);
            $appid_rules = $total_app_rules;
            $appid_norules = $total_rules - $appid_rules;
        }


        if ($total_app_rules == 0) {
            echo '{"statistics":[{"rules":"0","label":"Rules with User-id","total":"0","pct":"0"},{"rules":"1","label":"Rules without User-id","total":"0","pct":"0"}]}';
        } else {
            echo '{"statistics":[{"rules":"' . $appid_rules . '","label":"Rules with User-id","total":"'.$total_rules.'","pct":"'.$pct.'"},{"rules":"' . $appid_norules . '","label":"Rules without User-id","total":"'.$total_rules.'","pct":"'.$pct.'"}]}';
        }
    }
    elseif ($type == "bestpractices") {
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        if (($source == "0") || ($source == "")){
            $where = "";
        } else {
            $where = "WHERE source='$source'";
        }
        global $bestPracticesdb;
        $result= $projectdb->query("SELECT * FROM bestpractices_results WHERE date in (SELECT MAX(date) from bestpractices_results GROUP BY topic,params);");
        if ($result->num_rows>0) {
            while ($row = $result->fetch_object()) {
                $topic = $row->topic;

            }
        }


        if ($total_app_rules == "") {
            echo '{"statistics":[{"rules":"0","label":"Rules with User-id","total":"0","pct":"0"},{"rules":"1","label":"Rules without User-id","total":"0","pct":"0"}]}';
        } else {
            echo '{"statistics":[{"rules":"' . $appid_rules . '","label":"Rules with User-id","total":"'.$total_rules.'","pct":"'.$pct.'"},{"rules":"' . $appid_norules . '","label":"Rules without User-id","total":"'.$total_rules.'","pct":"'.$pct.'"}]}';
        }
    }
    elseif ($type == "duplicated") {
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        if (($source == "0") || ($source == "")){
            $where = "";
            $whereAddress = "WHERE dummy=0";
        } else {
            $where = "WHERE source='$source'";
            $whereAddress = "WHERE source='$source' AND dummy=0";
        }

        $getAddr = $projectdb->query("SELECT count(id) as t FROM address $whereAddress GROUP BY name HAVING t > 1;");
//        if($getAddr->num_rows>0){
//            $data = $getAddr->fetch_assoc();
//            $total_app_rules = $data['total'];
//        }
//        else{
//            $total_app_rules = 0;
//        }
        $total_addr = $getAddr->num_rows;

        $getAddrg = $projectdb->query("SELECT count(id) as t FROM address_groups_id $where GROUP BY name HAVING t > 1;");
//        if($getRuleswithapp->num_rows>0){
//            $data = $getRuleswithapp->fetch_assoc();
//            $total_app_rules = $data['total'];
//        }
//        else{
//            $total_app_rules = 0;
//        }
        $total_addrg = $getAddrg->num_rows;

        $getSrv = $projectdb->query("SELECT count(*) as total FROM (SELECT count(id) as t FROM services $where GROUP BY name HAVING t > 1) as subtable;");
        if($getSrv->num_rows>0){
            $data = $getSrv->fetch_assoc();
            $total_srv = $data['total'];
        }
        else{
            $total_srv = 0;
        }
//        $total_srv = $getSrv->num_rows;

        $getSrvg = $projectdb->query("SELECT count(*) as total FROM (SELECT count(id) as t FROM services_groups_id $where GROUP BY name HAVING t > 1) as subtable;");
        if($getSrvg->num_rows>0){
            $data = $getSrvg->fetch_assoc();
            $total_srvg = $data['total'];
        }
        else{
            $total_srvg = 0;
        }
//        $total_srvg = $getSrvg->num_rows;

        $getSec = $projectdb->query("SELECT count(*) as total FROM (SELECT count(id) as t FROM security_rules $where GROUP BY name HAVING t > 1) as subtable;");
        if($getSec->num_rows>0){
            $data = $getSec->fetch_assoc();
            $total_sec = $data['total'];
        }
        else{
            $total_sec = 0;
        }
//        $total_sec = $getSec->num_rows;

        $getNat = $projectdb->query("SELECT count(*) as total FROM (SELECT count(id) as t FROM nat_rules $where GROUP BY name HAVING t > 1) as subtable;");
        if($getNat->num_rows>0){
            $data = $getNat->fetch_assoc();
            $total_nat = $data['total'];
        }
        else{
            $total_nat = 0;
        }
//        $total_nat = $getNat->num_rows;

        $sum = $total_addr + $total_addrg + $total_srv + $total_srvg + $total_sec + $total_nat;
        if ($sum == 0) {
            echo '{"statistics":[{"field":"Address","value":"' . $total_addr . '"},{"field":"Services","value":"' . $total_srv . '"},{"field":"Address Group","value":"' . $total_addrg . '"},{"field":"Services Group","value":"' . $total_srvg . '"},{"field":"Security","value":"' . $total_sec . '"},{"field":"Nat","value":"' . $total_nat . '"}]}';
        }
        else {
            echo '{"statistics":[{"field":"Address","value":"' . $total_addr . '"},{"field":"Services","value":"' . $total_srv . '"},{"field":"Address Group","value":"' . $total_addrg . '"},{"field":"Services Group","value":"' . $total_srvg . '"},{"field":"Security","value":"' . $total_sec . '"},{"field":"Nat","value":"' . $total_nat . '"}]}';
        }
    }
}
?>