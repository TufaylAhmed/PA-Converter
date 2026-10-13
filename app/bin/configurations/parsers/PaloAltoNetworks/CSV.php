<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
//DEBUG
//$_SERVER['DOCUMENT_ROOT']="/var/www/html";
//$_SERVER['REQUEST_METHOD']="POST";
//DEBUG
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';

//Dependencies
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/sanitize.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';

$sourcesAdded = array();
global $source;
//Capture request paramenters

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');

        $columns    = (string)  (isset($_GET['columns'])   ? $_GET['columns'] : '');
        $id         = (string)  (isset($_GET['id'])        ? $_GET['id'] : '');
        $mapping    = (string)  (isset($_GET['mapping'])   ? $_GET['mapping'] : '');
        $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
        $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $objtype    =          (isset($_GET['objtype'])    ? $_GET['objtype']: '');
        $vr         = (string) (isset($_GET['vr'])         ? $_GET['vr'] : '');
        $template   = (string) (isset($_GET['template'])   ? $_GET['template'] : '');

        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');

        $columns    = (string)  (isset($_POST['columns'])   ? $_POST['columns'] : '');
        $id         = (string)  (isset($_POST['id'])        ? $_POST['id'] : '');
        $mapping    = (string)  (isset($_POST['mapping'])   ? $_POST['mapping'] : '');

        $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
        $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        $objtype    =          (isset($_POST['objtype'])    ? $_POST['objtype']: '');
        $vr         = (string) (isset($_POST['vr'])         ? $_POST['vr'] : '');
        $template   = (string) (isset($_POST['template'])   ? $_POST['template'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');

        $columns    = (string)  (isset($_POST['columns'])   ? $_POST['columns'] : '');
        $id         = (string)  (isset($_POST['id'])        ? $_POST['id'] : '');
        $mapping    = (string)  (isset($_POST['mapping'])   ? $_POST['mapping'] : '');
        $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
        $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        $objtype    =          (isset($_POST['objtype'])    ? $_POST['objtype']: '');
        $vr         = (string) (isset($_POST['vr'])         ? $_POST['vr'] : '');
        $template   = (string) (isset($_POST['template'])   ? $_POST['template'] : '');
        break;
}

$sourcesAdded[] = $source;


//DEBUG
//$project="";
//$action="import";
//$objtype="address";
//$source="3";
//$vsys="iron-skillet";
//DEBUG

require_once INC_ROOT.'/libs/projectdb.php';
global $projectdb;

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$columns = $projectdb->real_escape_string($columns);
$id = $projectdb->real_escape_string($id);
$mapping = $projectdb->real_escape_string($mapping);
$source = $projectdb->real_escape_string($source);
$vsys = $projectdb->real_escape_string($vsys);
$vsys = $projectdb->real_escape_string($vsys);
$objtype = $projectdb->real_escape_string($objtype);
$vr = $projectdb->real_escape_string($vr);
$template = $projectdb->real_escape_string($template);

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

if ($action == "get"){
    if ($type == "csv"){
        $getAll=$projectdb->query("SELECT * FROM csv_columns;");
        $count=$getAll->num_rows;
        $getLimit=$projectdb->query("SELECT * FROM csv_columns LIMIT $start, $limit ;");
        $x=0;
        while ($data=$getLimit->fetch_object()){
            $myData[]=$data;
        }
        if ($count==0){$myData="";}
        echo '{"total":"'.$count.'","csv":'.json_encode($myData).'}';
    }
    elseif ($type == "mapping"){
        $getAll=$projectdb->query("SELECT * FROM csv_columns;");
        $count=$getAll->num_rows;
        $getLimit=$projectdb->query("SELECT id,columns,mapping,objtype FROM csv_mapping;");
        $x=0;
        if ($getLimit->num_rows>0){
            while ($data=$getLimit->fetch_object()){
                $myData[]=$data;
            }
        }
        if ($count==0){$myData="";}
        echo '{"total":"'.$count.'","csv":'.json_encode($myData).'}';
    }
}
elseif ($action == "update"){
    if ($type == "mapping"){
        $projectdb->query("UPDATE csv_mapping SET mapping='$mapping' WHERE id='$id';");
    }

}
elseif ($action == "remove") {
    if($id == "all"){
        $projectdb->query("TRUNCATE TABLE csv_columns;");
        $projectdb->query("TRUNCATE TABLE csv_mapping;");
    }else{
        $projectdb->query("DELETE FROM csv_columns WHERE id = '$id';");
    }
}
elseif ($action == "import") {

    take_snapshot_last($project);

    switch ($objtype) {

        case "address":
            importCSVAddress($projectdb, $source, $vsys);
            break;

        case "address_groups":
            importCSVAddressGroups($projectdb, $source, $vsys);
            break;

        case "services":
            importCSVServices($projectdb, $source, $vsys);
            break;

        case "services_groups":
            importCSVServicesGroups($projectdb, $source, $vsys);
            break;

        case "regions":
            importCSVRegions($projectdb, $source, $vsys);
            break;

        case "security":
            importCSVSecurity($projectdb, $source, $vsys, $template, $project, $sourcesAdded);
            break;

        case "nat":
            importCSVNat($projectdb, $source, $vsys, $template, $project, $sourcesAdded);
            break;

        case "interfaces":
            importCSVInterfaces($projectdb, $source, $vsys, $template, $vr);
            break;

        case "routes_static":
            importCSVRoutesStatic($projectdb, $source, $vsys, $template, $vr);
            break;

        case "zones":
            importCSVZones($projectdb, $source, $vsys, $template, $vr);
            break;

        default:
            break;
    }

}


function importCSVAddress($projectdb, $source, $vsys){

    $address_type = "";
    $description = "";
    $cidr = "";

    $getMap = $projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns=array();
        while ($getMapData=$getMap->fetch_assoc()){
            $column=$getMapData['columns'];
            $map=$getMapData['mapping'];
            if ($map!=""){
                $columns["$map"]=$column;
            }

        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["ipaddress"])){
            $elements[]=$columns["ipaddress"]." as ipaddress";
        }
        if (isset($columns["description"])){
            $elements[]=$columns["description"]." as description";
        }
        if (isset($columns["netmask"])){
            $elements[]=$columns["netmask"]." as netmask";
        }
        if (isset($columns["cidr"])){
            $elements[]=$columns["cidr"]." as cidr";
        }
        if (isset($columns["ipaddress_start"])){
            $elements[]=$columns["ipaddress_start"]." as ipaddress_start";
        }
        if (isset($columns["ipaddress_end"])){
            $elements[]=$columns["ipaddress_end"]." as ipaddress_end";
        }
        if (isset($columns["ipaddress_range"])){
            $elements[]=$columns["ipaddress_range"]." as ipaddress_range";
        }
        if (isset($columns["ipaddress_netmask"])){
            $elements[]=$columns["ipaddress_netmask"]." as ipaddress_netmask";
        }
        if (isset($columns["ipaddress_cidr"])){
            $elements[]=$columns["ipaddress_cidr"]." as ipaddress_cidr";
        }
        if (isset($columns["tag"])){
            $elements[]=$columns["tag"]." as tag";
        }
        if (count($elements)>0){
            $sql="SELECT ".implode(",",$elements)." FROM csv_columns;";

            $getAll=$projectdb->query($sql);
            if ($getAll->num_rows>0){

                $addAddressv4 = array();
                $addAddressv6 = array();
                $addTag = array();

                #get Last ID for the table
                $getMax=$projectdb->query("SELECT MAX(id) as maxid FROM address;");
                if ($getMax->num_rows==1){
                    $getMaxData=$getMax->fetch_assoc();
                    $grpID=$getMaxData["maxid"]+1;
                    if ($grpID==""){
                        $grpID=1;
                    }
                }
                else{
                    $grpID=1;
                }

                while ($getAllData=$getAll->fetch_assoc()){
                    $tag_clean_array=array();
                    $tags="";

                    if (isset($getAllData["name"])){
                        $name_ext=$getAllData["name"];
                        $name_ext = htmlspecialchars($name_ext, ENT_QUOTES);
                        $name = truncate_names(normalizeNames($name_ext));

                        $name = sanitize_sql_string($name);

                    }
                    if ( (isset($getAllData['description'])) AND ($getAllData['description']!=NULL)){
                        $description_raw=$getAllData['description'];
                        $description=  addslashes($description_raw);
                    }

                    if (isset($getAllData['tag'])){
                        $tag_raw=$getAllData['tag'];
                        $tags_array=explode(",",$tag_raw);
                        foreach ($tags_array as $thetag){
                            $tag_clean_array[] = truncate_tags(normalizeNames($thetag));
                        }
                        $tags=implode(",",$tag_clean_array);
                    }

                    if (isset($getAllData['tag'])){

                        $members_all = $getAllData['tag'];
                        $members_array = explode(",",$members_all);

                        foreach($members_array as $themember) {

                            if(($themember != "any") && ($themember != "")){

                                $getDup = $projectdb->query("SELECT id FROM tag WHERE name='$themember' AND source='$source' AND vsys = '$vsys';");
                                if ($getDup->num_rows == 1) {
                                    $getDupData = $getDup->fetch_assoc();
                                    $tag_id = $getDupData['id'];
                                }
                                else {
                                    $projectdb->query("INSERT INTO tag (source,vsys,name,color) VALUES ('$source','$vsys','$themember','color4');");
                                    $tag_id = $projectdb->insert_id;
                                }
                                $addTag[] = "('address', '$grpID', '$tag_id')";
                            }
                        }
                    }

                    if ( (isset($getAllData["ipaddress"])) AND (isset($getAllData["netmask"])) AND ($getAllData["ipaddress"]!=NULL) AND ($getAllData["netmask"]!=NULL) ){
                        $ipaddress=$getAllData["ipaddress"];
                        $cidr = mask2cidrv4($getAllData["netmask"]);
                    }
                    elseif ( (isset($getAllData["ipaddress"])) AND (isset($getAllData["cidr"])) AND ($getAllData["ipaddress"]!=NULL) AND ($getAllData["cidr"]!=NULL) ){
                        $ipaddress=$getAllData["ipaddress"];
                        $cidr = $getAllData["cidr"];
                    }
                    elseif ( (isset($getAllData["ipaddress_start"])) AND (isset($getAllData["ipaddress_end"])) AND ($getAllData["ipaddress_start"]!=NULL) AND ($getAllData["ipaddress_end"]!=NULL)  ){
                        $ipaddress=$getAllData["ipaddress_start"]."-".$getAllData["ipaddress_end"];
                        $cidr = "";
                    }
                    elseif ((isset($getAllData["ipaddress_range"])) AND ($getAllData["ipaddress_range"]!=NULL)){
                        $ipaddress=$getAllData["ipaddress_range"];
                        $cidr = "";
                    }
                    elseif ((isset($getAllData['ipaddress_cidr'])) AND ($getAllData["ipaddress_cidr"]!=NULL) ){
                        $split=explode("/",$getAllData['ipaddress_cidr']);
                        $ipaddress=$split[0];
                        $cidr=$split[1];
                    }
                    elseif ((isset($getAllData['ipaddress_netmask'])) AND ($getAllData["ipaddress_netmask"]!=NULL)  ){
                        $split=explode("/",$getAllData['ipaddress_netmask']);
                        $ipaddress=$split[0];
                        $netmask=$split[1];
                        $cidr = mask2cidrv4($netmask);
                    }
                    elseif (isset($getAllData['ipaddress'])){
                        $ipaddress=$getAllData["ipaddress"];
                    }

                    $ip_version = ip_version($ipaddress);
                    if (preg_match("/-/", $ipaddress)) {
                        $address_type = "ip-range";
                        $address_tmp=explode("-",$ipaddress);
                        $ip_version=ip_version($address_tmp[0]);
                    }

                    if ($ip_version == "noip") {
                        if ($address_type==""){$address_type = "fqdn";}
                        if ($address_type=="ip-range"){$address_type="fqdn";}
                        $addAddressv4[]="('$grpID','$source','$vsys','$name_ext','$name','$description','$address_type','1','$cidr','csv','$ipaddress','$tags')";
                    }
                    elseif ($ip_version=="v4"){
                        if ($address_type==""){$address_type = "ip-netmask";}
                        $addAddressv4[]="('$grpID','$source','$vsys','$name_ext','$name','$description','$address_type','1','$cidr','csv','$ipaddress','$tags')";
                    }
                    elseif ($ip_version=="v6"){
                        if ($address_type==""){$address_type = "ip-netmask";}
                        $addAddressv6[]="('$grpID','$source','$vsys','$name_ext','$name','$description','$address_type','1','$cidr','csv','$ipaddress','$tags')";
                    }
                    else {
                        if ($address_type==""){$address_type = "ip-netmask";}
                        $addAddressv4[]="('$grpID','$source','$vsys','$name_ext','$name','$description','$address_type','1','$cidr','csv','$ipaddress','$tags')";
                    }

                    $address_type="";
                    $grpID++;
                }

                if (count($addAddressv4)>0){
                    $projectdb->query("INSERT INTO address (id,source,vsys,name_ext,name,description,type,v4,cidr,devicegroup,ipaddress,tag) VALUES ".implode(",",$addAddressv4).";");
                    unset($addAddressv4);
                }

                if (count($addAddressv6)>0){
                    $projectdb->query("INSERT INTO address (id,source,vsys,name_ext,name,description,type,v6,cidr,devicegroup,ipaddress,tag) VALUES ".implode(",",$addAddressv6).";");
                    unset($addAddressv6);
                }

                if (count($addTag)>0){
                    $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) VALUES ".implode(",",$addTag).";");
                    unset($addTag);
                }

                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }
    }
}

function importCSVAddressGroups($projectdb, $source, $vsys){

    $table="address_groups_id";
    $table_members="address_groups";
    $getMap=$projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns=array();
        while ($getMapData=$getMap->fetch_assoc()){
            $column=$getMapData['columns'];
            $map=$getMapData['mapping'];
            if ($map!=""){
                $columns["$map"]=$column;
            }
        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["members"])){
            $elements[]=$columns["members"]." as members";
        }
        if (isset($columns["description"])){
            $elements[]=$columns["description"]." as description";
        }
        if (isset($columns["tag"])){
            $elements[]=$columns["tag"]." as tag";
        }

        if (count($elements)>0){
            $sql="SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll=$projectdb->query($sql);
            if ($getAll->num_rows>0){
                $addGroup = array();
                $addMembers = array();
                $addTag = array();
                #get Last ID for the table
                $getMax=$projectdb->query("SELECT MAX(id) as maxid FROM address_groups_id;");
                if ($getMax->num_rows==1){
                    $getMaxData=$getMax->fetch_assoc();
                    $grpID=$getMaxData["maxid"]+1;
                    if ($grpID==""){
                        $grpID=1;
                    }
                }
                else{
                    $grpID=1;
                }
                $theFirstgrpID=$grpID;
                while ($getAllData=$getAll->fetch_assoc()){
                    $name="";$name_ext="";$latitude=0;$address_all="";
                    if (isset($getAllData["name"])){
                        $name_ext=$getAllData["name"];
                        $name=  truncate_names(normalizeNames($name_ext));
                    }
                    if (isset($getAllData['members'])){
                        $members_all=$getAllData['members'];
                        $members_array=explode(",",$members_all);
                        foreach($members_array as $themember){
                            $addMembers[]="('$grpID','$themember','$source','$vsys','csv')";
                        }
                    }
                    if (isset($getAllData['description'])){
                        $description_raw=$getAllData['description'];
                        $description=  addslashes($description_raw);
                    }

                    if (isset($getAllData['tag'])){

                        $members_all = $getAllData['tag'];
                        $members_array = explode(",",$members_all);

                        foreach($members_array as $themember) {

                            if(($themember != "any") && ($themember != "")){

                                $getDup = $projectdb->query("SELECT id FROM tag WHERE name='$themember' AND source='$source' AND vsys = '$vsys';");
                                if ($getDup->num_rows == 1) {
                                    $getDupData = $getDup->fetch_assoc();
                                    $tag_id = $getDupData['id'];
                                }
                                else {
                                    $projectdb->query("INSERT INTO tag (source,vsys,name,color) VALUES ('$source','$vsys','$themember','color4');");
                                    $tag_id = $projectdb->insert_id;
                                }
                                $addTag[] = "('address_groups_id', '$grpID', '$tag_id')";
                            }
                        }
                    }

                    $addGroup[]="('$grpID','$source','$vsys','$name','$name_ext','$description','csv')";
                    $grpID++;
                }

                if (count($addGroup)>0){
                    $projectdb->query("INSERT INTO address_groups_id (id,source,vsys,name,name_ext,description,devicegroup) VALUES ".implode(",",$addGroup).";");
                    unset($addGroup);
                    $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys,devicegroup) VALUES ".implode(",",$addMembers).";");
                    unset($addMembers);
                    #Calculate members id
                    GroupMember2IdAddress($source);
                }

                if (count($addTag)>0){
                    $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) VALUES ".implode(",",$addTag).";");
                    unset($addTag);
                }

                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }
    }
}

function importCSVServices($projectdb, $source, $vsys){

    $getMap=$projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns=array();
        while ($getMapData=$getMap->fetch_assoc()){
            $column=$getMapData['columns'];
            $map=$getMapData['mapping'];
            if ($map!=""){
                $columns["$map"]=$column;
            }
        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["description"])){
            $elements[]=$columns["description"]." as description";
        }
        if (isset($columns["tag"])){
            $elements[]=$columns["tag"]." as tag";
        }
        if (isset($columns["sport"])){
            $elements[]=$columns["sport"]." as sport";
        }
        if (isset($columns["dport"])){
            $elements[]=$columns["dport"]." as dport";
        }
        if (isset($columns["protocol"])){
            $elements[]=$columns["protocol"]." as protocol";
        }
        if (isset($columns["protocol_port"])){
            $elements[]=$columns["protocol_port"]." as protocol_port";
        }

        if (count($elements)>0){
            $sql="SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll=$projectdb->query($sql);

            if ($getAll->num_rows>0){
                $addServices = array();
                $addTag = array();

                #get Last ID for the table
                $getMax=$projectdb->query("SELECT MAX(id) as maxid FROM services;");
                if ($getMax->num_rows==1){
                    $getMaxData=$getMax->fetch_assoc();
                    $grpID=$getMaxData["maxid"]+1;
                    if ($grpID==""){
                        $grpID=1;
                    }
                }
                else{
                    $grpID=1;
                }

                while ($getAllData=$getAll->fetch_assoc()){
                    $name = "";
                    $name_ext = "";
                    $sport = "";
                    if (isset($getAllData["name"])){
                        $name_ext = $getAllData["name"];
                        $name = truncate_names(normalizeNames($name_ext));
                    }
                    if (isset($getAllData['description'])){
                        $description_raw = $getAllData['description'];
                        $description = addslashes($description_raw);
                    }

                    if (isset($getAllData['tag'])){

                        $members_all = $getAllData['tag'];
                        $members_array = explode(",",$members_all);

                        foreach($members_array as $themember) {

                            if(($themember != "any") && ($themember != "")){

                                $getDup = $projectdb->query("SELECT id FROM tag WHERE name='$themember' AND source='$source' AND vsys = '$vsys';");
                                if ($getDup->num_rows == 1) {
                                    $getDupData = $getDup->fetch_assoc();
                                    $tag_id = $getDupData['id'];
                                }
                                else {
                                    $projectdb->query("INSERT INTO tag (source,vsys,name,color) VALUES ('$source','$vsys','$themember','color4');");
                                    $tag_id = $projectdb->insert_id;
                                }
                                $addTag[] = "('services', '$grpID', '$tag_id')";
                            }
                        }
                    }

                    if (isset($getAllData['sport']) ){
                        $sport=$getAllData['sport'];
                    }
                    if ( (isset($getAllData['dport'])) AND (isset($getAllData['protocol'])) ){
                        $dport=$getAllData['dport'];
                        $protocol=$getAllData['protocol'];
                        $addServices[]="('$grpID','$source','$vsys','$name_ext','$name','$sport','$dport','$protocol','csv', '$description')";
                    }
                    elseif (isset($getAllData['protocol_port'])){
                        $protocol_port=explode("/",$getAllData['protocol_port']);
                        $dport=$protocol_port[1];
                        $protocol=$protocol_port[0];
                        $addServices[]="('$grpID','$source','$vsys','$name_ext','$name','$sport','$dport','$protocol','csv', '$description')";
                    }

                    $grpID++;

                }

                if (count($addServices)>0){
                    $projectdb->query("INSERT INTO services (id,source,vsys,name_ext,name,sport,dport,protocol,devicegroup, description) VALUES ".implode(",",$addServices).";");
                    unset($addServices);
                }

                if (count($addTag)>0){
                    $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) VALUES ".implode(",",$addTag).";");
                    unset($addTag);
                }

                #Check invalid protocols or ports
                $projectdb->query("UPDATE services SET invalid=1 WHERE (protocol != 'tcp' AND protocol != 'udp') AND id > $grpID;");
                $projectdb->query("UPDATE services SET invalid=1 WHERE (dport = '' OR dport = '0' OR dport>65535) AND id > $grpID;");

                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }
    }
}

function importCSVServicesGroups($projectdb, $source, $vsys){

    $table="services_groups_id";
    $table_members="services_groups";
    $getMap=$projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns=array();
        while ($getMapData=$getMap->fetch_assoc()){
            $column=$getMapData['columns'];
            $map=$getMapData['mapping'];
            if ($map!=""){
                $columns["$map"]=$column;
            }

        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["members"])){
            $elements[]=$columns["members"]." as members";
        }
        if (isset($columns["description"])){
            $elements[]=$columns["description"]." as description";
        }
        if (isset($columns["tag"])){
            $elements[]=$columns["tag"]." as tag";
        }

        if (count($elements)>0){
            $sql="SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll=$projectdb->query($sql);
            if ($getAll->num_rows>0){
                $addGroup = array();
                $addMembers = array();
                $addTag = array();

                #get Last ID for the table
                $getMax=$projectdb->query("SELECT MAX(id) as maxid FROM services_groups_id;");
                if ($getMax->num_rows==1){
                    $getMaxData=$getMax->fetch_assoc();
                    $grpID=$getMaxData["maxid"]+1;
                    if ($grpID==""){
                        $grpID=1;
                    }
                }
                else{
                    $grpID=1;
                }

                while ($getAllData=$getAll->fetch_assoc()){
                    $name="";$name_ext="";$latitude=0;$address_all="";
                    if (isset($getAllData["name"])){
                        $name_ext=addslashes($getAllData["name"]);
                        $name=  truncate_names(normalizeNames($name_ext));
                    }
                    if (isset($getAllData['members'])){
                        $members_all=$getAllData['members'];
                        $members_array=explode(",",$members_all);
                        foreach($members_array as $themember){
                            $addMembers[]="('$grpID','$themember','$source','$vsys','csv')";
                        }
                    }
                    if (isset($getAllData['description'])){
                        $description_raw=$getAllData['description'];
                        $description=  addslashes($description_raw);
                    }

                    if (isset($getAllData['tag'])){

                        $members_all = $getAllData['tag'];
                        $members_array = explode(",",$members_all);

                        foreach($members_array as $themember) {

                            if(($themember != "any") && ($themember != "")){

                                $getDup = $projectdb->query("SELECT id FROM tag WHERE name='$themember' AND source='$source' AND vsys = '$vsys';");
                                if ($getDup->num_rows == 1) {
                                    $getDupData = $getDup->fetch_assoc();
                                    $tag_id = $getDupData['id'];
                                }
                                else {
                                    $projectdb->query("INSERT INTO tag (source,vsys,name,color) VALUES ('$source','$vsys','$themember','color4');");
                                    $tag_id = $projectdb->insert_id;
                                }
                                $addTag[] = "('services_groups_id', '$grpID', '$tag_id')";
                            }
                        }
                    }

                    $addGroup[]="('$grpID','$source','$vsys','$name','$name_ext','$description','csv')";
                    $grpID++;
                }

                if (count($addGroup)>0){
                    $projectdb->query("INSERT INTO services_groups_id (id,source,vsys,name,name_ext,description,devicegroup) VALUES ".implode(",",$addGroup).";");
                    unset($addGroup);
                    $projectdb->query("INSERT INTO services_groups (lid,member,source,vsys,devicegroup) VALUES ".implode(",",$addMembers).";");
                    unset($addMembers);
                    #Calculate members id
                    GroupMember2IdServices($source);

                }

                if (count($addTag)>0){
                    $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) VALUES ".implode(",",$addTag).";");
                    unset($addTag);
                }

                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }
    }
}

function importCSVRegions($projectdb, $source, $vsys){

    $table = "regions";
    $getMap = $projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns = array();
        while ($getMapData = $getMap->fetch_assoc()){
            $column=$getMapData['columns'];
            $map=$getMapData['mapping'];
            if ($map!=""){
                $columns["$map"]=$column;
            }

        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["latitude"])){
            $elements[]=$columns["latitude"]." as latitude";
        }
        if (isset($columns["longitude"])){
            $elements[]=$columns["longitude"]." as longitude";
        }
        if (isset($columns["address"])){
            $elements[]=$columns["address"]." as address";
        }

        if (count($elements)>0){
            $sql="SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll=$projectdb->query($sql);
            if ($getAll->num_rows>0){
                $addAddressv4=array();
                $addAddressv6=array();
                while ($getAllData=$getAll->fetch_assoc()){
                    $name="";$name_ext="";$longitude=0;$latitude=0;$address_all="";
                    if (isset($getAllData["name"])){
                        $name_ext=$getAllData["name"];
                        $name=  truncate_names(normalizeNames($name_ext));
                    }
                    if (isset($getAllData['address'])){
                        $address_all2 = $getAllData['address'];
                        $address_all_array = explode(",", $address_all2);
                        asort($address_all_array);
                        $address_all = implode(",",$address_all_array);
                    }
                    if (isset($getAllData['latitude'])){
                        $latitude=$getAllData['latitude'];
                    }
                    if (isset($getAllData['longitude'])){
                        $longitude=$getAllData['longitude'];
                    }
                    $addAddressv4[]="('$source','$vsys','$name','$name_ext','$address_all','$longitude','$latitude','csv')";
                }

                if (count($addAddressv4)>0){
                    $projectdb->query("INSERT INTO $table (source,vsys,name,name_ext,address,longitude,latitude,devicegroup) VALUES ".implode(",",$addAddressv4).";");
                    unset($addAddressv4);
                }
                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }


    }
}

function importCSVSecurity($projectdb, $source, $vsys, $template, $project, $sourcesAdded){

    $table = "security_rules";
    $clone = array(); $identifier = 0;
    $getMap=$projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns=array();
        while ($getMapData=$getMap->fetch_assoc()){
            $column=$getMapData['columns'];
            $map=$getMapData['mapping'];
            if ($map!=""){
                $columns["$map"]=$column;
            }

        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["action"])){
            $elements[]=$columns["action"]." as action";
        }
        if (isset($columns["description"])){
            $elements[]=$columns["description"]." as description";
        }
        if (isset($columns["tag"])){
            $elements[]=$columns["tag"]." as tag";
        }

        if (isset($columns["from"])){
            $elements[]=$columns["from"]." as Zonefrom";
        }
        if (isset($columns["user"])){
            $elements[]=$columns["user"]." as user";
        }
        if (isset($columns["to"])){
            $elements[]=$columns["to"]." as Zoneto";
        }
        if (isset($columns["src"])){
            $elements[]=$columns["src"]." as src";
        }
        if (isset($columns["dst"])){
            $elements[]=$columns["dst"]." as dst";
        }
        if (isset($columns["isdisabled"])){
            $elements[]=$columns["isdisabled"]." as disabled";
        }
        if (isset($columns["service"])){
            $elements[]=$columns["service"]." as service";
        }
        if (isset($columns["app"])){
            $elements[]=$columns["app"]." as app";
        }
        if (isset($columns["negate_src"])){
            $elements[]=$columns["negate_src"]." as negate_src";
        }
        if (isset($columns["negate_dst"])){
            $elements[]=$columns["negate_dst"]." as negate_dst";
        }
        if (isset($columns["log_start"])){
            $elements[]=$columns["log_start"]." as log_start";
        }
        if (isset($columns["log_end"])){
            $elements[]=$columns["log_end"]." as log_end";
        }
        if (isset($columns["protocol"])){
            $elements[]=$columns["protocol"]." as protocol";
        }
        if (isset($columns["sport"])){
            $elements[]=$columns["sport"]." as sport";
        }
        if (isset($columns["dport"])){
            $elements[]=$columns["dport"]." as dport";
        }

        $addFrom = array();
        $addTo = array();
        $addUser = array();
        $addApp = array();
        $addSrv = array();
        $addSrc = array();
        $addDst = array();
        $allZones = array();
        $addTag = array();

        if (count($elements)>0){
            $sql="SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll=$projectdb->query($sql);
            if ($getAll->num_rows>0){
                $addGroup=array();
                $addMembers=array();
                #get Last ID for the table
                $getMax=$projectdb->query("SELECT MAX(id) as maxid FROM $table;");
                if ($getMax->num_rows==1){
                    $getMaxData=$getMax->fetch_assoc();
                    $grpID=$getMaxData["maxid"]+1;
                    if ($grpID==""){
                        $grpID=1;
                    }
                }
                else{
                    $grpID=1;
                }
                $getMax=$projectdb->query("SELECT MAX(position) as maxid FROM $table WHERE source='$source' AND vsys='$vsys';");
                if ($getMax->num_rows==1){
                    $getMaxData=$getMax->fetch_assoc();
                    $position=$getMaxData["maxid"]+1;
                    if ($position==""){
                        $position=1;
                    }
                }
                else{
                    $position=1;
                }
                $theFirstgrpID=$grpID;
                //$rulenameid=1;
                while ($getAllData=$getAll->fetch_assoc()){
                    $name="";$name_ext="";$latitude=0;$address_all="";$tag_clean_array=array();$negate_source=0;$negate_destination=0;$log_start=0;$log_end=1;$disabled=0;
                    if (isset($getAllData["name"])){
                        $name_ext=$getAllData["name"];
                        $name =  truncate_rulenames(normalizeNames($name_ext));
                    }
                    else{
                        //$name="Rule ".$rulenameid;
                        $name="Rule ".$grpID;
                        //$rulenameid++;
                    }
                    if (isset($getAllData['action'])){
                        $action_raw=  strtolower($getAllData['action']);
                        if ( ($action_raw=="allow") OR ($action_raw=="permit") OR ($action_raw=="") OR ($action_raw=="accept")){
                            $Action="allow";
                        }
                        else{
                            $Action="deny";
                        }
                    }
                    else{
                        $Action="allow";
                    }
                    if (isset($getAllData['Zonefrom'])){
                        $members_all=$getAllData['Zonefrom'];
                        $members_array=explode(",",$members_all);
                        foreach($members_array as $themember){
                            $addFrom[]="('$grpID','$themember','$source','$vsys','csv')";
                            $allZones[]=$themember;
                        }
                    }
                    if (isset($getAllData['user'])){
                        $members_all=$getAllData['user'];
                        $members_array=explode(",",$members_all);
                        foreach($members_array as $themember){
                            $addUser[]="('$grpID','$themember','$source','$vsys','csv')";
                        }
                    }
                    if (isset($getAllData['Zoneto'])){
                        $members_all=$getAllData['Zoneto'];
                        $members_array=explode(",",$members_all);
                        foreach($members_array as $themember){
                            $addTo[]="('$grpID','$themember','$source','$vsys','csv')";
                            $allZones[]=$themember;
                        }
                    }
                    if (isset($getAllData['app'])){

                        $members_all=$getAllData['app'];
                        $members_array=explode(",",$members_all);

                        foreach($members_array as $themember){

                            if(($themember != "any") && ($themember != "")){

                                $getApp = get_member_and_lid($themember,$source,$vsys,"application");
                                if ($getApp != ""){
                                    $member_lid = $getApp["member_lid"];
                                    $table_name = $getApp["table_name"];
                                    $addApp[] = "('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                }
                                else{
                                    #CREATE IT OR ALERT
                                    add_log2('error', 'Reading Applications from Security Policies', 'Security RuleID [' . $grpID . '] is using an Application that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'security_rules');
                                }
                            }
                        }
                    }
                    if (isset($getAllData['service'])){

                        $members_all=$getAllData['service'];
                        $members_array=explode(",",$members_all);

                        foreach($members_array as $themember){

                            if(($themember != "any") && ($themember != "")){

                                $getApp = get_member_and_lid($themember,$source,$vsys,"service");
                                if ($getApp != ""){
                                    $member_lid = $getApp["member_lid"];
                                    $table_name = $getApp["table_name"];
                                    $addSrv[] = "('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                }
                                else{
                                    #CREATE IT OR ALERT
                                    add_log2('error', 'Reading Services from Security Policies', 'Security RuleID [' . $grpID . '] is using a Service that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'security_rules');
                                }
                            }
                        }
                    }
                    if ( (isset($getAllData['protocol'])) AND (isset($getAllData['dport'])) ){
                        $table_name="services";
                        if (isset($getAllData['sport'])){
                            $sport=$getAllData['sport'];
                        }
                        else{
                            $sport="";
                        }
                        #Protocol IP change by TCP and UDP
                        if ($getAllData['protocol']=="ip"){$allprotocols=explode(",","tcp,udp");}
                        elseif ($getAllData['protocol']==""){$allprotocols="";}
                        else{
                            $allprotocols=explode(",",$getAllData['protocol']);
                        }
                        #Analyze to know if there are mixed tcp udp and other
                        $analyze=explode(",",$getAllData['protocol']);
                        $countall=count($analyze);
                        if(($kkkey = array_search("tcp", $analyze)) !== false) {
                            unset($analyze[$kkkey]);
                        }
                        if(($kkkey = array_search("udp", $analyze)) !== false) {
                            unset($analyze[$kkkey]);
                        }
                        $countafter=count($analyze);
                        if ($countafter=="0"){$mixer=0;}
                        else{
                            if ($countall==$countafter){
                                $mixer=0;
                            }
                            else{
                                $mixer=1;
                            }

                        }
                        # If mixer=1 means we have mixed tcp/udp with other protocols. Rule need to ne cloned and added the app in the new one.

                        if ($allprotocols!=""){
                            foreach ($allprotocols as $kkey=>$protocol){
                                $protocol=strtolower($protocol);
                                if (($protocol=="tcp") OR ($protocol=="udp")){
                                    $allports=array();
                                    if ($getAllData['dport']==""){
                                        $allports[]="1-65535";
                                    }
                                    else{
                                        $allports=explode(",",$getAllData['dport']);
                                    }

                                    foreach ($allports as $key=>$dport){

                                        $checkDup=$projectdb->query("SELECT id FROM $table_name WHERE protocol='$protocol' AND dport='$dport' AND sport='$sport' AND source='$source' LIMIT 1;");
                                        if ($checkDup->num_rows==1){
                                            $checkDupdata=$checkDup->fetch_assoc();
                                            $member_lid=$checkDupdata['id'];
                                        }
                                        else{
                                            if (preg_match("/-/",$dport)){
                                                $srvname0="range-".$protocol."-".$sport."-".$dport;
                                            }
                                            else{
                                                $srvname0=$protocol."-".$sport."-".$dport;
                                            }
                                            $srvname_ext = str_replace("--", "-", $srvname0);
                                            $srvname=  normalizeNames($srvname_ext);
                                            $projectdb->query("INSERT INTO $table_name (source,vsys,name,name_ext,used,devicegroup,sport,dport,protocol) VALUES ('$source','$vsys','$srvname','$srvname_ext','1','csv','$sport','$dport','$protocol');");
                                            $member_lid=$projectdb->insert_id;
                                        }
                                        $addSrv[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";

                                    }

                                }
                                elseif (is_numeric($protocol)){
                                    $getApp = $projectdb->query("SELECT id,name FROM default_applications WHERE default_protocol='$protocol';");
                                    if ($getApp->num_rows == 1) {
                                        $getAppData = $getApp->fetch_assoc();
                                        $member_lid = $getAppData['id'];
                                        $table_name = "default_applications";
                                        if ($mixer==0){
                                            $addApp[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                        }
                                        else {
                                            $clone[$grpID][$identifier]["member_lid"]=$member_lid;
                                            $clone[$grpID][$identifier]["table_name"]=$table_name;
                                            $identifier++;
                                        }
                                    }
                                    else{
                                        add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $grpID . '] is using an Unknown Protocol Number [' . $protocol . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'security_rules');
                                    }
                                }
                                else{
                                    # name
                                    $getApp = $projectdb->query("SELECT id,name FROM default_applications WHERE name='$protocol';");
                                    if ($getApp->num_rows == 1) {
                                        $getAppData = $getApp->fetch_assoc();
                                        $member_lid = $getAppData['id'];
                                        $table_name = "default_applications";
                                        if ($mixer==0){
                                            $addApp[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                        }
                                        else {
                                            $clone[$grpID][$identifier]["member_lid"]=$member_lid;
                                            $clone[$grpID][$identifier]["table_name"]=$table_name;
                                            $identifier++;
                                        }
                                    }
                                    else{
                                        add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $grpID . '] is using an Unknown Protocol Name [' . $protocol . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'security_rules');
                                    }
                                }
                            }
                        }
                    }

                    if (isset($getAllData['src'])){

                        $members_all=$getAllData['src'];
                        $members_array=explode(",",$members_all);

                        foreach($members_array as $themember) {

                            if(($themember != "any") && ($themember != "")){

                                $getApp = get_member_and_lid($themember, $source, $vsys, "address");
                                if ($getApp != "") {
                                    $member_lid = $getApp["member_lid"];
                                    $table_name = $getApp["table_name"];
                                    $addSrc[] = "('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                } else {
                                    if ((ip_version($themember) != "noip") OR (preg_match("/\//", $themember))) {
                                        $memberANetwork = explode("/", $themember);
                                        $memberAIPversion = ip_version($memberANetwork[0]);
                                        if (!isset($memberANetwork[1])) {
                                            if ($memberAIPversion == "v4") {
                                                $memberAmask = "32";
                                            } else {
                                                $memberAmask = "128";
                                            }
                                        } else {
                                            $memberAmask = $memberANetwork[1];
                                        }
                                        $getDup = $projectdb->query("SELECT id FROM address WHERE name='$themember' AND source='$source' AND vsys = 'shared' AND dummy=1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address";
                                        } else {
                                            $address_table = "address";
                                            $projectdb->query("INSERT INTO $address_table (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,devicegroup) VALUES ('$source','$vsys',0,'ip-netmask','$themember','$themember','$memberANetwork[0]','$memberAmask','csv');");
                                            $member_lid = $projectdb->insert_id;
                                            $table_name = $address_table;
                                        }
                                        $addSrc[] = "('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                    } else {
                                        #CREATE IT OR ALERT
                                        add_log2('error', 'Reading Sources from Security Policies', 'Security RuleID [' . $grpID . '] is using a Source that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'security_rules');
                                    }
                                }
                            }
                        }
                    }

                    if (isset($getAllData['dst'])){

                        $members_all=$getAllData['dst'];
                        $members_array=explode(",",$members_all);

                        foreach($members_array as $themember){

                            if(($themember != "any") && ($themember != "")){

                                $getApp=get_member_and_lid($themember,$source,$vsys,"address");
                                if ($getApp!=""){
                                    $member_lid=$getApp["member_lid"];
                                    $table_name=$getApp["table_name"];
                                    $addDst[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                }
                                else{
                                    if ((ip_version($themember) != "noip") OR ( preg_match("/\//", $themember))) {
                                        $memberANetwork = explode("/", $themember);
                                        $memberAIPversion = ip_version($memberANetwork[0]);
                                        if (!isset($memberANetwork[1])) {
                                            if ($memberAIPversion == "v4") {
                                                $memberAmask = "32";
                                            } else {
                                                $memberAmask = "128";
                                            }
                                        }
                                        else {
                                            $memberAmask=$memberANetwork[1];
                                        }
                                        $getDup = $projectdb->query("SELECT id FROM address WHERE name='$themember' AND source='$source' AND vsys = 'shared' AND dummy=1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address";
                                        } else {
                                            $address_table="address";
                                            $projectdb->query("INSERT INTO $address_table (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,devicegroup) VALUES ('$source','$vsys',0,'ip-netmask','$themember','$themember','$memberANetwork[0]','$memberAmask','csv');");
                                            $member_lid = $projectdb->insert_id;
                                            $table_name = $address_table;
                                        }
                                        $addDst[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                    }
                                    else{
                                        #CREATE IT OR ALERT
                                        add_log2('error', 'Reading Destination from Security Policies', 'Security RuleID [' . $grpID . '] is using a Destination that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'security_rules');
                                    }
                                }
                            }
                        }
                    }

                    if (isset($getAllData['tag'])){

                        $members_all = $getAllData['tag'];
                        $members_array = explode(",",$members_all);

                        foreach($members_array as $themember) {

                            if(($themember != "any") && ($themember != "")){

                                $getDup = $projectdb->query("SELECT id FROM tag WHERE name='$themember' AND source='$source' AND vsys = '$vsys';");
                                if ($getDup->num_rows == 1) {
                                    $getDupData = $getDup->fetch_assoc();
                                    $member_lid = $getDupData['id'];
                                }
                                else {
                                    $projectdb->query("INSERT INTO tag (source,vsys,name,color) VALUES ('$source','$vsys','$themember','color4');");
                                    $member_lid = $projectdb->insert_id;
                                }
                                $addTag[] = "('$grpID','$member_lid','tag','$source','$vsys','csv')";
                            }
                        }
                    }

                    if (isset($getAllData['negate_src'])){
                        $negate_source_raw = $getAllData['negate_src'];
                        if ( ($negate_source_raw=="yes") OR ($negate_source_raw=="1") ){
                            $negate_source="1";
                        }
                        else{
                            $negate_source="0";
                        }
                    }

                    if (isset($getAllData['negate_dst'])){
                        $negate_destination_raw = $getAllData['negate_dst'];
                        if ( ($negate_destination_raw=="yes") OR ($negate_destination_raw=="1") ){
                            $negate_destination="1";
                        }
                        else{
                            $negate_destination="0";
                        }
                    }

                    if (isset($getAllData['log_start'])){
                        $log_start_raw = $getAllData['log_start'];
                        if ( ($log_start_raw=="yes") OR ($log_start_raw=="1") ){
                            $log_start="1";
                        }
                        else{
                            $log_start="0";
                        }
                    }

                    if (isset($getAllData['disabled'])){
                        $disabled_raw = $getAllData['disabled'];
                        if ( ($disabled_raw=="yes") OR ($disabled_raw=="1") ){
                            $disabled="1";
                        }
                        else{
                            $disabled="0";
                        }
                    }

                    if (isset($getAllData['log_end'])){
                        $log_end_raw = $getAllData['log_end'];
                        if ( ($log_end_raw=="yes") OR ($log_end_raw=="1") ){
                            $log_end="1";
                        }
                        else{
                            $log_end="0";
                        }
                    }

                    if (isset($getAllData['description'])){
                        $description_raw=$getAllData['description'];
                        $description=  addslashes($description_raw);
                    }


                    $addRule[]="('$grpID','$position','$source','$vsys','$name','$name_ext','$description','csv','$negate_source','$negate_destination','$Action','$disabled','$log_start','$log_end','')";
                    $grpID++;$position++;$identifier=0;
                }

                if (count($addRule)>0){
                    $projectdb->query("INSERT INTO $table (id,position,source,vsys,name,name_ext,description,devicegroup,negate_source,negate_destination,action,disabled,log_start,log_end,tag) VALUES ".implode(",",$addRule).";");
                    unset($addRule);

                    if (count($addFrom)>0){
                        $UaddFrom=array_unique($addFrom);
                        $projectdb->query("INSERT INTO security_rules_from (rule_lid,name,source,vsys,devicegroup) VALUES ".implode(",",$UaddFrom).";");
                        unset($UaddFrom);
                    }

                    if (count($addTo)>0){
                        $UaddTo=array_unique($addTo);
                        $projectdb->query("INSERT INTO security_rules_to (rule_lid,name,source,vsys,devicegroup) VALUES ".implode(",",$UaddTo).";");
                        unset($UaddTo);
                    }
                    if (count($addUser)>0){
                        $projectdb->query("INSERT INTO security_rules_usr (rule_lid,name,source,vsys,devicegroup) VALUES ".implode(",",$addUser).";");
                        unset($addUser);
                    }
                    if (count($addApp)>0){
                        $projectdb->query("INSERT INTO security_rules_app (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addApp).";");
                        unset($addApp);
                    }
                    if (count($addSrv)>0){
                        $projectdb->query("INSERT INTO security_rules_srv (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addSrv).";");
                        unset($addSrv);
                    }
                    if (count($addSrc)>0){
                        $projectdb->query("INSERT INTO security_rules_src (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addSrc).";");
                        unset($addSrc);
                    }
                    if (count($addDst)>0){
                        $projectdb->query("INSERT INTO security_rules_dst (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addDst).";");
                        unset($addDst);
                    }
                    if (count($addTag)>0){
                        $projectdb->query("INSERT INTO security_rules_tag (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addTag).";");
                        unset($addTag);
                    }
                    if (count($allZones)>0){
                        $unique_zones=array_unique($allZones);
                        foreach ($unique_zones as $uzones){
                            $getZone=$projectdb->query("SELECT id FROM zones WHERE name='$uzones' AND source='$source' AND vsys='$vsys'");
                            if ($getZone->num_rows==0){
                                $projectdb->query("INSERT INTO zones (source,vsys,template,name,type) VALUES ('$source','$vsys','$template','$uzones','layer3');");
                            }
                        }
                    }

                    # Mixed Rules
                    if (count($clone)>0){
                        $getApplicationdefault = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND source='$source' AND vsys = 'shared';");
                        if ($getApplicationdefault->num_rows == 1) {
                            $getApplicationdefaultData = $getApplicationdefault->fetch_assoc();
                            $application_default = $getApplicationdefaultData['id'];
                        }
                        foreach ($clone as $rkey=>$values){
                            $newlid=clone_security_rule("", "-1", $vsys, $source, $rkey, "", $project);
                            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid='$newlid';");
                            foreach ($values as $akey=>$avalues){
                                $member_lid=$avalues["member_lid"];
                                $table_name=$avalues["table_name"];
                                $projectdb->query("INSERT INTO security_rules_app (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ('$newlid','$member_lid','$table_name','$source','$vsys','csv');");
                            }
                            if ($application_default!=""){
                                $projectdb->query("INSERT INTO security_rules_srv (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ('$newlid','$application_default','services','$source','$vsys','csv');");
                            }
                        }
                    }

                }
                #Calculate Used
                check_used_objects_new($sourcesAdded);
                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }

        #Calculate Layer4-7
        $queryRuleIds = "SELECT id from security_rules WHERE source = $source;";
        $resultRuleIds = $projectdb->query($queryRuleIds);
        if($resultRuleIds->num_rows>0){
            $rules = array();
            while($dataRuleIds = $resultRuleIds->fetch_assoc()){
                $rules[] = $dataRuleIds['id'];
            }
            $rulesString = implode(",", $rules);
            $securityRulesMan = new \SecurityRulePANObject();
            $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
        }


    }

}

function importCSVNat($projectdb, $source, $vsys, $template, $project, $sourcesAdded){

    $table = "nat_rules";
    $clone = array();

    $getMap=$projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns = array();

        while ($getMapData=$getMap->fetch_assoc()){
            $column = $getMapData['columns'];
            $map = $getMapData['mapping'];
            if ($map != ""){
                $columns["$map"] = $column;
            }

        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["description"])){
            $elements[]=$columns["description"]." as description";
        }
        if (isset($columns["tag"])){
            $elements[]=$columns["tag"]." as tag";
        }
        if (isset($columns["from"])){
            $elements[]=$columns["from"]." as Zonefrom";
        }
        if (isset($columns["to"])){
            $elements[]=$columns["to"]." as Zoneto";
        }
        if (isset($columns["src"])){
            $elements[]=$columns["src"]." as src";
        }
        if (isset($columns["dst"])){
            $elements[]=$columns["dst"]." as dst";
        }
        if (isset($columns["isdisabled"])){
            $elements[]=$columns["isdisabled"]." as disabled";
        }
        if (isset($columns["service"])){
            $elements[]=$columns["service"]." as service";
        }
        if (isset($columns["interface"])){
            $elements[]=$columns["interface"]." as interface";
        }
        if (isset($columns["tp_source"])){
            $elements[]=$columns["tp_source"]." as tp_source";
        }
        if (isset($columns["tp_destination"])){
            $elements[]=$columns["tp_destination"]." as tp_destination";
        }
        if (isset($columns["tp_port"])){
            $elements[]=$columns["tp_port"]." as tp_port";
        }

        if (isset($columns["tp_sat_bidirectional"])){
            $elements[]=$columns["tp_sat_bidirectional"]." as tp_sat_bidirectional";
        }

        if (count($elements)>0){
            $sql = "SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll = $projectdb->query($sql);
            if ($getAll->num_rows>0){
                $addGroup = array();
                $addMembers = array();

                #get Last ID for the table
                $getMax = $projectdb->query("SELECT MAX(id) as maxid FROM $table;");
                if ($getMax->num_rows == 1){
                    $getMaxData = $getMax->fetch_assoc();
                    $grpID = $getMaxData["maxid"]+1;
                    if ($grpID == ""){
                        $grpID = 1;
                    }
                }
                else{
                    $grpID = 1;
                }
                $getMax=$projectdb->query("SELECT MAX(position) as maxid FROM $table WHERE source='$source' AND vsys='$vsys';");
                if ($getMax->num_rows == 1){
                    $getMaxData = $getMax->fetch_assoc();
                    $position = $getMaxData["maxid"]+1;
                    if ($position == ""){
                        $position = 1;
                    }
                }
                else{
                    $position = 1;
                }
                $theFirstgrpID = $grpID;
                $addSrc = array();
                $addDst = array();
                $addFrom = array();
                $addTPSource = array();
                $addTag = array();
                $allZones = array();

                //$rulenameid = 1;
                while ($getAllData = $getAll->fetch_assoc()){
                    $name = ""; $name_ext = "";
                    $tag_clean_array = array();
                    $disabled = 0;
                    $tp_dat_address_lid = "";
                    $tp_dat_address_table = "";
                    $tp_dat_port = "";
                    $op_service_lid = "";
                    $op_service_table = "";
                    $tags = "";
                    $op_zone_to = "";
                    $op_to_interface = "";
                    $tp_sat_type = "None";
                    $tp_sat_bidirectional = "0";
                    $is_dat = "0";

                    if (isset($getAllData["name"])){
                        $name_ext = $getAllData["name"];
                        $name =  truncate_rulenames(normalizeNames($name_ext));
                    }
                    else{
                        //$name = "Rule ".$rulenameid;
                        $name = "Rule ".$grpID;
                        //$rulenameid ++;
                    }
                    if (isset($getAllData['Zonefrom'])){
                        $members_all = $getAllData['Zonefrom'];
                        $members_array = explode(",", $members_all);
                        foreach($members_array as $themember){
                            $addFrom[] = "('$grpID', '$themember', '$source', '$vsys', 'csv')";
                            $allZones[] = $themember;
                        }
                    }

                    if (isset($getAllData['Zoneto'])){
                        $op_zone_to = $getAllData['Zoneto'];
                        $allZones[] = $op_zone_to;

                    }

                    if (isset($getAllData['service'])){
                        $themember = $getAllData['service'];

                        if(($themember != "any") && ($themember != "")){

                            $getApp = get_member_and_lid($themember,$source,$vsys,"service");
                            if ($getApp!=""){
                                $op_service_lid = $getApp["member_lid"];
                                $op_service_table = $getApp["table_name"];
                            }
                            else{
                                #CREATE IT OR ALERT
                                add_log2('error', 'Reading Services from Nat Policies', 'Nat RuleID [' . $grpID . '] is using a Service that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'nat_rules');
                            }
                        }
                    }

                    if (isset($getAllData['src'])){

                        $members_all=$getAllData['src'];
                        $members_array=explode(",",$members_all);

                        foreach($members_array as $themember){

                            if(($themember != "any") && ($themember != "")){

                                $getApp=get_member_and_lid($themember,$source,$vsys,"address");
                                if ($getApp!=""){
                                    $member_lid=$getApp["member_lid"];
                                    $table_name=$getApp["table_name"];
                                    $addSrc[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                }
                                else{
                                    #CREATE IT OR ALERT
                                    if ((ip_version($themember) != "noip") OR ( preg_match("/\//", $themember))) {
                                        $memberANetwork = explode("/", $themember);
                                        $memberAIPversion = ip_version($memberANetwork[0]);
                                        if (!isset($memberANetwork[1])) {
                                            if ($memberAIPversion == "v4") {
                                                $memberAmask = "32";
                                            } else {
                                                $memberAmask = "128";
                                            }
                                        }
                                        else {
                                            $memberAmask=$memberANetwork[1];
                                        }
                                        $getDup = $projectdb->query("SELECT id FROM address WHERE name='$themember' AND source='$source' AND vsys = 'shared' AND dummy=1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address";
                                        } else {
                                            $address_table="address";
                                            $projectdb->query("INSERT INTO $address_table (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,devicegroup) VALUES ('$source','$vsys',0,'ip-netmask','$themember','$themember','$memberANetwork[0]','$memberAmask','csv');");
                                            $member_lid = $projectdb->insert_id;
                                            $table_name = $address_table;
                                        }
                                        $addSrc[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                    }
                                    else{

                                        add_log2('error', 'Reading Source from Nat Policies', 'Nat RuleID [' . $grpID . '] is using a Source that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'nat_rules');
                                    }
                                }
                            }
                        }
                    }

                    if (isset($getAllData['dst'])){

                        $members_all=$getAllData['dst'];
                        $members_array=explode(",",$members_all);

                        foreach($members_array as $themember){

                            if(($themember != "any") && ($themember != "")){

                                $getApp=get_member_and_lid($themember,$source,$vsys,"address");
                                if ($getApp!=""){
                                    $member_lid=$getApp["member_lid"];
                                    $table_name=$getApp["table_name"];
                                    $addDst[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                }
                                else{
                                    #CREATE IT OR ALERT
                                    if ((ip_version($themember) != "noip") OR ( preg_match("/\//", $themember))) {
                                        $memberANetwork = explode("/", $themember);
                                        $memberAIPversion = ip_version($memberANetwork[0]);
                                        if (!isset($memberANetwork[1])) {
                                            if ($memberAIPversion == "v4") {
                                                $memberAmask = "32";
                                            } else {
                                                $memberAmask = "128";
                                            }
                                        }
                                        else {
                                            $memberAmask=$memberANetwork[1];
                                        }
                                        $getDup = $projectdb->query("SELECT id FROM address WHERE name='$themember' AND source='$source' AND vsys = 'shared' AND dummy=1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address";
                                        } else {
                                            $address_table="address";
                                            $projectdb->query("INSERT INTO $address_table (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,devicegroup) VALUES ('$source','$vsys',0,'ip-netmask','$themember','$themember','$memberANetwork[0]','$memberAmask','csv');");
                                            $member_lid = $projectdb->insert_id;
                                            $table_name = $address_table;
                                        }
                                        $addDst[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                    }
                                    else{
                                        add_log2('error', 'Reading Destination from Nat Policies', 'Nat RuleID [' . $grpID . '] is using a Destination that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'nat_rules');
                                    }
                                }
                            }
                        }
                    }

                    // TP Destination
                    if(isset($getAllData['tp_destination'])){

                        $themember = $getAllData['tp_destination'];

                        if(($themember != "any") && ($themember != "")){

                            $getApp=get_member_and_lid($themember,$source,$vsys,"address");
                            if ($getApp!=""){
                                $is_dat = "1";
                                $tp_dat_address_lid = $getApp["member_lid"];
                                $tp_dat_address_table = $getApp["table_name"];

                            }
                            else{
                                #CREATE IT OR ALERT
                                if ((ip_version($themember) != "noip") OR ( preg_match("/\//", $themember))) {
                                    $memberANetwork = explode("/", $themember);
                                    $memberAIPversion = ip_version($memberANetwork[0]);
                                    if (!isset($memberANetwork[1])) {
                                        if ($memberAIPversion == "v4") {
                                            $memberAmask = "32";
                                        } else {
                                            $memberAmask = "128";
                                        }
                                    }
                                    else {
                                        $memberAmask=$memberANetwork[1];
                                    }
                                    $getDup = $projectdb->query("SELECT id FROM address WHERE name='$themember' AND source='$source' AND vsys = 'shared' AND dummy=1;");
                                    if ($getDup->num_rows == 1) {
                                        $getDupData = $getDup->fetch_assoc();
                                        $tp_dat_address_lid = $getDupData['id'];
                                        $tp_dat_address_table = "address";
                                    } else {
                                        $address_table="address";
                                        $projectdb->query("INSERT INTO $address_table (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,devicegroup) VALUES ('$source','$vsys',0,'ip-netmask','$themember','$themember','$memberANetwork[0]','$memberAmask','csv');");
                                        $tp_dat_address_lid = $projectdb->insert_id;
                                        $tp_dat_address_table = $address_table;
                                    }

                                }
                                else{
                                    add_log2('error', 'Reading TP Destination from Nat Policies', 'Nat RuleID [' . $grpID . '] is using a TP Destination that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'nat_rules');
                                }
                            }
                        }
                    }

                    // TP Source
                    if (isset($getAllData['tp_source'])){

                        $members_all=$getAllData['tp_source'];
                        $members_array=explode(",",$members_all);

                        foreach($members_array as $themember){

                            if(($themember != "any") && ($themember != "")){

                                $tp_sat_type = "dynamic-ip";
                                $getApp=get_member_and_lid($themember,$source,$vsys,"address");
                                if ($getApp!=""){
                                    $member_lid=$getApp["member_lid"];
                                    $table_name=$getApp["table_name"];
                                    $addTPSource[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                }
                                else{
                                    #CREATE IT OR ALERT
                                    if ((ip_version($themember) != "noip") OR ( preg_match("/\//", $themember))) {
                                        $memberANetwork = explode("/", $themember);
                                        $memberAIPversion = ip_version($memberANetwork[0]);
                                        if (!isset($memberANetwork[1])) {
                                            if ($memberAIPversion == "v4") {
                                                $memberAmask = "32";
                                            } else {
                                                $memberAmask = "128";
                                            }
                                        }
                                        else {
                                            $memberAmask=$memberANetwork[1];
                                        }
                                        $getDup = $projectdb->query("SELECT id FROM address WHERE name='$themember' AND source='$source' AND vsys = 'shared' AND dummy=1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address";
                                        } else {
                                            $address_table="address";
                                            $projectdb->query("INSERT INTO $address_table (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,devicegroup) VALUES ('$source','$vsys',0,'ip-netmask','$themember','$themember','$memberANetwork[0]','$memberAmask','csv');");
                                            $member_lid = $projectdb->insert_id;
                                            $table_name = $address_table;
                                        }
                                        $addTPSource[]="('$grpID','$member_lid','$table_name','$source','$vsys','csv')";
                                    }
                                    else{
                                        add_log2('error', 'Reading TP Source from Nat Policies', 'Nat RuleID [' . $grpID . '] is using a TP Source that does not exist [' . $themember . ']. Fix it before to finish', $source, 'Check it manually', 'rules', $grpID, 'nat_rules');
                                    }
                                }
                            }
                        }
                    }

                    if (isset($getAllData['tag'])){

                        $members_all = $getAllData['tag'];
                        $members_array = explode(",",$members_all);

                        foreach($members_array as $themember) {

                            if(($themember != "any") && ($themember != "")){

                                $getDup = $projectdb->query("SELECT id FROM tag WHERE name='$themember' AND source='$source' AND vsys = '$vsys';");
                                if ($getDup->num_rows == 1) {
                                    $getDupData = $getDup->fetch_assoc();
                                    $member_lid = $getDupData['id'];
                                }
                                else {
                                    $projectdb->query("INSERT INTO tag (source,vsys,name,color) VALUES ('$source','$vsys','$themember','color4');");
                                    $member_lid = $projectdb->insert_id;
                                }
                                $addTag[] = "('$grpID','$member_lid','tag','$source','$vsys','csv')";
                            }
                        }
                    }

                    if (isset($getAllData['disabled'])){
                        $disabled_raw = $getAllData['disabled'];
                        if ( ($disabled_raw=="yes") OR ($disabled_raw=="1") ){
                            $disabled="1";
                        }
                        else{
                            $disabled="0";
                        }
                    }

                    if (isset($getAllData['description'])){
                        $description_raw=$getAllData['description'];
                        $description=  addslashes($description_raw);
                    }

                    if (isset($getAllData['tp_port'])){
                        $tp_dat_port = $getAllData['tp_port'];
                    }

                    if (isset($getAllData['interface'])){
                        $op_to_interface = $getAllData['interface'];
                    }

                    if (isset($getAllData['tp_sat_bidirectional'])){

                        if(($getAllData['tp_sat_bidirectional'] == "true") || ($getAllData['tp_sat_bidirectional'] == "1") ){
                            $tp_sat_bidirectional = "1";
                        }else{
                            $tp_sat_bidirectional = "0";
                        }
                    }

                    $addRule[]="('$grpID','$position','$source','$vsys','$name','$name_ext','$description','csv','$disabled','', '$tp_sat_type','$tp_sat_bidirectional', '$op_zone_to', '$op_service_lid', '$op_service_table', '$tp_dat_address_lid', '$tp_dat_address_table', '$tp_dat_port', '$op_to_interface', '$is_dat')";
                    $grpID++;
                    $position++;$identifier=0;
                }

                if (count($addRule)>0){
                    $projectdb->query("INSERT INTO $table (id,position,source,vsys,name,name_ext,description,devicegroup,disabled,tag, tp_sat_type, tp_sat_bidirectional, op_zone_to, op_service_lid, op_service_table, tp_dat_address_lid, tp_dat_address_table, tp_dat_port, op_to_interface, is_dat) VALUES ".implode(",",$addRule).";");
                    unset($addRule);

                    if (count($addFrom)>0){
                        $UaddFrom=array_unique($addFrom);
                        $projectdb->query("INSERT INTO nat_rules_from (rule_lid,name,source,vsys,devicegroup) VALUES ".implode(",",$UaddFrom).";");
                        unset($UaddFrom);
                    }

                    if (count($addSrc)>0){
                        $projectdb->query("INSERT INTO nat_rules_src (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addSrc).";");
                        unset($addSrc);
                    }

                    if (count($addDst)>0){
                        $projectdb->query("INSERT INTO nat_rules_dst (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addDst).";");
                        unset($addDst);
                    }

                    if (count($addTPSource)>0){
                        $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addTPSource).";");
                        unset($addTPSource);
                    }

                    if (count($addTag)>0){
                        $projectdb->query("INSERT INTO nat_rules_tag (rule_lid,member_lid,table_name,source,vsys,devicegroup) VALUES ".implode(",",$addTag).";");
                        unset($addTag);
                    }

                    if (count($allZones)>0){
                        $unique_zones=array_unique($allZones);
                        foreach ($unique_zones as $uzones){
                            $getZone=$projectdb->query("SELECT id FROM zones WHERE name='$uzones' AND source='$source' AND vsys='$vsys'");
                            if ($getZone->num_rows==0){
                                $projectdb->query("INSERT INTO zones (source,vsys,template,name,type) VALUES ('$source','$vsys','$template','$uzones','layer3');");
                            }
                        }
                    }
                }
                #Calculate Used
                check_used_objects_new($sourcesAdded);
                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }
    }
}

function importCSVInterfaces($projectdb, $source, $vsys, $template, $vr){

    $table="interfaces";
    $getMap=$projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns=array();
        while ($getMapData=$getMap->fetch_assoc()){
            $column=$getMapData['columns'];
            $map=$getMapData['mapping'];
            if ($map!=""){
                $columns["$map"]=$column;
            }
        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["media"])){
            $elements[]=$columns["media"]." as media";
        }
        if (isset($columns["ipaddress"])){
            $elements[]=$columns["ipaddress"]." as ipaddress";
        }
        if (isset($columns["zone"])){
            $elements[]=$columns["zone"]." as zone";
        }
        if (isset($columns["netmask"])){
            $elements[]=$columns["netmask"]." as netmask";
        }
        if (isset($columns["cidr"])){
            $elements[]=$columns["cidr"]." as cidr";
        }
        if (isset($columns["tag"])){
            $elements[]=$columns["tag"]." as tag";
        }
        if (isset($columns["ipaddress_netmask"])){
            $elements[]=$columns["ipaddress_netmask"]." as ipaddress_netmask";
        }
        if (isset($columns["ipaddress_cidr"])){
            $elements[]=$columns["ipaddress_cidr"]." as ipaddress_cidr";
        }
        if (isset($columns["secondaryip"])){
            $elements[]=$columns["secondaryip"]." as secondaryip";
        }

        if (count($elements)>0){

            $sql="SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll=$projectdb->query($sql);
            $allInterfaces=array();
            $allZones = array();

            if ($getAll->num_rows>0){
                $addAddressv4=array();
                $addAddressv6=array();

                $tag = "";
                $zone = "";

                while ($getAllData=$getAll->fetch_assoc()){

                    if (isset($getAllData["name"])){
                        $name=$getAllData["name"];
                    }
                    if (isset($getAllData['zone'])){
                        $zone=$getAllData['zone'];
                        $allZones[]=$zone;
                    }
                    if (isset($getAllData['media'])){
                        if ( ($getAllData['media']=="loopback") OR ($getAllData['media']=="ethernet") OR ($getAllData['media']=="aggregate-ethernet") OR ($getAllData['media']=="tunnel") OR ($getAllData['media']=="vlan")){
                            $media=$getAllData['media'];
                        }
                        else{
                            $media="ethernet";
                        }
                    }
                    if (isset($getAllData['tag'])){
                        $tag=intval($getAllData['tag']);
                    }
                    if ( (isset($getAllData["ipaddress"])) AND (isset($getAllData["netmask"]))  ){
                        $ipaddress=$getAllData["ipaddress"];
                        $cidr = mask2cidrv4($getAllData["netmask"]);
                        $interface_ipaddress=$ipaddress."/".$cidr;
                    }
                    elseif ( (isset($getAllData["ipaddress"])) AND (isset($getAllData["cidr"]))  ){
                        $ipaddress=$getAllData["ipaddress"];
                        $cidr = $getAllData["cidr"];
                        $interface_ipaddress=$ipaddress."/".$cidr;
                    }
                    elseif (isset($getAllData['ipaddress_cidr'])){
                        $split=explode("/",$getAllData['ipaddress_cidr']);
                        $ipaddress=$split[0];
                        $interface_ipaddress=$getAllData['ipaddress_cidr'];
                    }
                    elseif (isset($getAllData['ipaddress_netmask'])){
                        $split=explode("/",$getAllData['ipaddress_netmask']);
                        $ipaddress=$split[0];
                        $netmask=$split[1];
                        $cidr = mask2cidrv4($netmask);
                        $interface_ipaddress=$ipaddress."/".$cidr;
                    }

                    if(isset($getAllData['secondaryip'])){
                        if($getAllData['secondaryip'] != ""){
                            $interface_ipaddress = $interface_ipaddress.",".$getAllData['secondaryip'];
                        }
                    }
                    $ip_version = ip_version($ipaddress);

                    if ($ip_version != "v6"){
                        if ($tag==0){
                            $unitname=$name;
                        }
                        else{
                            if (preg_match("/\./",$name)){
                                $unitname=$name;
                            }
                            else{
                                $unitname=$name.".".$tag;
                            }
                        }
                        $allInterfaces[]=$unitname;
                        $addAddressv4[]="('$source','$vsys','$name','$template','$vr','$interface_ipaddress','$unitname','$tag','$zone','$media')";
                    }
                    //elseif ($ip_version=="v6"){
                        # Not supported by now
                    //}
                }

                #get Last ID for the table
                $getMax=$projectdb->query("SELECT MAX(id) as maxid FROM $table;");
                if ($getMax->num_rows==1){
                    $getMaxData=$getMax->fetch_assoc();
                    $addressMax=$getMaxData["maxid"];
                    if ($addressMax==""){
                        $addressMax=0;
                    }
                }
                else{
                    $addressMax=0;
                }
                if (count($addAddressv4)>0){
                    $projectdb->query("INSERT INTO $table (source,vsys,name,template,vr_id,unitipaddress,unitname,unittag,zone,media) VALUES ".implode(",",$addAddressv4).";");
                    unset($addAddressv4);
                }
                if (count($addAddressv6)>0){

                }

                if (count($allZones) > 0) {
                    $unique_zones = array_unique($allZones);
                    foreach ($unique_zones as $uzones) {
                        $getZone = $projectdb->query("SELECT id FROM zones WHERE name='$uzones' AND source='$source' AND vsys='$vsys'");
                        if ($getZone->num_rows == 0) {
                            $projectdb->query("INSERT INTO zones (source,vsys,template,name,type) VALUES ('$source','$vsys','$template','$uzones','layer3');");
                        }
                    }
                }

                $getInterfaces=$projectdb->query("SELECT zone,unitname FROM interfaces WHERE id>$addressMax AND zone!='';");
                if ($getInterfaces->num_rows>0){
                    while($getInterfacesData=$getInterfaces->fetch_assoc()){
                        $intname=$getInterfacesData['unitname'];
                        $zoneInt=$getInterfacesData['zone'];
                        $getZones=$projectdb->query("SELECT id,interfaces FROM zones WHERE name='$zoneInt' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                        if ($getZones->num_rows==1){
                            $getZonesData=$getZones->fetch_assoc();
                            $zoneID=$getZonesData['id'];

                            if ($getZonesData['interfaces']!=""){
                                $interfaces0=explode(",",$getZonesData['interfaces']);
                                $interfaces0[]=$intname;
                                $unique=array_unique($interfaces0);
                            }
                            else{
                                $unique[]=$intname;
                            }

                            $projectdb->query("UPDATE zones SET interfaces='".implode(",",$unique)."' WHERE id='$zoneID';");
                            $unique=array();
                        }
                    }
                }

                #Update interfaces into the VR
                $getIntfromVR=$projectdb->query("SELECT interfaces FROM virtual_routers WHERE id='$vr';");
                if ($getIntfromVR->num_rows==1){
                    $getIntfromVRData=$getIntfromVR->fetch_assoc();
                    if ($getIntfromVRData['interfaces']!=""){
                        $interface_raw=explode(",",$getIntfromVRData['interfaces']);
                        $interfaceArray=array_merge($allInterfaces,$interface_raw);
                        $interfaceArrayUnique=array_unique($interfaceArray);
                    }
                    else{
                        $interfaceArrayUnique=$allInterfaces;
                    }

                    $projectdb->query("UPDATE virtual_routers SET interfaces ='".implode(",",$interfaceArrayUnique)."' WHERE id='$vr';");
                }

                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }
    }
}

function importCSVRoutesStatic($projectdb, $source, $vsys, $template, $vr){

    $table="routes_static";
    $getMap=$projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns=array();
        while ($getMapData=$getMap->fetch_assoc()){
            $column=$getMapData['columns'];
            $map=$getMapData['mapping'];
            if ($map!=""){
                $columns["$map"]=$column;
            }
        }
        if (isset($columns["name"])){
            $elements[]=$columns["name"]." as name";
        }
        if (isset($columns["metric"])){
            $elements[]=$columns["metric"]." as metric";
        }
        if (isset($columns["ipaddress"])){
            $elements[]=$columns["ipaddress"]." as ipaddress";
        }
        if (isset($columns["gateway"])){
            $elements[]=$columns["gateway"]." as gateway";
        }
        if (isset($columns["netmask"])){
            $elements[]=$columns["netmask"]." as netmask";
        }
        if (isset($columns["cidr"])){
            $elements[]=$columns["cidr"]." as cidr";
        }
        if (isset($columns["ipaddress_netmask"])){
            $elements[]=$columns["ipaddress_netmask"]." as ipaddress_netmask";
        }
        if (isset($columns["ipaddress_cidr"])){
            $elements[]=$columns["ipaddress_cidr"]." as ipaddress_cidr";
        }
        if (isset($columns["tointerface"])){
            $elements[]=$columns["tointerface"]." as tointerface";
        }

        if (count($elements)>0){
            $sql="SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll=$projectdb->query($sql);
            if ($getAll->num_rows>0){
                $addAddressv4=array();
                $addAddressv6=array();
                $x=1;
                while ($getAllData=$getAll->fetch_assoc()){
                    $tag_clean_array=array();$tags_array=array();$tags="";
                    if (isset($getAllData["name"])){
                        $name=$getAllData["name"];
                    }
                    if (isset($getAllData['zone'])){
                        $zone=$getAllData['zone'];
                        $allZones[]=$zone;
                    }
                    if (isset($getAllData['metric'])){
                        $metric=$getAllData['metric'];
                    }
                    if (isset($getAllData['gateway'])){
                        $gateway=$getAllData['gateway'];
                    }
                    if (isset($getAllData['tointerface'])){
                        $tointerface=$getAllData['tointerface'];
                    }

                    if ( (isset($getAllData["ipaddress"])) AND (isset($getAllData["netmask"]))  ){
                        $ipaddress=$getAllData["ipaddress"];
                        $cidr = mask2cidrv4($getAllData["netmask"]);
                        $interface_ipaddress=$ipaddress."/".$cidr;
                    }
                    elseif ( (isset($getAllData["ipaddress"])) AND (isset($getAllData["cidr"]))  ){
                        $ipaddress=$getAllData["ipaddress"];
                        $cidr = $getAllData["cidr"];
                        $interface_ipaddress=$ipaddress."/".$cidr;
                    }
                    elseif (isset($getAllData['ipaddress_cidr'])){
                        $split=explode("/",$getAllData['ipaddress_cidr']);
                        $ipaddress=$split[0];
                        $interface_ipaddress=$getAllData['ipaddress_cidr'];
                    }
                    elseif (isset($getAllData['ipaddress_netmask'])){
                        $split=explode("/",$getAllData['ipaddress_netmask']);
                        $ipaddress=$split[0];
                        $netmask=$split[1];
                        $cidr = mask2cidrv4($netmask);
                        $interface_ipaddress=$ipaddress."/".$cidr;
                    }

                    $ip_version = ip_version($ipaddress);

                    if ($ip_version=="v4"){
                        $ipversiongw=ip_version($gateway);
                        if ($ipversiongw=="v4"){
                            $nexthop="ip-address";
                            $nexthop_value=$gateway;
                        }
                        else{
                            #Can be a host or Interface
                            $nexthop="None";
                            $nexthop_value="";
                            $tointerface=$gateway;
                        }

                        if ($name==""){
                            $name="Route_csv ".$x; $x++;
                        }
                        $addAddressv4[]="('$source','$vsys','$name','$template','$vr','$interface_ipaddress','$metric','$tointerface','$nexthop','$nexthop_value')";
                        $name="";$tointerface="";$gateway="";$metric="";$nexthop="";$nexthop_value="";
                    }
                    elseif ($ip_version=="v6"){
                        //TODO
                        # Not supported by now
                    }
                }

                if (count($addAddressv4)>0){
                    $projectdb->query("INSERT INTO $table (source,vsys,name,template,vr_id,destination,metric,tointerface,nexthop,nexthop_value) VALUES ".implode(",",$addAddressv4).";");
                    unset($addAddressv4);
                }
                if (count($addAddressv6)>0){
                    //TODO
                }
                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }
    }
}

function importCSVZones($projectdb, $source, $vsys, $template, $vr){

    $getMap = $projectdb->query("SELECT columns, mapping FROM csv_mapping;");
    if ($getMap->num_rows>0){
        $columns = array();
        while ($getMapData = $getMap->fetch_assoc()){
            $column = $getMapData['columns'];
            $map = $getMapData['mapping'];
            if ($map != ""){
                $columns["$map"]=$column;
            }
        }
        if (isset($columns["name"])){
            $elements[] = $columns["name"]." as name";
        }
        if (isset($columns["type"])){
            $elements[] = $columns["type"]." as type";
        }
        if (isset($columns["interfaces"])){
            $elements[] = $columns["interfaces"]." as interfaces";
        }
        if (isset($columns["profile"])){
            $elements[] = $columns["profile"]." as profile";
        }
        if (isset($columns["log"])){
            $elements[] = $columns["log"]." as log";
        }
        if (isset($columns["include"])){
            $elements[] = $columns["include"]." as include";
        }
        if (isset($columns["exclude"])){
            $elements[] = $columns["exclude"]." as exclude";
        }
        if (isset($columns["enable_user"])){
            $elements[] = $columns["enable_user"]." as enable_user";
        }

        if (count($elements) > 0){
            $sql = "SELECT ".implode(",",$elements)." FROM csv_columns;";
            $getAll = $projectdb->query($sql);
            if ($getAll->num_rows > 0){
                while ($getAllData = $getAll->fetch_assoc()){
                    $interface = "";
                    $zone = "";
                    $profile = "";
                    $include = "";
                    $exclude = "";
                    $log_setting_id = "";
                    $log_setting_table_name = "";

                    if (isset($getAllData["name"])){
                        $zone = $getAllData["name"];
                    }

                    if (isset($getAllData['interfaces'])){
                        $interface = $getAllData['interfaces'];
                    }

                    $type = "layer3";

                    if (isset($getAllData['type'])){
                        if ( ($getAllData['type']=="virtual-wire") OR ($getAllData['type']=="tap") OR ($getAllData['type']=="layer2")
                            OR ($getAllData['type']=="tunnel") OR ($getAllData['type']=="layer3") OR ($getAllData['type']=="external")){
                            $type = $getAllData['type'];
                        }
                    }

                    if (isset($getAllData["profile"])){
                        $profile = $getAllData["profile"];
                    }

                    if (isset($getAllData["log"])){

                        $log = $getAllData["log"];

                        if($log != ""){
                            $getLog = $projectdb->query("SELECT id FROM log_settings WHERE name = '$log' AND source = '$source';");
                            if ($getLog->num_rows > 0) {
                                $getDataLog = $getLog->fetch_assoc();
                                $log_setting_id = $getDataLog["id"];
                                $log_setting_table_name = "log_settings";
                            }
                        }
                    }

                    if (isset($getAllData["include"])){
                        $include = $getAllData["include"];
                    }

                    if (isset($getAllData["exclude"])){
                        $exclude = $getAllData["exclude"];
                    }

                    if (isset($getAllData["enable_user"])){
                        $enable_user = $getAllData["enable_user"];
                    }

                    if($interface != ""){
                        $all_interfaces = explode(",", $interface);

                        foreach ($all_interfaces AS $interface_only){

                            if (preg_match("/ethernet/i", $interface_only)) {
                                $media = "ethernet";
                            }elseif(preg_match("/loopback/i", $interface_only)){
                                $media = "loopback";
                            }elseif(preg_match("/tunnel/i", $interface_only)){
                                $media = "tunnel";
                            }elseif(preg_match("/vlan/i", $interface_only)){
                                $media = "vlan";
                            }else{
                                $media = "ethernet";
                            }

                            $getInterface = $projectdb->query("SELECT id FROM interfaces WHERE unitname = '$interface_only' AND source = '$source' AND vsys = '$vsys'");
                            if ($getInterface->num_rows == 0) {
                                $projectdb->query("INSERT INTO interfaces (source, vsys, name, template, unitname, zone, media, type, vr_id) VALUES ('$source','$vsys','$interface_only','$template','$interface_only','$zone','$media', '$type', '$vr');");
                            }
                            else{
                                $getDataInterface = $getInterface->fetch_assoc();
                                $id_interfaces = $getDataInterface["id"];
                                $projectdb->query("UPDATE interfaces SET zone = '$zone' WHERE id = '$id_interfaces';");
                            }
                        }
                    }

                    $getZone = $projectdb->query("SELECT id FROM zones WHERE name='$zone' AND source='$source' AND vsys='$vsys'");
                    if ($getZone->num_rows == 0) {
                        $projectdb->query("INSERT INTO zones (source, vsys, template, name, type, interfaces, zone_protection_profile, log_setting_id, log_setting_table_name, include_list, exclude_list) VALUES ('$source', '$vsys', '$template', '$zone', '$type', '$interface', '$profile', '$log_setting_id', '$log_setting_table_name', '$include', '$exclude');");
                    }
                }

                $projectdb->query("TRUNCATE TABLE csv_columns;");
                $projectdb->query("TRUNCATE TABLE csv_mapping;");
            }
        }
    }

}

?>