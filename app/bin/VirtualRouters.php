<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action                 = (string)  (isset($_GET['action'])                 ? $_GET['action'] : '');
        $type                   = (string)  (isset($_GET['type'])                   ? $_GET['type'] : ''); // zip / xml / device
        $project                = (string)  (isset($_GET['project'])                ? $_GET['project'] : '');
        $devicename             = (string)  (isset($_GET['devicename'])             ? $_GET['devicename'] : '');
        $template               = (string)  (isset($_GET['template'])               ? $_GET['template'] : '');
        $source                 = (string)  (isset($_GET['source'])                 ? $_GET['source'] : '');
        $vsys                   = (string)  (isset($_GET['vsys'])                     ? $_GET['vsys'] : '');
        $start                  = (integer) (isset($_GET['start'])                  ? $_GET['start'] : '');
        $limit                  = (integer) (isset($_GET['limit'])                  ? $_GET['limit'] : '');
        $admin_dist_static      = (string) (isset($_GET['admin_dist_static'])       ? $_GET['admin_dist_static'] : '');
        $admin_dist_static_ipv6 = (string) (isset($_GET['admin_dist_static_ipv6'])  ? $_GET['admin_dist_static_ipv6'] : '');
        $admin_dist_ospf_int    = (string) (isset($_GET['admin_dist_ospf_int'])     ? $_GET['admin_dist_ospf_int'] : '');
        $admin_dist_ospf_ext    = (string) (isset($_GET['admin_dist_ospf_ext'])     ? $_GET['admin_dist_ospf_ext'] : '');
        $admin_dist_ospfv3_int  = (string) (isset($_GET['admin_dist_ospfv3_int'])   ? $_GET['admin_dist_ospfv3_int'] : '');
        $admin_dist_ospfv3_ext  = (string) (isset($_GET['admin_dist_ospfv3_ext'])   ? $_GET['admin_dist_ospfv3_ext'] : '');
        $admin_dist_ibgp        = (string) (isset($_GET['admin_dist_ibgp'])         ? $_GET['admin_dist_ibgp'] : '');
        $admin_dist_ebgp        = (string) (isset($_GET['admin_dist_ebgp'])         ? $_GET['admin_dist_ebgp'] : '');
        $admin_dist_rip         = (string) (isset($_GET['admin_dist_rip'])          ? $_GET['admin_dist_rip'] : '');
        $name                   = (string) (isset($_GET['name'])                    ? $_GET['name'] : '');
        $protocol               = (string) (isset($_GET['protocol'])                ? $_GET['protocol'] : '');
        $id                     = (string) (isset($_GET['id'])                      ? $_GET['id'] : '');
        $filter                 = (string)  (isset($_GET['filter'])                 ? $_GET['filter'] : '');
        break;
    case 'POST':
        $action                 = (string)  (isset($_POST['action'])                ? $_POST['action'] : '');
        $type                   = (string)  (isset($_POST['type'])                  ? $_POST['type'] : ''); // zip / xml / device
        $project                = (string)  (isset($_POST['project'])               ? $_POST['project'] : '');
        $devicename             = (string)  (isset($_POST['devicename'])            ? $_POST['devicename'] : '');
        $template               = (string)  (isset($_POST['template'])              ? $_POST['template'] : '');
        $source                 = (string)  (isset($_POST['source'])                ? $_POST['source'] : '');
        $vsys                   = (string)  (isset($_POST['vsys'])                  ? $_POST['vsys'] : '');
        $start                  = (integer) (isset($_POST['start'])                 ? $_POST['start'] : '');
        $limit                  = (integer) (isset($_POST['limit'])                 ? $_POST['limit'] : '');
        $admin_dist_static      = (string) (isset($_POST['admin_dist_static'])      ? $_POST['admin_dist_static'] : '');
        $admin_dist_static_ipv6 = (string) (isset($_POST['admin_dist_static_ipv6']) ? $_POST['admin_dist_static_ipv6'] : '');
        $admin_dist_ospf_int    = (string) (isset($_POST['admin_dist_ospf_int'])    ? $_POST['admin_dist_ospf_int'] : '');
        $admin_dist_ospf_ext    = (string) (isset($_POST['admin_dist_ospf_ext'])    ? $_POST['admin_dist_ospf_ext'] : '');
        $admin_dist_ospfv3_int  = (string) (isset($_POST['admin_dist_ospfv3_int'])  ? $_POST['admin_dist_ospfv3_int'] : '');
        $admin_dist_ospfv3_ext  = (string) (isset($_POST['admin_dist_ospfv3_ext'])  ? $_POST['admin_dist_ospfv3_ext'] : '');
        $admin_dist_ibgp        = (string) (isset($_POST['admin_dist_ibgp'])        ? $_POST['admin_dist_ibgp'] : '');
        $admin_dist_ebgp        = (string) (isset($_POST['admin_dist_ebgp'])        ? $_POST['admin_dist_ebgp'] : '');
        $admin_dist_rip         = (string) (isset($_POST['admin_dist_rip'])         ? $_POST['admin_dist_rip'] : '');
        $name                   = (string) (isset($_POST['name'])                   ? $_POST['name'] : '');
        $protocol               = (string) (isset($_POST['protocol'])               ? $_POST['protocol'] : '');
        $id                     = (string) (isset($_POST['id'])                     ? $_POST['id'] : '');
        $filter                 = (string)  (isset($_POST['filter'])                ? $_POST['filter'] : '');
        break;
    default:
        $action                 = (string)  (isset($_POST['action'])                ? $_POST['action'] : '');
        $type                   = (string)  (isset($_POST['type'])                  ? $_POST['type'] : ''); // zip / xml / device
        $project                = (string)  (isset($_POST['project'])               ? $_POST['project'] : '');
        $devicename             = (string)  (isset($_POST['devicename'])            ? $_POST['devicename'] : '');
        $template               = (string)  (isset($_POST['template'])              ? $_POST['template'] : '');
        $source                 = (string)  (isset($_POST['source'])                ? $_POST['source'] : '');
        $vsys                   = (string)  (isset($_POST['vsys'])                  ? $_POST['vsys'] : '');
        $start                  = (integer) (isset($_POST['start'])                 ? $_POST['start'] : '');
        $limit                  = (integer) (isset($_POST['limit'])                 ? $_POST['limit'] : '');
        $admin_dist_static      = (string) (isset($_POST['admin_dist_static'])      ? $_POST['admin_dist_static'] : '');
        $admin_dist_static_ipv6 = (string) (isset($_POST['admin_dist_static_ipv6']) ? $_POST['admin_dist_static_ipv6'] : '');
        $admin_dist_ospf_int    = (string) (isset($_POST['admin_dist_ospf_int'])    ? $_POST['admin_dist_ospf_int'] : '');
        $admin_dist_ospf_ext    = (string) (isset($_POST['admin_dist_ospf_ext'])    ? $_POST['admin_dist_ospf_ext'] : '');
        $admin_dist_ospfv3_int  = (string) (isset($_POST['admin_dist_ospfv3_int'])  ? $_POST['admin_dist_ospfv3_int'] : '');
        $admin_dist_ospfv3_ext  = (string) (isset($_POST['admin_dist_ospfv3_ext'])  ? $_POST['admin_dist_ospfv3_ext'] : '');
        $admin_dist_ibgp        = (string) (isset($_POST['admin_dist_ibgp'])        ? $_POST['admin_dist_ibgp'] : '');
        $admin_dist_ebgp        = (string) (isset($_POST['admin_dist_ebgp'])        ? $_POST['admin_dist_ebgp'] : '');
        $admin_dist_rip         = (string) (isset($_POST['admin_dist_rip'])         ? $_POST['admin_dist_rip'] : '');
        $name                   = (string) (isset($_POST['name'])                   ? $_POST['name'] : '');
        $protocol               = (string) (isset($_POST['protocol'])               ? $_POST['protocol'] : '');
        $id                     = (string) (isset($_POST['id'])                     ? $_POST['id'] : '');
        $filter                 = (string)  (isset($_POST['filter'])                ? $_POST['filter'] : '');
        break;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$template = $projectdb->real_escape_string($template);
$source = $projectdb->real_escape_string($source);
$vsys = $projectdb->real_escape_string($vsys);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$admin_dist_static = $projectdb->real_escape_string($admin_dist_static);
$admin_dist_static_ipv6 = $projectdb->real_escape_string($admin_dist_static_ipv6);
$admin_dist_ospf_int = $projectdb->real_escape_string($admin_dist_ospf_int);
$admin_dist_ospf_ext = $projectdb->real_escape_string($admin_dist_ospf_ext);
$admin_dist_ospfv3_int = $projectdb->real_escape_string($admin_dist_ospfv3_int);
$admin_dist_ospfv3_ext = $projectdb->real_escape_string($admin_dist_ospfv3_ext);
$admin_dist_ibgp = $projectdb->real_escape_string($admin_dist_ibgp);
$admin_dist_ebgp = $projectdb->real_escape_string($admin_dist_ebgp);
$admin_dist_rip = $projectdb->real_escape_string($admin_dist_rip);
$name = $projectdb->real_escape_string($name);
if($protocol!="") {
    $protocol = preg_replace('/\\\n\s*/', '', $protocol);
    $protocol = preg_replace('/\n\s*/', '', $protocol);
    $protocol = preg_replace('/\\\\+/', '', $protocol);
    $protocol = preg_replace('/>n\s</', '><', $protocol);
    $xml = simplexml_load_string($protocol);
    $protocol = preg_replace('/^<\?xml.*\?>\n/', '', $xml->asXML());
    //$protocol = $projectdb->real_escape_string($protocol);
}
$id = $projectdb->real_escape_string($id);
$filter = $projectdb->real_escape_string($filter);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if ($type == "vr") {

        // check if the "vsys" attribute is filled with a vsys or a DG
        // if it's a DG then we need to call generate_query method without taking the vsys in consideration: we are getting a call from autozone execution, for instance
        // otherwise we need to call generate_query method taking the vsys in consideration: we are getting the call from the main grid to display virtual_routers, for instance
        $generate_query_type = "template_not_vsys_all";
        $userSettings = get_UserSettings($project, $user_id);
        $get_vsys_array = getVsysBySourceByTemplate($source, $userSettings['msg']['panorama_template']);
        if (in_array($vsys,$get_vsys_array)){
            $generate_query_type = "template";
        }

        $query = generate_query($generate_query_type, $vsys);

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "20";
            $params['tools_advanced_columns_id'] = "None";
            $params['is_set_sql_filter'] = "yes";
            $params['source'] = $source;
            $params['vsys'] = $vsys;
            $params['case_sensitive'] = "0";

            setFilter($project, $params);
            executeSQL($project, $params);

        }
        elseif(($filter == "none") || ($filter == "0")){

        }

        list($query, $orderby) = generateQueryFilters($project, "virtual_routers", "", $query, $source);

        $myData = array();
        //$myData[]=array("id"=>"0","name"=>"None");
        $getAll = $projectdb->query("SELECT 'Static Routes: 0' as configuration,name,source,id,template,map_name,interfaces,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,multicast,protocol,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext FROM virtual_routers $query ORDER BY id,name;");
        if ($getAll->num_rows>0){
            while ($data = $getAll->fetch_assoc()) {
                $vrid = $data['id'];
                $source = $data['source'];
                $data['interfaces'] = implode(
                    ",",
                    array_sort(explode(
                        ",",
                        $data['interfaces'])
                    )
                );
                $getStatic = $projectdb->query("SELECT id FROM routes_static WHERE source='$source' AND vr_id='$vrid';");
                if ($getStatic->num_rows > 0) {
                    $data['configuration'] = "Static Routes: " . $getStatic->num_rows;
                }
                $myData[] = $data;
            }
        }

        echo '{"total":"' . count($myData) . '","vr":' . json_encode($myData) . '}';
    }
    elseif ($type == "vr_none") {

        $query = generate_query("template_not_vsys");

        $myData[]=array("id"=>"0","name"=>"None");

        $getAll = $projectdb->query("SELECT id, name FROM virtual_routers $query ORDER BY id,name;");
        if ($getAll->num_rows>0){
            while ($data = $getAll->fetch_assoc()) {
                $myData[] = $data;
            }
        }

        echo '{"total":"' . count($myData) . '","vr":' . json_encode($myData) . '}';
    }
    elseif ($type == "vsys_vr") {

        $query = generate_query("template_not_vsys_all");

        $getAll = $projectdb->query("SELECT 'Static Routes: 0' as configuration,name,source,id,template,map_name,interfaces,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,multicast,protocol,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext FROM virtual_routers $query ORDER BY id,name;");
        $count = $getAll->num_rows;
        if($count > 0){
            $myData[] = array("name" => "All Virtual Routers");
            while ($data = $getAll->fetch_assoc()) {
                $vrid = $data['id'];
                $source = $data['source'];

                $getStatic = $projectdb->query("SELECT id FROM routes_static WHERE source='$source' AND vr_id='$vrid';");

                if ($getStatic->num_rows > 0) {
                    $data['configuration'] = "Static Routes: " . $getStatic->num_rows;
                }

                $myData[] = $data;
            }
        }
        
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","vr":' . json_encode($myData) . '}';
    }
    elseif ($type == "static_routes") {

        $vrid = (string) (isset($_POST['vrid']) ? $_POST['vrid'] : $_GET['vrid']);
        $search = (string) (isset($_POST['search']) ? $_POST['search'] : $_GET['search']);

        $vrid = $projectdb->real_escape_string($vrid);
        $search = $projectdb->real_escape_string($search);

        $myData = [];
        if ($search == "") {
            $getAll = $projectdb->query("SELECT route_table,id, vr_id, template, source, ip_version, name_ext, name, destination, tointerface, nexthop, nexthop_value, metric, admin_dist, if(option_no_install = '1', 'on', '') AS option_no_install, zone, vsys, invalid, destination_member_lid, nexthop_value_member_lid  FROM routes_static WHERE vr_id='$vrid' AND source='$source' "
                    . "  ORDER BY id,name;");

            if ($getAll->num_rows>0){
                while ($data = $getAll->fetch_assoc()) {
                    $myData[] = $data;
                }
            }
        } else {
            $search = mysqli_real_escape_string($projectdb, $search);
            $search = str_replace("*", "", $search);
            $getAll = $projectdb->query("SELECT route_table,id, vr_id, template, source, ip_version, name_ext, name, destination, tointerface, nexthop, nexthop_value, metric, admin_dist, if(option_no_install = '1', 'on', '') AS option_no_install, zone, vsys, invalid, destination_member_lid, nexthop_value_member_lid FROM routes_static WHERE vr_id='$vrid' AND source='$source' "
                    . " AND ( name LIKE '%$search%' OR destination LIKE '%$search%' OR nexthop_value LIKE '%$search%' OR tointerface LIKE '%$search%')");

            if ($getAll->num_rows>0){
                while ($data = $getAll->fetch_assoc()) {
                    $myData[] = $data;
                }
            }
        }

        echo '{"total":"' . count($myData) . '","static_routes":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);

//        if ($idx != "") {
//            $thetag = array();
//            $getTag = $projectdb->query("SELECT interfaces FROM virtual_routers WHERE id='$idx';");
//            if ($getTag->num_rows == 1) {
//                $getTagData = $getTag->fetch_assoc();
//                $tags = $getTagData['interfaces'];
//                $tag = explode(",", $tags);
//                $count = count($tag);
//                foreach ($tag as $key => $value) {
//                    $thetag[] = array("name" => $value);
//                }
//                if ($tags == "") {
//                    $count = 0;
//                    $thetag = "";
//                }
//                echo '{"total":"' . $count . '","elements":' . json_encode($thetag) . '}';
//            }
//        }

        if($idx == ""){
            $idx = 0;
        }

        $address = array();
        $getAddress = $projectdb->query("SELECT interfaces FROM virtual_routers WHERE id = '$idx' AND interfaces != '';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['interfaces'];
            $add_explode = explode(",", $add);
            $count = count($add_explode);
            foreach ($add_explode as $key => $value) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value' AND type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                        $getIdData = $getBridgeId->fetch_assoc();
                        $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'interfaces', '$value', '$template', '0', '$user_id');");
                }

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'interfaces' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
                $count = $getLimit->num_rows;
                if ($getLimit->num_rows > 0) {
                    while ($data = $getLimit->fetch_object()) {
                        $address[] = $data;
                    }
                }
            }
            echo '{"total":"' . $count . '","elements":' . json_encode($address) . '}';
        }
        else{
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'interfaces' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            $count = $getLimit->num_rows;
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $address[] = $data;
                }
            }
            echo '{"total":"' . $count . '","elements":' . json_encode($address) . '}';
        }
    }
}
elseif ($action == "set") {
    if ($type == "remove_interface") {

        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $ids = $projectdb->real_escape_string($ids);

        if($idx == ""){
            $idx = 0;
        }

        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$value' AND lid = '$idx' AND type = 'interfaces' AND user_id = '$user_id';");
            }
        }

        echo json_encode(array("success" => true));
    }
    elseif ($type == "remove_vr") {

        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $template = $projectdb->real_escape_string($template);
        $ids = $projectdb->real_escape_string($ids);

        if ($ids != "") {

            $data = explode(",", $ids);
            take_snapshot_last($project);

            foreach ($data as $key => $value) {

                //Necesito el name del virtual router para poder eliminar la relación con virutal_system
                $getNameVr = $projectdb->query("SELECT name FROM virtual_routers WHERE id = '$value' ;");

                if ($getNameVr->num_rows != "") {
                    $getNameVrData = $getNameVr->fetch_assoc();
                    $name_vr = $getNameVrData['name'];
                }

                // 1. Dejar en "" el nexthop_value y el nexthop next-vr a None
                $getNextVr = $projectdb->query("SELECT rs.id AS id_route_static FROM routes_static rs, virtual_routers vr "
                        . "WHERE vr.id = '$value' AND vr.name = rs.nexthop_value;");

                if ($getNextVr->num_rows != "") {
                    while ($getNextVrData = $getNextVr->fetch_assoc()) {
                        $id_route_static = $getNextVrData['id_route_static'];
                        $projectdb->query("UPDATE routes_static SET nexthop_value = '', nexthop = 'None' WHERE id = '$id_route_static';");
                    }
                }

                // 2. En las interfaces poner a "" el vr_id que tiene asociado
                $getInterfaces = $projectdb->query("SELECT id, name FROM interfaces WHERE vr_id = '$value';");

                if ($getInterfaces->num_rows != "") {
                    while ($getInterfacesData = $getInterfaces->fetch_assoc()) {
                        $id_interface = $getInterfacesData['id'];
                        $name_interface = $getInterfacesData['name'];
                        $projectdb->query("UPDATE interfaces SET vr_id = '0' WHERE id = '$id_interface';");
                    }
                }

                // 3. Mirar en Virtual_systems si tiene asociado el virtual routers que se elimina y dejarlo a ""
                // La relación es 1 a n, pueden ser varios virtual_routers, por lo tanto, recorrer todos los registros y mirar
                // si tienen virtual routers asociados con el template asociado
                $getVirtualSystemVR = $projectdb->query("SELECT virtual_router, id FROM virtual_systems WHERE template = '$template';");

                if ($getVirtualSystemVR->num_rows != "") {
                    while ($getVirtualSystemVRData = $getVirtualSystemVR->fetch_assoc()) {

                        $virtual_routers = $getVirtualSystemVRData['virtual_router'];
                        $id_virtual_system = $getVirtualSystemVRData['id'];
                        $data_name_vr = explode(",", $name_vr);
                        $data = explode(",", $virtual_routers);
                        $diff = array_diff($data, $data_name_vr);

                        $projectdb->query("UPDATE virtual_systems SET virtual_router='" . implode(",", $diff) . "' WHERE id = '$id_virtual_system';");
                    }
                }

                // 4. Borrar static routes asociadas a este virtualroutes
                $projectdb->query("DELETE FROM routes_static WHERE vr_id = '$value';");
                // 5. Por ultimo, borrar el vr de la tabla virtual_routers
                $projectdb->query("DELETE FROM virtual_routers WHERE id = '$value';");
            }//foreach
        }//fin if ids
    }
    elseif ($type == "remove_static_routes") {

        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $ids = $projectdb->real_escape_string($ids);
        if ($ids != "") {
            $projectdb->query("DELETE FROM routes_static WHERE id IN ($ids);");
        }
    }
    elseif ($type == "remove_edit_table"){
        $getTruncate = $projectdb->query("DELETE FROM edit_table WHERE user_id = '$user_id';");
        $getDeleteVR = $projectdb->query("DELETE FROM routes_static WHERE vr_id = '0';");
        echo json_encode(array('success' => true));
    }
} 
elseif ($action == "add") {
    if ($type == "interfaces") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $template = $projectdb->real_escape_string($template);
        
        $query = generate_query("template");
        if (preg_match("/WHERE/i", $query)) {
            $query = $query . " AND (vr_id='' OR vr_id='0') AND type='layer3'";
        } else {
            $query = " WHERE (vr_id='' OR vr_id='0') AND type='layer3'";
        }
            
//        $set_all_interfaces = 0;
//
//        $getInterfaces = $projectdb->query("SELECT template,interfaces FROM virtual_routers WHERE id='$idx';");
//        if ($getInterfaces->num_rows == 1) {
//            $dataI = $getInterfaces->fetch_assoc();
//            $interfaces = $dataI['interfaces'];
//            $template = $dataI['template'];
//
//            if ($interfaces != "") {
//
//                $interfaces_array = explode(",", $interfaces);
//                $names_interfaces_array = explode(",", $total_name);
//
//                foreach($names_interfaces_array AS $name){
//
//                    if($set_all_interfaces != 1){
//
//                        if($name == "All Interfaces"){
//
//                            $projectdb->query("UPDATE interfaces SET vr_id='' WHERE template='$template' AND source='$source' AND vr_id='$idx';");
//
//                            $set_all_interfaces = 1;
//                            $getAllInterfaces = $projectdb->query("SELECT id,unitname FROM interfaces $query ORDER BY unitname;");
//                            $count = $getAllInterfaces->num_rows;
//                            if($count > 0){
//                                while ($dataAI = $getAllInterfaces->fetch_assoc()) {
//                                    $unitname_array[] = $dataAI['unitname'];
//                                    $id_interfaces_array[] = $dataAI['id'];
//                                }
//                                $ids_all_interfaces = implode(",", $id_interfaces_array);
//                                $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $unitname_array) . "' WHERE id='$idx';");
//                                $projectdb->query("UPDATE interfaces SET vr_id='$idx' WHERE template='$template' AND id IN ($ids_all_interfaces);");
//                            }
//                        }
//                        else{
//                            if (in_array($name, $interfaces_array)) {
//
//                            } else {
//                                $interfaces_array[] = $name;
//                                if (($key = array_search("", $interfaces_array)) !== false) {
//                                    unset($interfaces_array[$key]);
//                                }
//                                $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $interfaces_array) . "' WHERE id='$idx';");
//                                $projectdb->query("UPDATE interfaces SET vr_id='$idx' WHERE template='$template' AND unitname='$name';");
//                            }
//                        }
//                    }
//                }
//            }
//            else {
//
//                $projectdb->query("UPDATE virtual_routers SET interfaces='$total_name' WHERE id='$idx';");
//                $names_interfaces_array = explode(",", $total_name);
//                //aqui tb all interfaces
//                foreach($names_interfaces_array AS $name){
//
//                    if($set_all_interfaces != 1){
//
//                        if($name == "All Interfaces"){
//
//                            $set_all_interfaces = 1;
//                            $getAllInterfaces = $projectdb->query("SELECT id,unitname FROM interfaces $query ORDER BY unitname;");
//                            $count = $getAllInterfaces->num_rows;
//                            if($count > 0){
//                                while ($dataAI = $getAllInterfaces->fetch_assoc()) {
//                                    $unitname_array[] = $dataAI['unitname'];
//                                    $id_interfaces_array[] = $dataAI['id'];
//                                }
//                                $ids_all_interfaces = implode(",", $id_interfaces_array);
//                                $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $unitname_array) . "' WHERE id='$idx';");
//                                $projectdb->query("UPDATE interfaces SET vr_id='$idx' WHERE template='$template' AND id IN ($ids_all_interfaces);");
//                            }
//                        }
//                        else{
//                            $projectdb->query("UPDATE interfaces SET vr_id='$idx' WHERE template='$template' AND unitname='$name';");
//                        }
//                    }
//                }
//            }
//        }
//        echo json_encode(array("success" => true));

        if($idx == ""){
            $idx = 0;
        }

        $set_all_interfaces = 0;
        $name_interfaces = explode(",", $total_name);

        foreach ($name_interfaces AS $name){

            if($set_all_interfaces != 1){

                if($name != ""){

                    if($name == "All Interfaces"){

                        $set_all_interfaces = 1;
                        $getAllInterfaces = $projectdb->query("SELECT id,unitname FROM interfaces $query ORDER BY unitname;");
                        $count = $getAllInterfaces->num_rows;
                        if($count > 0){
                            while ($dataAI = $getAllInterfaces->fetch_assoc()) {
                                $unitname = $dataAI['unitname'];

                                $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'interfaces' AND name = '$unitname' AND user_id = '$user_id';");
                                if ($getBridge->num_rows == 0) {

                                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                                    if ($getBridgeId->num_rows == 1) {
                                        $getIdData = $getBridgeId->fetch_assoc();
                                        $ids = $getIdData['ids'] + 1;
                                    }else{
                                        $ids = 1;
                                    }

                                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                                        . "VALUES (NULL, '$ids', '$idx', 'interfaces', '$unitname', '$template', '0', '$user_id');");
                                }else{
                                    $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$unitname' AND type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                                }

                            }

                        }
                    }
                    else{
                        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'interfaces' AND name = '$name' AND user_id = '$user_id';");
                        if ($getBridge->num_rows == 0) {

                            $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                            if ($getBridgeId->num_rows == 1) {
                                $getIdData = $getBridgeId->fetch_assoc();
                                $ids = $getIdData['ids'] + 1;
                            }else{
                                $ids = 1;
                            }

                            $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                                . "VALUES (NULL, '$ids', '$idx', 'interfaces', '$name', '$template', '0', '$user_id');");
                        }else{
                            $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                        }
                    }
                }
            }

        }

        echo json_encode(array("success" => true));

    } 
    elseif ($type == "vr") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $template = $projectdb->real_escape_string($template);

        $protocol = "<bgp><routing-options><graceful-restart><enable>yes</enable></graceful-restart><as-format>2-byte</as-format></routing-options><enable>no</enable></bgp>";
        $id = $_POST['id'];

        if ($id == "") {
            $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys,protocol,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext) VALUES ('','$template','$source','$vsys','$protocol','10','30','110','200','20','120','10','30','110');");
        }
    } 
    elseif ($type == "static_router") {

        $admin_dist = (string) (isset($_POST['admin_dist']) ? $_POST['admin_dist'] : $_GET['admin_dist']);
        //$destination = (string) (isset($_POST['destination']) ? $_POST['destination'] : $_GET['destination']);
        $interface = (string) (isset($_POST['tointerface']) ? $_POST['tointerface'] : $_GET['tointerface']);
        $metric = (string) (isset($_POST['metric']) ? $_POST['metric'] : $_GET['metric']);
        $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $next_vr = (string) (isset($_POST['next-vr']) ? $_POST['next-vr'] : $_GET['next-vr']);
        $nexthop = (string) (isset($_POST['nexthop']) ? $_POST['nexthop'] : $_GET['nexthop']);
        $no_install = (string) (isset($_POST['option_no_install']) ? $_POST['option_no_install'] : '');
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $vrid = (string) (isset($_POST['vrid']) ? $_POST['vrid'] : $_GET['vrid']);

        $admin_dist = $projectdb->real_escape_string($admin_dist);
        $interface = $projectdb->real_escape_string($interface);
        $metric = $projectdb->real_escape_string($metric);
        $name = $projectdb->real_escape_string($name);
        $next_vr = $projectdb->real_escape_string($next_vr);
        $nexthop = $projectdb->real_escape_string($nexthop);
        $no_install = $projectdb->real_escape_string($no_install);
        $source = $projectdb->real_escape_string($source);
        $template = $projectdb->real_escape_string($template);
        $vsys = $projectdb->real_escape_string($vsys);
        $vrid = $projectdb->real_escape_string($vrid);


        if($interface == "All Interfaces") {
            echo json_encode(array("success" => false, "msg" => "Please select a valid Interface."));
            return -1;
        }

        // get the vsys from the virtual router selected so we make sure the new route is created with the valid vsys
        $query_vsys_from_VR = "SELECT vsys FROM virtual_routers where id = '$vrid';";
        $get_vsys = $projectdb->query($query_vsys_from_VR);
        if ($get_vsys->num_rows > 0 ){
            $data_vsys = $get_vsys->fetch_assoc();
            $vsys = $data_vsys['vsys'];
        }

        $ipaddress_value_name =  (isset($_POST['ipaddress_value_name']) ? $_POST['ipaddress_value_name'] : $_GET['ipaddress_value_name']);
        $nexthop_ipaddress_member_lid = (isset($_POST['nexthop_ipaddress_member_lid']) ? $_POST['nexthop_ipaddress_member_lid'] : $_GET['nexthop_ipaddress_member_lid']);

        $ipaddress_value_name = $projectdb->real_escape_string($ipaddress_value_name);
        $nexthop_ipaddress_member_lid = $projectdb->real_escape_string($nexthop_ipaddress_member_lid);

        $nexthop_fqdn_member_lid = (isset($_POST['nexthop_fqdn_member_lid']) ? $_POST['nexthop_fqdn_member_lid'] : $_GET['nexthop_fqdn_member_lid']);
        $fqdn_value_name = (isset($_POST['fqdn_value_name']) ? $_POST['fqdn_value_name'] : $_GET['fqdn_value_name']);

        $nexthop_fqdn_member_lid = $projectdb->real_escape_string($nexthop_fqdn_member_lid);
        $fqdn_value_name = $projectdb->real_escape_string($fqdn_value_name);

        $static_routes_destination = (isset($_POST['static_routes_destination']) ? $_POST['static_routes_destination'] : $_GET['static_routes_destination']);
        $static_routes_destination_member_lid = (isset($_POST['static_routes_destination_member_lid']) ? $_POST['static_routes_destination_member_lid'] : $_GET['static_routes_destination_member_lid']);


        $static_routes_destination = $projectdb->real_escape_string($static_routes_destination);
        $static_routes_destination_member_lid = $projectdb->real_escape_string($static_routes_destination_member_lid);

        # Panos 8
        $route_table = (string) (isset($_POST['route_table']) ? $_POST['route_table'] : 'unicast');

        $route_table = $projectdb->real_escape_string($route_table);

        take_snapshot_last($project);

        $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);
        $id = $projectdb->real_escape_string($id);

        $nexthop_member_lid = "";
        $nexthop_value = "";

        if(is_numeric($static_routes_destination_member_lid)){
            $destination_member_lid = $static_routes_destination_member_lid;
        }else{
            $destination_member_lid = "";
        }

        if ($nexthop == "ip-address") {
            $nexthop_value = $ipaddress_value_name;

            if(is_numeric($nexthop_ipaddress_member_lid)){
                $nexthop_member_lid = $nexthop_ipaddress_member_lid;
            }else{
                $nexthop_member_lid = "";
            }

        }
        elseif ($nexthop == "next-vr") {
            $nexthop_value = $next_vr;
        }
        elseif ($nexthop == "fqdn") {
            $nexthop_value = $fqdn_value_name;
            $nexthop_member_lid = $nexthop_fqdn_member_lid;
        }

        if ($no_install == "on") {
            $no_install = "1";
        } elseif ($no_install == "") {
            $no_install = "0";
        }

        if ($interface == "None") {
            $interface = "";
        }

        $zone = getZones($source, $vsys, $nexthop_value);

        //Comprovar si ya existe el vr_static_route en la BBDD, si es así, es un UPDATE
        $getStaticRoute = $projectdb->query("SELECT id FROM routes_static WHERE id='$id';");

        if ($getStaticRoute->num_rows == 1) {

            $projectdb->query("UPDATE routes_static "
                    . "SET name = '$name' ,"
                    . "destination = '$static_routes_destination' ,"
                    . "destination_member_lid = '$destination_member_lid' ,"
                    . "tointerface = '$interface',"
                    . "nexthop = '$nexthop',"
                    . "nexthop_value = '$nexthop_value',"
                    . "nexthop_value_member_lid = '$nexthop_member_lid',"
                    . "metric = '$metric', "
                    . "admin_dist = '$admin_dist', "
                    . "option_no_install = '$no_install', "
                    . "route_table = '$route_table', "
                    . "zone = '$zone' "
                    . "WHERE id='$id';");

        } else {

            $projectdb->query("INSERT INTO routes_static "
                    . "(route_table,vr_id, template, source, ip_version, name, destination, destination_member_lid, tointerface, nexthop, nexthop_value, nexthop_value_member_lid, metric, admin_dist, option_no_install, zone, vsys, invalid) "
                    . "VALUES "
                    . "('$route_table','$vrid','$template','$source', 'v4', '$name', '$static_routes_destination', '$destination_member_lid', '$interface', '$nexthop', '$nexthop_value', '$nexthop_member_lid','$metric', '$admin_dist', '$no_install', '$zone', '$vsys', '0');");
        }
        echo json_encode(array("success" => true));
    }
} 
elseif ($action == "update") {

    if ($type == "interfaces") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $oldname = $projectdb->real_escape_string($oldname);

        take_snapshot_last($project);
        
        $query = generate_query("template");
        if (preg_match("/WHERE/i", $query)) {
            $query = $query . " AND (vr_id='' OR vr_id='0') AND type='layer3'";
        } else {
            $query = " WHERE (vr_id='' OR vr_id='0') AND type='layer3'";
        }
//        $set_all_interfaces = 0;
//
//        if($oldname != ""){
//            $getInterfaces = $projectdb->query("SELECT interfaces FROM virtual_routers WHERE id='$idx';");
//            if ($getInterfaces->num_rows == 1) {
//                $dataI = $getInterfaces->fetch_assoc();
//                $interfaces = $dataI['interfaces'];
//                $interfaces_array = explode(",", $interfaces);
//                $names_interfaces_array = explode(",", $total_name);
//
//                if (($key = array_search($oldname, $interfaces_array)) !== false) {
//                    unset($interfaces_array[$key]);
//                }
//
//                foreach($names_interfaces_array AS $name){
//
//                    if($set_all_interfaces != 1){
//
//                        if($name == "All Interfaces"){
//
//                            $projectdb->query("UPDATE interfaces SET vr_id='' WHERE template='$template' AND source='$source' AND vr_id='$idx';");
//
//                            $set_all_interfaces = 1;
//                            $getAllInterfaces = $projectdb->query("SELECT id,unitname FROM interfaces $query ORDER BY unitname;");
//
//                            $count = $getAllInterfaces->num_rows;
//                            if($count > 0){
//                                while ($dataAI = $getAllInterfaces->fetch_assoc()) {
//                                    $unitname_array[] = $dataAI['unitname'];
//                                    $id_interfaces_array[] = $dataAI['id'];
//                                }
//                                $ids_all_interfaces = implode(",", $id_interfaces_array);
//                                $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $unitname_array) . "' WHERE id='$idx';");
//                                $projectdb->query("UPDATE interfaces SET vr_id='$idx' WHERE template='$template' AND id IN ($ids_all_interfaces);");
//                            }
//                        }
//                        else{
//                            if (in_array($name, $interfaces_array)) {
//
//                            } else {
//                                $interfaces_array[] = $name;
//                            }
//                        }
//                    }
//                }
//
//                if($set_all_interfaces != 1){
//                    if (($key = array_search("", $interfaces_array)) !== false) {
//                        unset($interfaces_array[$key]);
//                    }
//                    $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $interfaces_array) . "' WHERE id='$idx';");
//                    $names_interfaces_array2 = explode(",", $total_name);
//
//                    foreach($names_interfaces_array2 AS $name){
//                        $projectdb->query("UPDATE interfaces SET vr_id='$idx' WHERE template='$template' AND source='$source' AND unitname='$name';");
//                    }
//                    $projectdb->query("UPDATE interfaces SET vr_id='' WHERE template='$template' AND source='$source' AND unitname='$oldname';");
//                }
//            }
//        }
//
//        echo json_encode(array("success" => true));

        if($idx == ""){
            $idx = 0;
        }

        $set_all_interfaces = 0;
        $name_interfaces = explode(",", $total_name);

        foreach ($name_interfaces AS $name){

            if($set_all_interfaces != 1){

                if($name == "All Interfaces"){

                    $set_all_interfaces = 1;
                    $getAllInterfaces = $projectdb->query("SELECT id,unitname FROM interfaces $query ORDER BY unitname;");
                    $count = $getAllInterfaces->num_rows;
                    if($count > 0){
                        while ($dataAI = $getAllInterfaces->fetch_assoc()) {
                            $unitname = $dataAI['unitname'];

                            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'interfaces' AND name = '$unitname' AND user_id = '$user_id';");
                            if ($getBridge->num_rows == 0) {

                                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                                if ($getBridgeId->num_rows == 1) {
                                    $getIdData = $getBridgeId->fetch_assoc();
                                    $ids = $getIdData['ids'] + 1;
                                }else{
                                    $ids = 1;
                                }

                                $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                                    . "VALUES (NULL, '$ids', '$idx', 'interfaces', '$unitname', '$template', '0', '$user_id');");
                            }else{
                                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$unitname' AND type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                            }

                        }

                    }
                }
                else{
                    $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'interfaces' AND name = '$name' AND user_id = '$user_id';");
                    if ($getBridge->num_rows == 0) {

                        $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                        if ($getBridgeId->num_rows == 1) {
                            $getIdData = $getBridgeId->fetch_assoc();
                            $ids = $getIdData['ids'] + 1;
                        }else{
                            $ids = 1;
                        }

                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                            . "VALUES (NULL, '$ids', '$idx', 'interfaces', '$name', '$template', '0', '$user_id');");
                    }else{
                        $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                    }
                }
            }
        }
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "vr") {

        $is_new = 0;
        $invalid_interfaces = array();
        $vr_vsys = "-1";

        if ($id == "") {
            $protocol_ini = "<bgp><routing-options><graceful-restart><enable>yes</enable></graceful-restart><as-format>2-byte</as-format></routing-options><enable>no</enable></bgp>";
            $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys,protocol,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext) VALUES ('','$template','$source','$vsys','$protocol_ini','10','30','110','200','20','120','10','30','110');");
            $id = $projectdb->insert_id;
            $is_new = 1;
            $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
        }

        $getExistName = $projectdb->query("SELECT id FROM virtual_routers WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND template = '$template';");
        if ($getExistName->num_rows == 0) {
            $getOldName = $projectdb->query("SELECT name FROM virtual_routers WHERE id='$id';");
            if ($getOldName->num_rows == 1) {
                $getOldNameData = $getOldName->fetch_assoc();
                $oldName = $getOldNameData['name'];
                if ($oldName != $name) {
                    $getVSYS = $projectdb->query("SELECT id,virtual_router FROM virtual_systems WHERE virtual_router LIKE '%$oldName%' AND source='$source';");
                    if ($getVSYS->num_rows > 0) {
                        while ($data = $getVSYS->fetch_assoc()) {
                            $vsysid = $data['id'];
                            $virtualrouters = $data['virtual_router'];
                            $virtualrouters_split = explode(",", $virtualrouters);
                            $virtualrouters = array();
                            foreach ($virtualrouters_split as $key => $value) {
                                if ($value == $oldName) {
                                    $virtualrouters[] = $name;
                                } else {
                                    $virtualrouters[] = $value;
                                }
                            }
                            $projectdb->query("UPDATE virtual_systems SET virtual_router='" . implode(",", $virtualrouters) . "' WHERE id='$vsysid';");
                            unset($virtualrouters);
                        }
                    }
                }
            }
            $projectdb->query("UPDATE virtual_routers SET name='$name', admin_dist_static='$admin_dist_static', admin_dist_static_ipv6='$admin_dist_static_ipv6', admin_dist_ospf_int='$admin_dist_ospf_int', admin_dist_ospf_ext='$admin_dist_ospf_ext', admin_dist_ospfv3_int='$admin_dist_ospfv3_int', admin_dist_ibgp='$admin_dist_ibgp', admin_dist_ebgp='$admin_dist_ebgp', admin_dist_rip='$admin_dist_rip', admin_dist_ospfv3_ext='$admin_dist_ospfv3_ext', protocol = '$protocol' WHERE id='$id';");

            // Get the vr_vsys to validate it against the interface_vsys
            $query_vsys_from_VR = "SELECT name,vsys,source,template FROM virtual_routers where id = '$id';";
            $get_vsys = $projectdb->query($query_vsys_from_VR);
            $vr_name = "";
            $vr_source = "";
            $vr_template = "";
            if ($get_vsys->num_rows > 0 ){
                $data_vsys = $get_vsys->fetch_assoc();
                $vr_vsys = $data_vsys['vsys']; // get the vsys name
                $vr_name = $data_vsys['name']; // get the vr name
                $vr_source = $data_vsys['source']; // get the source name
                $vr_template = $data_vsys['template']; // get the template name
            }
            $vr_multi_vsys = array();
            $vr_multi_vsys[] = $vr_vsys;
            // Check if the config is from a multi vsys and vsys names are stored on virtual_systems table
            $query_vsys_from_VSYS = "SELECT name FROM virtual_systems where virtual_router = '$vr_name' and template = '$vr_template' and source = '$vr_source';";
            $get_vsys = $projectdb->query($query_vsys_from_VSYS);
            if ($get_vsys->num_rows > 0 ){
                while($data_vsys = $get_vsys->fetch_assoc()) {
                    $vr_multi_vsys[] = $data_vsys['name'];
                }
            }

            // Cambiar el nombre de la VR asociada con la tabla routes_static
            $projectdb->query("UPDATE routes_static SET nexthop_value = '$name' WHERE nexthop_value = '$oldName';");

            $interfaces_array = array();

            // Add Interfaces from edit_table
            $getInterfaces = $projectdb->query("SELECT name FROM edit_table WHERE type = 'interfaces' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
            if($getInterfaces->num_rows > 0){
                while($dataI = $getInterfaces->fetch_assoc()){
                    $inteface_name = $dataI['name'];

                    // review interface->vsys is equals to vr->vsys
                    $query_vsys_from_interface = "SELECT * FROM interfaces WHERE template = '$template' AND source = '$source' AND unitname = '$inteface_name';";
                    $get_vsys_from_interface = $projectdb->query($query_vsys_from_interface);
                    if ($get_vsys_from_interface->num_rows > 0 ) {
                        $data_vsys = $get_vsys_from_interface->fetch_assoc();
                        $interface_vsys = $data_vsys['vsys'];
                        if( in_array($interface_vsys, $vr_multi_vsys ) ) {
                            $projectdb->query("UPDATE interfaces SET vr_id = '$id' WHERE template = '$template' AND source = '$source' AND unitname = '$inteface_name';");
                            $interfaces_array[] = $dataI['name'];
                        } else {
                            $invalid_interfaces[] = $inteface_name;
                        }
                    } else {
                        $invalid_interfaces[] = $inteface_name;
                    }
                }
            }

            // Remove vr from interfaces
            $getInterfaces = $projectdb->query("SELECT name FROM edit_table WHERE type = 'interfaces' AND lid = '$id' AND remove = '1' AND user_id = '$user_id' ORDER BY ids ASC;");
            if($getInterfaces->num_rows > 0){
                while($dataI = $getInterfaces->fetch_assoc()){
                    $inteface_name = $dataI['name'];
                    $projectdb->query("UPDATE interfaces SET vr_id = '' WHERE template = '$template' AND source = '$source' AND unitname = '$inteface_name';");
                }
            }

            // Update routes_static with new id
            $projectdb->query("UPDATE routes_static SET vr_id = '$id' WHERE template = '$template' AND source = '$source' AND vr_id = '0';");

            if( count($invalid_interfaces)>0){
                echo json_encode(array("success"=>false, "msg"=>"Below interfaces [". implode(",", $invalid_interfaces) . "] are not assigned to the defined Virtual Router Vsys [".implode(",",$vr_multi_vsys)."].<br>Please review your data prior to change this record."));
            }else {
                // Update interfaces
                $projectdb->query("UPDATE virtual_routers SET interfaces = '" . implode(",", $interfaces_array) . "' WHERE id = '$id';");
                echo json_encode(array("success" => true));
            }
        }
        else{
            if($is_new == 1){
                $projectdb->query("DELETE FROM virtual_routers WHERE id = '$id';");
            }
            echo json_encode(array("success"=>false, "msg"=>"Virtual Router already exists with the same name."));
        }

    }
}
elseif($action == "remove"){

    if($type == "interfaces_in_zones"){
        
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $ids = $projectdb->real_escape_string($ids);
        
        take_snapshot_last($project);
        
        $getInterfaces = $projectdb->query("SELECT id, name, interfaces, template FROM virtual_routers WHERE id IN ($ids);");
        if ($getInterfaces->num_rows > 0) {
            while($dataI = $getInterfaces->fetch_assoc()){
                $vr_id = $dataI['id'];
                $zone_name = $dataI['name'];
                $interfaces = $dataI['interfaces'];
                $template = $dataI['template'];
                
                if ($interfaces != "") {
                    
                    $names_interfaces_array = explode(",", $interfaces);
                
                    foreach($names_interfaces_array AS $name_interface){
                        #Update the Interface with the Zone
                        $projectdb->query("UPDATE interfaces SET vr_id = '' WHERE source = '$source' AND template = '$template' AND unitname = '$name_interface';");
                    }
                }
            }
        }
        $projectdb->query("UPDATE virtual_routers SET interfaces='' WHERE id IN ($ids);");
        
        echo json_encode(array("success" => true));
        
    }
    
}

?>
