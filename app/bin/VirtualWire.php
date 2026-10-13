<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename']) ? $_GET['devicename'] : '');
        $template   = (string)  (isset($_GET['template'])   ? $_GET['template'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$template = $projectdb->real_escape_string($template);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$source = $projectdb->real_escape_string($source);
$vsys = $projectdb->real_escape_string($vsys);
$filter = $projectdb->real_escape_string($filter);

if ($action == "get") {
    if ($type == "vwire") {

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "21";
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

        list($query, $orderby) = generateQueryFilters($project, "virtual_wires", "", $query, $source);

        $getAll = $projectdb->query("SELECT source,vsys,template,name,interface1,interface2,multicast_firewalling,tag_allowed,link_state_pass_through,id FROM virtual_wires $query ORDER BY id,name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_assoc()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "vsys_vwire") {

        $query = generate_query("template_not_vsys");

        $getAll = $projectdb->query("SELECT source,vsys,template,name,interface1,interface2,multicast_firewalling,tag_allowed,link_state_pass_through,id FROM virtual_wires $query ORDER BY id,name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            $myData[] = array("name" => "All Virtual Wires");
            while ($data = $getAll->fetch_assoc()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
} elseif ($action == "add") {
    if ($type == "vwire") {
        $projectdb->query("INSERT INTO virtual_wires (template,source) VALUES ('$template','$source')");
        echo json_encode(array("success" => true));
    }
} elseif ($action == "update") {
    if ($type == "vwire") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $id                         = (string) (isset($_GET['id'])                      ? $_GET['id'] : '');
                $name                       = (string) (isset($_GET['name'])                    ? $_GET['name'] : '');
                $interface1                 = (string) (isset($_GET['interface1'])              ? $_GET['interface1'] : '');
                $interface2                 = (string) (isset($_GET['interface2'])              ? $_GET['interface2'] : '');
                $multicast_firewalling      = (string) (isset($_GET['multicast_firewalling'])   ? $_GET['multicast_firewalling'] : '');
                $tag_allowed                = (string) (isset($_GET['tag_allowed'])             ? $_GET['tag_allowed'] : '');
                $link_state_pass_through    = (string) (isset($_GET['link_state_pass_through']) ? $_GET['link_state_pass_through'] : '');
                break;
            case 'POST':
                $id                         = (string) (isset($_POST['id'])                      ? $_POST['id'] : '');
                $name                       = (string) (isset($_POST['name'])                    ? $_POST['name'] : '');
                $interface1                 = (string) (isset($_POST['interface1'])              ? $_POST['interface1'] : '');
                $interface2                 = (string) (isset($_POST['interface2'])              ? $_POST['interface2'] : '');
                $multicast_firewalling      = (string) (isset($_POST['multicast_firewalling'])   ? $_POST['multicast_firewalling'] : '');
                $tag_allowed                = (string) (isset($_POST['tag_allowed'])             ? $_POST['tag_allowed'] : '');
                $link_state_pass_through    = (string) (isset($_POST['link_state_pass_through']) ? $_POST['link_state_pass_through'] : '');
                break;
            default:
                $id                         = (string) (isset($_POST['id'])                      ? $_POST['id'] : '');
                $name                       = (string) (isset($_POST['name'])                    ? $_POST['name'] : '');
                $interface1                 = (string) (isset($_POST['interface1'])              ? $_POST['interface1'] : '');
                $interface2                 = (string) (isset($_POST['interface2'])              ? $_POST['interface2'] : '');
                $multicast_firewalling      = (string) (isset($_POST['multicast_firewalling'])   ? $_POST['multicast_firewalling'] : '');
                $tag_allowed                = (string) (isset($_POST['tag_allowed'])             ? $_POST['tag_allowed'] : '');
                $link_state_pass_through    = (string) (isset($_POST['link_state_pass_through']) ? $_POST['link_state_pass_through'] : '');
                break;
        }

        $id = $projectdb->real_escape_string($id);
        $name = $projectdb->real_escape_string($name);
        $interface1 = $projectdb->real_escape_string($interface1);
        $interface2 = $projectdb->real_escape_string($interface2);
        $multicast_firewalling = $projectdb->real_escape_string($multicast_firewalling);
        $tag_allowed = $projectdb->real_escape_string($tag_allowed);
        $link_state_pass_through = $projectdb->real_escape_string($link_state_pass_through);

        $is_new = 0;

        if($id == ""){
            $projectdb->query("INSERT INTO virtual_wires (template,source) VALUES ('$template','$source')");
            $id = $projectdb->insert_id;
            $is_new = 1;
        }

        $getExistName = $projectdb->query("SELECT id FROM virtual_wires WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND template = '$template';");
        if ($getExistName->num_rows == 0) {

            $getOld = $projectdb->query("SELECT name,interface1,interface2 FROM virtual_wires WHERE id='$id';");
            if ($getOld->num_rows == 1) {
                $getOlData = $getOld->fetch_assoc();
                $oldInterface1 = $getOlData['interface1'];
                $oldInterface2 = $getOlData['interface2'];
                $oldName = $getOlData['name'];
            }
            if (($interface1 == "") OR ( $interface1 == "None")) {
                $projectdb->query("UPDATE interfaces SET vwire_id='' WHERE unitname='$oldInterface1' AND template='$template' AND source='$source';");
            } else {
                $projectdb->query("UPDATE interfaces SET vwire_id='$id' WHERE unitname='$interface1' AND template='$template' AND source='$source';");
            }
            if (($interface2 == "") OR ( $interface2 == "None")) {
                $projectdb->query("UPDATE interfaces SET vwire_id='' WHERE unitname='$oldInterface2' AND template='$template' AND source='$source';");
            } else {
                $projectdb->query("UPDATE interfaces SET vwire_id='$id' WHERE unitname='$interface2' AND template='$template' AND source='$source';");
            }

            if ($oldName != $name) {
                $getVSYS = $projectdb->query("SELECT id,virtual_wire FROM virtual_systems WHERE virtual_wire LIKE '%$oldName%' AND source='$source' AND template='$template';");
                if ($getVSYS->num_rows > 0) {
                    while ($data = $getVSYS->fetch_assoc()) {
                        $vsysid = $data['id'];
                        $virtualrouters = $data['virtual_wire'];
                        $virtualrouters_split = explode(",", $virtualrouters);
                        $virtualrouters = array();
                        foreach ($virtualrouters_split as $key => $value) {
                            if ($value == $oldName) {
                                $virtualrouters[] = $name;
                            } else {
                                $virtualrouters[] = $value;
                            }
                        }
                        $projectdb->query("UPDATE virtual_systems SET virtual_wire='" . implode(",", $virtualrouters) . "' WHERE id='$vsysid';");
                        unset($virtualrouters);
                    }
                }
            }

            $projectdb->query("UPDATE virtual_wires SET name='$name', interface1='$interface1', interface2='$interface2',multicast_firewalling='$multicast_firewalling',tag_allowed='$tag_allowed',link_state_pass_through='$link_state_pass_through' WHERE id='$id';");

            echo json_encode(array("success" => true));
        }
        else{
            if($is_new == 1){
                $projectdb->query("DELETE FROM virtual_wires WHERE id = '$id';");
            }
            echo json_encode(array("success"=>false, "msg"=>"Virtual Wire already exists with the same name."));
        }

    }
}
elseif ($action == "remove") {
    if ($type == "vwire") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $ids = (string) (isset($_GET['ids']) ? $_GET['ids'] : '');
                break;
            case 'POST':
                $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : '');
                break;
            default:
                $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : '');
                break;
        }

        $ids = $projectdb->real_escape_string($ids);

//        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        //$data = split(",", $ids);
        $data = explode(",", $ids);
        foreach ($data as $key => $value) {
            $getVWIRE = $projectdb->query("SELECT name,interface1,interface2 FROM virtual_wires WHERE id='$value';");
            if ($getVWIRE->num_rows == 1) {
                $getVWIREData = $getVWIRE->fetch_assoc();
                $vwirename = $getVWIREData['name'];
                $interface1 = $getVWIREData['interface1'];
                if ($interface1 != "") {
                    $projectdb->query("UPDATE interfaces SET vwire_id='' WHERE unitname='$interface1' AND template='$template' AND source='$source'");
                }

                $interface2 = $getVWIREData['interface2'];
                if ($interface2 != "") {
                    $projectdb->query("UPDATE interfaces SET vwire_id='' WHERE unitname='$interface2' AND template='$template' AND source='$source'");
                }
                $getVSYS = $projectdb->query("SELECT id,virtual_wire FROM virtual_systems WHERE template='$template' AND source='$source' AND virtual_wire LIKE '%$vwirename%';");
                if ($getVSYS->num_rows == 1) {
                    $getVSYSData = $getVSYS->fetch_assoc();
                    $vsysid = $getVSYSData['id'];
                    $allvwires = $getVSYSData['virtual_wire'];
                    $oldInterfaces = explode(",", $allvwires);
                    if (($key2 = array_search($allvwires, $oldInterfaces)) !== false) {
                        unset($oldInterfaces[$key2]);
                    }
                    $projectdb->query("UPDATE virtual_systems SET virtual_wire='" . implode(",", $oldInterfaces) . "' WHERE id='$vsysid';");
                }
            }
        }
        $projectdb->query("DELETE FROM virtual_wires WHERE id IN ($ids);");
    }
}
?>