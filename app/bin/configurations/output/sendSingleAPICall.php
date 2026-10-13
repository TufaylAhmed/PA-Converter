<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/9/16 - 16:46
 */

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';


require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/device/device.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

//Parameter passing
$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = $pandb->real_escape_string((string)(isset($_GET['type'])         ? $_GET['type'] : ''));
}
$project        = $pandb->real_escape_string((string) (isset($_GET['project'])     ? $_GET['project'] : ''));
$queryCallID    = $pandb->real_escape_string((string) (isset($_GET['id'])          ? $_GET['id'] : ''));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
    $message = array();
    $message['code'] = false;
    $message['msg'] = 'Your account does not have the rights to send APIs to this device';
    echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
    return;
}

//Method control
switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = get_singleAPICall($project, $queryCallID);

        if($message['code']){
            echo json_encode(["total" => count($message['msg']), "rows"  => $message['msg'], ]);
        }
        else{
            echo json_encode([ "total" => 0, "rows"  => '',]);
        }
        break;

    case 'POST':
//        $data = ['project'=>$_POST['project'], 'modified'=>$_POST['modified'], 'api_call' => $_POST['api_call']];
        $project_POST   = (string) (isset($data['project'])     ? $data['project'] : '');

        if($data['action'] == 'remove_from_bulk'){
            
            $ids = (string) (isset($data['ids'])     ? $data['ids'] : '');
            $message = remove_from_bulk($project_POST, ['ids'=>$ids]);        
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }elseif($data['action'] == 'add_to_bulk'){
            $ids = (string) (isset($data['ids'])     ? $data['ids'] : '');
            $message = add_to_bulk($project_POST, ['ids' => $ids]);
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }
        else{
            $message = sendSingleAPICall($project, $data);
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }
        break;

    case 'PUT':
        if ($project==""){$project=$data['project'];}
        $message = save_request($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = remove_request($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}



function get_singleAPICall(STRING $projectName, STRING $id){
    global $app;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['project.admin','projectRole.'.$projectName.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to check API calls';
        return $message;
    }

    $message = array();

    $getCalls = $projectdb->query("SELECT id,name,output,xml_final,xml_initial,state,sync,object,action,xpath,member_lid,table_name FROM output_mapping WHERE id='$id';");
    $count = $getCalls->num_rows;
    if ($count > 0) {
        while ($data = $getCalls->fetch_object()) {
            $myData[] = $data;
        }
    }
    if ($count == 0) {
        $myData = "";
    }

    $message['code'] = true;
    $message['msg'] = $myData;
//        '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    return $message;
}

/*** Given a set of action=GET/SET/DELETE/EDIT/REMOVE, deviceID, queryID (from output_mapping), xpath and element to send to a FW,
 * sends the required Query to the device
 * @param String $project
 * @param array $data
 * @return array
 */
function sendSingleAPICall(String $project, ARRAY $data){
    global $projectdb;
//    global $pandb;
    global $app;

    $project= $data['project'];
    $projectdb =selectDatabase($project);

    $user = $app->container->sentinel->getUser();
    $userID = $user->id;

    $action = $data['action'];
    $device = $data['device'];
    $id = $data['id'];
    $xpath = str_replace("'", "\"", $data['xpath']);
    $element = $data['xml_final'];

    if (!$deviceEntity = $app->device->where('id', '=', $device)->get()->first() ) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Device not found';

        return $message;
    }

//    $getDevice = $pandb->query("SELECT hostname,port,serial,ispanorama,api_key FROM devices WHERE id='$device';");
//    $deviceData = $getDevice->fetch_assoc();
    $hostname = $deviceEntity->hostname;
    $serial = $deviceEntity->serial;
    $port = $deviceEntity->port;
    $ispanorama = $deviceEntity->ispanorama;
    $api_message = getApiKey($project, $deviceEntity->serial, $userID);
    $api_key = $api_message['msg'];
//    echo json_encode($api_key);
//    die();
    $managementSerial = $deviceEntity->management;

    if ($port == "") {
        $port = "443";
    }

    if ($ispanorama == 1) {
        if(!$api_message['code']){
            $message['code'] = false;
            $message['msg'] = 'You do not have a valid API key for this device';
            return $message;
        }
        $datatopost = array(
            "type" => "config",
            "action" => $action,
            "xpath" => $xpath,
            "element" => $element
        );
    }
    else {
        if($managementSerial =='') {
            if(!$api_message['code']){
                $message['code'] = false;
                $message['msg'] = 'You do not have a valid API key for this device';
                return $message;
            }
            $datatopost = array(
                "type" => "config",
                "action" => $action,
                "xpath" => $xpath,
                "element" => $element
            );
        }
        else{
            if (!$managementObject = $app->device->where('serial', '=', $managementSerial)->get()->first() ) {
                $message = array();
                $message['code'] = false;
                $message['msg'] = 'Device not found';

                return $message;
            }
            $hostname = $managementObject->hostname; //We use the management as a proxy
            $api_message = getApiKey($project, $managementSerial, $userID);
            if(!$api_message['code']){
                $message['code'] = false;
                $message['msg'] = 'You do not have a valid API key for this device';
                return $message;
            }
            $api_key = $api_message['msg'];
            $datatopost = array(
                "type" => "config",
                "action" => $action,
                "target" => $serial,  //We define the target device because we go via Panorama
                "xpath" => $xpath,
                "element" => $element
            );
        }
    }

    # Send the API CALL to the DEVICE
    $devicePath = $hostname . "/api";

    $debugapi = USERSPACE_PATH . "/devices/debug.txt";

    $curl_log = fopen($debugapi, 'a+');
    /*$fields_string = array();

    foreach ($datatopost as $key1 => $value1) {
        if ($key1 != "key") {
            $fields_string[] = $key1 . '=' . $value1;
        }
    }
    $url0 = "https://" . $devicePath . "?" . implode("&", $fields_string);
    $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
    fwrite($curl_log, $url);
    */

    $tuCurl = curl_init();
    // Custom headers to be added
    $headers = array(
        'X-PAN-KEY: ' . $api_key,
        'Content-Type: application/x-www-form-urlencoded'
    );
    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
    curl_setopt($tuCurl, CURLOPT_PORT, $port);
    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
    curl_setopt($tuCurl, CURLOPT_HEADER, 0);
    curl_setopt($tuCurl, CURLOPT_POST, 1);
    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, http_build_query($datatopost));
    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 60);
    $tuData = curl_exec($tuCurl);
    $e = curl_errno($tuCurl);
    $message = array();

    switch ($e){
        case 0:
            $line = curl_multi_getcontent($tuCurl);
            curl_close($tuCurl);
            $xml = simplexml_load_string($line);
            if (preg_match("/Not authorized to access/i", $line)) {
                $message['code'] = false;
                $message['msg'] = 'You do not have access to the device';
                return $message;
            }
            if (preg_match("/Invalid credentials./i", $line)) {
                $message['code'] = false;
                $message['msg'] = $line;
                return $message;
            }
            elseif (preg_match("/Authentication failed: Invalid username or password/i", $line)) {
                $message['code'] = false;
                $message['msg'] = 'Authentication failed: Invalid username or password';
                return $message;
            }
            else {
                $arr = $xml->attributes();
                if ($arr["status"] == "success") {
//                    $newline = addslashes($line);
                    updateAPICallOutput($project, $id, $device, 'success',$xml->msg);
                    $message['code'] = true;
                    $message['msg'] = '';
                    return $message;
                }
                else {
//                    $newline = addslashes($line);
                    $messageXML = $xml->msg->asXML();
                    if(isset($xml->result->msg)) {
                        $messageXML .= " ".$xml->result->msg->asXML();
                    }
                    updateAPICallOutput($project, $id, $device, 'fail',$messageXML);
                    $message['code'] = false;
                    $message['msg'] = "Fail: ".$messageXML;
                    return $message;
                }
            }

            break;

        case 6:
            $newline = 'Error Code '.$e.': The HostName could not be resolved';
            updateAPICallOutput($project, $id, $device, 'fail',$newline);
            $message['code'] = false;
            $message['msg'] =  $newline;
            return $message;
            break;

        case 7:
            $newline = 'Error Code '.$e.': The connection with the device cannot be established. Please, revise your connection parameters';
            updateAPICallOutput($project, $id, $device, 'fail',$newline);
            $message['code'] = false;
            $message['msg'] =  $newline;
            return $message;
            break;

        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
            $newline = 'Error Code '.$e.': The connection with the device returned an error. Please try again';
            updateAPICallOutput($project, $id, $device, 'fail',$newline);
            $message['code'] = false;
            $message['msg'] =  $newline;
            return $message;
            break;

        case 27:
            $newline = 'Error Code '.$e.': The connection with the device returned an error. Out of memory. Please, report this error for improvement';
            updateAPICallOutput($project, $id, $device, 'fail',$newline);
            $message['code'] = false;
            $message['msg'] =  $newline;
            return $message;
            break;

        case 28:
            $newline = 'The connection with the device cannot be established.';
            updateAPICallOutput($project, $id, $device, 'fail',$newline);
            $message['code'] = false;
            $message['msg'] = $newline;
            return $message;
            break;

        default:
            $newline ='Error Code '.$e.': The connection with the device cannot be established. Please, report Error Code for improvement';
            updateAPICallOutput($project, $id, $device, 'fail',$newline);
            $message['code'] = false;
            $message['msg'] =  $newline;
            return $message;
            break;
    }
}

function save_request(String $project, ARRAY $data){
    global $projectdb;
    $projectdb = selectDatabase($project);

    $api_action = $data['action'];
    $id = $data['id'];
    $xpath = $data['xpath'];
    $xml_final = $data['xml_final'];

    $projectdb->query("UPDATE output_mapping SET action='$api_action', xpath='" . addslashes($xpath) . "', xml_final='" . addslashes($xml_final) . "' WHERE id='$id';");
    $message = [
        'code' => true,
        'msg' => ''
    ];

    return $message;
}

function get_supported_bulk_policy_types():array{
    return [
            'Nat Rules',
            'Security Rules',

    ];
}

function get_supported_bulk_object_types():array{
    return [
        'Address',
        'Address Groups',
        'App Override Rules',
        'Applications',
        'Applications Filters',
        'Applications Groups',
        'Applications Tags',
        'External List',
        'Regions',
        'Services',
        'Services Groups',
        'Tag',
    ];
}

function get_supported_network_object_types():array{
    return [
//        'Virtual Router',
//        'Virtual Systems',
//        'VLAN',
        'Zones',
//        'DHCP',
//        'DNS PROXY',
//        'GlobalProtect IPSec Crypto',
//        'IKE Crypto Profile',
//        'IKE Gateway',
//        'Interface Ethernet',
//        'Interface loopback',
//        'Interface tunnel',
//        'Interface vlan',
//        'IPSEC Crypto Profile',
//        'IPSEC Tunnel',
    ];
}


function get_supported_bulk_types():array{
    return array_merge(
        get_supported_bulk_object_types(),
        get_supported_bulk_policy_types(),
        get_supported_network_object_types()
    );
    return [
//        'deviceconfig',
//        'Log Settings',
        'Management Profile',
        'Monitor Profile',
//        'order',
        'Profile Group',
        'Profiles',
//        'Reponse Page',
//        'Reports',
//        'Response Page',
        'Schedules',
//        'Server Profiles radius',
    ];
}

//Adds an object into a bulk API call. Bulk API calls are groupped by VSYS and Object type. This is, they need to have the same XPath
function add_to_bulk(String $project, array $data):array{
    $supported_bulk_types = get_supported_bulk_types();
    global $projectdb;

    $not_supported = [];

    $projectdb = selectDatabase($project);

    $api_action = 'SET';
    $ids = $data['ids']??[];

    //$ids = implode(",", $id);
    //xpath =  /config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='Algosec-Test']
    $query = "SELECT id, xpath, xml_final, table_name FROM output_mapping WHERE id in ($ids)\n";
    //echo "$query";
    $results_existing_single_apis = $projectdb->query($query);

    $grouping_sets = [];
    if($results_existing_single_apis->num_rows > 0){
        while($data_single_api = $results_existing_single_apis->fetch_assoc()){
            $api_id = $data_single_api['id'];
            $xpath = $data_single_api['xpath'];
            $xml_final = $data_single_api['xml_final'];
            $table_name = $data_single_api['table_name'];

            if(!in_array($table_name, $supported_bulk_types)){
                $not_supported[] = $table_name;
                continue;
            }

            $xpath_parts = explode("/", $xpath);

            if(in_array($table_name, get_supported_bulk_object_types())){
                if($xpath_parts[1]=='config' && $xpath_parts[2]=='devices'){
                    if($xpath_parts[4]=='vsys' || $xpath_parts[4]=='device-group'){
                        $vsys_part = $xpath_parts[5];
                        $output_array = [];
                        preg_match('/entry\[@name=\'(.*)\'\]/', $xpath_parts[5], $output_array);
                        $vsys_value = $output_array[1];
                        $section = $xpath_parts[6];

                        $new_xpath = $xpath_parts[0]."/".$xpath_parts[1]."/".$xpath_parts[2]."/".$xpath_parts[3]."/".$xpath_parts[4]."/".$xpath_parts[5]."/".$xpath_parts[6];

                        $name = "${vsys_value}/${section}";
                        $grouping_sets[$name]['ids'][] =  $api_id;
                        $grouping_sets[$name]['xpath'] = "$new_xpath";
                    }
                }
            }
            elseif(in_array($table_name, get_supported_bulk_policy_types())){
                //  0     1      2                       3                        4                 5               6          7       8            9    
                //    /config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='child1']/pre-rulebase/security/rules/entry[@name='test_sec_rule_david']
                if($xpath_parts[1]=='config' && $xpath_parts[2]=='devices'){
                    if($xpath_parts[4]=='vsys' || $xpath_parts[4]=='device-group'){
                        $vsys_part = $xpath_parts[5];
                        $output_array = [];
                        preg_match('/entry\[@name=\'(.*)\'\]/', $xpath_parts[5], $output_array);
                        $vsys_value = $output_array[1];
                        $section = $xpath_parts[6];

                        $item = array_pop($xpath_parts);
                        $section = array_pop($xpath_parts);
                        $new_xpath = implode("/", $xpath_parts)."/".$section;

                        //$new_xpath = $xpath_parts[0]."/".$xpath_parts[1]."/".$xpath_parts[2]."/".$xpath_parts[3]."/".$xpath_parts[4]."/".$xpath_parts[5]."/".$xpath_parts[6];

                        $name = "${vsys_value}/${section}";
                        $grouping_sets[$name]['ids'][] =  $api_id;
                        $grouping_sets[$name]['xpath'] = "$new_xpath";
                    }
                }
            }
        }
    }

    //Add the new ids in each group
    foreach($grouping_sets as $group_name => $content){
        $new_group_members = $content['ids'];
        $xpath = $content['xpath'];
        //echo "Name: ".$group_name."\n";
        //echo "Members: ". implode(",",$new_group_members)."\n";
        //echo "XPath: ".$xpath."\n";
        $new_xml_final = '';

        $query_get = "SELECT * from output_mapping WHERE name ='$group_name' LIMIT 1";
        //echo "$query_get"."\n";
        $result_existing_group = $projectdb->query($query_get);
        $new_xml_final_array = [];
        if($result_existing_group->num_rows >0){  //The group exists, so we Update it
            //echo "We need to edit"."\n";
            $data_existing_group = $result_existing_group->fetch_assoc();
            $members = $data_existing_group['xml_initial'];
            $members_array = explode(',', $members);

            $members_array = array_sort(array_unique(array_merge($new_group_members, $members_array)));
            $members_string = implode(",", $members_array);

            //Construct the resulting XML content
            $query_xmls = "SELECT xml_final FROM output_mapping WHERE id in ($members_string)";
            $result_xmls = $projectdb->query($query_xmls);
            
            while($data_xml_final_apis = $result_xmls->fetch_assoc()){
                $new_xml_final_array[] = $data_xml_final_apis['xml_final'];
            }
            $new_xml_final = implode("\n\n", $new_xml_final_array);
            $query = "UPDATE output_mapping SET xml_initial = '$members_string', xml_final ='$new_xml_final' WHERE name = '".addslashes($group_name)."'";
            $projectdb->query($query);
        }
        else{ //The group does not exist, so we create it
            //Construct the resulting XML content
            //echo "We need to insert"."\n";
            $members_string = implode(",", $new_group_members);
            $query_xmls = "SELECT xml_final FROM output_mapping WHERE id in ($members_string)";
            //echo "Query_xml: $query_xmls"."\n";
            $result_xmls2 = $projectdb->query($query_xmls);

            while($data_xml_final_apis2 = $result_xmls2->fetch_assoc()){
                $new_xml_final_array[] = $data_xml_final_apis2['xml_final'];
            }
            $new_xml_final = implode("\n\n", $new_xml_final_array);
            $query_insert = "INSERT into output_mapping (table_name, xml_initial, xml_final, state, sync, object, action, xpath, output, name, whereto, dst) VALUES ".
            "                                    ('grouping', '$members_string', '".addslashes($new_xml_final)."', '','','','set','".addslashes($xpath)."','','".addslashes($group_name)."','','') ";
            //echo $query_insert;
            $projectdb->query($query_insert);

        }

    }

    $msg = "";
    $not_supported = array_unique($not_supported);
    if(count($not_supported)>0){
        foreach($not_supported as &$not_supported_entry){
            $not_supported_entry = "<li><b>$not_supported_entry</b></li>";
        }
        $msg .= "The following objects are not supported for bulk: <ul>";
        $msg .= implode(" ", $not_supported);
        $msg .= "</ul>";
    }

    return ['msg'=> "$msg", 'code'=>0];
}


//Adds an object into a bulk API call. Bulk API calls are groupped by VSYS and Object type. This is, they need to have the same XPath
function remove_from_bulk(String $project, array $data):array{
    $supported_bulk_types = get_supported_bulk_types();
    global $projectdb;

    $not_supported = [];

    $projectdb = selectDatabase($project);

    $api_action = 'SET';
    $ids = $data['ids']??[];

    //$ids = implode(",", $id);
    //xpath =  /config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='Algosec-Test']
    $query = "SELECT id, xpath, xml_final, table_name FROM output_mapping WHERE id in ($ids)\n";
    //echo "$query";
    $results_existing_single_apis = $projectdb->query($query);

    $grouping_sets = [];
    if($results_existing_single_apis->num_rows > 0){
        while($data_single_api = $results_existing_single_apis->fetch_assoc()){
            $api_id = $data_single_api['id'];
            $xpath = $data_single_api['xpath'];
            $xml_final = $data_single_api['xml_final'];
            $table_name = $data_single_api['table_name'];


            if(!in_array($table_name, $supported_bulk_types)){
                $not_supported[] = $table_name;
                continue;
            }

            $xpath_parts = explode("/", $xpath);

            if(in_array($table_name, get_supported_bulk_object_types())){
                if($xpath_parts[1]=='config' && $xpath_parts[2]=='devices'){
                    if($xpath_parts[4]=='vsys' || $xpath_parts[4]=='device-group'){
                        $vsys_part = $xpath_parts[5];
                        $output_array = [];
                        preg_match('/entry\[@name=\'(.*)\'\]/', $xpath_parts[5], $output_array);
                        $vsys_value = $output_array[1];
                        $section = $xpath_parts[6];

                        $new_xpath = $xpath_parts[0]."/".$xpath_parts[1]."/".$xpath_parts[2]."/".$xpath_parts[3]."/".$xpath_parts[4]."/".$xpath_parts[5]."/".$xpath_parts[6];

                        $name = "${vsys_value}/${section}";
                        $grouping_sets[$name]['ids'][] =  $api_id;
                        $grouping_sets[$name]['xpath'] = "$new_xpath";
                    }
                }
            }

            elseif(in_array($table_name, get_supported_bulk_policy_types())){
                //  0     1      2                       3                        4                 5               6          7       8            9    
                //    /config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='child1']/pre-rulebase/security/rules/entry[@name='test_sec_rule_david']
                if($xpath_parts[1]=='config' && $xpath_parts[2]=='devices'){
                    if($xpath_parts[4]=='vsys' || $xpath_parts[4]=='device-group'){
                        $vsys_part = $xpath_parts[5];
                        $output_array = [];
                        preg_match('/entry\[@name=\'(.*)\'\]/', $xpath_parts[5], $output_array);
                        $vsys_value = $output_array[1];
                        $section = $xpath_parts[6];

                        $item = array_pop($xpath_parts);
                        $section = array_pop($xpath_parts);
                        $new_xpath = implode("/", $xpath_parts);

                        //$new_xpath = $xpath_parts[0]."/".$xpath_parts[1]."/".$xpath_parts[2]."/".$xpath_parts[3]."/".$xpath_parts[4]."/".$xpath_parts[5]."/".$xpath_parts[6];

                        $name = "${vsys_value}/${section}";
                        $grouping_sets[$name]['ids'][] =  $api_id;
                        $grouping_sets[$name]['xpath'] = "$new_xpath";
                    }
                }
            }
        }
    }


    //Remove the seelcted ids from each group
    foreach($grouping_sets as $group_name => $content){
        $new_group_members = $content['ids'];
        $xpath = $content['xpath'];
        $new_xml_final = '';

        $query_get = "SELECT * from output_mapping WHERE name ='$group_name' LIMIT 1";
        //echo "$query_get"."\n";
        $result_existing_group = $projectdb->query($query_get);
        $new_xml_final_array = [];
        if($result_existing_group->num_rows >0){  //The group exists, so we Update it
            $data_existing_group = $result_existing_group->fetch_assoc();
            $members = $data_existing_group['xml_initial'];
            $members_array = explode(',', $members);

            $members_array = array_sort(array_unique(array_diff($members_array, $new_group_members )));
            $members_string = implode(",", $members_array);

            //Construct the resulting XML content
            $query_xmls = "SELECT xml_final FROM output_mapping WHERE id in ($members_string)";
            $result_xmls = $projectdb->query($query_xmls);
            if($result_xmls->num_rows > 0){
                while($data_xml_final_apis = $result_xmls->fetch_assoc()){
                    $new_xml_final_array[] = $data_xml_final_apis['xml_final'];
                }
                $new_xml_final = implode("\n\n", $new_xml_final_array);
                $query = "UPDATE output_mapping SET xml_initial = '$members_string', xml_final ='$new_xml_final' WHERE name = '".addslashes($group_name)."'";
                $projectdb->query($query);
            }
            else{
                $query = "DELETE FROM output_mapping WHERE name = '".addslashes($group_name)."'";
                $projectdb->query($query);
            }
        }
        else{ //The group does not exist, nothing to remove
        }

    }

    $msg = "";
    $not_supported = array_unique($not_supported);
    if(count($not_supported)>0){
        foreach($not_supported as &$not_supported_entry){
            $not_supported_entry = "<li><b>$not_supported_entry</b></li>";
        }
        $msg .= "The following objects are not supported for bulk: <ul>";
        $msg .= implode(" ", $not_supported);
        $msg .= "</ul>";
    }

    return ['msg'=> $msg, 'code'=>0];
}

function remove_request(STRING $project, ARRAY $data){
    global $projectdb;
    $projectdb = selectDatabase($project);

    $ids = $data['ids'];
    $grouping = ($data['type']=== 'grouping')?true:false;

    if($ids == "all"){
        if($grouping){
            $projectdb->query("DELETE FROM output_mapping WHERE table_name ='grouping';");    
        }
        else{
            $projectdb->query("DELETE FROM output_mapping;");
        }
    }
    else{
        if ($ids != "") {
            $projectdb->query("DELETE FROM output_mapping WHERE id IN ($ids);");
        }
    }

    $message = [
        'code' => true,
        'msg' => ''
    ];
    return $message;
}

function updateAPICallOutput(STRING $project, STRING $id, STRING $device, STRING $status, STRING $text){
    global $projectdb;
    global $app;

    $projectdb = selectDatabase($project);

    if($deviceEntity = $app->device->where('id', '=', $device)->get()->first()){
        $query = "SELECT output FROM output_mapping WHERE id='$id'";
        $resultQuery = $projectdb->query($query);
        $dataQuery = $resultQuery->fetch_assoc();
        $output = $dataQuery['output'];

        $outputJson = json_decode($output);
//        echo print_r($outputJson);
        if(!isset($outputJson)){
            $outputJson = ((object) null);
        }
        $outputJson->{$device} = [
            'device' => $deviceEntity->devicename,
            'status' => $status,
            'text'=>addslashes($text),
            'date' => date("Y-m-d H:i:s"),
        ];

        $projectdb->query("UPDATE output_mapping SET output='".addslashes(json_encode($outputJson))."' WHERE id='$id';");
    }
}