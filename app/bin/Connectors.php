<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//error_reporting(E_ALL & ~E_NOTICE);

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

require_once INC_ROOT.'/libs/common/discovery/LogConnector.php';
use PaloAltoNetworks\Expedition\Discovery\LogConnector;

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);
parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type = $pandb->real_escape_string((string)(isset($_GET['type']) ? $_GET['type'] : ''));
}
$project    = $pandb->real_escape_string((string)(isset($_GET['project'])      ? $_GET['project']  : ''));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = $pandb->real_escape_string((string) (isset($_GET['action'])     ? $_GET['action'] : ''));
        $type       = $pandb->real_escape_string((string) (isset($_GET['type'])       ? $_GET['type'] : '')); // zip / xml / device
        $project    = $pandb->real_escape_string((string) (isset($_GET['project'])    ? $_GET['project'] : ''));
        $id         = $pandb->real_escape_string((string) (isset($_GET['id'])         ? $_GET['id'] : ''));
        $vendor     = $pandb->real_escape_string((string) (isset($_GET['vendor'])     ? $_GET['vendor'] : ''));
        $data       = $pandb->real_escape_string((string) (isset($_GET['data'])       ? $_GET['data'] : ''));
        $filename   = $pandb->real_escape_string((string) (isset($_GET['filename'])   ? $_GET['filename'] : ''));
        $device     = $pandb->real_escape_string((string) (isset($_GET['device'])     ? $_GET['device'] : ''));
        $vsys       = $pandb->real_escape_string((string) (isset($_GET['vsys'])       ? $_GET['vsys'] : ''));
        $vsysid     = $pandb->real_escape_string((string) (isset($_GET['vsysid'])     ? $_GET['vsysid'] : '0'));
        $panorama   = $pandb->real_escape_string((string) (isset($_GET['panorama'])   ? $_GET['panorama'] : ''));
        $period     = $pandb->real_escape_string((string) (isset($_GET['period'])     ? $_GET['period'] : ''));
        $source     = $pandb->real_escape_string((string) (isset($_GET['source'])     ? $_GET['source'] : ''));
        $startdate  = $pandb->real_escape_string((string) (isset($_GET['startdate'])  ? $_GET['startdate'] : ''));
        $starttime  = $pandb->real_escape_string((string) (isset($_GET['starttime'])  ? $_GET['starttime'] : ''));
        $enddate    = $pandb->real_escape_string((string) (isset($_GET['enddate'])    ? $_GET['enddate'] : ''));
        $endtime    = $pandb->real_escape_string((string) (isset($_GET['endtime'])    ? $_GET['endtime'] : ''));

        $data = [
            'action'     => $action,
            'type'       => $type, // zip / xml / device
            'project'    => $project,
            'id'         => $id,
            'vendor'     => $vendor,
            'data'       => $data,
            'filename'   => $filename,
            'device'     => $device,
            'vsys'       => $vsys,
            'vsysid'     => $vsysid,
            'panorama'   => $panorama,
            'period'     => $period,
            'source'     => $source,
            'startdate'  => $startdate,
            'starttime'  => $starttime,
            'enddate'    => $enddate,
            'endtime'    => $endtime,
        ];
        $message = getInformation($project, $data);
        echo json_encode(array('success' => $message['success'], 'total' => count($message['data']), 'connectors' => $message['data'], 'devices' => $message['data'], 'rows' => $message['data']));
        break;
    case 'POST':
        $message = addConnector($data);
        echo json_encode(array('success'=>$message['code'],'message'=>$message['msg']));
        break;
    case 'DELETE':
        if (!isset($data['project'])){$data['project']=$project;}
        $message = deleteConnector($data['project'], $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}


function getInformation(STRING $project, ARRAY $data ){
    global $app;

    if(!checkProjectRights($project,'view')){
        $message = [
            'success'   => true,
            'code' => -1,
            'data' => array(),
            'msg' => 'You do not have rights in this project'
        ];
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        return $message;
    }
    $projectdb = selectDatabase($project);
    $pandbRBAC = selectDatabase('pandbRBAC');
//    $pandb = selectDatabase('pandb');


    $action = $data['action'];

    $deviceID = $data['source'];
    $vsys = $data['vsys'];
    $vsysid = $data['vsysid'];
    $id = $data['id'];

    $myData = array();

    if ($action=="get"){
        $myData = array();
        $query = "SELECT c.id,c.name,c.vendor,c.image,c.device,e.device as source,  f.id as sourceid,
                    d.devicename, c.vsys,c.panorama,c.period,c.startdate,c.starttime,c.enddate,c.endtime,e.vsys as vsysname, c.top, c.type 
                  FROM connectors c, pandbRBAC.devices d, device_mapping e, (select id, device from device_mapping group by device) f
                  WHERE c.type='static' AND c.device = d.id AND c.vsys=e.id and f.device=e.device
                  UNION
                  SELECT c.id, c.name, c.vendor, c.image, 'N/A' as device, 'N/A' as source, '0' as sourceid, 'N/A' as devicename, 'N/A' as vsys, 'N/A' as panorama, c.period,c.startdate,c.starttime,c.enddate,c.endtime,'N/A' as vsysname, c.top, c.type FROM connectors c WHERE UPPER(c.type)='DYNAMIC';";
        $getDevices=$projectdb->query($query);
        //echo $query;
        $totalDevices=$getDevices->num_rows;

        if ($totalDevices!=0){
            while ($data = $getDevices->fetch_object()) {
                $myData[]=$data;
            }
        }
    }
    elseif ($action=="sourceByDevice"){
        $myData = array();
        /** @var  $deviceObj \PaloAltoNetworks\Sentinel\Devices\Device*/
        $deviceObj = $app->device->where("id",$deviceID)->get()->first();

        /*if($deviceObj->ispanorama == 1){
            $configFileName = $deviceObj->devicename."_".$deviceObj->serial.".xml%";
            $getAll = $projectdb->query(
                "SELECT id, device as source 
                        FROM device_mapping dm 
                        WHERE device like '$configFileName'  
                        GROUP BY device;");
            if ($getAll->num_rows > 0) {
                while ($data = $getAll->fetch_object()) {
                    $myData[] = $data;
                }
            }
        }
        else{
            $configFileName = $deviceObj->devicename."_".$deviceObj->serial.".xml%";
            $getAll = $projectdb->query(
                "SELECT id, device as source 
                        FROM device_mapping 
                        WHERE device like '$configFileName' 
                        GROUP BY device;");

            if ($getAll->num_rows > 0) {
                while ($data = $getAll->fetch_object()) {
                    $myData[] = $data;
                }
            }
        }*/

        $configFileName = $deviceObj->devicename."_".$deviceObj->serial.".xml%";
        $getAll = $projectdb->query(
            "SELECT id, device as source 
                        FROM device_mapping 
                        WHERE device like '$configFileName' 
                        GROUP BY device;");

        if ($getAll->num_rows > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        }
        /*while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }*/
    }
    elseif ($action=="vsysbysourceid"){
        $myData = array();
        /** @var  $deviceObj \PaloAltoNetworks\Sentinel\Devices\Device*/
        $deviceObj = $app->device->where("id",$deviceID)->get()->first();
        $sourceid = $projectdb->real_escape_string((integer) (isset($_POST['sourceid']) ? $_POST['sourceid'] : $_GET['sourceid']));

        if($deviceObj->ispanorama == 1){
            $getAll = $projectdb->query(
                "SELECT dm.id,dm.vsys as vsysname,dm.version,dm.vendor 
                        FROM device_mapping dm 
                        WHERE dm.device = (SELECT device FROM device_mapping WHERE id='$sourceid') 
                        GROUP BY vsys;");
            if ($getAll->num_rows > 1) {
                while ($data = $getAll->fetch_object()) {
                    $myData[] = $data;
                }
            }
        }
        else{
            $configFileName = $deviceObj->devicename."_".$deviceObj->serial.".xml";
            $getAll = $projectdb->query(
                "SELECT id,vsys as vsysname,version,vendor 
                        FROM device_mapping 
                        WHERE device = (SELECT device FROM device_mapping WHERE id='$sourceid') 
                        GROUP BY vsys;");
            if ($getAll->num_rows > 1) {
                while ($data = $getAll->fetch_object()) {
                    $myData[] = $data;
                }
            }
        }
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
    }
    elseif ($action=="vsysbysource"){
        $myData = array();
        /** @var  $deviceObj \PaloAltoNetworks\Sentinel\Devices\Device*/
        $deviceObj = $app->device->where("id",$deviceID)->get()->first();
        //echo "Device Obj: " .$deviceObj. "\n";
        //$source = (integer) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
//        $getDeviceName = $pandb->query("SELECT name FROM devices WHERE id='$source';");
//        $filename ='';
//        if ($getDeviceName->num_rows==1){
//            $getDeviceNameData = $getDeviceName->fetch_assoc();
//            $filename = $getDeviceNameData['name']."_config.xml";
//        }
//
//        if ($filename != "") {
//            $addQuery = "WHERE filename='$filename'";
//        } else {
//            $addQuery = "GROUP BY vsys";
//        }
//        echo "SELECT id,vsys,version,vendor FROM device_mapping $addQuery;";

        if($deviceObj->ispanorama == 1){
            $configFileName = $deviceObj->devicename."_".$deviceObj->serial.".xml";
            $getAll = $projectdb->query(
                "SELECT dm.id,dm.vsys,dm.version,dm.vendor 
                        FROM device_mapping dm, devicegroups dg 
                        WHERE device like '$configFileName' AND dg.device_mapping_id=dm.id 
                        GROUP BY vsys ORDER BY id;");
            if ($getAll->num_rows > 1) {
                while ($data = $getAll->fetch_object()) {
                    $myData[] = $data;
                }
            }
        }
        else{
            $configFileName = $deviceObj->devicename."_".$deviceObj->serial.".xml";
            $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping WHERE device like '$configFileName' GROUP BY vsys ORDER BY id;");
            //echo "SELECT id,vsys,version,vendor FROM device_mapping WHERE device like '$configFileName' GROUP BY vsys ORDER BY id;";
            if ($getAll->num_rows > 1) {
                while ($data = $getAll->fetch_object()) {
                    $myData[] = $data;
                }
            }
        }
//        $configFileName = $deviceObj->devicename."_".$deviceObj->serial.".xml";
//        $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping WHERE device like '$configFileName'  GROUP BY vsys ORDER BY id;");
//        $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping $addQuery;");
//        $count = $getAll->num_rows;
//        if ($count > 1) {
//            $myData[] = array("id" => "0", "vsys" => "all");
//        }
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
    }
    elseif (($action=="get_dg_devices") AND ($vsys!="")){
//        if ($id!=""){
            $myData = array();
            $connector_id = isset($id)?$id:'';
//            echo "SELECT devices FROM devicegroups WHERE device_mapping_id='$vsysid';";
            $vsyses = getVsysesDescIDs($projectdb, $vsys, $vsysid);
//            print_r($vsyses);
            $query = "SELECT devices FROM devicegroups WHERE device_mapping_id in (".implode(",", $vsyses).");";
//            echo "$vsys $query";
            $getDevices = $projectdb->query($query);
            $x = 0;
            
            if ($getDevices->num_rows > 0) {
                while($getDevicesData = $getDevices->fetch_assoc()) {
//                $getDevicesData = $getDevices->fetch_assoc();
                    $devices = $getDevicesData['devices'];
                    if ($devices != "") {
                        $xml = simplexml_load_string($devices);

                        foreach ($xml->entry as $key => $value) {
                            $serial = $value->attributes()->name;
                            $getDeviceName = $pandbRBAC->query("SELECT devicename FROM devices WHERE serial='$serial';");
                            if ($getDeviceName->num_rows == 1) {
                                $getDeviceNameData = $getDeviceName->fetch_assoc();
                                $deviceName = $getDeviceNameData['devicename'];
                            } else {
                                $deviceName = "<i>Not in our database</i>";
                            }

                            //Get existing devices in this LogConnector
                            $query = "SELECT * FROM connectors_dg_devices WHERE connector_id='$connector_id'";
                            $resultExistingDevicesInConnector = $projectdb->query($query);
                            $existingDevicesInConnector = array();
                            while ($dataExistingDevicesInConnector = $resultExistingDevicesInConnector->fetch_assoc()) {
                                $existingDevicesInConnector[] = $dataExistingDevicesInConnector['serial'];
                            }
                            if (isset($value->vsys)) {
                                foreach ($value->vsys->entry as $kkey => $vvalue) {
                                    $newvsys = $vvalue->attributes()->name;
                                    $myData[] = [
                                        'id' => $x,
                                        'device' => $deviceName,
                                        'serial' => (STRING)$serial,
                                        'vsys' => (STRING)$newvsys,
                                        'active' => in_array($serial, $existingDevicesInConnector) ? '1' : '0',
                                        'connector_id' => $connector_id,
                                        'devicegroup' => $vsys,
                                    ];
                                    $x++;
                                }
                            } else {
                                $myData[] = [
                                    'id' => $x,
                                    'device' => $deviceName,
                                    'serial' => (STRING)$serial,
                                    'vsys' => 'vsys1',
                                    'active' => in_array($serial, $existingDevicesInConnector) ? '1' : '0',
                                    'connector_id' => $connector_id,
                                    'devicegroup' => $vsys
                                ];
                                $x++;
                            }

                        }
                    }
                }
            }
        }
//    }

    elseif($action=='getLogConnectorInfo'){
        $connector_id = $id;

        if($connector_id == ''){
            //GetMyConnector
            $logConnector = new LogConnector($project);
            $connector_id = $logConnector->getMyLogConnectorID();
        }

//        echo "-$connector_id-";
//        die;

        $connectorQuery =
            "SELECT con.*, panDevices.devicename as deviceName, panDevices.device as originalName , panDevices.ispanorama
             FROM connectors con, pandbRBAC.devices panDevices 
             WHERE con.device = panDevices.id AND 
                   con.id='$connector_id'\n";
//        echo $connectorQuery;
        $connectorResult = $projectdb->query($connectorQuery);
        if($connectorResult->num_rows>0){
            while ($dataConnector = $connectorResult->fetch_assoc()){
//                print_r($dataConnector);
                if($dataConnector['period'] == "custom") {
                    $startDate = $dataConnector['startdate'];
                    $endDate = $dataConnector['enddate'];
                }
                else{
                    $nowString = date("Y-m-d H:i:s");
                    $now = new \DateTime($nowString);
                    switch ($dataConnector['period']) {
                        case 'last-60-seconds':
                            $ago60Secs = $now->sub(date_interval_create_from_date_string('last 60 seconds'));
                            $startDate = $ago60Secs->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-15-minutes':
                            $ago15mins = $now->sub(date_interval_create_from_date_string('last 15 minutes'));
                            $startDate = $ago15mins->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-hour':
                            $ago1hour = $now->sub(date_interval_create_from_date_string('last hour'));
                            $startDate = $ago1hour->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-6-hrs':
                            $ago6hour = $now->sub(date_interval_create_from_date_string('last 6 hours'));
                            $startDate = $ago6hour->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-12-hrs':
                            $ago12hour = $now->sub(date_interval_create_from_date_string('last 12 hours'));
                            $startDate = $ago12hour->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-24-hrs':
                        case 'last-calendar-day':
                            $ago24hour = $now->sub(date_interval_create_from_date_string('last day'));
                            $startDate = $ago24hour->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-7-days':
                            $ago7days = $now->sub(date_interval_create_from_date_string('last 7 days'));
                            $startDate = $ago7days->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-7-calendar-days':
                        case 'last-calendar-week':
                            //Check last Saturday
                            $today = date('Y-m-d H:i:s', strtotime("last Saturday"));
                            $lastSaturday = new \DateTime($today);
                            //Check the Sunday before last Sunday
                            $priorSunday = $lastSaturday->sub(date_interval_create_from_date_string('6 days'));
                            $startDate = $priorSunday->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-calendar-month':
                            //Calculate today's month
                            $firstDayStr = date("Y-n-j", strtotime("first day of previous month"));
                            $firstDay = new \DateTime($firstDayStr);
                            $startDate = $firstDay->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'last-30-days':
                            $ago30days = $now->sub(date_interval_create_from_date_string('last 30 days'));
                            $startDate = $ago30days->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;

                        case 'custom':
                            $startDate = $dataConnector['startdate'];
                            $endDate = $dataConnector['enddate'];
                            break;

                        default:
                            $beginningOfTimes = new \DateTime('1970-01-01');
                            $startDate = $beginningOfTimes->format('Y-m-d');
                            $endDate = date('Y-m-d');
                            break;
                    }
                }
                if($dataConnector['ispanorama'] == 0) {
                    $queryVSYS = "SELECT vsys FROM device_mapping WHERE id = '".$dataConnector['vsys']."';";
                    $vsysResult = $projectdb->query($queryVSYS);
                    if($vsysResult->num_rows>0){
                        $dataVsys = $vsysResult->fetch_assoc();
                        $vsys = $dataVsys['vsys'];
                    }

                    $myData[] = [
                        'id' => $connector_id,
                        'device' => $dataConnector['deviceName'],
                        'originalName' => $dataConnector['originalName'],
                        'serial' => $dataConnector['serial'],
                        'vsys' => $vsys,
                        'connector_id' => $connector_id,
                        'devicegroup' => '',
                        'startDate'  => $startDate,
                        'endDate'  => $endDate,

                    ];
                }
                else{

                    $query = "select connectors_dg_devices.* , devices.devicename as devicename, devices.type as type
                                from connectors_dg_devices 
                              LEFT JOIN pandbRBAC.devices devices
                                ON connectors_dg_devices.serial = devices.serial
                              WHERE connector_id =  '$connector_id'";
                    $results = $projectdb->query($query);
                    if($results->num_rows > 0){
                        while($data_ngfw = $results->fetch_assoc()){
                            $myData[] = [
                                'id' => $data_ngfw['id'],
                                'device' => isset($data_ngfw['devicename'])?$data_ngfw['devicename']:'unknown',
                                'originalName' => isset($data_ngfw['type'])?$data_ngfw['type']:'unknown',
                                'serial' => $data_ngfw['serial'],
                                'vsys' => $data_ngfw['vsys'],
                                'connector_id' => $connector_id,
                                'devicegroup' => '',
                                'startDate'  => $startDate,
                                'endDate'  => $endDate,
                            ];
                        }
                    }
                }
            }
        }
        else{
            $myData[] = [
                'id' => $connector_id,
                'device' => 'No connector selected',
                'serial' => '<b><font color="red">No connector selected</font></b>',
                'vsys' => '',
                'connector_id' => $connector_id,
                'devicegroup' => ''
            ];

//            print_r($myData);
        }
    }

    $message = [
        'success'   => true,
        'code'      => 0,
        'data'      => $myData,
    ];

    return $message;
}

function deleteConnector(STRING $project, ARRAY $data){
    global $app;

    if(!checkProjectRights($data['project'],'delete')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'You do not have rights in this project';
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        return $message;
    }

//    $project = isset($data['project'])?$data['project']:'';
    if($project==''){
        return
            $message = [
                'success'   => true,
                'code'      => 0,
                'msg'       => 'No connector deleted. Project not defined'
            ];
    }
    $projectdb = selectDatabase($project);
    $id     = isset($data['id'])?$data['id']: 'selected';

    if ($id=="all"){
        $projectdb->query("TRUNCATE connectors;");
        $projectdb->query("TRUNCATE connectors_dg_devices;");

        $message = [
            'success'   => true,
            'code'      => 0,
            'msg'       => 'All Connectors deleted correctly'
        ];
        //Remove the connector from the users in this project

        $query = "UPDATE pandbRBAC.user_settings SET selectedLogConnector='' WHERE project_id=(SELECT id FROM pandbRBAC.projects WHERE name = '$project');";
        $projectdb->query($query);
    }
    else{
//        echo "DELETE FROM connectors WHERE id IN ($id);";
        $projectdb->query("DELETE FROM connectors WHERE id IN ('$id');");
        $projectdb->query("DELETE FROM connectors_dg_devices WHERE connector_id IN ('$id');");

        $query = "UPDATE pandbRBAC.user_settings SET selectedLogConnector='' WHERE user_settings.selectedLogConnector='$id' AND project_id=(SELECT id FROM pandbRBAC.projects WHERE name = '$project');";
        $projectdb->query($query);

        $message = [
            'success'   => true,
            'code'      => 0,
            'msg'       => 'Connector(s) deleted correctly'
        ];
    }

    return $message;
}

function addConnector(ARRAY $data){
    global $app;

    if(!checkProjectRights($data['project'],'update')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'You do not have rights in this project';
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        return $message;
    }

    $project = isset($data['project'])?$data['project']:'';
    if($project==''){
        return
            $message = [
                'success'   => true,
                'code'      => 0,
                'msg'       => 'No connector created. Project not defined'
            ];
    }
    $projectdb = selectDatabase($project);

    if ($data['vendor']=="PANOS"){$image="paloalto_black.png";}
    elseif($data['vendor']=="SPLUNK"){$image="splunk.png";}
    else{$image="paloalto_black.png";}

    preg_match('/(?<date>[0-9]{4}-[0-9]{2}-[0-9]{2})(.)?/', $data['startdate'], $output_array);
    if(isset($output_array['date'])) {
        $data['startdate'] = $output_array['date'];
    }else{
        $data['startdate'] = "";
    }

    preg_match('/(?<date>[0-9]{4}-[0-9]{2}-[0-9]{2})(.)?/', $data['enddate'], $output_array);
    if(isset($output_array['date'])) {
        $data['enddate'] = $output_array['date'];
    }else{
        $data['enddate'] = "";
    }

    if($data['type']== 'Dynamic'){
        $exists=$projectdb->query("SELECT id FROM connectors WHERE id='".$data['id']."';");
        if ($exists->num_rows==1){
            $query = "UPDATE connectors 
                        SET image='$image', name='".htmlspecialchars($data['name'])."', vendor='".$data['vendor']."', 
                            device='', vsys='', panorama='', period='".htmlspecialchars($data['period'])."', serial ='', 
                            startdate='".$data['startdate']."', starttime='".$data['starttime']."', enddate='".$data['enddate']."', endtime='".$data['endtime']."', top='".$data['top']."', type='Dynamic'
                        WHERE id='".$data['id']."';";
            //echo "$query\n";
            $projectdb->query($query);
            $connector_id=$data['id'];
        }
        else {
            #ADD
            $projectdb->query("INSERT INTO connectors (name,vendor,device,vsys,panorama,period,image,startdate,starttime,enddate,endtime,serial,type,top) 
                              VALUES (  '".htmlspecialchars($data['name'])."','".$data['vendor']."','','','',
                                        '".htmlspecialchars($data['period'])."','$image','".$data['startdate']."','".$data['starttime']."','".$data['enddate']."','".$data['endtime']."','','Dynamic','".$data['top']."');");
            $connector_id=$projectdb->insert_id;
        }
    }
    else {

        if(isset($data['panorama']) && $data['panorama']==1){

            if(!isset($data['data']) || $data['data']==="" || count($data['data'])===0  ){
                $message_error = [
                    'code' => false,
                    'msg' => 'Please select a Device for the selected Device Group'
                ];

                return $message_error;
            }
        }

        $deviceObj = $app->device->where('id', '=', $data['device'])->get()->first();
        $serial = $deviceObj->serial;

//    $query = "SELECT vsys FROM device_mapping WHERE id=".$data['vsys']." LIMIT 1";
//    $result = $projectdb->query($query);
//    $data2 = $result->fetch_assoc();
//    $vsys = $data2['vsys'];
        $vsys = $data['vsys'];


        if (preg_match("/T00:00:00/", $data['startdate'])) {
            $data['startdate'] = str_replace("T00:00:00", "", $data['startdate']);
        }

        if (preg_match("/T00:00:00/", $data['enddate'])) {
            $data['enddate'] = str_replace("T00:00:00", "", $data['enddate']);
        }

        $exists = $projectdb->query("SELECT id FROM connectors WHERE id='" . $data['id'] . "';");
        if ($exists->num_rows == 1) {
            $query = "UPDATE connectors 
        SET image='$image', name='" . htmlspecialchars($data['name']) . "', vendor='" . $data['vendor'] . "', 
            device='" . htmlspecialchars($data['device']) . "', vsys='$vsys', panorama='" . $data['panorama'] . "', period='" . htmlspecialchars($data['period']) . "', 
            startdate='" . $data['startdate'] . "', starttime='" . $data['starttime'] . "', enddate='" . $data['enddate'] . "', endtime='" . $data['endtime'] . "', serial ='$serial', top='" . $data['top'] . "', type='Static'
        WHERE id='" . $data['id'] . "';";
            //echo "$query\n";
            $projectdb->query($query);
            $connector_id = $data['id'];
        } else {
            #ADD
            $projectdb->query("INSERT INTO connectors (name,vendor,device,vsys,panorama,period,image,startdate,starttime,enddate,endtime,serial,top, type) 
                              VALUES (  '" . htmlspecialchars($data['name']) . "','" . $data['vendor'] . "','" . htmlspecialchars($data['device']) . "','$vsys','" . $data['panorama'] . "',
                                        '" . htmlspecialchars($data['period']) . "','$image','" . $data['startdate'] . "','" . $data['starttime'] . "','" . $data['enddate'] . "','" . $data['endtime'] . "','$serial','" . $data['top'] . "', 'Static');");
            $connector_id = $projectdb->insert_id;

        }

        $projectdb->query("DELETE FROM connectors_dg_devices WHERE connector_id='$connector_id'");
        if (isset($data['data']) && count($data['data']) != 0) {
            $devicesTuples = explode(";", $data['data']);
            foreach ($devicesTuples as $devicesTuple) {
                list($serial, $vsys) = explode(",", $devicesTuple);
                $query = "INSERT INTO connectors_dg_devices (serial, vsys,active,connector_id) VALUES ('$serial', '$vsys','1','$connector_id')";
                $projectdb->query($query);
//            echo $query;
            }
//        $projectdb->query("UPDATE connectors_dg_devices SET active=0 WHERE connector_id='$connector_id';");
//        $projectdb->query("UPDATE connectors_dg_devices SET active=1 WHERE id IN ($data);");
        }
    }
    $message = [
        'code'  => true,
        'msg'   => 'Connector saved'
    ];
    return $message;
}