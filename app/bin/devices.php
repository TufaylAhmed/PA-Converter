<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/userManager/API/devices/register.php';
require_once INC_ROOT.'/userManager/API/devices/delete.php';
require_once INC_ROOT.'/userManager/API/devices/list.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

/*
$action = "";
$hostname = "";
$devicename = "";
$username = "";
$password = "";
$description = "";
$ispanorama = "";
$devices = "";
$port = "";
$type = "";
*/

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action = (string) (isset($_GET['action']) ? $_GET['action'] : '');
        $hostname = (isset($_GET['hostname']) ? $_GET['hostname'] : '');
        $devicename = (isset($_GET['name']) ? $_GET['name'] : '');
        $username = (isset($_GET['username']) ? $_GET['username'] : '');
        $password = (isset($_GET['password']) ? $_GET['password'] : '');
        $description = (isset($_GET['description']) ? $_GET['description'] : '');
        $ispanorama = (isset($_GET['ispanorama']) ? $_GET['ispanorama'] : '');
        $devices = (isset($_GET['devices']) ? $_GET['devices'] : '');
        $port = (isset($_GET['port']) ? $_GET['port'] : '');
        $type = (string) (isset($_GET['type']) ? $_GET['type'] : ''); // zip / xml / device
        break;
    case 'POST':
        $action = (string) (isset($_POST['action']) ? $_POST['action'] : '');
        $hostname = (isset($_POST['hostname']) ? $_POST['hostname'] : '');
        $devicename = (isset($_POST['name']) ? $_POST['name'] : '');
        $username = (isset($_POST['username']) ? $_POST['username'] : '');
        $password = (isset($_POST['password']) ? $_POST['password'] : '');
        $description = (isset($_POST['description']) ? $_POST['description'] : '');
        $ispanorama = (isset($_POST['ispanorama']) ? $_POST['ispanorama'] : '');
        $devices = (isset($_POST['devices']) ? $_POST['devices'] : '');
        $port = (isset($_POST['port']) ? $_POST['port'] : '');
        $type = (string) (isset($_POST['type']) ? $_POST['type'] : ''); // zip / xml / device
        break;

    default:
        $action = (string) (isset($_POST['action']) ? $_POST['action'] : '');
        $hostname = (isset($_POST['hostname']) ? $_POST['hostname'] : '');
        $devicename = (isset($_POST['name']) ? $_POST['name'] : '');
        $username = (isset($_POST['username']) ? $_POST['username'] : '');
        $password = (isset($_POST['password']) ? $_POST['password'] : '');
        $description = (isset($_POST['description']) ? $_POST['description'] : '');
        $ispanorama = (isset($_POST['ispanorama']) ? $_POST['ispanorama'] : '');
        $devices = (isset($_POST['devices']) ? $_POST['devices'] : '');
        $port = (isset($_POST['port']) ? $_POST['port'] : '');
        $type = (string) (isset($_POST['type']) ? $_POST['type'] : ''); // zip / xml / device
        break;
}

//$action = (isset($_POST['action']) ? $_POST['action'] : $_GET['action']);
//$hostname = (isset($_POST['hostname']) ? $_POST['hostname'] : $_GET['hostname']);
//$devicename = (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
//$username = (isset($_POST['username']) ? $_POST['username'] : $_GET['username']);
//$password = (isset($_POST['password']) ? $_POST['password'] : $_GET['password']);
//$description = (isset($_POST['description']) ? $_POST['description'] : $_GET['description']);
//$ispanorama = (isset($_POST['ispanorama']) ? $_POST['ispanorama'] : $_GET['ispanorama']);
//$devices = (isset($_POST['devices']) ? $_POST['devices'] : $_GET['devices']);
//$port = (isset($_POST['port']) ? $_POST['port'] : $_GET['port']);
//$type = (isset($_POST['type']) ? $_POST['type'] : $_GET['type']);


$action = $pandb->real_escape_string($action);
$hostname = $pandb->real_escape_string($hostname);
$devicename = $pandb->real_escape_string($devicename);
$username = $pandb->real_escape_string($username);
$password = $pandb->real_escape_string($password);
$description = $pandb->real_escape_string($description);
$ispanorama = $pandb->real_escape_string($ispanorama);
$devices = $pandb->real_escape_string($devices);
$port = $pandb->real_escape_string($port);
$type = $pandb->real_escape_string($type);

global $app;
$DEVICESPATH = USERSPACE_PATH."/devices/";
if (is_dir($DEVICESPATH)) {
    
} else {
    mkdir(USERSPACE_PATH."/devices", 0766);
}

if (isset($action)) {
    switch ($action) {
        case "get_panorama":
            $getDevices = $pandb->query("SELECT * FROM devices WHERE ispanorama='1';");
            $totalDevices = $getDevices->num_rows;
            if ($totalDevices != 0) {

                while ($row = $getDevices->fetch_assoc()) {
                    $deviceID = $row['id'];
                    $deviceHostname = $row['hostname'];
                    $deviceName = $row['name'];
                    $deviceDescription = $row['description'];
                    $deviceVsys = $row['vsys'];
                    $deviceApiKey = $row['api_key'];
                    $devicePanos = $row['panos'];
                    $deviceApps = $row['apps'];
                    $deviveThreats = $row['threats'];
                    $deviceIsPanorama = $row['ispanorama'];
                    $deviceConfig = $row['config'];
                    $deviceType = $row['type'];
                    $devicePort = $row['port'];

                    if ($deviceType == "m100") {
                        $thumb = "m100.png";
                        $deviceIsPanorama = 1;
                    } elseif ($deviceType == "vm-panorama") {
                        $thumb = "panorama.png";
                        $deviceIsPanorama = 1;
                    } else {
                        $thumb = $deviceType . ".png";
                        $deviceIsPanorama = 0;
                    }

                    if ($deviceVsys != "vsys1") {
                        $thumb = "vsys.png";
                    }

                    $myDevices[] = '{"name":"' . $deviceName . '","id":"' . $deviceID . '","hostname":"' . $deviceHostname . '","description":"' . $deviceDescription . '","vsys":"' . $deviceVsys . '","api_key":"' . $deviceApiKey . '","panos":"' . $devicePanos . '","apps":"' . $deviceApps . '","threats":"' . $deviveThreats . '","config":"' . $deviceConfig . '","ispanorama":"' . $deviceIsPanorama . '","thumb":"' . $thumb . '","port":"' . $devicePort . '","type":"' . $deviceType . '"}';
                }
                $output = implode(",", $myDevices);
                echo '{"total":"' . $totalDevices . '","devices":[' . $output . ']}';
            }

            break;
        case "get":
            $getDevices = $pandb->query("SELECT * FROM devices ORDER BY type DESC;");
            $totalDevices = $getDevices->num_rows;
            if ($totalDevices != 0) {

                while ($row = $getDevices->fetch_assoc()) {
                    $deviceID = $row['id'];
                    $deviceHostname = $row['hostname'];
                    $deviceName = $row['name'];
                    $deviceDescription = $row['description'];
                    $deviceVsys = $row['vsys'];
                    $deviceApiKey = $row['api_key'];
                    $devicePanos = $row['panos'];
                    $deviceApps = $row['apps'];
                    $deviveThreats = $row['threats'];
                    $deviceIsPanorama = $row['ispanorama'];
                    $deviceConfig = $row['config'];
                    $deviceType = $row['type'];
                    $devicePort = $row['port'];

                    if ($deviceType == "m100") {
                        $thumb = "m100.png";
                        $deviceIsPanorama = 1;
                    } elseif ($deviceType == "vm-panorama") {
                        $thumb = "panorama.png";
                        $deviceIsPanorama = 1;
                    } elseif ($deviceType == "vm-series") {
                        $thumb = "vmseries.png";
                    } else {
                        $thumb = $deviceType . ".png";
                        $deviceIsPanorama = 0;
                    }

                    if ($deviceVsys != "vsys1") {
                        $thumb = "vsys.png";
                    }

                    $myDevices[] = '{"name":"' . $deviceName . '","id":"' . $deviceID . '","hostname":"' . $deviceHostname . '","description":"' . $deviceDescription . '","vsys":"' . $deviceVsys . '","api_key":"' . $deviceApiKey . '","panos":"' . $devicePanos . '","apps":"' . $deviceApps . '","threats":"' . $deviveThreats . '","config":"' . $deviceConfig . '","ispanorama":"' . $deviceIsPanorama . '","thumb":"' . $thumb . '","port":"' . $devicePort . '","type":"' . $deviceType . '"}';
                }
                $output = implode(",", $myDevices);
                echo '{"total":"' . $totalDevices . '","devices":[' . $output . ']}';
            }

            break;
        case "add":
            if(!accessControl("any", ['device.create', 'device.admin'])){
                $message = array();
                $message['code'] = false;
                $message['msg'] = 'Your account does not have device creation rights';
                echo json_encode(array('success' => $message['code'], 'message' => $message['msg']));
                return;
            }

            //if ((isset($hostname)) and ( isset($devicename)) and ( isset($username)) and ( isset($password))) {
            if (($hostname != "") && ($devicename != "") && ($username != "") && ($password != "")) {

                $message= registerDevice($devicename);
                if($message['code']) {

                    if (str_start($type,"m") OR ($type == "vm-panorama")) {
                        $ispanorama = 1;
                    } else {
                        $ispanorama = 0;
                    }

//                if (($hostname == "") or ( $devicename == "")) {  //Not necessary. We saw before that they can't be empty
//                    # Received ADD but all the fields are empty
//                    echo json_encode(array('success' => false, 'message' => 'Some fields are empty.'));
//                }
//                else {
                    $getDevice = $pandb->query("SELECT id FROM devices WHERE name='$devicename';");
                    if ($getDevice->num_rows == 0) {
                        if ($port == "") {
                            $port = "443";
                        }

                        $api_key = generate_key($hostname, $username, $password, $port);
                        if ($api_key != "") {
                            $pandb->query("INSERT INTO devices (name,description,api_key,hostname,ispanorama,type,port) VALUES ('$devicename','$description','$api_key','$hostname','$ispanorama','$type','$port');");
                            $configtype = "running";
                            getConfigBackup($hostname, $devicename, $api_key, $port, $configtype);
                            getThreats($hostname, $devicename, $api_key, $port);
                            getApplications($hostname, $devicename, $api_key, $port);
                            getApplications_container($hostname, $devicename, $api_key, $port);
                            getRegions($hostname, $devicename, $api_key, $port);
                            getSystemInfo_Target($hostname, $devicename, $api_key, $port);
                            getUrlCategories($hostname, $devicename, $api_key, $port);

                            if ($ispanorama == 1) {
                                getPanoramaDevicesConnected($hostname, $devicename, $api_key, $port);
                            } else {
                                #getVsys($hostname, $devicename, $api_key,$port);
                            }


                            echo json_encode(array('success' => true, 'message' => 'The device has been added.'));
                        } else {
                            echo json_encode(array('success' => false, 'message' => 'Error generating the api key.'));
                        }
                    }
                    else {
                        #the device exists and i will save the changes
                        if ($port == "") {
                            $port = "443";
                        }
                        if (($username != "") and ($password != "") and ($hostname != "") and ($devicename != "")) {
                            $api_key = generate_key($hostname, $username, $password, $port);
                            if ($api_key != "") {
                                $pandb->query("UPDATE devices SET api_key='$api_key' WHERE name='$devicename'");
                            }
                        }
                        if (($devicename != "") and ($hostname != "")) {
                            $pandb->query("UPDATE devices SET hostname='$hostname',port='$port',description='$description',ispanorama='$ispanorama',type='$type' WHERE name='$devicename'");
                            //echo "UPDATE devices SET hostname='$hostname',port='$port',description='$description',ispanorama='$ispanorama',type='$type' WHERE name='$devicename'";
                            $getDevice = $pandb->query("SELECT api_key FROM devices WHERE name='$devicename'");
                            if ($getDevice->num_rows == 1) {
                                $data = $getDevice->fetch_assoc();
                                $api_key = $data['api_key'];
                                if ($ispanorama == 1) {
                                    getPanoramaDevicesConnected($hostname, $devicename, $api_key, $port);
                                }
                                $configtype = "running";
                                getConfigBackup($hostname, $devicename, $api_key, $port, $configtype);
                                getThreats($hostname, $devicename, $api_key, $port);
                                getApplications($hostname, $devicename, $api_key, $port);
                                getApplications_container($hostname, $devicename, $api_key, $port);
                                getRegions($hostname, $devicename, $api_key, $port);
                                getSystemInfo_Target($hostname, $devicename, $api_key, $port);
                                getUrlCategories($hostname, $devicename, $api_key, $port);
                                //echo json_encode(array('success'=>true,'message'=>'Config retrieved and saved.'));
                            }
                            $pandb->query("UPDATE devices SET hostname='$hostname',port='$port',description='$description',ispanorama='$ispanorama',type='$type' WHERE name='$devicename'");
                            //echo "UPDATE devices SET hostname='$hostname',port='$port',description='$description',ispanorama='$ispanorama',type='$type' WHERE name='$devicename'";

                        }

                        echo json_encode(array('success' => true, 'message' => 'The changes have been saved.'));
                    }
//                }
                }
                else{
                    echo json_encode(array('success' => false, 'message' => $message["msg"]));
                }
            }
            else{
                echo json_encode(array('success' => false, 'message' => 'Some fields are empty.'));
            }

            break;
        case "generatekey":
            $getKey = generate_key($hostname, $username, $password, $port);
            if ($getKey != "") {
                echo json_encode(array('success' => true, 'key' => $getKey));
            }
            break;
        case "remove":
            if(!accessControl("any", ['device.delete', 'device.admin'])){
                $message = array();
                $message['code'] = false;
                $message['msg'] = 'Your account does not have device delete rights';
                echo json_encode(array('success' => $message['code'], 'message' => $message['msg']));
                return;
            }
            if ($devices != "") {
//                $device = split(",", $devices);
                $device = explode(",", $devices);

                foreach ($device as $key => $value) {
                    if ($value != "") {
                        $value = $pandb->real_escape_string($value);

                        $getDevice = $pandb->query("SELECT panos FROM devices WHERE name ='$value';");
                        $getData = $getDevice->fetch_assoc();
                        $panos = $getData['panos'];

                        $cmd = "rm -rf ".escapeshellarg(USERSPACE_PATH."/Templates/$value-$panos.xml");
                        shell_exec($cmd);

                        $cmd = "rm -rf ".escapeshellarg(USERSPACE_PATH."/devices/$value");
                        shell_exec($cmd);

//                        $pandb->query("DELETE FROM devices WHERE name LIKE '$value%'");
                        $pandb->query("DELETE FROM devices WHERE name LIKE '$value'");
                    }
                }
            }
            echo json_encode(array('success' => true, 'message' => 'The selected Device has been deleted'));
            break;
        case "removeALL":
            $getDevices = $pandb->query("SELECT panos,name FROM devices;");
            while ($data = $getDevices->fetch_assoc()) {
                $panos = $data['panos'];
                $value = $data['name'];

                $cmd = "rm -rf ".escapeshellarg(USERSPACE_PATH."/Templates/$value-*.xml");
                shell_exec($cmd);
            }
            $pandb->query("truncate devices;");
            $DeviceFolders = USERSPACE_PATH.'/devices/*';
            $cmd = "rm -rf ".USERSPACE_PATH.'/devices/*';
            shell_exec($cmd);
            echo json_encode(array('success' => true, 'message' => 'All the Devices have been deleted'));
            break;
        case "retrieve":
            if ((isset($hostname)) and ( isset($devicename)) and ( isset($username)) and ( isset($password))) {
                if (($hostname == "") or ( $devicename == "")) {
                    # Received ADD but all the fields are empty
                    echo json_encode(array('success' => false, 'message' => 'Some fields are empty.'));
                } else {
                    $getDevice = $pandb->query("SELECT id,port,management,api_key,ispanorama,serial FROM devices WHERE name='$devicename';");
                    if ($getDevice->num_rows == 1) {
                        #the device exists and i will save the changes
                        while ($getDeviceData = $getDevice->fetch_assoc()) {
                            $api_key = $getDeviceData['api_key'];
                            $port = $getDeviceData['port'];
                            $ispanorama=$getDeviceData['ispanorama'];
                            $management=$getDeviceData['management'];
                            $serial=$getDeviceData['serial'];
                            if ($port == "") {
                                $port = "443";
                            }
                            if ($api_key == "") {
                                $getPanorama=$pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$management';");
                                if ($getPanorama->num_rows==1){
                                    $getPanoramaData=$getPanorama->fetch_assoc();
                                    $panorama_hostname=$getPanoramaData['hostname'];
                                    $panorama_port=$getPanoramaData['port'];
                                    $panorama_devicename=$getPanoramaData['name'];
                                    $api_key=$getPanoramaData['api_key'];
                                    getConfigBackup_Target($panorama_hostname, $panorama_devicename, $api_key,$panorama_port,$serial,$devicename);
                                    //MT-301: Disable getPushedSharedPolicy
//                                    if (file_exists(USERSPACE_PATH."/devices/".$devicename."/ConfigBackup.xml")){
//                                        $xml1=simplexml_load_file(USERSPACE_PATH."/devices/".$devicename."/ConfigBackup.xml");
//                                        $vsys1=$xml1->xpath("//vsys/entry");
//                                        foreach ($vsys1 as $key=>$val){
//                                            $getDGVsys=$val->attributes()->name;
//                                            getPushedSharedPolicy_Target($panorama_hostname, $panorama_devicename, $api_key,$panorama_port,$serial,$devicename,$getDGVsys);
//                                        }
//                                    }
//                                    elseif(file_exists(USERSPACE_PATH."/devices/".$devicename."/ConfigBackup.xml.dat")){
//                                        $deviceObj = $app->device->where("serial", $devicename)->first();
//                                        $keyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObj->id)->first();
//                                        $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);
//                                        $content = $encryptor->decryptFromFile(USERSPACE_PATH."/devices/".$devicename."/ConfigBackup.xml.dat");
//                                        $xml1 = simplexml_load_string($content);
//                                        $vsys1=$xml1->xpath("//vsys/entry");
//                                        foreach ($vsys1 as $key=>$val){
//                                            $getDGVsys=$val->attributes()->name;
//                                            getPushedSharedPolicy_Target($panorama_hostname, $panorama_devicename, $api_key,$panorama_port,$serial,$devicename,$getDGVsys);
//                                        }
//                                    }
                                }
                                    
                            } 
                            else{
                                $configtype = "running";
                                getConfigBackup($hostname, $devicename, $api_key, $port, $configtype);
                            }
                        }
                        echo json_encode(array('success' => true, 'message' => 'The changes have been saved.'));
                    }
                }
            }

            break;
    }
}
?>
