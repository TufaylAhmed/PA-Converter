<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//error_reporting(E_ALL & ~E_NOTICE);

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string) (isset($_GET['action'])      ? $_GET['action'] : '');
        $type       = (string) (isset($_GET['type'])        ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string) (isset($_GET['project'])     ? $_GET['project'] : '');
        $id         = (string) (isset($_GET['id'])          ? $_GET['id'] : '');
        $ids        = (string) (isset($_GET['ids'])         ? $_GET['ids'] : '');
        $name       = (string) (isset($_GET['name'])        ? $_GET['name'] : ''); // zip / xml / device
        $device     = (string) (isset($_GET['device'])      ? $_GET['device'] : '');
        $vsys       = (string) (isset($_GET['vsys'])        ? $_GET['vsys'] : '');
        $start      = (integer)(isset($_GET['start'])       ? $_GET['start'] : '');
        $limit      = (integer)(isset($_GET['limit'])       ? $_GET['limit'] : '');
        $connector  = (string) (isset($_GET['connector'])   ? $_GET['connector'] : '');
        $source     = (string) (isset($_GET['source'])      ? $_GET['source'] : '');
        break;
    case 'POST':
        $action     = (string) (isset($_POST['action'])     ? $_POST['action'] : '');
        $type       = (string) (isset($_POST['type'])       ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string) (isset($_POST['project'])    ? $_POST['project'] : '');
        $id         = (string) (isset($_POST['id'])         ? $_POST['id'] : '');
        $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
        $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : ''); // zip / xml / device
        $device     = (string) (isset($_POST['device'])     ? $_POST['device'] : '');
        $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        $start      = (integer)(isset($_POST['start'])      ? $_POST['start'] : '');
        $limit      = (integer)(isset($_POST['limit'])      ? $_POST['limit'] : '');
        $connector  = (string) (isset($_POST['connector'])  ? $_POST['connector'] : '');
        $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
        break;

    default:
        $action     = (string) (isset($_POST['action'])     ? $_POST['action'] : '');
        $type       = (string) (isset($_POST['type'])       ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string) (isset($_POST['project'])    ? $_POST['project'] : '');
        $id         = (string) (isset($_POST['id'])         ? $_POST['id'] : '');
        $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
        $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : ''); // zip / xml / device
        $device     = (string) (isset($_POST['device'])     ? $_POST['device'] : '');
        $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        $start      = (integer)(isset($_POST['start'])      ? $_POST['start'] : '');
        $limit      = (integer)(isset($_POST['limit'])      ? $_POST['limit'] : '');
        $connector  = (string) (isset($_POST['connector'])  ? $_POST['connector'] : '');
        $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
        break;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$id = $projectdb->real_escape_string($id);
$ids = $projectdb->real_escape_string($ids);
$name = $projectdb->real_escape_string($name);
$device = $projectdb->real_escape_string($device);
$vsys = $projectdb->real_escape_string($vsys);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$connector = $projectdb->real_escape_string($connector);
$source = $projectdb->real_escape_string($source);

if ($action=="add"){
	
	$image="paloalto_black.png";

	$name = htmlspecialchars($name);

	$exists=$projectdb->query("SELECT id FROM connectors_userid WHERE id='$id';");
	if ($exists->num_rows==1){
		#EDIT
		$projectdb->query("UPDATE connectors_userid SET image='$image',name='$name',  device='$device'  WHERE id='$id';");
	}
	else {
		#ADD
		$projectdb->query("INSERT INTO connectors_userid (name,device,image) VALUES ('$name','$device','$image');");
        }
	echo json_encode(array('success'=>true,'message'=>'Connector saved'));
}
elseif ($action=="get"){
    $getDevices = $projectdb->query("SELECT id,name,image,device,vsys FROM connectors_userid;");
    $totalDevices = $getDevices->num_rows;
    if ($totalDevices != 0) {
        while ($data = $getDevices->fetch_object()) {
            $myData[] = $data;
        }
    }
    if ($totalDevices == 0) {
        $myData = "";
    }
    echo '{"total":"'.$totalDevices.'","connectors":'.json_encode($myData).'}';
}
elseif ($action=="remove"){
	if ($type=="selected"){
		$ids = $projectdb->real_escape_string( (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));

		if($ids != ""){

		    $projectdb->query("DELETE FROM connectors_userid WHERE id IN ($ids);");

            $more=$projectdb->query("SELECT id FROM connectors_userid;");
            if ($more->num_rows==0){
                $projectdb->query("TRUNCATE userid_group;");
                $projectdb->query("TRUNCATE userid_group_members;");
            }
            else{
                $projectdb->query("DELETE FROM userid_group WHERE connector IN ($ids);");
                $projectdb->query("DELETE FROM userid_group_members WHERE connector IN ($ids);");
            }
            $pandb->query("UPDATE projects SET userid_connector='' WHERE name='$project' AND userid_connector IN ($ids);");

		}

	}
	elseif ($type=="all"){
		$projectdb->query("TRUNCATE connectors_userid;");
                $projectdb->query("TRUNCATE userid_group;");
                $projectdb->query("TRUNCATE userid_group_members;");
                $pandb->query("UPDATE projects SET userid_connector='' WHERE name='$project';");
	}
}
elseif ($action=="retrieve"){
    if ($type=="groups"){
        getRetrieveUserIdGroups($connector, $source, $project);
        sleep(3); del_progress($project);
    }
    elseif ($type=="users"){
        add_progress($project, '0.00', 'Retrieving Reports');
        echo json_encode(array("success"=>true));
        getRetrieveUserIdGroupsMembers($connector, $source, $project);
        update_progress($project, '1.00', 'Finished.');sleep(4); del_progress($project);
    }
}
elseif ($action=="enable"){
    if ($type=="all"){
        $projectdb->query("UPDATE userid_group SET enabled=1;");
    }
    else{
        $projectdb->query("UPDATE userid_group SET enabled=1 WHERE id IN ($ids)");
    }
}
elseif ($action=="disable"){
    if ($type=="all"){
        $projectdb->query("UPDATE userid_group SET enabled=0;");
        $projectdb->query("TRUNCATE userid_group_members;");
    }
    else{
        $projectdb->query("UPDATE userid_group SET enabled=0 WHERE id IN ($ids);");
        $projectdb->query("DELETE FROM userid_group_members WHERE lid IN ($ids);");
    }
}

# Common functions 
function getRetrieveUserIdGroups($connector, $source, $project){
    
    global $projectdb;
    global $pandb;
    $target="";
    $getConn = $projectdb->query("SELECT device, vsys FROM connectors_userid WHERE id = '$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        
        #Get Device
        $getDevice = $pandb->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_api_key = $datadevice['api_key'];
            $device_hostname = $datadevice['hostname'];
            $device_port = $datadevice['port'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];
            $device_serial = $datadevice['serial'];
        }
        
        if ($device_api_key==""){
            $getPanorama=$pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
            if ($getPanorama->num_rows==1){
                $getPanoramaData=$getPanorama->fetch_assoc();
                $device_hostname=$getPanoramaData['hostname'];
                $device_port=$getPanoramaData['port'];
                $panorama_devicename=$getPanoramaData['name'];
                $device_api_key=$getPanoramaData['api_key'];
                $target=$device_serial;
            }
        }
        
        # Clean before re-import
        $projectdb->query("DELETE FROM userid_group WHERE connector='$connector';");
        $projectdb->query("DELETE FROM userid_group_members WHERE connector='$connector';");
        
        $tuCurl = curl_init();
        
        $theGroups = array();
        
        $theGroups = get_dynamic_report_user_id_groups($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_port,$target);

        if (count($theGroups) > 0) {
            $groups_array = explode("\n", $theGroups);            
            
            foreach($groups_array as $key => $group){
                
                if (preg_match("/Total/i", $group)) {}
                elseif ($group==""){}
                elseif (preg_match("/: Custom Group/i", $group)){}
                else{
                    $group=trim($group);
                    $group = addslashes($group);
                    $projectdb->query("INSERT INTO userid_group (id, connector, name) VALUES (NULL, '$connector', '$group')");
                }
            }
        }
         
        curl_close($tuCurl);
    } 
}

function getRetrieveUserIdGroupsMembers($connector, $source, $project){
    
    global $projectdb;
    global $pandb;
    
    $getConn = $projectdb->query("SELECT device, vsys FROM connectors_userid WHERE id = '$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        
        #Get Device
        $getDevice = $pandb->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_id = $datadevice['id'];
            $device_api_key = $datadevice['api_key'];
            $device_hostname = $datadevice['hostname'];
            $device_port = $datadevice['port'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];
            $device_serial = $datadevice['serial'];
            
        }
        
        if ($device_api_key==""){
            $getPanorama=$pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
            if ($getPanorama->num_rows==1){
                $getPanoramaData=$getPanorama->fetch_assoc();
                $device_hostname=$getPanoramaData['hostname'];
                $device_port=$getPanoramaData['port'];
                $panorama_devicename=$getPanoramaData['name'];
                $device_api_key=$getPanoramaData['api_key'];
                $target=$device_serial;
            }
        }
        
        $tuCurl = curl_init();
        
        $theGroupsMembers = array();
        
        $getGroupsSelected = $projectdb->query("SELECT id, connector, name FROM userid_group WHERE connector = '$connector' AND enabled = '1';");
        $allrules=$getGroupsSelected->num_rows;
        $x=1;
        if ($getGroupsSelected->num_rows >= 1) {
            
            while($dataG = $getGroupsSelected->fetch_assoc()){
                
                $lid_group = $dataG['id'];
                $name_group = $dataG['name'];
                $theGroupsMembers = get_dynamic_report_user_id_groups_members($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_port, $name_group,$target);    
                if (count($theGroupsMembers) > 0) {
                    $projectdb->query("DELETE FROM userid_group_members WHERE lid='$lid_group';");
                    $groups_array = explode("\n", $theGroupsMembers);

                    foreach($groups_array as $key => $group){
                        if (preg_match("/short name:/i", $group)) {
                            $group_col = explode(":", $group);
                            $short_name = trim(addslashes($group_col[1]));
                        }
                        
                        if (preg_match("/source type:/i", $group)) {
                            $group_col = explode(":", $group);
                            $source_type = trim(addslashes($group_col[1]));
                        }
                        
                        if (preg_match("/source:/i", $group)) {
                            $group_col = explode(":", $group);
                            $source = trim(addslashes($group_col[1]));
                        }
                        
                        if (preg_match("/]/i", $group)) {
                            $group_col = explode("]", $group);
                            $user = trim(addslashes($group_col[1]));
                            
                            $projectdb->query("INSERT INTO userid_group_members (id, lid, name, connector) VALUES (NULL, '$lid_group', '".$user."', '$connector');");
                            
                        }
                    }
                    
                    $projectdb->query("UPDATE userid_group SET short_name = '".$short_name."', type = '$source_type', origin = '$source' WHERE id = '$lid_group' ;");
                    $short_name="";$source_type="";$source="";
                }
                $progress = $x / $allrules;
                if ($progress == 1) {
                  $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
                  update_progress($project, '1.00', 'Finished.');
                } else {
                  update_progress($project, $progress, $x . ' from ' . $allrules);
                  $x++;
                }
            }
        }
        else{
            sleep(3);
            update_progress($project, '1.00', 'Finished.');
            
        }
        curl_close($tuCurl);
    }
}

