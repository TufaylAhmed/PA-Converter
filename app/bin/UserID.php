<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $id         = (string)  (isset($_GET['id'])         ? $_GET['id'] : '');
        $name       = (string)  (isset($_GET['name'])       ? $_GET['name'] : ''); // zip / xml / device
        $connector  = (string)  (isset($_GET['connector'])  ? $_GET['connector'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])     ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])       ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])    ? $_POST['project'] : '');
        $id         = (string)  (isset($_POST['id'])         ? $_POST['id'] : '');
        $name       = (string)  (isset($_POST['name'])       ? $_POST['name'] : ''); // zip / xml / device
        $connector  = (string)  (isset($_POST['connector'])  ? $_POST['connector'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])     ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])       ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])    ? $_POST['project'] : '');
        $id         = (string)  (isset($_POST['id'])         ? $_POST['id'] : '');
        $name       = (string)  (isset($_POST['name'])       ? $_POST['name'] : ''); // zip / xml / device
        $connector  = (string)  (isset($_POST['connector'])  ? $_POST['connector'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        break;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$id = $projectdb->real_escape_string($id);
$name = $projectdb->real_escape_string($name);
$connector = $projectdb->real_escape_string($connector);
$vsys = $projectdb->real_escape_string($vsys);

require_once INC_ROOT.'/libs/database.php';

if ($action=="get"){
    if ($type=="groups"){
        $getconnector=$projectdb->query("SELECT device FROM connectors_userid WHERE id='$connector';");
        if ($getconnector->num_rows==1){
            $getconnectorData=$getconnector->fetch_assoc();
            $device=$getconnectorData['device'];
            
            $getDevices=$projectdb->query("SELECT id,name,connector,enabled,type,origin,short_name FROM userid_group WHERE connector='$connector';");
            $totalDevices=$getDevices->num_rows;
            if ($totalDevices!=0){
                    while ($data = $getDevices->fetch_object()) {
                            $lid=$data->id;
                            $getID=$projectdb->query("SELECT count(id) as users FROM userid_group_members WHERE lid='$lid' GROUP BY lid;");
                            if ($getID->num_rows==1){
                                $getIDData=$getID->fetch_assoc();
                                $data->users=$getIDData['users'];
                            }
                            else{
                                $data->users=0;
                            }
                            $myData[]=$data;
                    }
                    if ($totalDevices==0){$myData="";}
                    echo '{"total":"'.$totalDevices.'","groups":'.json_encode($myData).'}';
            }
        }
            
    }
    elseif($type == "userid_all"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $search = (string) (isset($_GET['search']) ? $_GET['search'] : '');
                break;
            case 'POST':
                $search = (string) (isset($_POST['search']) ? $_POST['search'] : '');
                break;
            default:
                $search = (string) (isset($_POST['search']) ? $_POST['search'] : '');
                break;
        }

        $search = $projectdb->real_escape_string($search);

        if($search != ""){
            $connector=0;
            $message = getUserSettings($project);
            if ($message['msg']->selectedUIDConnector!==NULL){
                $connector=$message['msg']->selectedUIDConnector;
                $getCon=$projectdb->query("SELECT device FROM connectors_userid WHERE id='$connector';");

                if ($getCon->num_rows==1){
                    $getConData=$getCon->fetch_assoc();
                    $device=$getConData['device'];
                }
                else{
                    $device=0;
                }
            }
            else{
                $device=0;
            }
            /*$getConnector=$pandb->query("SELECT userid_connector FROM projects WHERE name='$project';");
            
            if ($getConnector->num_rows==1){
                $getConnectorData=$getConnector->fetch_assoc();
                if ($getConnectorData['userid_connector']==0){
                    $device=0;
                }
                else{
                    $connector=$getConnectorData['userid_connector'];
                    $getCon=$projectdb->query("SELECT device FROM connectors_userid WHERE id='$connector';");
                    
                    if ($getCon->num_rows==1){
                        $getConData=$getCon->fetch_assoc();
                        $device=$getConData['device'];
                    }
                    else{
                        $device=0;
                    }
                }
            } */
            
            if ($device==0){
                $myData=[];
                $myData[] = array("idx" => "pre-logon", "short_name" => "pre-logon", "name" => "pre-logon", "type" => "userp.png", "icon" => "fa fa-user");
                $myData[] = array("idx" => "known-user", "short_name" => "known-user", "name" => "known-user", "type" => "userp.png", "icon" => "fa fa-user");
                $myData[] = array("idx" => "unknown", "unknown" => "unknown", "name" => "unknown", "type" => "userp.png", "icon" => "fa fa-user");
                echo '{"total":"'.count($myData).'","userid":'.json_encode($myData).'}';
            }
            else{
                $getUserId = $projectdb->query("SELECT id AS idx, name AS short_name, name, 'userp.png' as type, 'fa fa-user' AS icon FROM userid_group_members WHERE name LIKE '%$search%' GROUP BY name ".
                                                "UNION SELECT id AS idx, short_name, name,'user-groups.png' as type, 'fa fa-users' AS icon FROM userid_group WHERE (enabled = '1' AND (short_name LIKE '%$search%' OR name LIKE '%$search%') AND connector='$connector');");
                $total_user_id = $getUserId->num_rows;
                if ($total_user_id > 0){
                    //while ($dataUI = $getUserId->fetch_object()) {
                    while ($dataUI = $getUserId->fetch_assoc()) {    
                        if($dataUI['short_name'] != ""){
                            $dataUI['name'] = $dataUI['short_name'];
                        }
                        $myData[] = $dataUI;
                    }
                    //$myData[] = array("idx" => "any", "short_name" => "any", "name" => "any", "type" => "userp.png");
                    $myData[] = array("idx" => "pre-logon", "short_name" => "pre-logon", "name" => "pre-logon", "type" => "userp.png", "icon" => "fa fa-user");
                    $myData[] = array("idx" => "known-user", "short_name" => "known-user", "name" => "known-user", "type" => "userp.png", "icon" => "fa fa-user");
                    $myData[] = array("idx" => "unknown", "unknown" => "unknown", "name" => "unknown", "type" => "userp.png", "icon" => "fa fa-user");
                    //print_r($myData);
                    if ($total_user_id == 0){$myData = "";}
                    echo '{"total":"'.$total_user_id.'","userid":'.json_encode($myData).'}';
                }
                else{
                    //$myData[] = array("idx" => "any", "short_name" => "any", "name" => "any", "type" => "userp.png");
                    $myData[] = array("idx" => "pre-logon", "short_name" => "pre-logon", "name" => "pre-logon", "type" => "userp.png", "icon" => "fa fa-user");
                    $myData[] = array("idx" => "known-user", "short_name" => "known-user", "name" => "known-user", "type" => "userp.png", "icon" => "fa fa-user");
                    $myData[] = array("idx" => "unknown", "unknown" => "unknown", "name" => "unknown", "type" => "userp.png", "icon" => "fa fa-user");
                    //print_r($myData);
                    //if ($total_user_id == 0){$myData = "";}
                    echo '{"total":"'.$total_user_id.'","userid":'.json_encode($myData).'}';
                }
            }
            
        }
        else{
            $myData = [];
            $myData[] = array("idx" => "pre-logon", "short_name" => "pre-logon", "name" => "pre-logon", "type" => "userp.png", "icon" => "fa fa-user");
            $myData[] = array("idx" => "known-user", "short_name" => "known-user", "name" => "known-user", "type" => "userp.png", "icon" => "fa fa-user");
            $myData[] = array("idx" => "unknown", "unknown" => "unknown", "name" => "unknown", "type" => "userp.png", "icon" => "fa fa-user");
            echo '{"total":"'.count($myData).'","userid":'.json_encode($myData).'}';
        }
        
        
    }
    elseif($type == "userid_all_non_options"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $search = (string) (isset($_GET['search']) ? $_GET['search'] : '');
                break;
            case 'POST':
                $search = (string) (isset($_POST['search']) ? $_POST['search'] : '');
                break;
            default:
                $search = (string) (isset($_POST['search']) ? $_POST['search'] : '');
                break;
        }

        $search = $projectdb->real_escape_string($search);

//        $search = (string) (isset($_POST['search']) ? $_POST['search'] : $_GET['search']);
        //$search = (string) (isset($_POST['query']) ? $_POST['query'] : $_GET['query']);
        if($search != ""){
            $getConnector=$pandb->query("SELECT userid_connector FROM projects WHERE name='$project';");
            if ($getConnector->num_rows==1){
                $getConnectorData=$getConnector->fetch_assoc();
                if ($getConnectorData['userid_connector']==0){
                    $device=0;
                }
                else{
                    $connector=$getConnectorData['userid_connector'];
                    $getCon=$projectdb->query("SELECT device FROM connectors_userid WHERE id='$connector';");
                    if ($getCon->num_rows==1){
                        $getConData=$getCon->fetch_assoc();
                        $device=$getConData['device'];
                    }
                    else{
                        $device=0;
                    }
                }
            }
            
            if ($device==0){
                $myData = "";
                echo '{"total":"0","userid":'.json_encode($myData).'}';
            }
            else{
                $getUserId = $projectdb->query("SELECT id AS idx, name AS short_name, name, 'userp.png' as type FROM userid_group_members WHERE name LIKE '%$search%' GROUP BY name UNION SELECT id AS idx, short_name, name,'user-groups.png' as type FROM userid_group WHERE (enabled = '1' AND (short_name LIKE '%$search%' OR name LIKE '%$search%') AND connector='$connector');");
                $total_user_id = $getUserId->num_rows;
                if ($total_user_id > 0){
                    //while ($dataUI = $getUserId->fetch_object()) {
                    while ($dataUI = $getUserId->fetch_assoc()) {    
                        if($dataUI['short_name'] != ""){
                            $dataUI['name'] = $dataUI['short_name'];
                        }
                        $myData[] = $dataUI;
                    }
                    
                    //print_r($myData);
                    if ($total_user_id == 0){$myData = "";}
                    echo '{"total":"'.$total_user_id.'","userid":'.json_encode($myData).'}';
                }
                else{
                    //print_r($myData);
                    //if ($total_user_id == 0){$myData = "";}
                    $myData = "";
                    echo '{"total":"'.$total_user_id.'","userid":'.json_encode($myData).'}';
                }
            }
            
        }else{
            $myData = "";
            echo '{"total":"'.$total_user_id.'","userid":'.json_encode($myData).'}';
        }
        
        
    }
    elseif($type == "groups_all"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $search = (string) (isset($_GET['search']) ? $_GET['search'] : '');
                $filter = (string) (isset($_GET['filter']) ? $_GET['filter'] : '');
                $users  = (string) (isset($_GET['users'])  ? $_GET['users'] : '');
                break;
            case 'POST':
                $search = (string) (isset($_POST['search']) ? $_POST['search'] : '');
                $filter = (string) (isset($_POST['filter']) ? $_POST['filter'] : '');
                $users  = (string) (isset($_POST['users'])  ? $_POST['users'] : '');
                break;
            default:
                $search = (string) (isset($_POST['search']) ? $_POST['search'] : '');
                $filter = (string) (isset($_POST['filter']) ? $_POST['filter'] : '');
                $users  = (string) (isset($_POST['users'])  ? $_POST['users'] : '');
                break;
        }


        $search = $projectdb->real_escape_string($search);
        $filter = $projectdb->real_escape_string($filter);
        $users = $projectdb->real_escape_string($users);

//        $search = (string) (isset($_POST['search']) ? $_POST['search'] : $_GET['search']);
//        $filter = (string) (isset($_POST['filter']) ? $_POST['filter'] : $_GET['filter']);
//        $users = (string) (isset($_POST['users']) ? $_POST['users'] : $_GET['users']);
        
        $sql_groups_lid = "";
        
        if($search != ""){
            $sql_search = " AND name LIKE '%$search%' OR short_name LIKE '%$search%' ";
        }else{
            $sql_search = " ";
        }
        
        if($users != ""){
            $getGroupsLid = $projectdb->query("SELECT DISTINCT(lid) FROM userid_group_members WHERE name IN ($users);");
            if ($getGroupsLid->num_rows > 0){
                while ($dataGI = $getGroupsLid->fetch_assoc()) {
                    $groups_lid[] = $dataGI['lid'];
                }
                $sql_groups_lid = " AND id IN (".implode(",", $groups_lid).") ";
            }
            
        }
        
        if($filter == "groups_without_members"){
            
            $getGroupsWithout = $projectdb->query("SELECT id FROM userid_group WHERE id NOT IN (SELECT lid FROM userid_group_members);");
            if ($getGroupsWithout->num_rows > 0){
                while ($dataGW = $getGroupsWithout->fetch_assoc()) {
                    $groups_lid[] = $dataGW['id'];
                }
                $sql_groups_lid = " AND id IN (".implode(",", $groups_lid).") ";
            }
        }
         
        $getConnector = $pandb->query("SELECT userid_connector FROM projects WHERE name = '$project';");
        //echo "Connector:".$getConnector;
        if (isset($getConnector) && $getConnector!="" && $getConnector->num_rows==1){
            $getConnectorData = $getConnector->fetch_assoc();
            if ($getConnectorData['userid_connector'] == 0){
                $device = 0;
            }
            else{
                $connector = $getConnectorData['userid_connector'];
                $getCon = $projectdb->query("SELECT device FROM connectors_userid WHERE id = '$connector';");
                if ($getCon->num_rows == 1){
                    $getConData=$getCon->fetch_assoc();
                    $device = $getConData['device'];
                }
                else{
                    $device = 0;
                }
            }
        }
        else{
            //Blank value to avoid undefined variables
            $device = 0;
        }

        if ($device == 0){
            $myData = "";
            echo '{"total":"0","users_group":'.json_encode($myData).'}';
        }
        else{
            $getGroups = $projectdb->query("SELECT id AS idx, short_name, name FROM userid_group WHERE connector = '$connector' $sql_search $sql_groups_lid;");
            $total_groups = $getGroups->num_rows;
            if ($total_groups > 0){
                //while ($dataUI = $getUserId->fetch_object()) {
                while ($dataUI = $getGroups->fetch_assoc()) {    
                    if($dataUI['short_name'] != ""){
                        $dataUI['name'] = $dataUI['short_name'];
                    }
                    $myData[] = $dataUI;
                }
                echo '{"total":"'.$total_groups.'","users_group":'.json_encode($myData).'}';
            }
            else{

                $myData = "";
                echo '{"total":"'.$total_groups.'","users_group":'.json_encode($myData).'}';
            }
        }
            
        
    }
    elseif($type == "users_all"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $search = (string) (isset($_GET['search']) ? $_GET['search'] : '');
                $groups_lid = (string) (isset($_GET['groups_lid']) ? $_GET['groups_lid'] : '');
                $filter = (string) (isset($_GET['filter']) ? $_GET['filter'] : '');
                break;
            case 'POST':
                $search = (string) (isset($_POST['search']) ? $_POST['search'] : '');
                $groups_lid = (string) (isset($_POST['groups_lid']) ? $_POST['groups_lid'] : '');
                $filter = (string) (isset($_POST['filter']) ? $_POST['filter'] : '');
                break;
            default:
                $search = (string) (isset($_POST['search']) ? $_POST['search'] : '');
                $groups_lid = (string) (isset($_POST['groups_lid']) ? $_POST['groups_lid'] : '');
                $filter = (string) (isset($_POST['filter']) ? $_POST['filter'] : '');
                break;
        }

        $search = $projectdb->real_escape_string($search);
        $groups_lid = $projectdb->real_escape_string($groups_lid);
        $filter = $projectdb->real_escape_string($filter);

        $sql_lid = "";
        
        if($search != ""){
            $sql_search = " AND name LIKE '%$search%' ";
        }else{
            $sql_search = " ";
        }
        
        if($groups_lid != ""){
            $sql_lid = " AND lid IN ($groups_lid)";
        }
        
        if($filter == "groups_without_members"){
            
            $getGroupsWithout = $projectdb->query("SELECT id FROM userid_group WHERE id NOT IN (SELECT lid FROM userid_group_members);");
            if ($getGroupsWithout->num_rows > 0){
                while ($dataGW = $getGroupsWithout->fetch_assoc()) {
                    $groups_lid2[] = $dataGW['id'];
                }
                $sql_lid = " AND lid IN (".implode(",", $groups_lid2).") ";
            }
        }
        
        $getConnector = $pandb->query("SELECT userid_connector FROM projects WHERE name = '$project';");
        if (isset($getConnector) && $getConnector!="" && $getConnector->num_rows == 1){
            $getConnectorData = $getConnector->fetch_assoc();
            if ($getConnectorData['userid_connector'] == 0){
                $device = 0;
            }
            else{
                $connector = $getConnectorData['userid_connector'];
                $getCon = $projectdb->query("SELECT device FROM connectors_userid WHERE id = '$connector';");
                if ($getCon->num_rows == 1){
                    $getConData = $getCon->fetch_assoc();
                    $device = $getConData['device'];
                }
                else{
                    $device = 0;
                }
            }
        }
        else{
            //Blank value to avoid undefined variables
            $device = 0;
        }

        if ($device == 0){
            $myData = "";
            echo '{"total":"0","users":'.json_encode($myData).'}';
        }
        else{
            $getUsers = $projectdb->query("SELECT id AS idx, name FROM userid_group_members WHERE connector = '$connector' $sql_search $sql_lid GROUP BY name;");
            $total_users = $getUsers->num_rows;
            if ($total_users > 0){
                while ($dataUI = $getUsers->fetch_object()) {
                //while ($dataUI = $getUsers->fetch_assoc()) {    
                    $myData[] = $dataUI;
                }
                echo '{"total":"'.$total_users.'","users":'.json_encode($myData).'}';
            }
            else{

                $myData = "";
                echo '{"total":"'.$total_users.'","users":'.json_encode($myData).'}';
            }
        }
    }
}

function getUserSettings(STRING $project){
    global $app;
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;
    $message = get_UserSettings($project, $userID);
    return $message;
}