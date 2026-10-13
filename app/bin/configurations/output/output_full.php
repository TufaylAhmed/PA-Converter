<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
#DEBUG
//$_SERVER['DOCUMENT_ROOT']="/var/www/html";
//$_SERVER['REQUEST_METHOD']="POST";
#DEBUG

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/common/xml/panosxml.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/device/device.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $obj_filter      = $pandb->real_escape_string((string) ($_GET['objfilter'] ?? ''));
        $action      = $pandb->real_escape_string((string) ($_GET['action'] ?? ''));
        $object_search      = $pandb->real_escape_string((string) ($_GET['objsearch'] ?? ''));
        $name_search     = $pandb->real_escape_string((string) ($_GET['namesearch'] ?? ''));
        $vsys           = $pandb->real_escape_string((string) ($_GET['vsys'] ?? ''));

        $project        = $pandb->real_escape_string((string) ($_GET['project'] ?? ''));
        $start       = $pandb->real_escape_string((string) ($_GET['start'] ?? ''));
        $limit       = $pandb->real_escape_string((string) ($_GET['limit'] ?? ''));

        if ($action == 'get_api_calls_bulk'){
            $message = get_api_calls_bulk($project, $obj_filter, $object_search, $name_search, $vsys, $start, $limit);
        }
        else{
            $message = get_api_calls($project, $obj_filter, $object_search, $name_search, $vsys, $start, $limit);
        }
        if($message['code']){
            echo json_encode(["total" => $message['total'], "rows"  => $message['msg'], ]);
        }
        else{
            echo json_encode([ "total" => 0, "rows"  => '',]);
        }
        break;

    case 'POST':
        $message = broker($data);
        //echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $project        = $pandb->real_escape_string((string) ($_GET['project'] ?? ''));
        $message = send_api_calls($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

/***
 * @param $data
 * @return array
 */
function broker($data):array{
    global $app;
    $project=$data['project'];

    if(!checkProjectRights($project,'view')){
        $msg = [
            'code'  => false,
            'jobid' => -1,
            'msg'   => 'Your account does not have the rights to view this project contents'
        ];
        echo json_encode($msg);
        return $msg;
    }

    if (!$app->project->where('name', '=', $project)->get()->first() ) {
        $msg = [
            'code'  => false,
            'jobid' => -1,
            'msg'   => 'Project not found in our registry'
        ];
        echo json_encode($msg);
        return $msg;
    }

    $user = $app->container->sentinel->getUser();

    $projectdb = selectDatabase($project);

    $getBC=$projectdb->query("SELECT id FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
    if ($getBC->num_rows===1){
        $job_id=create_jobid($project,$projectdb);
        $path=INC_ROOT."/bin/configurations/output/output_function.php";
        $string="{sender:".$user->email.",api_key:".getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id")).",".",action:import,project:".$project.",jobid:".$job_id.",api_call:".$data['api_call']."}";

        $encodedString = base64_encode($string);

        if (XDEBUG===true){
            exec("export PHP_IDE_CONFIG=\"serverName=Expedition1\"; php $path \"".$encodedString."\"  > /tmp/error 2>/tmp/error &");
        }else {
            exec("php $path \"" . $encodedString . "\" > /tmp/error 2>/tmp/error &");
        }

        $msg = ["success"=>true,"jobid"=>$job_id, "msg"=>"Generating the XML files"];
        echo json_encode($msg);
        return $msg;
    }

    $msg = ["success"=>false,"jobid"=>-1, "msg"=>"You need to upload a PanOS Configuration first"];
    echo json_encode($msg);
    return $msg;
}

/***
 * @param string $projectName
 * @param string $object_filter
 * @param string $object_search
 * @param string $name_search
 * @param string $vsys
 * @param string $start
 * @param string $limit
 * @return array
 */
function get_api_calls(string $projectName, string $object_filter, string $object_search, string $name_search='', string $vsys='', string $start='0', string $limit='0'):array{
//    global $app;
    $projectdb = selectDatabase($projectName);

    $object_filter=$projectdb->real_escape_string($object_filter);
    $object_search=$projectdb->real_escape_string($object_search);
    $name_search=$projectdb->real_escape_string($name_search);
    $vsys=$projectdb->real_escape_string($vsys);
    $start=$projectdb->real_escape_string($start);
    $start=$projectdb->real_escape_string($start);
    $limit=$projectdb->real_escape_string($limit);

    if ($limit===""){
        $limit ='0';
    }
    if(!accessControl("any", ['project.admin','projectRole.'.$projectName.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to check API calls';
        return $message;
    }

    $message = array();
    $addFilter = "";
    if ($object_filter !== "All") {
        $addFilter = " WHERE table_name='$object_filter' AND table_name != 'grouping'";
    }
    else{
        $addFilter = " WHERE table_name != 'grouping'";
    }
    if ($object_search !== "") {
        if ($addFilter === "") {
            $addFilter = " WHERE (name LIKE '%$object_search%' OR xpath LIKE '%$object_search%' OR xml_final LIKE '%$object_search%') ";
        } else {
            $addFilter .= " AND (name LIKE '%$object_search%' OR xpath LIKE '%$object_search%' OR xml_final LIKE '%$object_search%')";
        }
    }

    $vsysSearch = explode(",", $vsys);
    $vsyses = [];
    foreach($vsysSearch as $item){
        if($item !== '' && $item !=='all' && $item !== 'shared') {
            $vsyses[] = ' OR lower(xpath) LIKE ("%/device-group/entry[@name=\'' . strtolower(trim($item)) . '\'%") OR lower(xpath) LIKE ("%/vsys/entry[@name=\'' . strtolower(trim($item)) . '\'%") ';
        }
        elseif($item === 'shared') {
            $vsyses[] = 'lower(xpath) LIKE ("/config/shared/%")';
        }
    }
    if(count($vsyses)>0){
        if($addFilter === ''){
            $addFilter = " WHERE (".implode(" OR ",$vsyses).")";
        }
        else{
            $addFilter .= "AND (" . implode(" OR ", $vsyses) . ")";
        }
    }

    $name_searches = explode(",", $name_search);
    $names = [];
    foreach ($name_searches as $item){
        $names[] = '"'.strtoupper(trim($item)).'"';
    }
    if($name_search !== "" ){
        if ($addFilter === "") {
            $addFilter = " WHERE name IN (".implode(",",$names).") ";
        } else {
            $addFilter .= " AND UPPER(name) IN (" . implode(",", $names) . ")";
        }
    }

    // Check if they are Clean (delete) calls to change the id order

    $queryCalls = "SELECT *, if(output like '%\"status\":\"success\"%', 'Successful', (if(output like '%\"status\":\"fail\"%', 'Failed', 'Pending'))) as 'status'  FROM output_mapping $addFilter;";
    //echo $queryCalls;
    $getCalls = $projectdb->query($queryCalls);
    $total = $getCalls->num_rows;
    $message['total']=$total;
    $queryCalls = "SELECT *, if(output like '%\"status\":\"success\"%', 'Successful', (if(output like '%\"status\":\"fail\"%', 'Failed', 'Pending'))) as 'status' FROM output_mapping $addFilter LIMIT $start, $limit ;";
    $getCalls = $projectdb->query($queryCalls);
    $count = $getCalls->num_rows;
    $myData = array();
    if ($count > 0) {
        while ($data = $getCalls->fetch_object()) {
            $myData[] = $data;
        }
    }
    if ($count === 0) {
        $myData = [];
        $message['total']=0;
    }

    //Check which of these entries are in a bulk call and report it in the answer.
    $included_query = "SELECT GROUP_CONCAT(xml_initial) as included_apis FROM output_mapping WHERE table_name ='grouping';";
    $result_included = $projectdb->query($included_query);
    $included_apis = [];
    if($result_included->num_rows > 0){
        $included_row = $result_included->fetch_assoc();
        $included_apis = explode(",", $included_row['included_apis']);
    }
    //Adding the flag to know that an API call is included in a bulk API
    foreach($myData as &$api_entry){
        if(in_array($api_entry->id, $included_apis)){
            $api_entry->in_bulk = true;
        }
        else{
            $api_entry->in_bulk = false;
        }
    }

    /*
    //Check which of these entries are in a bulk call and report it in the answer.
    $executed_query = "SELECT GROUP_CONCAT(xml_initial) as included_apis FROM output_mapping WHERE table_name ='grouping' AND output like '%\"status\":\"success\"%';";
    $result_executed = $projectdb->query($executed_query);
    $executed_apis = [];
    if($result_executed->num_rows > 0){
        $executed_row = $result_executed->fetch_assoc();
        $executed_apis = explode(",", $executed_row['included_apis']);
    }
    //Adding the flag to know that an API call is included in a bulk API
    foreach($myData as &$api_entry){
        if(in_array($api_entry->id, $executed_apis) && $api_entry->output === ''){
            $api_entry->output = 
            "{\"".$api_entry->id."\":{\"device\":\"\",\"status\":\"success\",\"text\":\"<msg>in Bulk API Call<\\/msg>\"}}";
        }
    }
    */

    $message['code'] = true;
    $message['msg'] = $myData;

    return $message;
}


function get_api_calls_bulk(string $projectName, string $object_filter, string $object_search, string $name_search='', string $vsys='', string $start='0', string $limit='0'):array{
    //    global $app;
        $projectdb = selectDatabase($projectName);

        $object_search = $projectdb->real_escape_string($object_search);
        $object_filter = $projectdb->real_escape_string($object_filter);
        $name_search = $projectdb->real_escape_string($name_search);
        $vsys = $projectdb->real_escape_string($vsys);
        $start = $projectdb->real_escape_string($start);
        $limit = $projectdb->real_escape_string($limit);

        if ($limit===""){
            $limit ='0';
        }
        if(!accessControl("any", ['project.admin','projectRole.'.$projectName.'.view'])){
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Your account does not have the rights to check API calls';
            return $message;
        }
    
        $message = array();
        $addFilter = " WHERE table_name = 'grouping'";
        if ($object_search !== "") {
            if ($addFilter === "") {
                $addFilter = " WHERE (name LIKE '%$object_search%' OR xpath LIKE '%$object_search%' OR xml_final LIKE '%$object_search%') ";
            } else {
                $addFilter .= " AND (name LIKE '%$object_search%' OR xpath LIKE '%$object_search%' OR xml_final LIKE '%$object_search%')";
            }
        }
    
        $vsysSearch = explode(",", $vsys);
        $vsyses = [];
        foreach($vsysSearch as $item){
            if($item !== '' && $item !=='all' && $item !== 'shared') {
                $vsyses[] = ' OR lower(xpath) LIKE ("%/device-group/entry[@name=\'' . strtolower(trim($item)) . '\'%") OR lower(xpath) LIKE ("%/vsys/entry[@name=\'' . strtolower(trim($item)) . '\'%") ';
            }
            elseif($item === 'shared') {
                $vsyses[] = 'lower(xpath) LIKE ("/config/shared/%")';
            }
        }
        if(count($vsyses)>0){
            if($addFilter === ''){
                $addFilter = " WHERE (".implode(" OR ",$vsyses).")";
            }
            else{
                $addFilter .= "AND (" . implode(" OR ", $vsyses) . ")";
            }
        }
    
        $name_searches = explode(",", $name_search);
        $names = [];
        foreach ($name_searches as $item){
            $names[] = '"'.strtoupper(trim($item)).'"';
        }
        if($name_search !== "" ){
            if ($addFilter === "") {
                $addFilter = " WHERE name IN (".implode(",",$names).") ";
            } else {
                $addFilter .= " AND UPPER(name) IN (" . implode(",", $names) . ")";
            }
        }
    
        // Check if they are Clean (delete) calls to change the id order
    
        $queryCalls = "SELECT *, if(output like '%\"status\":\"success\"%', 'Successful', (if(output like '%\"status\":\"fail\"%', 'Failed', 'Pending'))) as 'status'  FROM output_mapping $addFilter;";
        //echo $queryCalls;
        $getCalls = $projectdb->query($queryCalls);
        $total = $getCalls->num_rows;
        $message['total']=$total;
        $queryCalls = "SELECT *, if(output like '%\"status\":\"success\"%', 'Successful', (if(output like '%\"status\":\"fail\"%', 'Failed', 'Pending'))) as 'status' FROM output_mapping $addFilter LIMIT $start, $limit ;";
        $getCalls = $projectdb->query($queryCalls);
        $count = $getCalls->num_rows;
        $myData = array();
        if ($count > 0) {
            while ($data = $getCalls->fetch_object()) {
                $myData[] = $data;
            }
        }
        if ($count === 0) {
            $myData = [];
            $message['total']=0;
        }
    
        foreach($myData as &$record){
            $loc = explode("/",$record->name);
            $table_name = array_pop($loc);
            $dg = implode(" ", $loc);
            $record->dg = $dg;
            $record->table_name = $table_name;
        }
        $message['code'] = true;
        $message['msg'] = $myData;
    
        return $message;
    }

function create_jobid($project, $project_db){
    $query = "INSERT INTO project_status (datetime,project,percentage,message) values (NOW(),'$project','0.00','Initializing')";
    $project_db->query($query);
    return $project_db->insert_id;
}

/***
 * @param STRING $projectName
 * @param array $data
 * @return array
 */
function send_api_calls(STRING $projectName, ARRAY $data):array{
    global $app;

//    ini_set('max_execution_time', 10000);
//    ini_set("memory_limit", "1000M");
//    $isProxy=false;
//    global $pandb;
    $projectdb = selectDatabase($projectName);

    $ids = $data['ids'] ?? '';

    if($ids === '' && $data['type']==='bulk'){
        echo "It is bulk";
        $query_bulk_apis = "SELECT GROUP_CONCAT(id) as ids FROM output_mapping WHERE table_name ='grouping';";
        $result_bulk_apis = $projectdb->query($query_bulk_apis);
        if($result_bulk_apis->num_rows >0){
            $data_bulk_apis = $result_bulk_apis->fetch_assoc();
            $ids = $data_bulk_apis['ids'];
        }
    }

    echo "ids: ".$ids;

    //Get selected devices
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;
    $api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));
    $project = $app->project->where('name', '=', $projectName)->get()->first();
    $userSettings = $app->userSettings->where('user_id','=',$userID)->where('project_id','=',$project->id)->first();
    $devices = explode(',',$userSettings->selectedDevices);

    $message = array();
    $message['code'] = true;

    $parentJobID = registerParentJob($user, $project->id, 'Bundle of Send API Calls');

    foreach($devices as $device) {
        if ($deviceEntity = $app->device->where('id', '=', $device)->get()->first()) {
            $data_individual = [
                'serial'     => $deviceEntity->serial,
                'devicename' => $deviceEntity->devicename,
                'params' => $ids,
                'project' => $projectName,
                'type' => $data['type'],
                'key'   => $api_key,
            ];

            $jobID = registerJob($data_individual, $user, 'Send API calls', $parentJobID);

            $taskID = registerTask($data_individual, $user, $jobID, "SendAPICall", "Send API Calls to PANOS device");
            send_APICallMessage($data_individual, $user, $taskID, "SendAPICall");

        }
    }
//    update_progress($project->name, '0.00', 'Done.');
    $message['msg'] = $parentJobID;
    return $message;
}

function registerTask(ARRAY $data, $user, INT $jobID, STRING $processCode, STRING $processName){
    global $app;

    if(!isset($data['params'])){
        $data['params'] = '';
    }
    $data['userId'] = $user->id;

    $params = [
        'job_id'        => $jobID,
        'taskType'      => 'Send API Call',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    //Count number of API calls that will be sent
    $idsString = $data['params'];
    $project = $data['project'];
    global $projectdb;
    $projectdb = selectDatabase($project);
    if($idsString === ''){
        $query = "SELECT count(*) as total FROM output_mapping";
        $result = $projectdb->query($query);
        $dataQuery = $result->fetch_assoc();
        $number_calls = $dataQuery['total'];
    }
    else{
        $ids = explode(',', $idsString);
        $number_calls = count($ids);
    }
    $job = $app->job->where('id', $jobID)->first();
    $jobParams = [
        'tasks' => $job->tasks + $number_calls,
    ];
    $job->update($jobParams);

    if($job->parentJob !== ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks + $number_calls,
        ];
        $parentJob->update($parentJobParams);
    }

    return $task->id;
}

function send_APICallMessage(ARRAY $data, $user, INT $taskID, STRING $process):array{
    $configtype = $data['configtype'] ?? 'running';
    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'params'        => [
            'serial'        => $data['serial'],
            'devicename'    => $data['devicename'],
            'configtype'    => $configtype,
            'taskId'        => $taskID,
            'project'   => $data['project'],
            'userId'    => $user->id,
            'params'    => $data['params'],
            'type'      => $data['type'],
            'key'       => $data['key'],
        ]
    ];

    sendMessage($message);

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Done';
    return $message;
}

function sendMessage($message){
    $messageSender = new MessageSender($message);
    $messageSender->send();
}

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $device = $app->device->where('devicename',$data['devicename'])->first();
    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'devices',
        'parentId'      => $device->id,
        'description'   => $description .' to '.$data['devicename'],
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerParentJob($user, $projectID, STRING $description){
    global $app;

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'project',
        'parentId'      => $projectID,
        'description'   => $description,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}