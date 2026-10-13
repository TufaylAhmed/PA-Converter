<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserverd.
 *
 * Development Team: Business Development
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com).
 * Date: 02/01/17 - 09:39
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/userManager/API/devices/list.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';

use realTimeConfigChanges\ProjectConfigChanger;

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

//State Machine States, Transitions and Consequence validity of changes
define ('Action', 0);
define ('CommitSucceeded', 1);
//define ('CommitEnqueued', 11);
define ('CommitDescription', 11);
//define ('CommitStarted', 12);
define ('LoadRunning', 2);
define ('LoadSpecific', 3);

define ('StateMachine_Normal',1);
define ('StateMachine_Warning',2);
define ('StateMachine_Undesired',3);

define ('StateMachine_Transition_Normal', 1);
define ('StateMachine_Transition_ToWarning', 2);
define ('StateMachine_Transition_Recovered', 3);
define ('StateMachine_Transition_ToUndesired', -1);

define ('RTU_Action_NotAnalyzed', 0);
define ('RTU_Action_Active', 1);
define ('RTU_Action_Applied', 2);
define ('RTU_Action_Invalid', -1);


parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

if(isset($post_vars['type'])){
    $type = $post_vars['type'];
}
else {
    $ids            = $pandb->real_escape_string((string)(isset($_GET['ids'])          ? $_GET['ids'] : ''));
    $serial         = $pandb->real_escape_string((string)(isset($_GET['serial'])       ? $_GET['serial']: ''));
    $page           = $pandb->real_escape_string((string)(isset($_GET['page'])         ? $_GET['page']: ''));
    $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])        ? $_GET['limit']: ''));
    $start          = $pandb->real_escape_string((string)(isset($_GET['start'])        ? $_GET['start']: ''));

    $params = [
        'ids'=>$ids,
        'serial'=>$serial,
        'page'=>$page,
        'limit'=>$limit,
        'start'=>$start
    ];}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_changes($params);
        if($message['code']) {
            $totalTags = $message['total'];
            echo json_encode(array('total' => $totalTags, 'changes' => $message['msg']));
        }
        else{
            echo '{"total":"0","changes":[]}';
        }
        break;

    case 'POST':
        $message = apply_changes($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_changes($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_changes($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function calculateAffectedProjects(STRING $serial){
    $RTUpdatesDB = selectDatabase("RealTimeUpdates");
    //Get the list of affected projects
    $involvedProjectsQuery = "SELECT proj.name 
                                          FROM pandbRBAC.project_devices proj_dev,
                                               pandbRBAC.devices dev, 
                                               pandbRBAC.projects proj 
                                          WHERE '$serial' = dev.serial AND
                                                 dev.id = proj_dev.device_id AND
                                                 proj_dev.project_name = proj.id";
    $projects = array();
    $involvedProjectsResults = $RTUpdatesDB->query($involvedProjectsQuery);
    while($involvedProjectsData = $involvedProjectsResults->fetch_assoc()){
        # '{"7":{"device":"FWlocal","status":"fail","text":"<response status = \\''error\\'' code = \\''403\\''><result><msg>Invalid credentials.<\/msg><\/result><\/response>","date":"2017-02-16 18:06:59"}}'
        $projects[$involvedProjectsData['name']] = [
            "project"   => $involvedProjectsData['name'],
            "date"      => "Pending",
        ];
    }
    $projectsJSON =json_encode($projects);

    //Get the list of changes that require to be updated
    $query = "UPDATE firewallUpdates SET projects = '$projectsJSON' WHERE deviceID ='$serial' AND projects IS NULL";
//    echo $query;
    $results= $RTUpdatesDB->query($query);

}

function list_changes(ARRAY $params){
    $simplifyList = true;
    $hasBeenSimplified = false;

    $realTimeChanges = array();
    $RTUpdatesDB = selectDatabase('RealTimeUpdates');
    $conditions = array("deviceID='".$params['serial']."'");

    $verificationMessage = verifyChanges($params['serial']);

    calculateAffectedProjects($params['serial']);

    if(isset($params['id']) && $params['id'] !='') {
        $conditions[]="   member_lid = '".mysqli_real_escape_string($RTUpdatesDB, $params['id'])."'";
    }
    if(!isset($params['showApplied']) OR $params['showApplied']=='not') {
        $conditions[] = "projects LIKE '%\"Pending\"%' ";
    }

//    $query  = "SELECT firewallUpdates.* ";
//    $query .= "FROM   firewallUpdates WHERE ".implode(' AND ',$conditions)." ORDER BY id ASC";
//
//    $results= $RTUpdatesDB->query($query);
//    $total=$results->num_rows;

    $query = "SELECT firewallUpdates.* ";
    $query .= "FROM   firewallUpdates WHERE ".implode(' AND ',$conditions)." AND NOT (state_control=0 AND active<0) AND active!=-5 ORDER BY id ASC";
    $results= $RTUpdatesDB->query($query);
    $total=$results->num_rows;

    while ($data = $results->fetch_assoc() ){
        $realTimeChanges[] = $data;
    }

//    print_r($verificationMessage);
    if(!$verificationMessage['code'] AND $verificationMessage['val']<0){
        $realTimeChanges[] = [
            "id"=>"-1",
            "deviceID"=>$params['serial'],
            "seqnu"=>"0",
            "command"=>"#### PROJECTS MAY BE CORRUPTED ####",
            "target"=>"SYSTEM",
            "before_value"=>"Comming from a loaded config",
            "after_value"=>"Commited a specific config. We are not in synch with the Firewall",
            "active"=>"-1",
            "projects"=>null,
            "generated_time"=>null,
            "applied"=>"0",
            "state_control"=>"1"
        ];
    }

    if($simplifyList) {
        $realTimeChanges2 = $realTimeChanges;
        for ($i = 0; $i < count($realTimeChanges) - 1; $i++) {
            if ($realTimeChanges[$i]['target'] == 'SYSTEM' && $realTimeChanges[$i]['target'] == $realTimeChanges[$i + 1]['target']) {
                unset($realTimeChanges2[$i]);
                $hasBeenSimplified = true;
            }
        }
        $realTimeChanges = array();
        if($hasBeenSimplified){
            $realTimeChanges[] = [
                "id"=>"-1",
                "deviceID"=>$params['serial'],
                "seqnu"=>"0",
                "user"=>"",
                "command"=>"... commits ...",
                "target"=>"SYSTEM",
                "before_value"=>"Summarized prior commits",
                "after_value"=>"",
                "active"=>"0",
                "projects"=>null,
                "generated_time"=>null,
                "applied"=>"0",
                "state_control"=>"1"
            ];
        }
        foreach ($realTimeChanges2 as $change) {
            $realTimeChanges[] = $change;
        }
    }
    $total = count($realTimeChanges);

    $message = array();
    $message['code']=true;
    $message['msg'] = $realTimeChanges;
    $message['total']=$total;
    return $message;

}

class PendingRealTimeChange{
    public $id;
    public $state;
    public $active;
    public $command;
    public $target;
    public $user;
    public $scope;
    public $jobID;

    public function __construct(INT $id, $state, INT $active, STRING $command, STRING $target, STRING $user=NULL){
        $this->id = $id;
        $this->state = $state;
        $this->active = $active;
        $this->command = $command;
        $this->user = $user;
        $this->target = $target;
    }
}

function setPendingActionsActive(ARRAY &$changes, INT $start, INT $end, PendingRealTimeChange $change){
    if(isset($change->user)){
       //This is PANOS >= 8.0
        for ($j = $start; $j < $end; $j++) {
//            echo "Checking against $change->user: ";

            if ($changes[$j]->active == RTU_Action_NotAnalyzed AND
                $changes[$j]->state  == 0 AND
                $changes[$j]->user   == $change->user) {
                //Verify is the scope of this change is within the commit scope

//                echo $changes[$j]->scope[0]."\n";
//                print_r ($change->scope);
                if(in_array($changes[$j]->scope[0],$change->scope)){
//                    echo "Needs to be applied\n";
                    setActionActive($changes, $j);
                }
            }
        }

    }
    else {
        //No user is defined, activate all potential changes
        for ($j = $start; $j < $end; $j++) {
            if ($changes[$j]->active == RTU_Action_NotAnalyzed AND $changes[$j]->state == 0) {
                setActionActive($changes, $j);
            }
        }
    }
}

function setPendingActionsInvalid(ARRAY &$changes, INT $start, INT $end, STRING $scope=NULL){
    $scope = is_null($scope) ? 'local': $scope;

    if($scope=='all') {
        for ($j = $start; $j < $end; $j++) {
            if ($changes[$j]->state == 0) {
                setActionInvalid($changes, $j);
            }
        }
    }
    else{
        for ($j = $start; $j < $end; $j++) {
            if ($changes[$j]->active != RTU_Action_Active AND $changes[$j]->state == 0) {
                setActionInvalid($changes, $j);
            }
        }
    }
}

function setActionInvalid(ARRAY &$changes, INT $position){
    $changes[$position]->active = RTU_Action_Invalid;
}

function setActionActive(ARRAY &$changes, INT $position){
    $changes[$position]->active = RTU_Action_Active;
}

function setUndesiredState(ARRAY &$changes, $position){
    $changes[$position]->active = StateMachine_Transition_ToUndesired;
}

function setRecoveredState(ARRAY &$changes, $position){
    $changes[$position]->active = StateMachine_Transition_Recovered;
}


/***
 * Calculates the actions that became active to be applied into the projects. Determines, as well, whether the state machine is on a correct state.
 * @param STRING $deviceID
 * @return array
 */
function verifyChanges(STRING $deviceID){

    $RTUpdatesDB = selectDatabase('RealTimeUpdates');
    $serials = array();

    // Find all the serials that could relate to changes on this device config
    $query = "SELECT id, serial, serialHA FROM pandbRBAC.devices WHERE serial ='$deviceID' OR serialHA='$deviceID' GROUP BY id";
    $resultHA = $RTUpdatesDB->query($query);
    if($resultHA->num_rows != 1) {
        $serialCorrect = false;
    }
    else{
        $serialCorrect = true;
        $data = $resultHA->fetch_assoc();
        $serials[] = $data['serial'];
        if($data['serialHA'] != '') {
            $serials[] = $data['serialHA'];
        }
    }
    $deviceIDList = implode(',',$serials);


    if($serialCorrect) {

        $changes = array();
        $changesObj = array();
        $machineState=1;  //1:Normal state, 2:Warning state, 3:Unrecoverable state

        $query = "SELECT id FROM firewallUpdates WHERE deviceID IN ('$deviceIDList') AND 
                applied=0 ORDER BY generated_time LIMIT 1";  //Getting the first change (state_control=0) that has not been applied (applied=0) yet and it has not been calculated either
        $result = $RTUpdatesDB->query($query);
        while ($data = $result->fetch_assoc()) {
            $changes[] = $data['id'];
        }

        if (count($changes)) {
            $firstChange = $changes[0];
            $query = "SELECT id, state_control,active,command, user, target FROM firewallUpdates WHERE deviceID IN ('$deviceIDList') AND id>=$firstChange ORDER BY id";
            $result = $RTUpdatesDB->query($query);
            while ($data = $result->fetch_assoc()) {
                $id = $data['id'];
                $newChange = new PendingRealTimeChange($id, $data['state_control'], $data['active'], $data['command'],$data['target'], $data['user']);
                $changesObj[] = $newChange;
            }

            $position = 0;
            foreach ($changesObj as $change){
                $transition = $change->state;

                switch ($transition){
                    case CommitDescription:
                        //Partial Commit for JobId=24 by User: admin are: changes to configuration by administrators: admin.Changes to policy and objects configuration.Changes to configuration in device and network. Enqueue TIme=2017/02/16 10:19:44.'
                        /***
                         * Partial Commit for JobId=24 by User: admin are: changes to configuration by administrators: admin.Changes to policy and objects configuration.Changes to configuration in device and network. Enqueue TIme=2017/02/16 10:19:44.
                          Array
                            (
                                [0] => Partial Commit for JobId=24 by User: admin are: changes to configuration by administrators: admin.Changes to policy and objects configuration.Changes to configuration in device and network. Enqueue TIme=2017/02/16 10:19:44.
                                [1] => 24
                                [2] => admin
                                [3] => changes to configuration by administrators: admin.Changes to policy and objects configuration.Changes to configuration in device and network.
                                [4] => TIme=2017/02/16 10:19:44.
                            )
                         */
                        preg_match("/^Partial Commit for JobId=(.*) by User: (.*) are: (.*) Enqueue (.*)$/", $change->command, $output_array);
                        $change->jobID = $output_array[1];
                        $commandArr = explode('.', $output_array[3]);
                        foreach ($commandArr as $argument){
                            if($pos = strpos($argument, "by administrators:")){
                                $a = explode(':', $argument);
                                $change->user=trim($a[1]);
                            }
                            if($pos = strpos($argument, "policy and objects")){
                                $change->scope[]="policy and objects";
                            }
                            elseif($pos = strpos($argument, "device and network")){
                                $change->scope[]="device and network";
                            }
                        }
                        //Those states are informative to a following CommitSucceeded
                        break;

                    case Action:
                        //Parse the target to determine the scope of this action
                        calculateScope($change);

                        if ($machineState==StateMachine_Normal) {
                            //activate all prior non-commited actions since the last commit. Set them as active=1
                            $machineState=StateMachine_Normal;
                        }
                        elseif($machineState==StateMachine_Warning){
                            //We come from a warning state. Eitherway, to recover, we will have to go to
                            setActionInvalid($changesObj, $position);
                            $machineState=StateMachine_Warning;
                        }
                        elseif($machineState==StateMachine_Undesired){
                            //We come from an invalid state. So this edit will be invalid as well
                            setActionInvalid($changesObj, $position);
                            $machineState=StateMachine_Undesired;
                        }
                        break;

                    case CommitSucceeded: //We get a commit
                        //Or it is one of the possible Commit messages from PANOS >=8.x
                        if ($machineState==StateMachine_Normal) {
                            //Check whether it is a Commit from PANOS <=7.x
                            $commandArr = explode('.', $change->command);
                            foreach ($commandArr as $argument){
                                if($pos = strpos($argument, "JobId=")){
                                    $a = explode('=', $argument);
                                    $change->jobID=$a[1];
                                }
                            }
                            if(isset($change->jobID)){
                                //This is a PANOS >=8.x, we need to collect information regarding the user and scope of this commit
                                //Check the CommitEnqueued with the same JobID to see the "user" and the "scope"
                                for ($i=0; $i < $position; $i++){
                                    if($changesObj[$i]->jobID == $change->jobID && $changesObj[$i]->state == CommitDescription){
                                        $change->user   = trim($changesObj[$i]->user);
                                        $change->scope  = $changesObj[$i]->scope;
                                    }
                                }
                            }
                            //activate all prior non-commited actions since the last commit. Set them as active=1
                            setPendingActionsActive($changesObj, 0, $position, $change);
                            $machineState=StateMachine_Normal;
                        }
                        elseif($machineState==StateMachine_Warning){
                            //Set a flag that at this point the configuration in the MT is not valid anymore
                            setPendingActionsInvalid($changesObj, 0, $position, 'all');
                            setUndesiredState($changesObj, $position);
                            $machineState=StateMachine_Undesired;
                        }
                        elseif($machineState==StateMachine_Undesired){
                            //remove all non-commited actions. Set them as active=-1
                            setPendingActionsInvalid($changesObj, 0, $position);
                            $machineState=StateMachine_Undesired;
                        }
                        break;

                    case LoadRunning: //We get a load running
                        if ($machineState==StateMachine_Normal) {
                            //remove all non-commited actions. Set them as active=-1
                            setPendingActionsInvalid($changesObj, 0, $position);
                            $machineState=StateMachine_Normal;
                        }
                        elseif($machineState==StateMachine_Warning){
                            //remove all non-commited actions. Set them as active=-1
                            setPendingActionsInvalid($changesObj, 0, $position);
                            $machineState=StateMachine_Normal;
                        }
                        elseif($machineState==StateMachine_Undesired){
                            //remove all non-commited actions. Set them as active=-1
                            setPendingActionsInvalid($changesObj, 0, $position);
                            $machineState=StateMachine_Undesired;
                        }
                        break;

                    case LoadSpecific: //We get a load specific
                        if ($machineState==StateMachine_Normal) {
                            //remove all non-commited actions. Set them as active=-1
                            setPendingActionsInvalid($changesObj, 0, $position);
                            $machineState=StateMachine_Warning;
                        }
                        elseif($machineState==StateMachine_Warning){
                            //remove all non-commited actions. Set them as active=-1
                            setPendingActionsInvalid($changesObj, 0, $position);
                            $machineState=StateMachine_Warning;
                        }
                        elseif($machineState==StateMachine_Undesired){
                            //remove all non-commited actions. Set them as active=-1
                            setPendingActionsInvalid($changesObj, 0, $position);
                            $machineState=StateMachine_Undesired;
                        }
                        break;
                }

                $position++;
            }

//            print_r($changesObj);

            $actionsActive = array();
            $actionsInvalid = array();
            foreach ($changesObj as $change){
                if($change->active==1)      $actionsActive[]  = $change->id;
                elseif($change->active==-1) $actionsInvalid[] = $change->id;
            }

            if(count($actionsActive)>0){
                $query = "UPDATE firewallUpdates SET active=1 WHERE id in (".implode(',',$actionsActive).")";
//                echo "$query\n";
                $RTUpdatesDB->query($query);
            }
            if(count($actionsInvalid)>0){
                $query = "UPDATE firewallUpdates SET active=-1 WHERE id in (".implode(',',$actionsInvalid).")";
//                echo "$query\n";
                $RTUpdatesDB->query($query);
            }

            if($machineState == StateMachine_Normal) {
                $msg = [
                    'code' => true,
                    'val'  => 0,
                    'msg' => 'The changes are fine'
                ];
            }
            elseif ($machineState == StateMachine_Warning){
                $msg = [
                    'code' => false,
                    'val'  => 0,
                    'msg' => 'Side config load that may corrupt the MT state'
                ];
            }else{
                $msg = [
                    'code' => false,
                    'val'  => -1,
                    'msg' => 'Side config load commited that corrupted the MT state'
                ];
            }
        }
        else {
            //Nothing has been changed. So, no issues
            $msg = [
                'code' => true,
                'msg' => 'No new changes from this device'
            ];
        }
    }
    else{
        $msg = [
            'code' => false,
            'val'  => 0,
            'msg' => "There is no firewall with such serial"
        ];
    }

    return $msg;
}

function calculateScope(PendingRealTimeChange &$change){
    $targetArray2 = array();
    $targetArray = explode('  ',$change->target);

    foreach ($targetArray as &$item){
        $item = trim($item);
    }

    for($i=1;$i<count($targetArray)-1; $i++){
        $arr = explode(' ',$targetArray[$i]);
        $count = count($arr);
        if($count>1){
            $targetArray[$i-1].="=".$arr[0];
            $newValue = '';
            for($j=1; $j<$count; $j++){
                $newValue .= " ".$arr[$j];
            }
            $targetArray[$i] = $newValue;
        }
    }

    if(count($targetArray)>1) {
        $targetArray[$i - 1] .= "=" . $targetArray[$i];
        unset($targetArray[$i]);
    }
    foreach ($targetArray as $item){
        $pair = explode('=',$item);
        if(count($pair)==2){
            $key = trim($pair[0]);
            $value = trim($pair[1]);
            $targetArray2[$key]=$value;
        }
    }
    if(isset($targetArray2['address'])) {
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = "address";
    }
    elseif(isset($targetArray2['address-group'])) {
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = "address-group";
    }
    elseif(isset($targetArray2['service'])){
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = 'service';
    }
    elseif(isset($targetArray2['service-group'])) {
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = 'service-group';
    }
    elseif(isset($targetArray2['application'])){
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = 'application';
    }
    elseif(isset($targetArray2['application-group'])) {
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = 'application-group';
    }
    elseif(isset($targetArray2['rulebase security rules'])){
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = 'rulebase security rules';
    }
    elseif(isset($targetArray2['rulebase nat rules'])){
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = 'rulebase nat rules';
    }
    elseif(isset($targetArray2['tag'])){
        $change->scope[0] = 'policy and objects';
        $change->scope[1] = 'tag';
    }
    elseif(isset($targetArray2['zone'])){
        $change->scope[0] = 'device and network';
        $change->scope[1] = 'zone';
    }
    elseif(isset($targetArray2['network interface ethernet'])) {
        $change->scope[0] = 'TODO - device and network';
        $change->scope[1] = 'network interface ethernet';
    }
}

/***
 * This function collects IDs of changes that need to be applied to projects related to a Firewall.
 * Given a set of modifications on a FW configuration, the function gathers information of those changes and applies it
 * to all the projects in which the firewall has been attached.
 * Notice that the changes need to be all from the same firewall.
 *
 * @param array $data
 * @return array
 */
function apply_changes(ARRAY $data){
    $error = array();

    $RTUpdatesDB = selectDatabase('RealTimeUpdates');
    $changesLIST = (isset($data['ids']) && $data['ids']!='') ? mysqli_real_escape_string($RTUpdatesDB, $data['ids']) : null;
    $selectedChanges = (!is_null($changesLIST))? explode(',',$changesLIST) : array();

    $conditions = array();
    $conditions[] = "state_control = 0";

    if (isset($data['scope'])){
        if($data['scope'] == 'candidate'){
            //This should not be allowed, tho.
        }
        else{
            $conditions[] = "active = 1";
        }
    }
    else{
        $conditions[] = "active = 1";
    }

    if(!isset($params['showApplied']) OR $params['showApplied']=='not') {
        $conditions[] = "projects LIKE '%\"Pending\"%' ";
    }

//    if(!isset($data['showApplied']) OR $data['showApplied']=='not') {
//        $conditions[] = "applied!=1";
//    }

    if (count($selectedChanges)==0){
        $fwSerial = $data['serial'];
        $query = "SELECT fwUpdates.id FROM firewallUpdates fwUpdates WHERE fwUpdates.deviceID = '$fwSerial' AND ".implode(" AND ",$conditions);
//        echo "$query\n";
        $result = $RTUpdatesDB->query($query);
        while($data = $result->fetch_assoc()){
            $selectedChanges[] = $data['id'];
        }
    }

    if(!count($selectedChanges)>0) {
        $msg['code'] = true;
        $msg['msg']  = "No changes to apply";
    }
    else {
        //STEP 1 - Download the running config from this FW
        $query = "SELECT fwUpdates.deviceID FROM firewallUpdates fwUpdates WHERE fwUpdates.id in (".implode(',',$selectedChanges).") GROUP BY fwUpdates.deviceID";
        $result = $RTUpdatesDB->query($query);
        if($result->num_rows != 1){
            $serials = array();
            while($serialData = $result->fetch_assoc()){
                $serials[] = "'".$serialData['deviceID']."'";
            }
            //Check that the serials are all from the same device (considering the HA values)
            $query = "SELECT id, serial FROM pandbRBAC.devices WHERE serial in (".implode(',',$serials).") OR serialHA in (".implode(',',$serials).") GROUP BY id";
            $resultHA = $RTUpdatesDB->query($query);
            if($resultHA->num_rows != 1) {
                $serialCorrect = false;
                $msg = [
                    'code' => false,
                    'msg' => "The list of changes refers to more than one single firewall"
                ];
            }
            else{
                $serialCorrect = true;
                $data = $resultHA->fetch_assoc();
                $deviceSerial = $data['serial'];
            }
        }
        else{
            $serialCorrect = true;
            $data = $result->fetch_assoc();
            $deviceSerial = $data['deviceID'];
        }

        //if $serialCorrect, we have validated that the changes refer to the same firewall (including the HA) and the firewall serial is stored in the variable $deviceSerial
        if ($serialCorrect) {
            $deviceIDResults = $result->fetch_assoc();
//            print_r($deviceIDResults);

            $message = getConfig($deviceSerial, 'admin', true);
            if (!$message['code']) {
                //There has been an error retrieving the running configuration from the firewall that reported the changes
                $msg = $message;
            }
            else {
                //Copy the config to all the projects in which the device is included. Also, for each project, get the ID of the source that refers to the config
                $involvedProjectsQuery = "SELECT proj.name 
                                          FROM pandbRBAC.project_devices proj_dev,
                                               pandbRBAC.devices dev, 
                                               pandbRBAC.projects proj 
                                          WHERE '$deviceSerial' = dev.serial AND
                                                 dev.id = proj_dev.device_id AND
                                                 proj_dev.project_name = proj.id";
                $projects = array();
                $involvedProjectsResults = $RTUpdatesDB->query($involvedProjectsQuery);
                while($involvedProjectsData = $involvedProjectsResults->fetch_assoc()){
                    $projectName = $involvedProjectsData['name'];

                    $sourceQuery = 'SELECT id FROM ' . $projectName . '.device_mapping WHERE filename LIKE "%_' . $deviceSerial . '.xml" GROUP BY device LIMIT 1';
                    $sourceResults = $RTUpdatesDB->query($sourceQuery);
                    if ($sourceResults->num_rows == 1) {
                        $sourceInfo = $sourceResults->fetch_assoc();
                        $projects[$projectName] = $sourceInfo['id'];

                        $message = transferConfigToProject($deviceSerial, $involvedProjectsData['name']);
                        if (!$message['code']) {
                            $error[] = $message['msg'];
                        }
                    }
                    else{

                    }
                }

                //STEP 2 - Collect information from all the changes that need to be applied
                include_once INC_ROOT . "/libs/realTimeConfigChanges/ProjectConfigChanger.php";
                $changeInfoQuery = "SELECT fwUpdates.id, fwUpdates.deviceID, fwUpdates.seqnu, fwUpdates.command, fwUpdates.target, fwUpdates.before_value, fwUpdates.after_value 
                                    FROM firewallUpdates fwUpdates 
                                    WHERE fwUpdates.id in (".implode(',',$selectedChanges).")";
                $changeInfoResults = $RTUpdatesDB->query($changeInfoQuery);

                while ($selectedChange = $changeInfoResults->fetch_assoc()) {
                    $projectConfigChanger = new ProjectConfigChanger($RTUpdatesDB, $selectedChange['id']);

                    $changeID = $selectedChange['id'];
                    $projectConfigChanger->setDeviceSerial($selectedChange['deviceID']);
                    $projectConfigChanger->setCommand($selectedChange['command']);
                    $projectConfigChanger->setTarget($selectedChange['target']);
                    $projectConfigChanger->setBefore($selectedChange['before_value']);
                    $projectConfigChanger->setAfter($selectedChange['after_value']);
                    $projectConfigChanger->setSeqnu($selectedChange['seqnu']);
                    $projectConfigChanger->addProjects($projects);

//                    echo $selectedChange['deviceID'].", ".$selectedChange['seqnu'].", ".$selectedChange['command'].", ".$selectedChange['target'].", ".$selectedChange['after_value'].", ".$selectedChange['before_value']."\n";
//                    print_r($projectConfigChanger);
                    $msgResult = $projectConfigChanger->applyChange();

                    if (!$msgResult['code']) {
                        $error[] = $msgResult['msg'];
                    }
                    else{
                        //Update the change as applied
                        $query = "UPDATE firewallUpdates SET applied=1 WHERE id='$changeID'";
                        $RTUpdatesDB->query($query);
                    }
                }

                $msg = array();
                if (count($error)) {
                    $msg['code'] = false;
                    $msg['msg'] = implode(',', $error);
                }
                else {
                    $msg['code'] = true;
                    $msg['msg'] = "Changes applied correctly";
                }
            }
        }
    }
    return $msg;
}

function update_changes(ARRAY $data){
//    global $app;
//    global $projectdb;
//
//    $project = $data['project'];
//
//    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
//        $message = array();
//        $message['code'] = false;
//        $message['msg'] = 'Your account does not have the rights to edit this project contents';
//        return $message;
//    }
//
//    $projectdb = selectDatabase($project);
//    $modified = 1;
//    $dummy = 0;
//    $vtype = '';
//    $name = mysqli_real_escape_string($projectdb, $data['name']);
//    $source = mysqli_real_escape_string($projectdb, $data['source']);
//    $vsys = mysqli_real_escape_string($projectdb, $data['vsys']);
//    $vtype = mysqli_real_escape_string($projectdb, $data['vtype']);
//    $comments = mysqli_real_escape_string($projectdb, $data['comments']);
//    $devicegroup = mysqli_real_escape_string($projectdb, $data['devicegroup']);
//    $color = mysqli_real_escape_string($projectdb, $data['color']);
//    $id = mysqli_real_escape_string($projectdb, $data['id']);
//
//    $query = "UPDATE tag SET name='$name', devicegroup='$devicegroup', vsys='$vsys', vtype='$vtype', color='$color',
//              comments='$comments', source='$source', modified='$modified', dummy='$dummy'
//              WHERE id=$id";
//    $projectdb->query($query);
//
    $message = array();
    $message['code'] = true;
    $message['msg']['warning'] = false;
    $message['msg']['content'] = '';

    return $message;
}

function delete_changes(ARRAY $data){
    global $app;

    $error = array();

    $RTUpdatesDB = selectDatabase('RealTimeUpdates');
    $selectedChanges = (isset($data['ids']) && $data['ids']!='') ? $data['ids'] : null;

    if(!count($selectedChanges)>0) {
        $msg['code'] = true;
        $msg['msg']  = "No changes to delete";
    }
    else {
        $listToDelete = mysqli_real_escape_string($RTUpdatesDB,
                                                  implode(',',$selectedChanges));
        $query = "DELETE FROM firewallUpdates 
                  WHERE id in (".$listToDelete.")";
        echo $query;
        $result = $RTUpdatesDB->query($query);
//        echo $query;
        $msg = [
            'code'  => true,
            'msg'   => 'Changes deleted from the list'
        ];
    }
    return $msg;
}

function transferConfigToProject(STRING $deviceSerial, STRING $project){
    global $app;

    //Get info from the device
    if(! $deviceObj = $app->container->device->where('serial', '=', $deviceSerial)->get()->first()){
        $message = [
          'code' => false,
          'msg'  => 'Device not found',
        ];
        return $message;
    }

    $sourcePath = USERSPACE_PATH."/devices/$deviceSerial/ConfigBackup.xml";
    $fileName = $deviceObj->devicename."_".$deviceObj->serial.".xml";
    $destinationPath = USERSPACE_PATH."/projects/".$project."/".$fileName;

    //Copy the new configuration config to the project folder
    $result = copy($sourcePath, $destinationPath);

    if($result){
        $message = [
            'code'  => true,
            'msg'   => 'Config file '.$deviceSerial.' transferred to project '.$project,
        ];
    }
    else{
        $message = [
            'code'  => false,
            'msg'   => 'Failed to transfer Config file '.$deviceSerial.' to project '.$project,
        ];
    }
    return $message;
}

function getConfig(STRING $deviceSerial, $role, bool $doBackup=NULL){
    global $app;
    global $pandbRBAC;
    $pandbRBAC = selectDatabase('pandbRBAC');

    $errors = array();

    //Get info from device!
    if ($deviceObj = $app->container->device->where('serial', '=', $deviceSerial)->get()->first()) {
        $success = true;
        if($deviceObj->management == '') {
            $hostname = $deviceObj->hostname;
            $port = $deviceObj->port;

            $key_name = $deviceSerial . "_" . $role;
            if ($key = $app->apikey->where('key_name', '=', $key_name)->get()->first()) {
                $success = getConfigBackup($hostname, $deviceSerial, $key->api_key, $port, 'running', "RTUConfigBackup.xml",$doBackup);
            }
            if ($success != 0) {
                $errors[] = $success;
                $errorDev[] = $deviceSerial;
            }
        }
        else{
            $panorama = $deviceObj->management;
            $panoramaObj = $app->device->where('serial',$panorama)->get()->first();
            $hostname = $panoramaObj->hostname;
            $port = $panoramaObj->port;

            $key_name = $panoramaObj->serial . "_" . $role;
            if ($key = $app->apikey->where('key_name', '=', $key_name)->get()->first()) {
                $success = getConfigBackup_Target($hostname, $panorama, $key->api_key, $port, $deviceObj->serial, $deviceSerial);
            }
            if ($success != 0) {
                $errors[] = $success;
                $errorDev[] = $deviceSerial;
            }
        }
    }
    if(count($errors) == 0){
        $message = [
            'code'  => true,
            'msg'   => 'Configuration downloaded from '.$deviceSerial,
        ];
    }
    else{
        $message = [
            'code'  => false,
            'msg'   => 'Problems downloading Configuration from '.$deviceSerial,
        ];
    }
    return $message;
}