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
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($data['action'])){
    $action = $data['action'];
}
else {
    $type = filter_input(INPUT_GET, "type", FILTER_SANITIZE_STRING);
    $projectName = filter_input(INPUT_GET, "project", FILTER_SANITIZE_STRING);
    $source=filter_input(INPUT_GET, "source", FILTER_SANITIZE_STRING);
    $vsys=filter_input(INPUT_GET, "vsys", FILTER_SANITIZE_STRING);
    $rulelids=filter_input(INPUT_GET, "rulelids", FILTER_SANITIZE_STRING);
    $filters=filter_input(INPUT_GET, "filters", FILTER_SANITIZE_STRING);
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

#DEBUG
/*$_SERVER['REQUEST_METHOD']="GET";
$source=1;
$projectName="DL1";
$type="chart_categories";*/
#DEBUG


switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        switch($type){
            /*case "threat_categories":
                $message = list_threat_categories($projectName, $source);
                if($message['code']) {
                    echo json_encode($message['msg']);
                }
                else{
                    echo '{"total":"0","audits":[]}';
                }
                break;*/
            case "rule_analitics":
                $message = rule_analitics($projectName, $source,$vsys,$rulelids,$filters);
                if($message['code']) {
                    echo '{"total":"'.$message['count'].'","audits":'.json_encode($message['msg']).'}';;
                }
                else{
                    echo '{"total":"0","audits":[]}';
                }
                break;
            case "chart_categories":
                $message = chart_threat_categories($projectName, $source,$vsys);
                if($message['code']) {
                    echo '{"total":"'.$message['count'].'","audits":'.json_encode($message['msg']).'}';;
                }
                else{
                    echo '{"total":"0","audits":[]}';
                }
                break;
        }

        break;

    case 'POST':
        switch ($action){
            case "filter":
                $message = addFilter($data);
                break;

        }

        echo json_encode(array('success'=>$message['code'],'message'=>$message['msg']));
        break;
    case 'PUT':
    case 'DELETE':
    default:
        break;
}

function addFilter($data){
    $message['code']=false;
    $project=$data['project'];
    $rulelids=$data['rulelids'];
    $source=$data['source'];
    $vsys=$data['vsys'];

    foreach($rulelids as $key=>$value){
        $sql[]="( (category_of_threatid='".$value['category_of_threatid']."') AND (app='".$value['app']."') AND (severity_of_threatid='".$value['severity_of_threatid']."') AND (action='".$value['action']."'))";
    }

    $projectdb = selectDatabase($project);
    $vsyses=getVsyses($projectdb, $vsys,$source);
    if (count($vsyses)>0){
        $vsyses=array_reverse($vsyses);
        foreach ($vsyses as $id=>$vsysA) {
            $tmp=getRulesFromVsysParents($vsysA,$source,$rulesInMemory,$projectdb);
            if ($tmp!=FALSE){
                $rules[]=$tmp;
            }
        }
    }

    $entireSQL="SELECT rule_lid FROM threats_from_log WHERE rule_lid IN (".implode(",",$rules).") AND (".implode(" OR ",$sql).") GROUP BY rule_lid";
    //echo $entireSQL;
    $getRules=$projectdb->query($entireSQL);
    if ($getRules->num_rows>0){
        while($getRulesData=$getRules->fetch_assoc()){
            $output[]=$getRulesData['rule_lid'];
        }
        $message['code']=true;
        $message['total']=count($output);
        $message['msg']=implode(",",$output);
    }
    return $message;
}

function chart_threat_categories($projectName,$source,$vsys){
    $projectdb = selectDatabase($projectName);
    $rulesInMemory=[];
    $message=[];
    $message['code']=false;
    $Data=[];
    //$vsys="AM1-FW01";

    $vsyses=getVsyses($projectdb, $vsys,$source);
    if (count($vsyses)>0){
        foreach ($vsyses as $id=>$vsysA) {
            $tmp=getRulesFromVsysParents($vsysA,$source,$rulesInMemory,$projectdb);
            if ($tmp!=FALSE){
                $rules[]=$tmp;
            }
        }

        if (count($rules)>0){
            $allRules=implode(",",$rules);
            $getThreats=$projectdb->query("SELECT app,category_of_threatid, severity_of_threatid,action,sum(count) as count FROM threats_from_log 
                                                WHERE rule_lid IN ($allRules) AND severity_of_threatid!='informational' AND severity_of_threatid!='low' 
                                                group by category_of_threatid,severity_of_threatid,action,app;");
            if ($getThreats->num_rows>0){
                while($getThreatsData=$getThreats->fetch_assoc()){
                    $Data[]=array(
                        "category_of_threatid"=>$getThreatsData['category_of_threatid'],
                        "count"=>$getThreatsData['count'],
                        "app"=>$getThreatsData['app'],
                        "severity_of_threatid"=>$getThreatsData['severity_of_threatid'],
                        "action"=>$getThreatsData['action'],
                    );
                }
            }
        }

        $message['code']=true;
        $message['count']=count($Data);
        $message['msg']=$Data;
    }

    return $message;

}

function rule_analitics($projectName,$source,$vsys,$rulelids=null,$filters=null){
    $projectdb = selectDatabase($projectName);
    $rulesInMemory=[];
    $message=[];
    $message['code']=false;
    $Data=[];

    if (($rulelids!=null) AND (is_array($rulelids))){
        $rules=$rulelids;
    }
    else{
        $vsyses=getVsyses($projectdb, $vsys,$source);
        if (count($vsyses)>0){
            $vsyses=array_reverse($vsyses);
            foreach ($vsyses as $id=>$vsysA) {
                $tmp=getRulesFromVsysParents($vsysA,$source,$rulesInMemory,$projectdb);
                if ($tmp!=FALSE){
                    $rules[]=$tmp;
                }
            }
        }
    }

    if (count($rules)>0){
        $Data=analyzeARule($rules,$projectdb,$source);
        $message['code']=true;
        $message['count']=count($Data['msg']);
        $message['msg']=$Data['msg'];
    }

    return $message;

}

function analyzeARule($rule_lid,$projectdb,$source){

    if (is_array($rule_lid)){
        $rules=implode(",",$rule_lid);
    }

    $message=[];
    $message['code']=false;

    $getRules=$projectdb->query("SELECT * FROM security_rules WHERE id IN ($rules);");
    if ($getRules->num_rows>0){

        $objectsInMemory=[];
        $getFrom=$projectdb->query("SELECT * FROM security_rules_from WHERE rule_lid IN ($rules) GROUP BY rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['from'][$getFromData['rule_lid']]=1;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM security_rules_to WHERE rule_lid IN ($rules) GROUP BY rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['to'][$getFromData['rule_lid']]=1;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM security_rules_src WHERE rule_lid IN ($rules) GROUP BY rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['src'][$getFromData['rule_lid']]=1;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM security_rules_dst WHERE rule_lid IN ($rules) GROUP BY rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['dst'][$getFromData['rule_lid']]=1;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM security_rules_srv WHERE rule_lid IN ($rules) GROUP BY rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['srv'][$getFromData['rule_lid']]=1;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM security_rules_usr WHERE rule_lid IN ($rules) GROUP BY rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['users'][$getFromData['rule_lid']]=1;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM security_rules_hip WHERE rule_lid IN ($rules) GROUP BY rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['hip'][$getFromData['rule_lid']]=1;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM security_rules_app WHERE rule_lid IN ($rules) GROUP BY rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['app'][$getFromData['rule_lid']]=1;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM profiles WHERE source='$source';");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['profiles'][$getFromData['id']]['name']=$getFromData['name'];
                $objectsInMemory['profiles'][$getFromData['id']]['type']=$getFromData['type'];
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM profiles_groups WHERE source='$source';");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['profiles_groups'][$getFromData['id']]['name']=$getFromData['name'];

            }
        }
        $getFrom=$projectdb->query("SELECT id,app,threatid,action,tid,category_of_threatid,source,sum(count) as count,rule_lid,vsys,subtype,severity_of_threatid,date_retrieve 
            FROM threats_from_log WHERE threatid REGEXP '^[0-9]+$' AND rule_lid IN ($rules) GROUP BY app,action,category_of_threatid,subtype,severity_of_threatid,rule_lid;");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['threatsvialog'][$getFromData['rule_lid']][]=$getFromData;
            }
        }
        $getFrom=$projectdb->query("SELECT * FROM threats_from_log WHERE not threatid REGEXP '^[0-9]+$' AND rule_lid IN ($rules);");
        if ($getFrom->num_rows>0){
            while($getFromData=$getFrom->fetch_assoc()){
                $objectsInMemory['threatsvialog'][$getFromData['rule_lid']][]=$getFromData;
            }
        }

        while($getRulesData=$getRules->fetch_assoc()){

            # Meta
            $ruleSet[$getRulesData['id']]['meta']['name']=$getRulesData['name'];
            $ruleSet[$getRulesData['id']]['meta']['position']=$getRulesData['position'];
            $ruleSet[$getRulesData['id']]['meta']['action']=$getRulesData['action'];
            $ruleSet[$getRulesData['id']]['meta']['vsys']=$getRulesData['vsys'];
            $ruleSet[$getRulesData['id']]['meta']['rule_lid']=$getRulesData['id'];
            $ruleSet[$getRulesData['id']]['rule_lid']=$getRulesData['id'];

            # Source
            if (isset($objectsInMemory['from'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['src']['from']=$objectsInMemory['from'][$getRulesData['id']];
            }
            else{
                $ruleSet[$getRulesData['id']]['src']['from']=0;
            }

            if (isset($objectsInMemory['src'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['src']['src']=$objectsInMemory['src'][$getRulesData['id']];
            }
            else{
                $ruleSet[$getRulesData['id']]['src']['src']=0;
            }

            if (isset($objectsInMemory['users'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['src']['users']=$objectsInMemory['users'][$getRulesData['id']];
            }
            else{
                $ruleSet[$getRulesData['id']]['src']['users']=0;
            }

            if (isset($objectsInMemory['hip'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['src']['hip']=$objectsInMemory['hip'][$getRulesData['id']];
            }
            else{
                $ruleSet[$getRulesData['id']]['src']['hip']=0;
            }

            # Destination
            if (isset($objectsInMemory['to'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['dst']['to']=$objectsInMemory['to'][$getRulesData['id']];
            }
            else{
                $ruleSet[$getRulesData['id']]['dst']['to']=0;
            }

            if (isset($objectsInMemory['dst'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['dst']['dst']=$objectsInMemory['dst'][$getRulesData['id']];
            }
            else{
                $ruleSet[$getRulesData['id']]['dst']['dst']=0;
            }
            if (isset($objectsInMemory['srv'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['dst']['srv']=$objectsInMemory['srv'][$getRulesData['id']];
            }
            else{
                $ruleSet[$getRulesData['id']]['dst']['srv']=0;
            }
            $ruleSet[$getRulesData['id']]['dst']['logprofile']=$getRulesData['log_forwarding'];

            # App and Threat ID
            if (isset($objectsInMemory['app'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['app']['app']=$objectsInMemory['app'][$getRulesData['id']];
            }
            else{
                $ruleSet[$getRulesData['id']]['app']['app']=0;
            }


            $ruleSet[$getRulesData['id']]['app']['log_start']=$getRulesData['log_start'];
            $ruleSet[$getRulesData['id']]['app']['log_end']=$getRulesData['log_end'];

            # Threats via Log
            if (isset($objectsInMemory['threatsvialog'][$getRulesData['id']])){
                $ruleSet[$getRulesData['id']]['threatsvialog']=$objectsInMemory['threatsvialog'][$getRulesData['id']];
            }

        }
        $message['code']=true;
        $msg=[];
        foreach ($ruleSet as $k=>$item) {
            $msg[]=$item;
        }
        $message['msg']=$msg;
    }

    return $message;
}

function getRulesFromVsysParents($vsys,$source,&$rulesInMemory,$projectdb){
    # From leaf (devicegroup) [last in hierarchy] sum all the threats from here to Shared
    if (count($rulesInMemory)==0){
        # Create Array with RuleIDS and VSYS
        $query="SELECT id,vsys from security_rules where source=$source;";
        $getRules=$projectdb->query($query);
        if ($getRules->num_rows>0){
            # Read Vsys/DeviceGroups From Rules and associate in array
            while($getRulesData=$getRules->fetch_assoc()){
                $rulesInMemory[$getRulesData['vsys']][]=$getRulesData['id'];
            }
        }
    }
    if (isset($rulesInMemory[$vsys])){
        return implode(",",$rulesInMemory[$vsys]);
    }
    else{
        return FALSE;
    }
}

