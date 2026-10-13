<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';
//Dependencies
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/bestpractices/bpat.php';
require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project    = $pandb->real_escape_string((string)  (isset($_GET['project'])    ? $_GET['project'] : ''));
        $template   = $pandb->real_escape_string((string)  (isset($_GET['template'])   ? $_GET['template'] : ''));
        $vsys       = $pandb->real_escape_string((string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : ''));
        $mode       = $pandb->real_escape_string((string)  (isset($_GET['mode'])       ? $_GET['mode'] : 'none'));
        $filter     = $pandb->real_escape_string((string)  (isset($_GET['filter'])     ? $_GET['filter'] : ''));
        $message=array();
        switch($mode){
            case "topic3d":
                $message = list_bpat($project);
                break;
            case "heatmap":
                $message = list_bpat_tree($project,$filter);
                break;
            case "percentage":
                $message = list_bpat_pct($project);
                break;
            case "radarchart":
                $message = list_bpat_radar($project);
                break;

        }

        if(isset($message['code'])) {

            if ($mode=="heatmap"){
                echo json_encode(array('children'=>$message['msg']));
            }
            else{

                echo json_encode(array('total' => $message['count'], 'stats' => $message['msg']));
            }

        }
        else{
            echo '{"total":"0","stats":[]}';
        }
        break;
    case 'POST':
        //$project     = (string)  (isset($_POST['project'])    ? $_POST['project'] : '');
        //$message = import_json_bpat($project);
        //echo json_encode(array('success' => $message['code']));
        break;
    default:
        $project     = $pandb->real_escape_string((string)  (isset($_POST['project'])    ? $_POST['project'] : ''));
        break;
}

function list_bpat($project){
    if(!checkProjectRights($project,'view')){
        $message = [
            'code' => true,
            'count' => 0,
            'msg' => array()
        ];
        return $message;
    }

    global $projectdb;

    $projectdb = selectDatabase($project);
    $Data=array();
    $get3d=$projectdb->query("SELECT topic FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) GROUP BY topic ORDER BY topic;");
    if ($get3d->num_rows>0){
        $ids=array();
        while ($get3dData=$get3d->fetch_assoc()){
            $subtype=$get3dData['topic'];
            $getSubtype=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND topic='$subtype' AND subtype!='security_rules';");
            if ($getSubtype->num_rows>0){
                while($getSubtypeData=$getSubtype->fetch_assoc()){
                    $ids[]=$getSubtypeData['id'];
                }

                if (count($ids)>0){
                    #Calc Fail
                    $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
                    if ($getFail->num_rows==1){
                        $getFailData=$getFail->fetch_assoc();
                        $failed=$getFailData['fail'];
                    }
                    else{
                        $failed=0;
                    }
                    #Calc Remediation
                    $getFail=$projectdb->query("SELECT count(id) as remediation FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail' AND remediation=1;");
                    if ($getFail->num_rows==1){
                        $getFailData=$getFail->fetch_assoc();
                        $remediation=$getFailData['remediation'];
                        if (($remediation!=0) AND ($failed!=0)){
                            $total=$failed;
                            $calc=($remediation*100)/$total;
                            $calcR=round($calc);
                        }
                        else{$calcR=0;}
                    }
                    else{
                        $failed=0;
                    }
                    #Calc Pass
                    $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
                    if ($getFail->num_rows==1){
                        $getFailData=$getFail->fetch_assoc();
                        $pass=$getFailData['pass'];
                    }
                    else{
                        $pass=0;
                    }
                    $Data[]=array("topic"=>$subtype,"passed"=>$pass,"failed"=>$failed,"remediation"=>$remediation,"avg"=>$calcR);
                    $ids=array();
                }

            }
        }
    }
    $message = array();
    $message['code'] = true;
    $message['count'] = count($Data);
    $message['msg'] = $Data;
    return $message;
}

function list_bpat_pct($project){
    if(!checkProjectRights($project,'view')){
        $message = [
            'code' => true,
            'count' => 0,
            'msg' => array("current"=>'',"remediable"=>0,"failed"=>0,"pass"=>0,"remediate"=>0,"date"=>'',"total"=>0),
        ];
        return $message;
    }

    global $projectdb;

    $projectdb = selectDatabase($project);
    $Data=array();
    $totals['pass']=0;
    $totals['failed']=0;
    $totals['remediable']=0;
    $get3d=$projectdb->query("SELECT topic,timestamp FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) GROUP BY topic ORDER BY topic;");
    if ($get3d->num_rows>0){
        $ids=array();
        while ($get3dData=$get3d->fetch_assoc()){
            $date=$get3dData['timestamp'];
            $subtype=$get3dData['topic'];
            $getSubtype=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND topic='$subtype' AND subtype!='security_rules';");
            if ($getSubtype->num_rows>0){
                while($getSubtypeData=$getSubtype->fetch_assoc()){
                    $ids[]=$getSubtypeData['id'];
                }

                if (count($ids)>0){
                    #Calc Fail
                    $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail' AND remediation=0;");
                    if ($getFail->num_rows==1){
                        $getFailData=$getFail->fetch_assoc();
                        $failed=$getFailData['fail'];
                    }
                    else{
                        $failed=0;
                    }
                    #Calc Remediation
                    $getFail=$projectdb->query("SELECT count(id) as remediation FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail' AND remediation=1;");
                    if ($getFail->num_rows==1){
                        $getFailData=$getFail->fetch_assoc();
                        $remediation=$getFailData['remediation'];
                        if (($remediation!=0) AND ($failed!=0)){
                            $total=$failed;
                            $calc=($remediation*100)/$total;
                            $calcR=round($calc);
                        }
                        else{$calcR=0;}
                    }
                    else{
                        $failed=0;
                    }
                    #Calc Pass
                    $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
                    if ($getFail->num_rows==1){
                        $getFailData=$getFail->fetch_assoc();
                        $pass=$getFailData['pass'];
                    }
                    else{
                        $pass=0;
                    }
                    $totals['pass']=$totals['pass']+$pass;
                    $totals['failed']=$totals['failed']+$failed;
                    $totals['remediable']=$totals['remediable']+$remediation;
                    //$Data[]=array("topic"=>$subtype,"passed"=>$pass,"failed"=>$failed,"remediation"=>$remediation,"avg"=>$calcR);
                    $ids=array();
                }

            }
        }
        $total=$totals['pass']+$totals['failed']+$totals['remediable'];
        if ($total!=0){
            $current=round(($totals['pass']/$total)*100,1);
            $remediable=round((($totals['pass']+$totals['remediable'])/$total)*100,1);
        }
        else{
            $current=0;
            $remediable=0;
        }
    }
    else{
        $total=$current=$remediable=0;$date="Never Analyzed";
    }

    $Data[]=array("current"=>$current,"remediable"=>$remediable,"failed"=>$totals['failed'],"pass"=>$totals['pass'],"remediate"=>$totals['remediable'],"date"=>$date,"total"=>$total);

    $message = array();
    $message['code'] = true;
    $message['count'] = count($Data);
    $message['msg'] = $Data;
    return $message;
}

function list_bpat_tree($project,$filter){
    if(!checkProjectRights($project,'view')){
        $message = [
            'code' => true,
            'count' => 0,
            'msg' => array("text"=>'',"value"=>0,"children"=>''),
        ];
        return $message;
    }

    global $projectdb;
    $projectdb = selectDatabase($project);

    $addFilter="";
    if ($filter!=""){
        $addFilter=" AND topic='$filter' ";
    }

    $Data=array();$Data0=array();$topicavg=array();
    $get3d=$projectdb->query("SELECT subtype FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) $addFilter GROUP BY subtype ORDER BY subtype;");
    if ($get3d->num_rows>0){
        $ids=array();
        while ($get3dData=$get3d->fetch_assoc()){
            $subtype=$get3dData['subtype'];
            $getSubtype=$projectdb->query("SELECT topic,id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND subtype='$subtype' AND subtype!='security_rules';");
            if ($getSubtype->num_rows>0){
                while($getSubtypeData=$getSubtype->fetch_assoc()){
                    $topic=$getSubtypeData['topic'];
                    $ids[$topic][]=$getSubtypeData['id'];
                }

                foreach ($ids as $topic=> $arrayIds){

                    if (count($arrayIds)>0){
                        #Calc Fail
                        $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$arrayIds).") AND result='fail';");
                        if ($getFail->num_rows==1){
                            $getFailData=$getFail->fetch_assoc();
                            $failed=$getFailData['fail'];
                        }
                        else{
                            $failed=0;
                        }

                        #Calc Pass
                        $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$arrayIds).") AND result='pass';");
                        if ($getFail->num_rows==1){
                            $getFailData=$getFail->fetch_assoc();
                            $pass=$getFailData['pass'];
                        }
                        else{
                            $pass=0;
                        }

                        $total=$failed+$pass;

                        if ($total!=0){
                            $calc=($pass*100)/$total;
                            $calcR=round($calc);

                        }
                        else{
                            $calcR=0;
                        }

                        if ($calcR!=0){
                            $calcR2=$calcR/100;
                        }
                        else{
                            $calcR2=0;
                        }

                        $Data0[$topic][]=array("expanded"=>true,"leaf"=>true,"text"=>camelize(trim($subtype)),"value"=>$calcR2,"failed"=>$failed,"pass"=>$pass);
                        if (!isset($topicavg[$topic])){
                            $topicavg[$topic]['total']=1;
                            $topicavg[$topic]['avg']=$calcR;
                        }
                        else{
                            $topicavg[$topic]['avg']=$topicavg[$topic]['avg']+$calcR;
                            $topicavg[$topic]['total']=$topicavg[$topic]['total']+1;
                        }





                        $ids=array();
                    }


                }





            }
        }
    }
    if (count($Data0)>0){
        foreach ($Data0 as $topic=>$value){
            $a=$topicavg[$topic]['avg'];
            $b=$topicavg[$topic]['total'];
            $calc2=round($a/$b);
            $calc3=$calc2/100;
            $Data[]=array("text"=>$topic,"value"=>$calc3,"children"=>$value);
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = count($Data);
    $message['msg'] = $Data;
    return $message;
}

function camelize($input, $separator = '_')
{
    return str_replace($separator, ' ', ucwords($input, $separator));
}