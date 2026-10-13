<?php
/**
 * Created by PhpStorm.
 * User: aestevez
 * Date: 11/15/16
 * Time: 11:06 AM
 */
$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function load_bestpractices(){
    global $app;
    global $bestPracticesdb;
    if(!accessControl("any", ['project.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view keys in this device';
        return $message;
    }
    # LOAD Benchmark
    if (file_exists(INC_ROOT.'/contents/benchmarks.xml')){
        $xml  = simplexml_load_file(INC_ROOT.'/contents/benchmarks.xml');
        $bestPracticesdb->query("TRUNCATE benchmarks_topics;");
        $bestPracticesdb->query("TRUNCATE benchmarks;");
        $bestPracticesdb->query("TRUNCATE benchmarks;");
        $benchmark_version=$xml->attributes()->version;
        $benchmark_date=$xml->attributes()->date;
        $checks=array();
        $tests=array();

        $check_default_pack=$bestPracticesdb->query("SELECT id FROM bestpractices_packs WHERE name='default';");
        if ($check_default_pack->num_rows==0){
            $bestPracticesdb->query("INSERT INTO bestpractices_packs (name,created_at,userid,updated_at,description,bestpractices_version) VALUES ('default',NOW(),1,NOW(),'All the Checks enabled by default','$benchmark_version');");
        }

        foreach($xml->entry as $benchmark){
            $topic_name=$benchmark->attributes()->name;
            $topic_description=addslashes($benchmark->description);
            $color=$benchmark->color;
            $icon=$benchmark->icon;
            $bestPracticesdb->query("INSERT INTO benchmarks_topics (name,description,version,date,color,icon) VALUES ('$topic_name','$topic_description','$benchmark_version','$benchmark_date','$color','$icon');");
            $topic_id=$bestPracticesdb->insert_id;
            if (isset($benchmark->checks)) {
                foreach ($benchmark->checks->check as $check) {
                    $check_enabled=$check->enabled;
                    if ($check_enabled=="yes"){$check_enabled=1;}else{$check_enabled=0;}
                    $check_topic = $check->attributes()->name;
                    $check_title = addslashes($check->title);
                    $check_description = mysqli_real_escape_string($bestPracticesdb, $check->description);
                    $check_rationale = mysqli_real_escape_string($bestPracticesdb, $check->rationale);
                    $check_reference = mysqli_real_escape_string($bestPracticesdb, $check->reference);
                    $check_audit = mysqli_real_escape_string($bestPracticesdb, $check->audit);
                    $check_default_value = $check->default_value;
                    $check_score = $check->score;
                    $check_panos = $check->panos;
                    $check_topic_id = $topic_id;

                    if (isset($check->tests)){
                        foreach ($check->tests->test as $test) {
                            $checkname = $test->attributes()->name;
                            $checkvalue=addslashes($test);
                            $tests[]="('$check_topic','$checkname','$checkvalue')";
                        }
                    }

                    $checks[] = "('$check_topic','$check_title','$check_description','$check_rationale','$check_reference','$check_audit','$check_default_value','$check_score','$check_panos','$check_topic_id','$check_enabled')";
                }
            }


        }
        if (count($checks)>0){
            $bestPracticesdb->query("INSERT INTO benchmarks (topic,title,description,rationale,reference,audit,default_value,score,panos,topic_id,enabled) VALUES ".implode(",",$checks).";");
            unset($checks);
        }
        if (count($tests)>0){
            $bestPracticesdb->query("INSERT INTO benchmarks_checks (topic,checkname,checkvalue) VALUES " . implode(",",$tests).";");
            unset ($tests);
        }
        $message = array();
        $message['code'] = true;
        $message['msg'] = 'Best Practices imported.';
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'XML with Best Practices was not found.';
    }
    return $message;
}

