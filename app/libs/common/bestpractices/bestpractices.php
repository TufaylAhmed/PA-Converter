<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

function list_benchmarks(ARRAY $params){

    //if(!accessControl("any", ['project.admin'])){
     //   $message = array();
    //    $message['code'] = false;
    //    $message['msg'] = 'Your account does not have the rights to view this project contents';
    //    return $message;
    //}

    switch ($params['mode']){
        case 'benchmarks':
            global $bestPracticesdb;
            $query ="SELECT * FROM benchmarks;";
            $result= $bestPracticesdb->query($query);
            $myData=array();

            if ($result->num_rows==0){
                require_once INC_ROOT.'/libs/common/bestpractices/loadXML.php';
                $message=load_bestpractices();
                if ($message['code']==false){
                    return $message;
                }
                else{
                    $result= $bestPracticesdb->query($query);
                }

            }

            while($row = $result->fetch_object()){
                $myData[]= $row;
            }
            $message = array();
            $message['code'] = true;
            $message['count'] = $result->num_rows;
            $message['msg'] = $myData;
            break;
        default:
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'No Action defined';
            break;
    }

    return $message;

}

function register_pack(ARRAY $data){
    global $app;
    global $bestPracticesdb;
    $message = array();

    if(!accessControl("any", ['project.admin'])){
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to create this contents';
        return $message;
    }

    $userid=mysqli_real_escape_string($bestPracticesdb, $app->sentinel->getUser()->id);
    $name = mysqli_real_escape_string($bestPracticesdb, $data['name']);
    $description = mysqli_real_escape_string($bestPracticesdb, $data['description']);
    $getversion=$bestPracticesdb->query("SELECT version FROM benchmarks_topics LIMIT 1;");
    if ($getversion->num_rows==1){
        $getversionData=$getversion->fetch_assoc();
        $version = mysqli_real_escape_string($bestPracticesdb, $getversionData['version']);
        $getDup=$bestPracticesdb->query("SELECT id FROM bestpractices_packs WHERE name='$name';");
        if ($getDup->num_rows==0){
            $query = "INSERT INTO bestpractices_packs (name, description, created_at, updated_at, userid, bestpractices_version)
              VALUES ('$name', '$description', NOW(), NOW(),'$userid', '$version')";
            $bestPracticesdb->query($query);
            $message['code'] = true;
            $message['msg'] ='BestPractice Pack succesfuly created.';
        }
        else{
            $message['code'] = false;
            $message['msg'] ='BestPractice Pack name already exists.';
        }

    }
    else{
        $message['code'] = false;
        $message['msg'] = 'There are no BestPractices loaded into the Tool';

    }
    return $message;
}