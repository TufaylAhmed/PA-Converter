<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 27/5/16 - 11:44
 */

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function updateProject(ARRAY $params){
    global $app;


    $v = $app->projectValidation;
    $v->validate([
        'name'          => [$params['name'],            'required|xssSave'],
        'tag'           => [$params['tag'],             'xssSave'],
        'active'        => [$params['active'],          'isBoolean'],
    ]);

    $projectName = $params['name'];

    if (!accessControl("any", ['project.create', 'project.admin', 'PANProject_' . $projectName . '_admin'])) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Your account does not have the rights to manage this project '$projectName'";
        return $message;
    }
    if ($v->passes()) {
        if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
            $message['code'] = false;
            $message['msg'] = 'Project not found in our registry';
            return $message;
        }
        unset($params['vendors']);
        $project->update($params);

        $message = array();
        $message['code'] = true;
        $message['msg'] = "Project information updated successfully";
        return $message;
    }

    $message['code'] = false;
    $message['msg'] = $v->errors()->all();
    return $message;
}

function addVendor(ARRAY $params){
    global $app;

    $projectName = $params['name'];
    $vendor = $params['vendor'];

    if (!accessControl("any", ['project.create', 'project.admin', 'PANProject_' . $projectName . '_admin'])) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Your account does not have the rights to manage this project '$projectName'";
        return $message;
    }

    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }
    $vendors = json_decode($project->vendors);
    if(!isset($vendors)){
        $vendors = ((object) null);
    }
    if(!isset($vendors->$vendor)){
        $amount = 1;
    }
    else{
        $amount = $vendors->$vendor +1;
    }
    $vendors->$vendor = $amount;
    $params['vendors'] = json_encode($vendors);

    $project->update($params);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "Project information updated successfully";
    return $message;

}