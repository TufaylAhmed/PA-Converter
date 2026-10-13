<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 4/4/16 - 17:36
 */

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function listAdminProject(STRING $project){
    if(!accessControl("any", ['project.admin',                 'projectRole.'.$project.'.admin'])){
        return false;
    }
    return true;
}

function listUserProject(STRING $project){
    if(!accessControl("any", ['project.admin','project.create','projectRole.'.$project.'.admin','projectRole.'.$project.'.user'])){
        return false;
    }
    return true;
}

function listViewProject(STRING $project){
    if(!accessControl("any", ['project.admin','project.create','projectRole.'.$project.'.*'])){
        return false;
    }
    return true;
}

function listProjects(){
    if(!accessControl("any", ['project.*', 'projectRole.*'])){
        //This is not an Admin user, however, he should be able to list projects he has been assigned to

        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have project listing rights';
        return $message;
    }

    global $app;
    $project = $app->container->project->where('active','=','1')->orderBy('name')->get();

    $message = array();
    $message['code'] = true;
    $message['msg'] = json_decode(json_encode($project));

    return $message;
}