<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 4/4/16 - 15:35
 */


if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function deleteAllProjects(){
    global $app;

    //List first the existing projects
    $projects = $app->project->get();
    $deletedProjects = array();

    foreach ($projects as $project){
        $message = deleteProject($project['name']);
        if ($message['code']){
            $deletedProjects[] = $project['name'];
        }
    }

    return $deletedProjects;
}

function deleteProject(STRING $project){
    global $app;

//    if($project == "demo"){
//        $message = array();
//        $message['code'] = false;
//        $message['msg'] = '"demo" is a Non-deleteable project';
//        return $message;
//    }

    if(!accessControl("any", ['project.admin','projectRole.'.$project.'.delete'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to delete the project';
        return $message;
    }


    $name = $project;
    $slug_pre = "PANProject_".$project;

    //Delete project from the pandbRBAC
    if (!($projectObject = $app->project->where('name', $name)->get(['id'])->first())) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }

    //Detach users from project
    if($roleViewer = $app->container->sentinel->findRoleBySlug($slug_pre.'_viewer')) {
        $roleViewer->users()->detach();
        $roleViewer->delete();
    }
    if($roleUser   = $app->container->sentinel->findRoleBySlug($slug_pre.'_user')) {
        $roleUser->users()->detach();
        $roleUser->delete();
    }
    if($roleAdmin  = $app->container->sentinel->findRoleBySlug($slug_pre.'_admin')) {
        $roleAdmin->users()->detach();
        $roleAdmin->delete();
    }

    //Detach devices from project
    $projectObject->devices()->detach();

    //Remove user settings related to this project
    $projectObject->settings()->detach();

    //Execute delete project
    $projectObject->delete();

    if($accessKeyObj = $app->accessKey->where("type", "project")->where("lid", $projectObject->id)->first()){
        $accessKeyObj->delete();
    }


    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Project correctly deleted';
    return $message;

}