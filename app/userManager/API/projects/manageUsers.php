<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/5/16 - 12:00
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function getUserRoleInProject(String $project, int $userID){
    global $app;

    //$user = $app->container->sentinel->getUser();

    if(accessControl("any", [ 'projectRole.'.$project.'.admin'], $userID)){
        $message = array();
        $message['code'] = true;
        $message['msg'] = 'admin';
        return $message;
    }
    if(accessControl("any", [ 'projectRole.'.$project.'.update'], $userID)){
        $message = array();
        $message['code'] = true;
        $message['msg'] = 'user';
        return $message;
    }
    if(accessControl("any", [ 'projectRole.'.$project.'.view'], $userID)){
        $message = array();
        $message['code'] = true;
        $message['msg'] = 'viewer';
        return $message;
    }

    $message = array();
    $message['code'] = false;
    $message['msg'] = '';
    return $message;
}


function listUsersInProject(String $data){
    global $app;

    $project = $data;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view users in this project';
        return $message;
    }

    $userlist = array();
    $slug = "PANProject_".$project."_admin";
    if(!$role_admins = $app->container->sentinel->findRoleBySlug($slug)){
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Project not found";
        return $message;
    }
    $admins = $role_admins->users()->get([
        'id', 'email', 'first_name', 'last_name', 'active'
    ]);
    $admins = json_decode(json_encode($admins));
    foreach ($admins as $user){
        $user->role = 'admin';
        $userlist[] = $user;
    }

    $slug = "PANProject_".$project."_user";
    $role_users = $app->container->sentinel->findRoleBySlug($slug);
    $users = $role_users->users()->get([
        'id', 'email', 'first_name', 'last_name', 'active'
    ]);
    $users = json_decode(json_encode($users));
    foreach ($users as $user){
        $user->role = 'user';
        $userlist[] = $user;
    }

    $slug = "PANProject_".$project."_viewer";
    $role_viewers = $app->container->sentinel->findRoleBySlug($slug);
    $viewers = $role_viewers->users()->get([
        'id', 'email', 'first_name', 'last_name', 'active'
    ]);
    $viewers = json_decode(json_encode($viewers));
    foreach ($viewers as $user){
        $user->role = 'viewer';
        $userlist[] = $user;
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $userlist;
    return $message;
}

function assignUsersToProject($project, ARRAY $data){
    return updateUserAttachement($project, $data);
}

function removeUserFromProject($project, ARRAY $data){
    $userId = $data['id'];

    switch ($data['role']){
        case "admin":
            $message = remove_AdminFromProject($project, $userId);
            break;

        case "user":
            $message = remove_UserFromProject($project, $userId);
            break;

        case "viewer":
            $message = remove_ViewerFromProject($project, $userId);
            break;

        default:
            break;
    }
    return $message;
}

function assign_AdminToProject($projectName, String $userId){
    global $app;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this project';
        return $message;
    }

    $slug = "PANProject_".$projectName."_admin";
    $role_user = $app->container->sentinel->findRoleBySlug($slug);
    $userEntry = $app->container->sentinel->findById($userId);
    $role_user->users()->attach($userEntry);

    create_userSettings($projectName, $userId);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "User assigned successfully to project '$projectName' as Project Admin";
    return $message;
}

function remove_AdminFromProject($projectName, String $userId){
    global $app;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this project';
        return $message;
    }

    $slug = "PANProject_".$projectName."_admin";
    $role_user = $app->container->sentinel->findRoleBySlug($slug);
    $user = $app->container->sentinel->findById($userId);
    $role_user->users()->detach($user);

    delete_userSettings($projectName, $userId);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "User successfully removed as Project Admin from project '$projectName'";
    return $message;
}

function assign_UserToProject($projectName, String $userId){
    global $app;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this project';
        return $message;
    }

    $slug = "PANProject_".$projectName."_user";
    $role_user = $app->container->sentinel->findRoleBySlug($slug);
    if($userEntry = $app->container->sentinel->findById($userId)) {
        $role_user->users()->attach($userEntry);
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = "User not found";
        return $message;
    }

    create_userSettings($projectName, $userId);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "User assigned successfully to project '$projectName' as Project User";
    return $message;
}

function remove_UserFromProject($projectName, String $userId){
    global $app;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this project';
        return $message;
    }

    $slug = "PANProject_".$projectName."_user";
    $role_user = $app->container->sentinel->findRoleBySlug($slug);
    $user = $app->container->sentinel->findById($userId);
    $role_user->users()->detach($user);

    delete_userSettings($projectName, $userId);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "User removed successfully as Project User from project '$projectName'";
    return $message;
}

function assign_ViewerToProject($projectName, String $userId){
    global $app;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this project';
        return $message;
    }

    $slug = "PANProject_".$projectName."_viewer";
    $role_user = $app->container->sentinel->findRoleBySlug($slug);
    $user = $app->container->sentinel->findById($userId);
    $role_user->users()->attach($user);

    create_userSettings($projectName, $userId);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "User assigned successfully to project '$projectName' as Project Viewer";
    return $message;
}

function remove_ViewerFromProject($projectName, String $userId){
    global $app;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this project';
        return $message;
    }

    $slug = "PANProject_".$projectName."_viewer";
    $role_user = $app->container->sentinel->findRoleBySlug($slug);
    $user = $app->container->sentinel->findById($userId);
    $role_user->users()->detach($user);

    delete_userSettings($projectName, $userId);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "Users removed successfully as Project Viewers from project '$projectName'";
    return $message;
}

function updateUserAttachement($project, $data){
    if(is_int($data['id'])) {
        $userId = $data['id'];
    }
    else{
        $userId = $data['email'];
    }

    switch ($data['role']){
        case "admin":
            remove_AdminFromProject($project, $userId);
            remove_UserFromProject($project, $userId);
            remove_ViewerFromProject($project, $userId);
            $message = assign_AdminToProject($project, $userId);
            break;

        case "user":
            remove_AdminFromProject($project, $userId);
            remove_UserFromProject($project, $userId);
            remove_ViewerFromProject($project, $userId);
            $message = assign_UserToProject($project, $userId);
            break;

        case "viewer":
            remove_AdminFromProject($project, $userId);
            remove_UserFromProject($project, $userId);
            remove_ViewerFromProject($project, $userId);
            $message = assign_ViewerToProject($project, $userId);
            break;

        default:
            break;
    }
    return $message;
}

function delete_userSettings($projectName, String $userId){
    global $app;
    //Create user_settings
    $project = $app->project->where('name', '=', $projectName)->get()->first();
    if($userSettings = $app->userSettings->where('user_id', $userId)->where('project_id',$project->id)->first()) {
        $userSettings->delete();
    }
}

function create_userSettings($projectName, String $userId){
    global $app;
    //Create user_settings
    $project = $app->project->where('name', '=', $projectName)->get()->first();
    if(!$userSettings = $app->userSettings->where('user_id', $userId)->where('project_id',$project->id)->first()) {
        $params = [
            'user_id' => $userId,
            'project_id' => $project->id,
        ];

        $userSettings = $app->userSettings->create($params);
    }
}