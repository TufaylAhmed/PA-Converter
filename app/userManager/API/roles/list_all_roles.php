<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 28/4/16 - 12:18
 */

use Cartalyst\Sentinel\Native\Facades\Sentinel;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

function list_all_roles(){
    global $app;

    $accessValid = accessControl("any", ['user.admin', 'role.admin', 'project.admin']);

    if(!accessControl("any", ['user.admin', 'role.admin', 'project.admin'])){
        $roles = array();
        return $roles;
    }

    $roles = $app->container->sentinel->getRoleRepository()->get();
    return $roles;
}

function list_local_roles(){
    global $app;

    if(!accessControl("any", ['user.*', 'role.*'])){
        $roles = array();
        return $roles;
    }

    $roles = $app->container->sentinel->getRoleRepository()->where("slug", "=", "admin")->orWhere("slug", "=", "user")->orWhere("slug", "=", "superuser")->get();
    return $roles;
}