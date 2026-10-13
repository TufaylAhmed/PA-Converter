<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 28/4/16 - 12:29
 */

use Cartalyst\Sentinel\Native\Facades\Sentinel;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

function list_all_users(){
    global $app;

    if(accessControl("any", ['user.admin'])) {
//        $users = $app->container->sentinel->getUserRepository()->with('roles')->get([
        $users = Sentinel::getUserRepository()->get([
            'id', 'email', 'last_login', 'first_name', 'last_name', 'created_at', 'updated_at', 'location_id', 'location_type', 'timezone', 'active'
        ]);
    }
    elseif(accessControl("any", ['user.update'])){
        /* @var $role \Cartalyst\Sentinel\Roles\EloquentRole
         * @var $users \Cartalyst\Sentinel\Users\UserRepositoryInterface
         * @var $myUser \Cartalyst\Sentinel\Users\UserRepositoryInterface
         * @var $otherUsers \Cartalyst\Sentinel\Users\UserRepositoryInterface
         */
        $roleUsers = Sentinel::findRoleBySlug('user');
        $roleAdmins = Sentinel::findRoleBySlug('admin');

        $userUsers = $roleUsers->users()->get([
            'id', 'email', 'last_login', 'first_name', 'last_name', 'location_id', 'location_type', 'timezone', 'active'
        ]);
        $adminUsers = $roleAdmins->users()->get([
            'id', 'email', 'last_login', 'first_name', 'last_name', 'location_id', 'location_type', 'timezone', 'active'
        ]);

        $userUsers      = json_decode(json_encode($userUsers), true);
        $adminUsers = json_decode(json_encode($adminUsers), true);
        $users = array_merge($userUsers, $adminUsers);
    }
    elseif(accessControl("any", ['user.*'])){
        $myID = $app->container->sentinel->getUser()->getUserId();
        $users = $app->user->where('id', $myID)->get([
            'id', 'email', 'last_login', 'first_name', 'last_name', 'location_id', 'location_type', 'timezone', 'active'
        ]);
    }
    else{
        return null;
    }


    $users2 = json_decode(json_encode($users), true);
    for ($i=0; $i < count($users2); $i++){
        //Provide only the first ROLE
        $user = $users2[$i];
        $firstRole = $app->container->sentinel->findById($user['id'])->roles()->first();
//        $role = ["name" => $firstRole['name'], "id" =>$firstRole['id'], "slug" =>$firstRole['slug'] ];
        $user['roles'] = $firstRole['name'];
        $users2[$i] = $user;

        //Retrieve the server's name
        $serverName = "";
        if ($user['location_type'] == "ldap") {
            $serverldap = $app->container->ldapserver->select()->where('id','=',$user['location_id'])->first();
            $serverName = $serverldap->name;
        }
        elseif ($user['location_type'] == "radius"){
            $serverradius = $app->container->radiusserver->select()->where('id','=',$user['location_id'])->first();
            $serverName = $serverradius->name;
        }
        elseif ($user['location_type'] == "local"){
            $serverName = "Local";
        }

        $users2[$i]['location_name'] = $serverName;
    }

    return $users2;
}