<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 29/4/16 - 10:20
 */

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

function list_all_servers(){
    global $app;

    //user.admin requires server listing to update the server to which the user needs to make the authentication
    if(!accessControl("any", ['user.admin', 'server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server listing rights';
        return $message;
    }

    $ldapservers = $app->container->ldapserver
        ->select('name', 'id')
        ->where('active','=','1')
        ->orderBy('name')
        ->get();

    foreach($ldapservers as $server){
        $server['ide'] = "ldap.".$server['id'];
        unset($server['id']);
    }

    $radiusservers = $app->container->radiusserver
        ->where('active','=','1')
        ->orderBy('name')
        ->select('name', 'id')
        ->get();

    foreach($radiusservers as $server){
        $server['ide'] = "radius.".$server['id'];
        unset($server['id']);
    }


    $servers = array();
    $localserver['name']="Local";
//    $localserver['id']="0";
    $localserver['ide']="local.0";
    $servers[] = $localserver;


    if(count($ldapservers)>0){
        $servers=array_merge(
            $servers,
            json_decode($ldapservers)
        );
    }

    if(count($radiusservers)>0){
        $servers= array_merge(
            $servers,
            json_decode($radiusservers)
        );
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $servers;

    return $message;
}

function list_servers_LDAP(){
    global $app;

    //user.admin requires server listing to update the server to which the user needs to make the authentication
    if(!accessControl("any", ['user.admin', 'server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server listing rights';
        return $message;
    }

    $ldapservers = $app->container->ldapserver
//        ->select('name', 'id')
//        ->where('active','=','1')
        ->orderBy('name')
        ->get();

    foreach($ldapservers as $server){
        $server['ide'] = "ldap.".$server['id'];
        $server['crypto'] = ($server['uses_ssl'] == 1)? 'SSL':
                            (($server['uses_tls'] == 1)? 'TLS': 'None');
        //print_r($server);

    }

    $servers = array();

    if(count($ldapservers)>0){
        $servers=array_merge(
            $servers,
            json_decode($ldapservers)
        );
    }


    $message = array();
    $message['code'] = true;
    $message['msg'] = $servers;

    return $message;
}

function list_servers_Radius(){
    global $app;

    //user.admin requires server listing to update the server to which the user needs to make the authentication
    if(!accessControl("any", ['user.admin', 'server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server listing rights';
        return $message;
    }

    $radiusservers = $app->container->radiusserver
//        ->where('active','=','1')
        ->orderBy('name')
//        ->select('name', 'id')
        ->get();

    foreach($radiusservers as $server){
        $server['ide'] = "radius.".$server['id'];
    }


    $servers = array();

    if(count($radiusservers)>0){
        $servers= array_merge(
            $servers,
            json_decode($radiusservers)
        );
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $servers;

    return $message;
}