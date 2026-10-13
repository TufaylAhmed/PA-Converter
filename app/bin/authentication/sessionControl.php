<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 11:29
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/userManager/API/accessControl.php';
$accessValid = accessControl("any", ['user.*','*']);

global $renewSession;
if(!$accessValid){
    unset($_SESSION['authenticated']);
    unset($_SESSION['username']);
    unset($_SESSION['timezone']);
    session_destroy();
    echo json_encode(array("success"=>false, "msg"=>"No valid session. (00)"));
    die();
}
else{
    if(isset($renewSession) && $renewSession==false){
        //Nothing to do
    }
    else{
        //renew the session with extra time?
        renewSession(); //This method i in accessControl.php
    }
}


//Functions for access rights control
function hasViewAccess(STRING $project){
    if(!accessControl("any", ['projectRole.'.$project.'.view'])) {
        $message = [
            'permitted' => false,
            'msg' => 'Your account does not have the rights to see this project contents',
        ];
    }
    else{
        $message= [
            'permitted' => true,
        ];
    }
    return $message;
}

function hasUpdateAccess(STRING $project){
    if(!accessControl("any", ['projectRole.'.$project.'.update'])) {
        $message = [
            'permitted' => false,
            'msg' => 'Your account does not have the rights to edit this project contents',
        ];
    }
    else{
        $message = [
            'permitted' => true,
        ];

    }
    return $message;
}


/*
 $control = hasViewAccess($project);
 if(! $control['permitted'])
    return $control['msg'];

  */