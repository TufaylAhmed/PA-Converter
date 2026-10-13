<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 2/6/16 - 17:52
 */
//Loads all global PHP definitions

//require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/userManager/start_CLI.php';
require_once INC_ROOT .'/libs/database_user.php';



/** This method validates that a user has a set of given privileges
 * @param STRING $combination Values can be: "any", "all"
 * @param array $role_required
 * @param int $userId
 */
function accessControl(STRING $combination, ARRAY $role_required, int $userId=null)
{
    global $app;

    //Check if session still valid an $app->container->sentinel->login should be done before doing this check
    $loggedUser = $app->container->sentinel->check();

    //If not valid, remove the session
    if (!$loggedUser) {
//        $message = 'You need to be logged in to access this page.';
//        $app->flash('global', $message);
//        $app->response->redirect($app->urlFor('home'));
        $accessValid = false;
    }
    else {
        if($combination == "any") {
            if (!$loggedUser->hasAnyAccess($role_required)) {
//                $message = "You don't have the permission to access this page.";
//                $app->flash('global', $message);
//                $app->response->redirect($app->urlFor('home'));
                $accessValid = false;
            } else {
                $accessValid = true;
            }
        }
        else{
            if (!$loggedUser->hasAccess($role_required)) {
//                $message = "You don't have the permission to access this page.";
//                $app->flash('global', $message);
//                $app->response->redirect($app->urlFor('home'));
                $accessValid = false;
            } else {
                $accessValid = true;
            }
        }
    }
    return $accessValid;

}

function checkProjectRights(STRING $project, STRING $mode, int $userId=0):bool{

    //echo "ANTES: " .$userId. "\n";
    if(($userId == 0) || ($userId == NULL)){
        global $app;
        //echo "En checkProjectRights: \n";
        //print_r($app);
        $user = $app->container->sentinel->getUser();
        $userId = $user->id;
    }
    //echo "DESPUEs: " .$userId. "\n";

    switch ($mode){
        case "view":
            $type = '*';
            break;

        case "delete":
        case "create":
        case "update":
            $type = 'update';
            break;

        default:
            $type = 'admin';

    }

    return accessControl("any",['projectRole.'.$project.'.'.$type], $userId);
}

function checkDeviceRights(STRING $serial, STRING $mode, int $userId):bool{
    switch ($mode){
        case "view":
            $type = '*';
            break;

        case "delete":
        case "create":
        case "update":
            $type = 'update';
            break;

        default:
            $type = 'admin';

    }

    return accessControl("any",['deviceRole.'.$serial.'.'.$type], $userId);
}

function getUserApiKey(STRING $api_key, STRING $valid_til, int $user_id){
    require_once INC_ROOT.'/userManager/API/accessControl_Utils.php';
    return getOrCreateApiKey( $api_key,  $valid_til,  $user_id);
}
