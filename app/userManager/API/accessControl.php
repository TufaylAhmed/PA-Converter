<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 16/3/16 - 15:15
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/libs/vendor/autoload.php';
require_once INC_ROOT .'/libs/database_user.php';
require_once INC_ROOT.'/libs/projectdb.php';

function renewSession(){
    global $app;
    $user = $app->container->sentinel->getUser();
    $app->container->sentinel->login($user);
}

/** This method validates that a user has a set of given privileges
 * @param STRING $combination Values can be: "any", "all"
 * @param array $role_required
 */
function accessControl(string $combination, array $role_required, int $userId=null)
{
    global $app;
    $user = $app->container->sentinel->getUser();

    //Check if session still valid
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

function checkProjectRights(string $project, string $mode):bool{
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

    return accessControl("any",['projectRole.'.$project.'.'.$type]);
}

function checkDeviceRights(string $serial, string $mode):bool{
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

    return accessControl("any",['deviceRole.'.$serial.'.'.$type]);
}

function getUserApiKey(string $api_key, string $valid_til, int $user_id){
    require_once INC_ROOT.'/userManager/API/accessControl_Utils.php';
    return getOrCreateApiKey( $api_key,  $valid_til,  $user_id);
}