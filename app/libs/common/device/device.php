<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/9/16 - 17:05
 */

/***
 * Get the api_key of a device based on the user's role
 * @param String $project
 * @param String $device
 * @return array
 */
function getApiKey(String $project, String $deviceSerial, int $userID){
    require_once INC_ROOT.'/userManager/API/projects/manageUsers.php';
    require_once INC_ROOT.'/userManager/API/devices/manageKeys.php';

    $roleMessage = getUserRoleInProject($project, $userID);
    if(!$roleMessage['code']) {
        return $roleMessage;
    }

    $keyMessage = getKeyFromDevice($deviceSerial, $roleMessage['msg']);
    return $keyMessage;
}
