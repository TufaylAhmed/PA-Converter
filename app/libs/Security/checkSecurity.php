<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';
//require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT . '/userManager/start_CLI.php';

require_once INC_ROOT . '/libs/Security/SecureProject.php';
require_once INC_ROOT . '/libs/Security/SecureDevice.php';

use \PaloAltoNetworks\Expedition\Security\SecureDevice;
use \PaloAltoNetworks\Expedition\Security\SecureProject;

secureHomeUserspace();

function secureHomeUserspace(){
    global $app;


    $secureDevice = new SecureDevice();
    $devicesObj = $app->device->orderBy('serial')->get();
    foreach ($devicesObj as $deviceObj){
        $secureDevice->secure($deviceObj->serial);
    }

    $secureProject = new SecureProject();
    $projectsObj = $app->project->orderBy('name')->get();
    foreach ($projectsObj as $projectObj){
        $secureProject->secure($projectObj->name);
    }
}

