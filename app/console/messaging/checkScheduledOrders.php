<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 28/6/16 - 13:01
 */

require_once '/var/www/html/libs/common/definitions.php';
require_once INC_ROOT.'/libs/vendor/autoload.php';

require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/console/messaging/classes/PaloAltoNetworks/Processes/ClassLoader.php';
require_once INC_ROOT.'/libs/definitions/taskDefinitions.php';

use PaloAltoNetworks\Processes\ClassLoader;
use PhpAmqpLib\Message\AMQPMessage;

global $app;

$pendingTasks = $app->task
    ->where('statusCode', TO_RELAUNCH)
    ->whereRow('now() > updated_at + statusMessage')
    ->get();

foreach ($pendingTasks as $pendingTask){
    echo $pendingTask->id."\n";

    $message = [
        'params'        => json_decode($pendingTask->params),
        'proccessCode'  => $pendingTask->processCode
    ];
    $message['params']->taskId = $pendingTask->id;

    $message = json_encode($message);

    $msg = new AMQPMessage(
        $message,
        array('delivery_mode' => 2) #make the message persistent
    );

    processOrder(json_decode($msg->body));

}



function processOrder($message)
{
    $loader = new ClassLoader($message);
}