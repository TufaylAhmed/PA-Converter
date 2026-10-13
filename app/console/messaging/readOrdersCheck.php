<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 20/9/16 - 15:40
 */
require_once INC_ROOT.'/libs/jobs/JobsController.php';
use PaloAltoNetworks\Expedition\Jobs\JobsController;

function getStatus(){
    $response = exec('sh /var/www/html/OS/startup/pan-readOrders status | grep -v Running | wc -l');
    return [
        'code'  => true,
        'msg'   => $response,
    ];
}

function restart(){
    $response = exec('sh /var/www/html/OS/startup/pan-readOrders restart');
    return [
        'code'  => true,
        'msg'   => $response,
    ];

}

function stop(){
    $response = exec('sh /var/www/html/OS/startup/pan-readOrders stop');
    return [
        'code'  => true,
        'msg'   => $response,
    ];

}

function start(){
    $response = exec('sh /var/www/html/OS/startup/pan-readOrders start');
    return [
        'code'  => true,
        'msg'   => $response,
    ];
}

function force_start(){
    $response = exec('sh /var/www/html/OS/startup/pan-readOrders force_start');
    return [
        'code'  => true,
        'msg'   => $response,
    ];
}

function flush_jobs(){
    $response = exec('/bin/php /var/www/html/console/messaging/checkPendingOrders.php > /dev/null 2>/dev/null &');
    return [
        'code'  => true,
        'msg'   => $response,
    ];
}

function remove_jobs(){
    $jobController = new JobsController();
    //Get all the pending jobs
    $pendingJobs = $jobController->getPendingTasks();

    //Cancel each one of the pending jobs
    foreach ($pendingJobs as $pendingJob){
        $jobId = $pendingJob['job_id'];
        $jobController->deleteJob($jobId);
    }

    return [
        'code'  => true,
        'msg'   => 'All Jobs removed',
    ];
}
