<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;

require_once INC_ROOT.'/console/messaging/readOrdersCheck.php';

class PanOrdersAgentCheck extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify the PanOrders agent is running to accept background jobs";
    }

    public function getCategory(): string
    {
        return "Expedition Status";
    }

    public function check(): CheckResponse
    {
        $agentStatus = getStatus();

        // getStatus() returns line count after filtering "Running"; any positive count means up
        if((int)$agentStatus['msg'] >= 1){
            $success = true;
            $code = 0;
            $msg = "PanOrders Agent is running";
            $remediation = "N/A";
        }
        else{
            $success = false;
            $code = -1;
            $msg = "PanOrders Agent is stopped";
            $remediation = "Start the agent";
        }

        $response = new CheckResponse($this,$success, $code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        //Only start the service if it is not running. Do not restart if if already running, as it may crash a task it is performing now
        $agentStatus = getStatus();
        if($agentStatus['msg']==0) {
            start();
            $success = true;
            $code = 0;
            $remediation = "PanOrders Agent has been started";
            $msg = "PanOrders Agent was not running";

        }
        else{
            $success = false;
            $code = -1;
            $msg = "PanOrders Agent was already running";
            $remediation = "N/A";
        }

        $response = new CheckResponse($this,$success, $code, $msg, $remediation);
        return $response;
    }

}