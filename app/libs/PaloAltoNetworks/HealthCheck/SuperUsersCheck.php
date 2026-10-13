<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;

require_once INC_ROOT.'/libs/PaloAltoNetworks/HealthCheck/HealthCheck.php';

use Cartalyst\Sentinel\Native\Facades\Sentinel;

class SuperUsersCheck extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify that there are not too many Super User accounts";
    }

    public function getCategory(): string
    {
        return "Authentication and Authorization";
    }

    public function check(): CheckResponse
    {
        global $app;

        if(!defined("MAXSUPERUSERS")){
            $maxSuperUsers=3;
        }
        else{
            $maxSuperUsers =MAXSUPERUSERS;
        }
            $roleSuperUsers = Sentinel::findRoleBySlug('superuser');

        $superUserNames = array();
        $superUsers = $roleSuperUsers->users()->get([
            'id', 'email', 'last_login', 'first_name', 'last_name', 'location_id', 'location_type', 'timezone', 'active'
        ]);

        foreach ($superUsers as $superUser){
            $superUserNames[]= $superUser->email;
        }

        $code = 0;
        $msg = 'Super User Accounts: Satisfied';
        $remediation = 'N/A';
        $success = count($superUsers)<=$maxSuperUsers?true:false;


        if(!$success){
            $code = -1;
            $msg = "There are more than ".$maxSuperUsers." Super Users: ".implode(", ",$superUserNames);
            $remediation = "Remove accounts of convert them into Admin accounts. Candidates: <b>".implode(", ",$superUserNames)."</b>.";
        }

        $response = new CheckResponse($this,$success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        return $this->check();
    }

}