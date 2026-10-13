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

class UnusedAccountsCheck extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify that there are no inactive accounts";
    }

    public function getCategory(): string
    {
        return "Authentication and Authorization";
    }

    public function check(): CheckResponse
    {
        global $app;

        $users = $app->user->get();

        $userNames = array();
        foreach ($users as $user){
            $today = date("Y-m-d");
            $today_time = strtotime($today);
            $lastLogin_time = strtotime($user->last_login);
            $created_at = strtotime($user->created_at);
            $date = strtotime("+7 day", $lastLogin_time);
            $date2 = strtotime("+7 day", $created_at);

//            echo $user->email." Today: $today_time, Created: $created_at, Fixed: $date2 \n";

            if ($lastLogin_time == '' && $today_time < $date2){
                continue;
            }

            //echo "$user->email, \nlast: $lastLogin_time, \ntoday:$today, \ntoda2:$today_time, \ndate: $date\n\n";
            if( $today_time > $date) { //do something; }
            //    echo "Its been more than 10 days\n";
                $userNames[] = $user->first_name;
            }
        }

        $code = 0;
        $msg = 'Inactive accounts: Satisfied';
        $remediation = 'N/A';
        $success = count($userNames)<1?true:false;

        if(!$success){
            $code = -1;
            $msg = "There are inactive users (7 days): <b>".implode(", ",$userNames)."</b>";
            $remediation = "Consider removing the following accounts: <b>".implode(", ",$userNames)."</b>";
        }

        $response = new CheckResponse($this,$success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        return $this->check();
    }

}