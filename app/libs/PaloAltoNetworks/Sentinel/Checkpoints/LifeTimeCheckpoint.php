<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 24/3/16 - 12:23
 */

namespace PaloAltoNetworks\Sentinel\Checkpoints;

use Cartalyst\Sentinel\Users\UserInterface;
use Cartalyst\Sentinel\Checkpoints\CheckpointInterface;
use PaloAltoNetworks\Sentinel\Checkpoints\SessionTimeoutException;

class LifeTimeCheckpoint implements CheckpointInterface
{
    /**
     * Create a new lifetime checkpoint.
     *
     * @return void
     */


    public function __construct()
    {
    }

    /**
     * {@inheritDoc}
     */
    public function login(UserInterface $user)
    {
        return $this->checkSession("login", $user);
    }

    /**
     * {@inheritDoc}
     */
    public function check(UserInterface $user)
    {
        return $this->checkSession("check", $user);
    }

    /**
     * Checks the activation status of the given user.
     *
     * @param  \Cartalyst\Sentinel\Users\UserInterface  $user
     * @return bool
     * @throws \PaloAltoNetworks\Sentinel\Checkpoints\SessionTimeoutException
     */
    protected function checkSession($action, UserInterface $user)
    {
        global $app;
        $timeThreshold=$app->config->get('session.timeout');

        //Get the time of the last_login
        if ($action == "check") {
            $last_login = $user->last_login;
            $last_login = strtotime($last_login);
            $timeZone = $user->timezone;
            date_default_timezone_set($timeZone);

            $time = time() - $last_login;
            $minutes = floor($time/60);

            if ($minutes >= $timeThreshold) {
                $exception = new SessionTimeoutException('Your session has expired');
                $exception->setUser($user);

//                echo json_encode(array("success"=>false, "msg"=>"No valid session."));
                return false;
//                exit();
            }
            else{
                //DO NOT Update last_login with time(); checkSession is called every minute to validate that the session is still alive.
                // Instead, a session refresh should be done in Authentication.php, that it is called when the user interacts with the system
//                $app->container->sentinel->login($user);
            }
        }
        elseif($action == "login"){
        }

        return true;
    }

    public function fail(UserInterface $user = null)
    {
//        // We'll check throttling firstly from any previous attempts. This
//        // will throw the required exceptions if the user has already
//        // tried to login too many times.
//        $this->checkThrottling('login', $user);
//
//        // Now we've checked previous attempts, we'll log this latest attempt.
//        // It'll be picked up the next time if the user tries again.
//        $this->throttle->log($this->ipAddress, $user);
    }
}