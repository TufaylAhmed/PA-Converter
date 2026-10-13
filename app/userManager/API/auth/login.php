<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 29/3/16 - 13:14
 */
use Adldap\Adldap;
use Adldap\AdldapException;
use Cartalyst\Sentinel\Checkpoints\ActivationCheckpoint;

function login(string $identifier, string $password, ?string $remember = null, string $type = 'password'){
    global $app;

    $remember = (isset($remember) && $remember == 'on') ? true : false;

    //First, check either it is a local user or a remote user
    $credentials = [
        'login' => $identifier,
    ];

    $user = $app->container->sentinel->findByCredentials($credentials);


    if ($user) {
        //First check that the user has not been disabled, so that it is "active"
        $active = $user->active;
        if(!$active){
            return false;
        }

        date_default_timezone_set($user->timezone);

        if ($user->location_type == "local") //This is a local user
        {
            try {
                global $pandb;
                $password = $pandb->real_escape_string($password);

                if($type == 'API_Key'){
                    if(!$user = $app->user->where('email',$identifier)->where('api_key',$password)->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()){
                        return false;
                    }
                    else{
                        $user = $app->container->sentinel->authenticate([
                            'login' => $identifier
                        ]);
                    }
                }
                elseif (!$user = $app->container->sentinel->authenticate([
                    'login' => $identifier,
                    'password' => $password,
                ], $remember)
                ) {
                    return false;
                }
                else {
                    $_SESSION[$app->config->get('auth.session')] = $user->id;
                    $_SESSION[$app->config->get('auth.session_username')] = $user->email;
                    $_SESSION[$app->config->get('auth.session_timezone')] = $user->timezone;
                    $_SESSION[$app->config->get('auth.session_authenticated')] = true;
//                    $message = 'Welcome!';
                    return true;
                }
            } catch (ThrottlingException $ex) {
//                $message = "Too many attempts!";
                return false;
            } catch (NotActivatedException $ex) {
//                $message = "Please activate your account before trying to log in";
                return false;
            }
        }
        elseif($user->location_type == "ldap") //This is a remote user
        {
            $server = $app->container->ldapserver->where('id', '=', $user->location_id)->first();
            $params = [
//                'admin_username'        =>  $server->admin_user,
//                'admin_password'        =>  $server->admin_password,
                'account_prefix'        =>  $server->account_prefix,
                'account_suffix'        =>  $server->account_suffix,
                'hosts'                 =>  [$server->address],
                'port'                  =>  $server->port,
                'base_dn'               =>  $server->dn,
                'use_ssl'               => ($server->uses_ssl == 0) ? false : true,
                'use_tls'               => ($server->uses_tsl == 0) ? false : true,
                'follow_referrals' => false,
                'custom_options' => [],
            ];


            try {
                $adldap = new Adldap();
                $adldap->addProvider($params);

                $provider = $adldap->getDefaultProvider();

                if ($provider->auth()->attempt($identifier, $password)) {
                    //We did the authentication against a different server. Therefore, the user is not automatically
                    //logged in Sentinel. We need to manually log the user in so that we can carry the user's credentials
                    //through the application
                    $app->container->sentinel->login($user);
                    //Then, we can create a PHP session
                    $_SESSION[$app->config->get('auth.session')] = $user->id;
                    $_SESSION[$app->config->get('auth.session_username')] = $user->email;
                    $_SESSION[$app->config->get('auth.session_timezone')] = $user->timezone;
                    $_SESSION[$app->config->get('auth.session_authenticated')] = true;

//                $my = fopen("/tmp/access.txt","a"); fwrite($my, "Auth via userManagement. Logged User ".$_SESSION['user_id'].", ".$_SESSION['username']."\n"); fclose($my);
                    return true;

                }
                else {
//                    $my = fopen("/tmp/access.txt","a"); fwrite($my, "NO Auth via userManagement. Logged User ".$_SESSION['user_id'].", ".$_SESSION['username']."\n"); fclose($my);
                    return false;
                }


            }
            catch (adLDAPException $e) {
//                $message= $e;
//                print_r($e);
//                $my = fopen("/tmp/access.txt","a"); fwrite($my, $e->getMessage()."\n"); fclose($my);
                return false;
            } catch (Exception $e){
//                $my = fopen("/tmp/access.txt","a"); fwrite($my, $e->getMessage()."\n"); fclose($my);
//                $message= $e;
                return false;
            }
        }
        elseif($user->location_type == "radius")
        {

            $server = $app->container->radiusserver->where('id', '=', $user->location_id)->first();
            $ip_address     = $server->address;
            $port           = $server->port;
            $shared_secret  = $server->shared_key;

            $radius = radius_auth_open();
            define("PALO_ALTO_RADIUS_ID", 25461);
            define('RADIUS_PROXY_STATE', 33);
            define('RADIUS_USER_NAME', 1);
            radius_put_vendor_string($radius, PALO_ALTO_RADIUS_ID, RADIUS_USER_NAME, "expedition-vm");
            radius_add_server($radius, $ip_address, $port, $shared_secret, 5, 3);

            radius_create_request($radius, RADIUS_ACCESS_REQUEST);
            radius_put_attr($radius, RADIUS_USER_NAME, $identifier);
            radius_put_attr($radius, RADIUS_USER_PASSWORD, $password);

            $result = radius_send_request($radius);

            switch ($result) {
                case RADIUS_ACCESS_ACCEPT:
                    // An Access-Accept response to an Access-Request indicating that the RADIUS server authenticated the user successfully.

                    //We did the authentication against a different server. Therefore, the user is not automatically
                    //logged in Sentinel. We need to manually log the user in so that we can carry the user's credentials
                    //through the application
                    $app->container->sentinel->login($user);
                    //Then, we can create a PHP session
                    $_SESSION[$app->config->get('auth.session')] = $user->id;
                    $_SESSION[$app->config->get('auth.session_username')] = $user->email;
                    $_SESSION[$app->config->get('auth.session_timezone')] = $user->timezone;
                    $_SESSION[$app->config->get('auth.session_authenticated')] = true;

//                    $message = 'Welcome!';
                    return true;
                    break;
                case RADIUS_ACCESS_REJECT:
                    // An Access-Reject response to an Access-Request indicating that the RADIUS server could not authenticate the user.
//                    $message = 'Login and password combination are incorrect!';
                    return false;
                    break;
                case RADIUS_ACCESS_CHALLENGE:
                    // An Access-Challenge response to an Access-Request indicating that the RADIUS server requires further information in another Access-Request before authenticating the user.
//                    $message = 'This server requires a Challenge';
                    return false;
                    break;
                default:
//                    $message = 'A RADIUS error has occurred';
                    return false;
                    break;
            }
        }
    }

    else{
//        $message = 'Login and password combination are incorrect!';
        return false;
    }
}