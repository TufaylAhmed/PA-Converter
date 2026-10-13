<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 26/4/16 - 17:48
 */

function logout()
{
    global $app;

    $user = null; //NULL = current user. Otherwise, specify the user
    $app->container->sentinel->logout($user, true);  //Destroy all the sessions from this user.

    unset($_SESSION[$app->config->get('auth.session')]);

//        unset($_SESSION['authenticated']);
//        unset($_SESSION['username']);
//        unset($_SESSION['timezone']);
//    session_destroy();

//    $message = 'You have been logged out.';
//    $app->flash('global', $message);
//    $app->response->redirect($app->urlFor('home'));

    return true;

}