<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 27/4/16 - 16:20
 */

use Cartalyst\Sentinel\Native\Facades\Sentinel;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

function register(ARRAY $data)
//function register(STRING $email, STRING $first_name, STRING $last_name, $password, $passwordConfirm,$location,$role ,$timezone )
{
    global $app;

    if(!accessControl("any", ['user.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have user creation rights';
        return $message;
    }

    $request = $app->request;

    $server_location = $data['location'];
    $server = explode(".", $server_location);
    $is_external = ($server[0] != "" && $server[0] != "local") ? true : false;


    /**
     * @var \PaloAltoNetworks\Validation\UserValidator $v
     */
    $v = $app->userValidation;
    //Check unique user
    $v->validate([
        'email' => [$data['email'], 'required|uniqueEmail('.$data['id'].')'],
    ]);

    if (!$v->passes()){
//        $message = json_encode(array("success" => false, "msg" => "This user identified is already taken."));
        $message['code'] = false;
        $message['msg'] =  "This user identified is already taken.";
        return $message;
    }

    if ($is_external) {
        $v->validate([
            'email'         => [$data['email'],                 'required|uniqueEmail('.$data['id'].')|xssSave'],
            'last_name'     => [$data['last_name'],             'required|xssSave'],
            'first_name'    => [$data['first_name'],            'required|xssSave'],
            'timezone'      => [$data['timezone'],              'required|xssSave'],
            'location'      => [$data['location'],              'required|locationExists'],
            'role'          => [$data['role'],                  'required|roleExists'],
        ]);
    }
    else {
        $v->validate([
            'email'             => [$data['email'],             'required|uniqueEmail('.$data['id'].')|xssSave'],
            'last_name'         => [$data['last_name'],         'required|xssSave'],
            'first_name'        => [$data['first_name'],        'required|xssSave'],
            'timezone'          => [$data['timezone'],          'required|xssSave'],
            'location'          => [$data['location'],          'required|locationExists'],
            'password'          => [$data['password'],          'required|min(10)'],
            'password_confirm'  => [$data['password_confirm'],  'required|matches(password)'],
            'role'              => [$data['role'],              'required|roleExists'],
        ]);
    }

    if ($v->passes()) {
        $api_key    = $app->randomlib->generateString(128);  //Not a valid password, but Sentinel::register requires a password to create a user.
        if ($is_external) {
            $random_password = $app->randomlib->generateString(128);  //Not a valid password, but Sentinel::register requires a password to create a user.

            $credentials = [
                'email'         => $data['email'],
                'password'      => $random_password,
                'first_name'    => $data['first_name'],
                'last_name'     => $data['last_name'],
                'location_id'   => $server[1],
                'location_type' => $server[0],
                'timezone'      => $data['timezone'],
                'active'        => 1,
                'api_key'       => $api_key
            ];
        }
        else {
            $credentials = [
                'email'         => $data['email'],
                'password'      => $data['password'],
                'first_name'    => $data['first_name'],
                'last_name'     => $data['last_name'],
                'location_id'   => 0,
                'location_type' => 'local',
                'timezone'      => $data['timezone'],
                'active'        => 1,
                'api_key'       => $api_key
            ];
        }

        //Create an entry in the Database with the new User
        $automatic = $app->config->get('registration.direct_registration');
        $user = Sentinel::register($credentials, $automatic);

        $role = $app->container->sentinel->findRoleBySlug($data['role']);
        $role->users()->attach($user);

        if (!$automatic) {
            //Generate a key for validation
            $activation = (new Activation)->create($user);

            $app->mail->send('email/auth/registered.php', ['user' => $user, 'identifier' => $activation->code], function ($message) use ($user) {
                $message->to($user->email);
                $message->subject('Registered to the Migration Tool');
            });
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = "User registered correctly.";
        return $message;
    }
    $message['code'] = false;
    $message['msg'] = array_merge(["The following errors have ocurred:"],$v->errors()->all());
    return $message;
}