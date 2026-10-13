<?php

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

return [
    'app' => [
        'url' => 'http://172.16.26.130',
        'hash' => [
            'algo' => PASSWORD_BCRYPT,
            'cost' => 5
        ]
    ],

    'error' => [
        'display' => 'On'
    ],
    
    'db' => [
        'driver' => 'mysql',
        'host' => DBServer,
        'name' => 'pandbRBAC',
        'username' => DBUser,
        'password' => DBPass,
        'charset' => 'utf8',
        'collation' => 'utf8_unicode_ci',
        'prefix' => ''
    ],
    
    'auth' => [
        'session'               => 'user_id',
        'remember'              => 'user_r',
        'session_authenticated' => 'authenticated',
        'session_username'      => 'username',
        'session_timezone'      => 'timezone'
    ],
    
    'mail' => [
        'smtp_auth' => true,
        'smtp_secure' => 'tls',
        'host' => '',
        'username' => '',
        'password' => '',
        'port' => '587',
        'html' => true,
        'debuglevel' => 2
    ],
    
    'twig' => [
        'debug' => true
    ],
    
    'csrf' => [
        'key' => 'csrf_token',
        'enabled'=> false,
        'maxTime'=>5000
    ],

    'registration' => [
        'direct_registration' => true   //Activate the user automatically
    ],

    'session' => [
        'timeout'        => 20,
        'checkFreqInSec' => 60,
    ]
    
];