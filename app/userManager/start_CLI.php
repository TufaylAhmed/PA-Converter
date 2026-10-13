<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 2/6/16 - 17:56
 */

use Slim\Slim;
//use Slim\Views\Twig;
//use Slim\Views\TwigExtension;

use Noodlehaus\Config;

use RandomLib\Factory as RandomLib;

use Cartalyst\Sentinel\Native\Facades\Sentinel;
use Cartalyst\Sentinel\Native\SentinelBootstrapper;

//use PaloAltoNetworks\User\User;
//use PaloAltoNetworks\Role\Role;
use PaloAltoNetworks\Sentinel\User\User;
use PaloAltoNetworks\Sentinel\Role\Role;
//use PaloAltoNetworks\Server\LDAPServer;
//use PaloAltoNetworks\Server\RadiusServer;
use PaloAltoNetworks\Sentinel\Devices\Device;
use PaloAltoNetworks\Sentinel\Projects\Project;
use PaloAltoNetworks\Sentinel\ApiKeys\ApiKey;
use PaloAltoNetworks\Sentinel\AccessKeys\AccessKey;
use PaloAltoNetworks\Sentinel\FWLogs\FWLog;
use PaloAltoNetworks\Sentinel\UserSettingsInProject\UserSettingsInProject;

use PaloAltoNetworks\MTJobs\Jobs\Job;
use PaloAltoNetworks\MTJobs\Tasks\Task;
use PaloAltoNetworks\MTJobs\PeriodicTasks\PeriodicTask;

//use PaloAltoNetworks\Mail\Mailer;

//use PaloAltoNetworks\Validation\UserValidator;
//use PaloAltoNetworks\Validation\RoleValidator;
//use PaloAltoNetworks\Validation\LDAPServerValidator;
//use PaloAltoNetworks\Validation\RadiusServerValidator;
//use PaloAltoNetworks\Validation\DeviceValidator;
//use PaloAltoNetworks\Validation\ProjectValidator;
//use PaloAltoNetworks\Validation\ApiKeyValidator;

use PaloAltoNetworks\Helpers\Hash;

//use PaloAltoNetworks\Middleware\BeforeMiddleware;
//use PaloAltoNetworks\Middleware\CsrfMiddleware;

session_cache_limiter(false);
session_start();

ini_set('display_errors','On');

define('CLI', true);

// Include the composer autoload file
require INC_ROOT.'/libs/vendor/autoload.php';

$app = new Slim([
    'mode' => file_get_contents(INC_ROOT .'/mode.php'),
//    'view' => new Twig(),
    'templates.path' => INC_ROOT . '/userManager/views'
]);


// Load the server mode. Uses the Noodlehaus\Config to allow multiple configuration options
$app->configureMode($app->config('mode'), function() use ($app){
    $app->config = Config::load(INC_ROOT . "/config/{$app->mode}.php");
});

//$app->add(new BeforeMiddleware());
//$app->add(new CsrfMiddleware());

require INC_ROOT.'/libs/database_user.php';
//require INC_ROOT.'/userManager/filters.php'; //We should be able to comment out this line
//require INC_ROOT.'/userManager/routes.php';  //We should be able to comment out this line

$app->auth = false;
$app->roles = array();

//Data Models used
$app->container->set('user', function() {
    return new User;
});
$app->container->set('role', function() {
    return new Role;
});
//$app->container->set('ldapserver', function() {
//    return new LDAPServer;
//});
//$app->container->set('radiusserver', function() {
//    return new RadiusServer;
//});
$app->container->set('device', function() {
    return new Device;
});
$app->container->set('project', function() {
    return new Project;
});
$app->container->set('apikey', function() {
    return new ApiKey;
});
$app->container->set('accessKey', function() {
    return new AccessKey;
});
$app->container->set('userSettings', function() {
    return new UserSettingsInProject;
});

$app->container->set('devicelog', function() {
    return new FWLog;
});
$app->container->set('job', function() {
    return new Job;
});
$app->container->set('task', function() {
    return new Task;
});
$app->container->set('periodicTask', function() {
    return new PeriodicTask;
});

//Validators for Registration and forms
//$app->container->singleton('userValidation', function() use ($app){
//    return new UserValidator($app->user, $app->hash, $app->auth);
//});
//$app->container->singleton('roleValidation', function() use ($app){
//    return new RoleValidator($app->role);
//});
//$app->container->singleton('serverValidation', function() use ($app){
//    return new LDAPServerValidator($app->ldapserver);
//});
//$app->container->singleton('serverRadiusValidation', function() use ($app){
//    return new RadiusServerValidator($app->radiusserver);
//});
//$app->container->singleton('deviceValidation', function () use ($app) {
//    return new DeviceValidator($app->device);
//});
//$app->container->singleton('projectValidation', function () use ($app) {
//    return new ProjectValidator($app->project);
//});
//$app->container->singleton('apikeyValidation', function () use ($app) {
//    return new ApiKeyValidator($app->apikey);
//});

//Libraries for security.
// Hash generates secure hash strings.
// randomLib generates complex random values, with higher security messures than default random method.
$app->container->singleton('hash', function() use ($app){
    return new Hash($app->config);
});
$app->container->singleton('randomlib', function() {
    $factory = new RandomLib;
    return $factory->getMediumStrengthGenerator();
});

//$app->container->singleton('mail', function() use ($app){
//    $mailer = new PHPMailer;
//
//    $mailer->isSMTP();
//    $mailer->SMTPDebug  = $app->config->get('mail.debuglevel');
//    $mailer->Host       = $app->config->get('mail.host');
//    $mailer->SMTPAuth   = $app->config->get('mail.smtp_auth');
//    $mailer->SMTPSecure = $app->config->get('mail.smtp_secure');
//    $mailer->Port       = $app->config->get('mail.port');
//    $mailer->Username   = $app->config->get('mail.username');
//    $mailer->Password   = $app->config->get('mail.password');
//
//    $mailer->isHTML($app->config->get('mail.html'));
//
//    //Return mailer object
//    return new Mailer($app->view, $mailer);
//});

//Load Sentinel for User validation with our specific configurations
$sentinelConfigFile = INC_ROOT.'/libs/PaloAltoNetworks/Sentinel/config/config.php';
$sentinelConfig = new SentinelBootstrapper($sentinelConfigFile);
$app->container->sentinel = (new Sentinel($sentinelConfig))->getSentinel();


//$view = $app-> view();
//
//$view->parserOptions = [
//    'debug' => $app->config->get('tiwg.debug')
//];

//$view->parserExtensions = [
//    new TwigExtension
//];

