<?php

/* CSRF Protection*/
include_once INC_ROOT."/libs/PaloAltoNetworks/Middleware/NoCSRF.php";
$maxCsrfTokenTime = (isset($app->config['csrf']['maxTime']))?  $app->config['csrf']['maxTime']: 60*24;
if(!NoCSRF::check( 'csrfToken', apache_request_headers(), true,$maxCsrfTokenTime,true)){
    echo json_encode(['msg'=>'Not a valid CSRF token', 'success'=> false]);   exit(-1);
}
