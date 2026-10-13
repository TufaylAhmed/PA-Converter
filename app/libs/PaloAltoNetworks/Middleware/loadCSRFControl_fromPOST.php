<?php
/***
 *
 *          //Control CSRF on some specific POST calls via a second CRF control function. Notice that in some specific cases, the CSRF token is sent via GET
 *           include INC_ROOT . '/libs/PaloAltoNetworks/Middleware/loadCSRFControl_fromPOST.php';
 *           checkCSRF($_GET);
 */
/* CSRF Protection*/
include_once INC_ROOT."/libs/PaloAltoNetworks/Middleware/NoCSRF.php";
function checkCSRF($data)
{
    global $app;
    $maxCsrfTokenTime = (isset($app->config['csrf']['maxTime']))?  $app->config['csrf']['maxTime']: 60*24;
    if (!NoCSRF::check('csrfToken', $data, true, $maxCsrfTokenTime, true)) {
        echo json_encode(['msg' => 'Not a valid CSRF token in the POST', 'success'=> false]);
        exit(-1);
    }
}
