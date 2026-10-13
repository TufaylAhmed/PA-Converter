<?php

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

//include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

require_once INC_ROOT.'/libs/shared.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
    case 'POST':
    case 'PUT':
        echo json_encode(getLoggedInUsers());
        break;

    case 'DELETE':
        $message = disconnectUser($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function getLoggedInUsers()
{
    global $app;
    $connected = [];
    $query = "SELECT users.id, auditlogs.task, auditlogs.datetime, auditlogs.obj_type as email, if(task='Login' || task='Renew Session', timediff(now(), datetime), '0') as elapsed, if(task='Login' || task='Renew Session', TIME_TO_SEC(timediff(now(), datetime))/60, '0') as minutes 
              FROM users, 
	               (SELECT MAX(id) as lastReport, obj_id FROM auditlogs WHERE type='login' GROUP BY obj_id, obj_table) logs2,
                   auditlogs
              WHERE users.id=auditlogs.obj_id AND logs2.lastReport = auditlogs.id ORDER BY task";
    $pandbRBAC = selectDatabase("pandbRBAC");

    $user = $app->container->sentinel->getUser();
    $loggedUser = $app->container->sentinel->check();
    //print_r($user);

    $results = $pandbRBAC->query($query);

    if($results->num_rows>0){
        while($data = $results->fetch_assoc()){
            if($data['task'] == 'Login' || $data['task'] == 'Renew Session'){
                if($user->id == $data['id']){

                    $data['minutes'] = -1;  //Indicator that this is me
                }
                $connected[] = [
                    'id'        => $data['id'],
                    'status'    => $data['minutes'],
                    'email'     => $data['email'],
                    'last_login'=> $data['datetime'],
                    'elapsed'   => $data['elapsed'],
                ];
            }
        }
    }

    return ['users' => $connected];

}

function disconnectUser($params){
    global $app;

    $user = $app->container->sentinel->findUserById($params['id']);
    if ($app->container->sentinel->logout($user)){
        add_audit_log("ok",
            "Logout",
            "User: \"".$user->email."\" logged out at: ".date(DATE_RFC2822),
            "",
            "login",
            $user->email,
            $user->id,
            'users');
        return [
            'code' => 0,
            'msg'   => "User ".$user->email." session terminated"
        ];
    }

    return [
      'code' => -1,
      'msg'  => 'The user does not exist'
    ];
}
