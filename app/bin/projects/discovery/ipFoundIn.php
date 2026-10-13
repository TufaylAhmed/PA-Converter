<?php

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/common/lib-rules.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);


parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project        = $pandb->real_escape_string((string) (isset($_GET['project'])     ? $_GET['project']  : ''));
        $source         = $pandb->real_escape_string((string) (isset($_GET['source'])      ? $_GET['source']   : ''));
        $vsys           = $pandb->real_escape_string((string) (isset($_GET['vsys'])        ? $_GET['vsys']     : ''));
        $vr             = $pandb->real_escape_string((string) (isset($_GET['vr'])          ? $_GET['vr']       : ''));
        $template       = $pandb->real_escape_string((string) (isset($_GET['template'])    ? $_GET['template'] : ''));
        $section        = $pandb->real_escape_string((string) (isset($_GET['section'])     ? $_GET['section'] : ''));
        $ips            = $pandb->real_escape_string((string) (isset($_GET['ips'])         ? $_GET['ips']      : ''));
        $start          = $pandb->real_escape_string((string) (isset($_GET['start'])       ? $_GET['start']    : ''));
        $limit          = $pandb->real_escape_string((string) (isset($_GET['limit'])       ? $_GET['limit']    : ''));

        $connection = selectDatabase($project);

        $ipsArray = explode(",", $ips);
        getMatchingSecurityRules($connection, $source, $vsys, $vr, $template, $project,$ipsArray, $section);
        if($message['code']){
            echo json_encode(["total" => $message['total'], "rows"  => $message['msg'], ]);
        }
        else{
            echo json_encode([ "total" => 0, "rows"  => '',]);
        }
        break;

    case 'POST':
        break;

    case 'PUT':
        $project = $pandb->real_escape_string((string) (isset($_GET['project'])   ? $_GET['project'] : ''));
        $message = send_api_dynThreatreports_calls($project, $data);
        echo json_encode(array('success' => $message['code'], 'jobid' => $message['jobid'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $project = $pandb->real_escape_string((string) (isset($_GET['project'])   ? $_GET['project'] : ''));
        $message = remove_threat_fromlog($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}
