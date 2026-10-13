<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 21/6/16 - 11:15
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';

include_once INC_ROOT.'/bin/authentication/devices/device_functions.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $mode       = (string)(isset($_GET['mode'])         ? $_GET['mode']         : '');
    $format     = (string)(isset($_GET['format'])       ? $_GET['format']       : 'json');
    $deviceSerial = (string)(isset($_GET['serial'])     ? $_GET['serial']   : '');

    $mode = $pandb->real_escape_string($mode);
    $format = $pandb->real_escape_string($format);
    $deviceSerial = $pandb->real_escape_string($deviceSerial);
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = getContents($deviceSerial);
        switch ($format){
            case "xml":
                $xml_data = $xml = new SimpleXMLElement('<?xml version="1.0"?><data></data>');
                array_to_xml( $message['msg'], $xml_data );
                echo $xml_data->asXML();
                break;

            default:
                if($message['code'] == 2) {
                    echo json_encode(array('total' => count($message['msg']), 'state' => 'updating', 'contents' => $message['msg']));
                }elseif ($message['code'] == 1){
                    echo json_encode(array('total' => count($message['msg']), 'state' => 'completed', 'contents' => $message['msg']));
                }
                else{
                    echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
                }
                break;
        }
        break;

    case 'POST':
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}


function array_to_xml( $data, &$xml_data ) {
    foreach( $data as $key => $value ) {
        if( is_array($value) ) {
            if( is_numeric($key) ){
                $key = 'item'.$key; //dealing with <0/>..<n/> issues
            }
            $subnode = $xml_data->addChild($key);
            array_to_xml($value, $subnode);
        } else {
            $xml_data->addChild("$key",htmlspecialchars("$value"));
        }
    }
}

