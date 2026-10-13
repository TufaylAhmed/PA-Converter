<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/6/16 - 12:33
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/userManager/API/accessControl.php';

require_once INC_ROOT.'/libs/settings/ML_Settings.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_mlsettings($data);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'settings' => $message['msg']));
        }
        else{
            echo '{"total":"0","settings":[]}';
        }
        break;

    case 'POST':
        $message = register_mlsettings($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':

        break;

    case 'DELETE':
        $message = delete_object($data);
        echo json_encode(array('success' => check_sanitize($message['code']), 'msg' => check_sanitize($message['msg'])));
        break;

    default:
        break;
}

function list_mlsettings($params){
    global $pandbRBAC;
    $mlSettings = new ML_Settings($pandbRBAC);
    return $mlSettings->get();
}

function register_mlsettings($params){
    global $pandbRBAC;

    if(!accessControl("any", ['expedition.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have Expedition admin rights';
        return $message;
    }

    $mlSettings = new ML_Settings($pandbRBAC);
    return $mlSettings->set($params);
}

/**
 * @desc    Do a DELETE request with cURL
 *
 * @param   string $path   path that goes after the URL fx. "/user/login"
 * @param   array  $json   If you need to send some json with your request. For me delete requests are always blank
 * @return  Obj    $result HTTP response from REST interface in JSON decoded.
 */
function curl_del($path, $json='')
{
    $url = $path;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,$url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    $result = curl_exec($ch);
    $result = json_decode($result);
    curl_close($ch);

    return $result;
}

function delete_object($params){
    global $pandbRBAC;

    if(!accessControl("any", ['expedition.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to modify Expedition settings';
        return $message;
    }

    $fileName = '';
    if(isset($params['parquet'])){
        $fileName = '/'.$params['parquet'].'.parquet';
    }
    else{
        $message = [
            'code'  => false,
            'msg'   => 'No file provided'
        ];

        return $message;
    }

    $mlSettings = new ML_Settings($pandbRBAC);
    $message = $mlSettings->get();
    $mlParams_arr = $message['msg'];
    if(count($mlParams_arr)>0){
        $ExpeditionML = $mlParams_arr[0]['server'];
        $parquetPath = $mlParams_arr[0]['parquetPath'];
    }
    else{
        $ExpeditionML = $_SERVER['SERVER_ADDR'];
        $parquetPath = '/tmp';
    }

    $params = [
        'path' => $parquetPath.$fileName
        ];

    //$url = "https://$ExpeditionML/API/deleteParquet.php";
    //$result = curl_del($url, json_encode($file));
    $result = deleteFiles($params);

    if(isset($result['code']) && $result['code']==true) {
        // Delete the list of processed files
        $query = "DELETE FROM device_logs";
        $pandbRBAC->query($query);

        $query = "DELETE FROM device_logsPerDay";
        $pandbRBAC->query($query);

        $query = "DELETE FROM processedLogs";
        $pandbRBAC->query($query);

        $message = [
            'code'  => true,
            'msg'   => $result->msg
        ];
    }
    else{
        $message = [
            'code'  => isset($result->code)? $result->code:false,
            'msg'   => isset($result->msg)?$result->msg:'Problems deleting file'
        ];
    }


    return $message;
}

function deleteFiles(ARRAY $params=null){

    if(!(isset($params) && isset($params['path']))){
        $message = [
            'code'    => false,
            'msg'   => 'path not defined',
        ];
    }
    else {
        if(!(file_exists($params['path']) && is_dir($params['path']))){

            $message = [
                'code' => true,
                'msg' => 'Given path does not exist. Nothing to delete.'
            ];
        }
        else
        {

            $message = [
                'code' => true,
                'msg' => 'Given path is not valid. Nothing to delete.'
            ];

            // Check the parquet defined file
            global $pandbRBAC;
            $mlSettings = new ML_Settings($pandbRBAC);
            $message = $mlSettings->get();
            $mlParams_arr = $message['msg'];
            if(count($mlParams_arr)>0) {
                $parquetPath = $mlParams_arr[0]['parquetPath'];
                $parquetPath .= "/connections.parquet";
                $dir = $params['path'];
                if ($parquetPath == $dir) {
                    $it = new RecursiveDirectoryIterator($parquetPath, RecursiveDirectoryIterator::SKIP_DOTS);
                    $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                    foreach ($files as $file) {
                        if ($file->isDir()) {
                            rmdir($file->getRealPath());
                        } else {
                            unlink($file->getRealPath());
                        }
                    }
                    rmdir($dir);

                    $message = [
                        'code' => true,
                        'msg' => $params['path'] . ' deleted'
                    ];
                }else{
                    $message = [
                        'code' => true,
                        'msg' => 'Given path is not the defined one. Nothing to delete.'
                    ];
                }
            }
        }
    }

    return $message;
}

