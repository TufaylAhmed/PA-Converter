<?php
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

$authenticationMethod = "userManagement";

include INC_ROOT.'/bin/middleware_sanitizer.php';

global $app;

if($authenticationMethod == "legacy") {
//Comment these if you use the userManager
    require_once '../libs/shared.php';
    require_once '../libs/database.php';
    session_start();

    if (isset($_SESSION['timezone'])){
        date_default_timezone_set($_SESSION['timezone']);
    }

//echo "Dentro de authentication: " .date_default_timezone_get()."\n";

    if (!isset($_SESSION['username'])){
        //header("location: ../index3.php");
        echo json_encode(array("success"=>false, "msg"=>"No valid session. (1)"));
        exit();
    }
    else{
        $user = $_SESSION['username'];

        $getSession = $pandb->query("SELECT id, user, last_session, TIMESTAMPDIFF(hour, last_session, NOW()) AS horas, disable FROM users WHERE user = '$user' ;");
        if ($getSession->num_rows == 1){
            $getEUData = $getSession->fetch_assoc();

            $id = $getEUData['id'];
            $last_login = $getEUData['last_session'];
            $horas = $getEUData['horas'];
            $disable = $getEUData['disable'];

            if($disable == "1"){
                unset($_SESSION['authenticated']);
                unset($_SESSION['username']);
                unset($_SESSION['timezone']);
                session_destroy();
                echo json_encode(array("success"=>false, "msg"=>"No valid session. (2)"));
                exit();
            }

            if($horas >= "1"){
                unset($_SESSION['authenticated']);
                unset($_SESSION['username']);
                unset($_SESSION['timezone']);
                session_destroy();
                echo json_encode(array("success"=>false, "msg"=>"No valid session. (3)"));
                exit();
            }else{
                $pandb->query("UPDATE users SET last_session = NOW() WHERE user = '$user';");
            }

        }
        else{
            echo json_encode(array("success"=>false, "msg"=>"No valid session. (4)"));
            exit();
        }


    }

}

elseif ($authenticationMethod == "userManagement"){
    global $app;
    require_once INC_ROOT.'/userManager/start.php';

    if(defined('CLI')){
        require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
    }
    else{
        require_once INC_ROOT .'/userManager/API/accessControl.php';
    }
    $me = $app->container->sentinel->getUser();
    $accessValid = accessControl("any", ['user.*','*']);

    if(!$accessValid){
//        $my = fopen("access.txt","a"); fwrite($my, "Auth via userManagement. User ".$_SESSION['username']."not valid.\n"); fclose($my);
        unset($_SESSION['authenticated']);
        unset($_SESSION['username']);
        unset($_SESSION['timezone']);
        session_destroy();
        echo json_encode(array("success"=>false, "msg"=>"No valid session. (5)"));
        exit();
    }
    else{
        //renew the session with extra time?
        renewSession(); //This method i in accessControl.php
//        $my = fopen("access.txt","a"); fwrite($my, "Auth via userManagement. User ".$_SESSION['username']."\n"); fclose($my);
    }
}

