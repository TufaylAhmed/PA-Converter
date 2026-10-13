<?php
/**
 * Created by PhpStorm.
 * User: aestevez
 * Date: 9/22/16
 * Time: 1:54 PM
 */

$user_id = $api_key = $project = "";

include INC_ROOT.'/bin/middleware_sanitizer.php';



if(isset($argv)) {
//    $myFile = fopen("/tmp/file","a");
//    fwrite($myFile, $argv[1]);
    $decodedString = base64_decode($argv[1]);
    $clean = str_replace(array("{", "}"), "", $decodedString);
    $argv = explode(",", $clean);

    foreach ($argv as $arg) {
        $tupla = explode(':', $arg);
        $tupla[0] = str_replace('"', '', $tupla[0]);
        $tupla[1] = isset($tupla[1])?str_replace('"', '', $tupla[1]):'';
        switch ($tupla[0]) {
            case "api_key":
                $api_key = $tupla[1];
                break;
            case "sender":
                $user_id = $tupla[1];
                break;
            case "project":
                $project = $tupla[1];
                if (!is_dir("/home/userSpace/projects/".$project)) {
                    echo "Project not valid";
                    exit;
                }
                break;
            case "vendor":
                $vendor = $tupla[1];
                break;
            case "action":
                $action = $tupla[1];
                break;
            case "asPanorama":
                $asPanorama = (boolean) $tupla[1];
                break;
            case "signatureid":
                $signatureid = $tupla[1];
                break;
            case "username":
                $username = $tupla[1];
                break;
            case "password":
                $password = $tupla[1];
                break;
            //case "afa_hostname":
            //    $afa_hostname = $tupla[1];
            //    break;
            case "jobid":
                $jobid = $tupla[1];
                break;
            case "noDNAT":
                $noDNAT = (boolean) $tupla[1];
//                echo "This field is given with value $noDNAT\n";
                break;
            case "checkpoint_name":
                $checkpointName = $tupla[1];
                break;
            case "api_call":
                $api_call = $tupla[1];
                break;
            case "groupbydescription":
                $groupbydescription = $tupla[1];
                break;
            default:
                break;
        }
    }
}

//Log in this script that was executed via CLI as the user that made the call via the GUI
//if(!isset($userid)){
//    $userid=0;
//}
$credentials = [
    'email' => $user_id,
    'api_key' => $api_key
];

if($user = $app->user->where('email',$user_id)->where('api_key',$api_key)->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
//if($user = $app->container->sentinel->findByCredentials($credentials)) {
    $app->sentinel->login($user);
}





function checkFiles2Import($filename,$vendor=""){

    $forbidden=[
        ".",
        "..",
        "parsers.txt",
        "Backups",
        "Pcaps",
        "Reports",
        "XGS",
        "CPviewer.html",
        "iron-skillet_vars.txt",
        "toImport",
    ];

    if (in_array($filename,$forbidden)){
        return false;
    }

    if (preg_match("/^MT-/", $filename)){
        return false;
    }

    if (preg_match("/^\._/", $filename)){
        return false;
    }

    if ($vendor!="Paloalto Networks"){
        if (preg_match("/\.dat$/", $filename)){
            return false;
        }
    }

    return true;

}