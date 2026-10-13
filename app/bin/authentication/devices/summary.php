<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/5/16 - 15:28
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = get_summary();
        if($message['code']) {
            $total = count($message['msg']);
            echo json_encode($message['msg']);
        }
        else{
            echo '
            {
                "text": "Root",
                "expanded": true,
                "children": []
            }';
        }


    case 'POST':
//        $message = register_Device($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
//        $message = update_Device($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
//        $message = delete_Device($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function get_summary(){
    global $pandbRBAC;

    $message['code']=false;
    $message['msg']="";

    $i = 1;
    $structure_panorama = array();

    $getPanoramas=$pandbRBAC->query("SELECT devicename,serial FROM devices WHERE ispanorama=1;");
    if ($getPanoramas->num_rows>0){
        while($data=$getPanoramas->fetch_object()){
            $panorama_children=array();
            $panorama_serial=$data->serial;
            $panorama_devicename=$data->devicename;

            $getChildren=$pandbRBAC->query("SELECT * FROM devices WHERE management='$panorama_serial' ORDER BY devicename;");
            if ($getChildren->num_rows>0){
                while($data2=$getChildren->fetch_object()){
                    $serial=$data2->serial;
                    $panorama_children[]= collect_all_data($serial,$data2,$i,"managed");
                    $i++;
                }

            }

            $structure_panorama[] = [
                'text' => $panorama_devicename,
                'expanded' => true,
                'children' => $panorama_children,
                'leaf' => (count($panorama_children)>0)?false:true,
                'serial' => $panorama_serial,
                'id' => $i,
                'iconCls' => "icon-devices",
                'connected' => 'yes'
            ];
            $i++;


        }
    }

    $getOtherDevices=$pandbRBAC->query("SELECT * FROM devices WHERE management='' AND ispanorama=0;");
    if ($getOtherDevices->num_rows>0){
        while($data3=$getOtherDevices->fetch_object()){

            $structure_panorama[] =collect_all_data($data3->serial,$data3,$i);

            /*$structure_panorama[] = [
                'text' => $data3->devicename,
                'expanded' => false,
                'leaf' => true,
                'serial' => $data3->serial,
                'id' => $i,
                'iconCls' => "icon-device",
                'connected' => 'yes'
            ];*/
            $i++;
        }
    }

    $structure =[

        'expanded' => true,
        'children' => $structure_panorama
        //'visible'  => true
    ];

    return ['code'=>true, 'msg'=>$structure];

}

function collect_all_data($serial,$data2,$i, string $isManaged=""){
    global $pandbRBAC;

    $support=[];

    $tp="<img src='/resources/images/services/threat-prevention-gray.svg' width='25' height='25' alt='Threat Prevention License'>";
    $wf="<img src='/resources/images/services/wildfire-gray.svg' width='25' height='25' alt='Wildfire License'>";
    $dns="<img src='/resources/images/services/dns-gray.svg' width='25' height='25' alt='DNS Security License'>";
    $uf="<img src='/resources/images/services/url-filtering-gray.svg' width='25' height='25' alt='URL Filtering License'>";
    $af="<img src='/resources/images/services/autofocus-gray.svg' width='25' height='25' alt='AutoFocus License'>";
    $ls="<img src='/resources/images/services/logging-service-gray.svg' width='25' height='25' alt='Logging Service License'>";
    $gp="<img src='/resources/images/services/globalprotect-gray.svg' width='25' height='25' alt='Global Protect Licenses'>";
    $dm='';
    $premium="<font color='gray'><b>[PS]</b>&nbsp</font>";

    $getLicenses=$pandbRBAC->query("SELECT * FROM licenses WHERE serial='$serial'");
    if ($getLicenses->num_rows>0){
        $element="";


        while($data4=$getLicenses->fetch_object()){
            switch ($data4->feature){
                case "Threat Prevention":
                    if ($data4->expired=="no"){
                        $tp="<img src='/resources/images/services/threat-prevention-green.svg' width='25' height='25'>";
                    }
                    else{
                        $tp="<img src='/resources/images/services/threat-prevention-red.svg' width='25' height='25'>";
                    }
                    break;

                case "PAN-DB URL Filtering":
                case "BrightCloud URL Filtering":
                    if ($data4->expired=="no"){
                        $uf="<img src='/resources/images/services/url-filtering-green.svg' width='25' height='25'>";
                    }
                    else{
                        $uf="<img src='/resources/images/services/url-filtering-red.svg' width='25' height='25'>";
                    }
                    break;

                case "DNS Security":
                    if ($data4->expired=="no"){
                        $dns="<img src='/resources/images/services/dns-green.svg' width='25' height='25'>";
                    }
                    else{
                        $dns="<img src='/resources/images/services/dns-red.svg' width='25' height='25'>";
                    }
                    break;

                case "AutoFocus Device License":
                    if ($data4->expired=="no"){
                        $af="<img src='/resources/images/services/autofocus-green.svg' width='25' height='25'>";
                    }
                    else{
                        $af="<img src='/resources/images/services/autofocus-red.svg' width='25' height='25'>";
                    }
                    break;

                case "WildFire License":
                    if ($data4->expired=="no"){
                        $wf="<img src='/resources/images/services/wildfire-green.svg' width='25' height='25'>";
                    }
                    else{
                        $wf="<img src='/resources/images/services/wildfire-red.svg' width='25' height='25'>";
                    }
                    break;

                case "Logging Service":
                    if ($data4->expired=="no"){
                        $ls="<img src='/resources/images/services/logging-service-green.svg' width='25' height='25'>";
                    }
                    else{
                        $ls="<img src='/resources/images/services/logging-service-red.svg' width='25' height='25'>";
                    }
                    break;

                case "GlobalProtect Gateway":
                case "GlobalProtect Portal":
                    if ($data4->expired=="no"){
                        $gp="<img src='/resources/images/services/globalprotect-green.svg' width='25' height='25'>";
                    }
                    else{
                        $gp="<img src='/resources/images/services/globalprotect-red.svg' width='25' height='25'>";
                    }
                    break;

                case "Device Management License":
                    $dm="<font size:12px>Device Management</font>";
                    break;

                case "Premium Partner":
                case "Premium":
                case "Standard":
                case "Software warranty":
                case "4-Hour Premium":
                    if ($data4->expired=="yes"){
                        $support[]="<font color=red>".$data4->feature."<br>".$data4->expires."</font>";
                    }
                    else{
                        $support[]=$data4->feature."<br>".$data4->expires;
                    }

                    break;
                case "PA-VM":
                    $support[]="PA-VM AuthCode:".$data4->authcode."<br>Issued:".$data4->issued;
                    break;
            }
        }
        $element=$tp.'&nbsp;'.$wf.'&nbsp;'.$dns.'&nbsp;'.$uf.'&nbsp;'.$af.'&nbsp;'.$ls.'&nbsp;'.$gp.'&nbsp;'.$dm;
    }
    else{
        //$element=$tp."<font color='gray'><b>[WF]</b>&nbsp</font><font color='gray'><b>[DNS]</b>&nbsp</font><font color='gray'><b>[UF]</b>&nbsp</font><font color='gray'><b>[AF]</b>&nbsp</font><font color='gray'><b>[LS]</b>&nbsp</font><font color='gray'><b>[GP]</b>&nbsp</font>";
        $element=$tp.'&nbsp;'.$wf.'&nbsp;'.$dns.'&nbsp;'.$uf.'&nbsp;'.$af.'&nbsp;'.$ls.'&nbsp;'.$gp.'&nbsp;'.$dm;
    }

    // Old Apps
    $getlic=$pandbRBAC->query("SELECT devicename,serial,appversion,appreleasedate FROM devices WHERE (appreleasedate < NOW() - INTERVAL 30 DAY) AND ( (appversion!=0) AND (appversion!='') ) AND connected='yes' AND serial='$data2->serial';");
    if ($getlic->num_rows==1){
        $getlicData=$getlic->fetch_object();
        if ($getlicData->appreleasedate=="0000-00-00 00:00:00"){
            $appversion[]="[".$getlicData->appversion. "] <font color=\"#cd383f\">Unknown</font>";
        }
        else{
            $appversion[]="[".$getlicData->appversion. "] <font color=\"#cd383f\"> <i>".$data2->appreleasedate."</i></font>";
        }

    }
    else{
        if ($data2->appreleasedate=="0000-00-00 00:00:00"){
            $appversion[]="[".$data2->appversion. "] <font color=\"#cd383f\">Unknown</font>";
        }
        else{
            $appversion[]="[".$data2->appversion. "] <font color=\"#5fba7d\"> ".$data2->appreleasedate."</font>";
        }

    }

    //Old Threats
    if ($data2->threatversion=="0"){
        $appversion[]="<font color=\"#cd383f\">[No Threats]</font>";
    }
    else{
        $getlic=$pandbRBAC->query("SELECT devicename,serial,threatversion,threatreleasedate FROM devices WHERE (threatreleasedate < NOW() - INTERVAL 30 DAY) AND ( (threatversion!='0') AND (threatversion!='') ) AND connected='yes' AND serial='$data2->serial';");
        if ($getlic->num_rows==1){
            $getlicData=$getlic->fetch_object();
            if ($getlicData->threatreleasedate=="0000-00-00 00:00:00"){
                $appversion[]="[".$getlicData->threatversion. "] <font color=\"#cd383f\">Unknown</font>";
            }
            else{
                $appversion[]="[".$getlicData->threatversion. "] <font color=\"#cd383f\"> <i>".$getlicData->threatreleasedate."</i></font>";
            }
        }
        else{
            if ($data2->threatreleasedate=="0000-00-00 00:00:00"){
                $appversion[]="[".$data2->threatversion. "] <font color=\"#cd383f\">Unknown</font>";
            }
            else{
                $appversion[]="[".$data2->threatversion. "] <font color=\"#5fba7d\"> ".$data2->threatreleasedate."</font>";
            }
        }
    }

    if($isManaged == "managed") {
        if ($data2->connected == "yes") {
            $deviceName = '<font color="#5fba7d"><i class="fa fa-circle" aria-hidden="true"></i></font>&nbsp;' . $data2->devicename . ' (Connected)';
        } else {
            $deviceName = '<font color="#cd383f"><i class="fa fa-circle" aria-hidden="true"></i></font>&nbsp;' . $data2->devicename . ' (Disconnected)';
        }
    }
    else{
        $deviceName = $data2->devicename;
    }


    return [
        'text' => $deviceName,
        'leaf' => true,
        'serial' => $data2->serial,
        'id' => $i,
        'element' => $element,
        'iconCls' => "icon-device",
        'appversion' => implode("<br>",$appversion),
        'support' => implode("<br>",$support),
        'connected' => ($data2->connected == "no")?"no":"yes"
    ];
}

function getMyChildren(array $vsysTable, array $vsysNames, int $id):array{
    $children = array();
    foreach ($vsysTable[$id] as $child) {
        $myChildren = getMyChildren($vsysTable, $vsysNames, $child);
        if(count($myChildren)>0) {
            $children[] = [
                'text' => $vsysNames[$child],
                'expanded' => true,
                'children' => $myChildren,
                'visible'  => true,
                'level'     => 'gray'
            ];
        }
        else{
            $children[] = [
                'leaf' => true,
                'text' => $vsysNames[$child],
                'visible'  => true,
                "cls"=> "icon-blue",
            ];
        }
    }

    return $children;
}