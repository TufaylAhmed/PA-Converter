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

require_once INC_ROOT.'/bin/authentication/devices/monitor.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl_fromPOST.php';

checkCSRF($_GET);

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);
?>


<!DOCTYPE html>
<html>
<head>
    <title>Expedition - Devices Overview</title>
    <meta charset="UTF-8">
<!-- Styles -->

   <!-- <script src="js/Chart.min.js"></script> -->
   <!--  <script src="js/utils.js"></script> -->
    <style>
        canvas {
            -moz-user-select: none;
            -webkit-user-select: none;
            -ms-user-select: none;
        }
    </style>

     <!--===============================================================================================-->
    <link rel="stylesheet" type="text/css" href="/bin/authentication/devices/reportDevices/css/util.css">
    <link rel="stylesheet" type="text/css" href="/bin/authentication/devices/reportDevices/css/main.css">
    <!--===============================================================================================-->
    <link rel="stylesheet" href="/resources/font-awesome/css/font-awesome.min.css">
    <link rel="stylesheet" href="/resources/css/MT3.css">

    <style>
        thead {
            background-image: url("/resources/images/report-devices/bg.png");
            background-position: 50% 50%;
            background-repeat: repeat;
            color:white;
        }


    </style>

</head>

<body>
<div class="limiter">
    <div class="container-table100">
        <div class="wrap-table100">
            <div class="table100">

                <table width="100%"  border="0" >
                    <thead>
                        <tr class="table100-head">
                            <td height="50" vlaign=middle align=center width="144" style="padding:13px;">
                                <svg version="1.1" x="0px" y="0px" viewBox="0 0 124 43" style="enable-background:new 0 0 124 43;" xml:space="preserve" fill="white">
                                        <g transform="translate(-151.000000, -38.000000)">
                                            <path d="M214,79.8l1.1,0c0,0,0-4,0-4.5c0.3,0.4,3.6,4.5,3.6,4.5l1.1,0l0-6.1l-1.1,0c0,0,0,4,0,4.5
                                                c-0.3-0.4-3.6-4.5-3.6-4.5l-1.1,0L214,79.8z"></path>
                                            <path d="M221.2,79.9l4.9,0v-1c0,0-3.7,0-3.9,0l0-1.7l3.7,0l0-1l-3.7,0c0-0.2,0-1.3,0-1.5
                                                c0.2,0,3.8,0,3.8,0l0-1l-4.8,0L221.2,79.9z"></path>
                                            <path d="M227.1,74.7c0,0,2,0,2.2,0c0,0.2,0,5.1,0,5.1l1.1,0c0,0,0-4.9,0-5.1c0.2,0,2.2,0,2.2,0v-1l-5.4,0
                                                V74.7z"></path>
                                            <path d="M235.3,79.9l1.1,0c0,0,1.4-4.2,1.5-4.7c0.2,0.5,1.5,4.7,1.5,4.7l1.1,0l2-6.1l-1.1,0
                                                c0,0-1.3,4.1-1.4,4.6c-0.2-0.5-1.5-4.6-1.5-4.6l-1.2,0c0,0-1.3,4.1-1.5,4.6c-0.2-0.5-1.4-4.6-1.4-4.6l-1.1,0L235.3,79.9z"></path>
                                            <path d="M246.2,73.6c-1,0-1.9,0.3-2.4,0.9c-0.6,0.6-0.9,1.4-0.9,2.3c0,0.9,0.3,1.7,0.9,2.3
                                                c0.6,0.6,1.4,0.9,2.4,0.9c2.4,0,3.3-1.7,3.3-3.2C249.5,75.3,248.7,73.6,246.2,73.6 M244.6,78.4c-0.4-0.4-0.6-0.9-0.6-1.6l0,0
                                                c0-0.7,0.2-1.2,0.6-1.6c0.4-0.4,1-0.6,1.7-0.6l0,0c1.4,0,2.2,0.9,2.2,2.2c0,1.4-0.9,2.2-2.2,2.2C245.5,79.1,245,78.8,244.6,78.4"></path>
                                            <path d="M250.7,79.9l1.1,0c0,0,0-2.3,0-2.5l2.1,0c0.6,0,1,0.2,1,1.3l0,0.2c0,0.6,0,0.8,0.2,1l0,0l1.2,0
                                                l-0.1-0.2c-0.2-0.2-0.2-0.5-0.2-1.5c0-0.7-0.3-1.1-0.7-1.3c0.5-0.3,0.8-0.8,0.8-1.4c0-0.8-0.4-1.7-1.7-1.7l-3.7,0L250.7,79.9z
                                                 M251.8,74.7c0.2,0,2.3,0,2.3,0c0.6,0,0.9,0.3,0.9,0.8c0,0.3-0.1,0.8-0.9,0.8c0,0-2.1,0-2.3,0C251.8,76.2,251.8,74.9,251.8,74.7
                                                L251.8,74.7z"></path>
                                            <path d="M257.6,79.9l1.1,0c0,0,0-1.9,0-2c0.1-0.1,0.8-0.7,0.9-0.8c0.1,0.2,2.3,2.8,2.3,2.8l1.4,0
                                                c0,0-2.8-3.4-3-3.6c0.1-0.1,2.9-2.6,2.9-2.6l-1.5,0c0,0-2.8,2.5-3.1,2.8l0-2.8l-1.1,0L257.6,79.9z"></path>
                                            <path d="M264.2,75.5c0,1.3,1.4,1.6,1.8,1.7l1.3,0.2c0.7,0.1,1,0.3,1,0.8c0,0.2-0.1,0.4-0.2,0.5
                                                c-0.2,0.2-0.7,0.4-1.3,0.4c-0.6,0-1.7-0.2-1.8-1.2l0-0.1l-1.1,0l0,0.1c0,0.6,0.2,1.1,0.5,1.5c0.6,0.6,1.5,0.7,2.2,0.7
                                                c0.5,0,1.5-0.1,2.1-0.7c0.3-0.3,0.5-0.8,0.5-1.3c0-1.3-1.4-1.5-1.8-1.6c0,0-1.4-0.2-1.4-0.2c-0.8-0.1-0.9-0.5-0.9-0.7
                                                c0-0.2,0.1-0.4,0.2-0.5c0.2-0.2,0.6-0.4,1-0.4c1.3,0,1.5,0.6,1.6,1l0,0.1l1.1,0l0-0.1c-0.1-1.2-1-2-2.6-2
                                                C265.1,73.6,264.2,74.4,264.2,75.5"></path>
                                            <path d="M272.6,77.5c-1,0-1.8-0.8-1.8-1.9c0-1,0.8-1.8,1.8-1.8c1,0,1.8,0.8,1.8,1.9
                                                C274.4,76.6,273.6,77.5,272.6,77.5L272.6,77.5z M272.6,74c-0.8,0-1.5,0.7-1.5,1.6c0,0.9,0.7,1.6,1.5,1.6c0.8,0,1.5-0.7,1.5-1.6
                                                C274.1,74.8,273.4,74,272.6,74L272.6,74z M273,76.6l-0.5-0.8l-0.3,0l0,0.8l-0.3,0l0-2l0.7,0c0.3,0,0.6,0.3,0.6,0.6
                                                c0,0.3-0.2,0.5-0.4,0.6l0.5,0.9L273,76.6z M272.7,74.9l-0.4,0l0,0.7l0.4,0c0.2,0,0.4-0.1,0.4-0.4C273,75,272.9,74.9,272.7,74.9
                                                L272.7,74.9z"></path>
                                        </g>
                                    <g transform="translate(213.297166, 60.256149) rotate(12.000000) translate(-213.297166, -60.256149) translate(149.297166, 32.756149)">
                                        <path d="M-141.9,20.3c-1.2-0.8-3-1.1-4.8-0.7c-2,0.4-3.4,1.3-4.4,3.2l-0.2-1.1c-0.5-0.5-1.3-0.7-2-0.5
                                                c-0.7,0.2-1.3,0.7-1.6,1.3l5.4,25.4l3.7-0.8l-2-9.5c1.7,1.3,3.3,1.5,5.3,1.1c1.8-0.4,3.3-1.4,4.1-2.6c1.4-2.3,1-5.5,0.4-8.4
                                                C-138.8,24.9-139.7,21.8-141.9,20.3 M-144.3,35.6c-3.3,0.7-4.4-2.1-5.2-5.4c-0.7-3.3-0.8-6.3,2.5-7c3.3-0.7,4.4,2.1,5.1,5.4
                                                S-141,34.9-144.3,35.6"></path>
                                        <path d="M-122.7,34.3l-0.4-1.7c-1,1.6-2.2,2.5-4.5,3c-2.3,0.5-3.9,0.3-5.3-0.7c-1.2-0.8-2-2.1-2.3-3.7
                                                c-0.7-3.1,1-5.8,5.2-6.7l4.8-1l-0.3-1.3c-0.5-2.4-1.9-3.3-4.7-2.7c-2,0.4-2.9,1.1-3.6,2.7l-2.9-1.8c1.3-2.4,3-3.4,6-4.1
                                                c5-1.1,8,0.6,8.9,4.8l2.7,12.5L-122.7,34.3z M-124.5,26l-4.3,0.9c-2.2,0.5-3.1,1.7-2.7,3.4c0.4,1.7,1.6,2.4,3.9,1.9
                                                c1.4-0.3,2.4-0.6,3.2-1.8c0.4-0.7,0.5-1.6,0.2-2.9L-124.5,26z"></path>
                                        <path d="M-110.5,28.3c-1.5,0.3-2.1-0.3-2.4-1.8l-4.4-20.9c-0.6-0.5-1.3-0.7-2-0.5
                                                c-0.8,0.2-1.3,0.7-1.6,1.3l4.5,21.1c0.6,2.8,2.6,4.8,6.1,4.1l2.3-0.5l-0.7-3.2L-110.5,28.3z"></path>
                                        <path d="M-94.2,26.1c-0.9,1.5-2.5,2.8-5,3.4c-2.5,0.5-4.5-0.1-5.9-1.1c-2.1-1.5-3.1-3.7-3.7-6.9
                                                c-0.7-3.1-0.7-5.6,0.6-7.8c0.9-1.5,2.5-2.8,5-3.4c2.5-0.5,4.5,0,6,1.1c2.1,1.5,3.1,3.7,3.7,6.9C-93,21.5-92.9,23.9-94.2,26.1
                                                 M-99.7,14.2c-0.8-0.6-1.9-0.7-2.9-0.5c-1.1,0.2-1.9,0.8-2.4,1.6c-0.9,1.4-0.6,3.4-0.2,5.4c0.4,2,1,4,2.4,4.9
                                                c0.8,0.6,1.8,0.8,2.9,0.5c1.1-0.2,1.9-0.8,2.5-1.7c0.9-1.4,0.6-3.4,0.2-5.4C-97.8,17-98.3,15.1-99.7,14.2"></path>
                                        <path d="M-65.5,18.8c-1.5,0.3-2.1-0.3-2.4-1.8l-4.4-20.9c-0.5-0.5-1.3-0.7-2-0.5
                                                c-0.8,0.2-1.3,0.7-1.6,1.3l4.5,21.1c0.6,2.8,2.6,4.8,6.1,4.1l2.3-0.5l-0.7-3.2L-65.5,18.8z"></path>
                                        <path d="M-78.2,24.8l-0.4-1.7c-1,1.6-2.2,2.5-4.5,3c-2.3,0.5-3.9,0.3-5.3-0.7c-1.1-0.8-2-2.1-2.3-3.7
                                                c-0.7-3.1,1-5.8,5.2-6.7l4.8-1l-0.3-1.3c-0.5-2.4-1.9-3.3-4.7-2.7c-2,0.4-2.9,1.1-3.6,2.7l-2.9-1.8c1.3-2.4,3-3.4,6-4.1
                                                c5-1.1,8,0.6,8.9,4.8l2.7,12.5L-78.2,24.8z M-80,16.6l-4.3,0.9c-2.2,0.5-3.1,1.7-2.7,3.4c0.4,1.7,1.6,2.4,3.9,1.9
                                                c1.4-0.3,2.4-0.6,3.2-1.8c0.4-0.7,0.5-1.6,0.2-2.9L-80,16.6z"></path>
                                        <path d="M-56.3,4l-0.6-2.9l-3.5,0.7l-1.2-5.7c-0.6-0.5-1.3-0.7-2-0.5C-64.4-4.2-65-3.7-65.3-3l1.2,5.7
                                                l-2.1,0.4l0.6,2.9l2.1-0.4l2.2,10.3c0.6,2.7,2.7,4.9,6.1,4.1l2.2-0.5l-0.7-3.2l-1.5,0.3c-1.4,0.3-2.2-0.4-2.5-1.7l-2.2-10.1
                                                L-56.3,4z"></path>
                                        <path d="M-38.1,14.2c-0.9,1.5-2.5,2.8-5,3.4c-2.5,0.5-4.5-0.1-5.9-1.1c-2.1-1.5-3.1-3.7-3.7-6.9
                                                c-0.7-3.1-0.7-5.6,0.6-7.8c0.9-1.5,2.5-2.8,5-3.4c2.5-0.5,4.5,0,6,1.1c2.1,1.5,3.1,3.7,3.7,6.9C-36.8,9.6-36.7,12-38.1,14.2
                                                 M-43.5,2.3c-0.8-0.6-1.9-0.7-2.9-0.5c-1.1,0.2-1.9,0.8-2.4,1.6c-0.9,1.4-0.6,3.4-0.2,5.4c0.4,2,1,4,2.4,4.9
                                                c0.8,0.6,1.8,0.8,2.9,0.5c1.1-0.2,1.9-0.8,2.5-1.7c0.9-1.4,0.6-3.4,0.2-5.4C-41.6,5.1-42.2,3.2-43.5,2.3"></path>
                                    </g>
                                    </svg>
                            </td>
                            <td align="right">
                                <span style="font-size:28px;">&nbsp;&nbsp;| Devices Overview | by EXpedition&copy;</span>
                            </td>

                        </tr>
                    </thead>
                </table>

                <?php
                $getPanoramas=$pandbRBAC->query("SELECT devicename,serial FROM devices WHERE ispanorama=1;");
                if ($getPanoramas->num_rows>0) {
                    while ($getPanoramasData = $getPanoramas->fetch_assoc()) {
                        //$panoramaList[]=$getPanoramasData['serial'];
                        //$result = stats_panos($getPanoramasData['serial']);
//                        foreach ($result['msg'] as $values) {
//                            $myLabels[$getPanoramasData['serial']][] = $values['name'];
//                            $myValues[$getPanoramasData['serial']][] = intval($values['name_count']);
//                        }

                        print "<br>";
                        print "<table border='1' style='color:black'>";
                        print "<thead>";
                        print "<tr>";
                        print "<td colspan='5'>Panorama: [".$getPanoramasData['devicename']. "] Serial: " .$getPanoramasData['serial']."</td>";
                        print "</tr>";

                        print "<tr>";
                        print "<td>DeviceName</td>";
                        print "<td>Serial</td>";
                        print "<td>Licenses</td>";
                        print "<td>Support</td>";
                        print "<td>Apps and Threats</td>";
                        print "</tr>";
                        print "</thead>";
                        $panoramaSerial=$getPanoramasData['serial'];
                        $getChildren=$pandbRBAC->query("SELECT * FROM devices WHERE management='$panoramaSerial';");
                        if ($getChildren->num_rows>0){
                            while($getChildrenData=$getChildren->fetch_assoc()){
                                $Childrenserial=$getChildrenData['serial'];
                                $getLicensesAndSupport=read_licenses($Childrenserial);
                                if($getChildrenData['connected']=="yes"){$connected="<font color=\"#5fba7d\"><i class=\"fa fa-circle\" aria-hidden=\"true\"></i></font>&nbsp;Connected";}
                                else{$connected="<font color=\"#cd383f\"><i class=\"fa fa-circle\" aria-hidden=\"true\"></i></font>&nbsp;Disconnected";}
                                print "<tr>";
                                print "<td>".$getChildrenData['devicename']."<br>".$connected."</td>";
                                print "<td>$Childrenserial</td>";
                                print "<td>".$getLicensesAndSupport[0]."</td>";
                                print "<td>".implode('<br>',$getLicensesAndSupport[1])."</td>";
                                print "<td>".read_oldassets($Childrenserial,$getChildrenData)."</td>";
                                print "</tr>";
                            }
                        }
                        print "</table>";

                    }
                }




                $getChildren=$pandbRBAC->query("SELECT * FROM devices WHERE management='' AND ispanorama=0;");
                if ($getChildren->num_rows>0){

                    print "<br>";
                    print "<table border='1' style='color:black'>";
                    print "<thead>";
                    print "<tr>";
                    print "<td>DeviceName</td>";
                    print "<td>Serial</td>";
                    print "<td>Licenses</td>";
                    print "<td>Support</td>";
                    print "<td>Apps and Threats</td>";
                    print "</tr>";
                    print "</thead>";

                    while($getChildrenData=$getChildren->fetch_assoc()){
                        $Childrenserial=$getChildrenData['serial'];
                        $getLicensesAndSupport=read_licenses($Childrenserial);
                        if($getChildrenData['connected']=="yes"){$connected="<font color=\"#5fba7d\"><i class=\"fa fa-circle\" aria-hidden=\"true\"></i></font>&nbsp;Connected";}
                        else{$connected="<font color=\"#cd383f\"><i class=\"fa fa-circle\" aria-hidden=\"true\"></i></font>&nbsp;Disconnected";}
                        print "<tr>";
                        print "<td>".$getChildrenData['devicename']."<br>".$connected."</td>";
                        print "<td>$Childrenserial</td>";
                        print "<td>".$getLicensesAndSupport[0]."</td>";
                        print "<td>".implode('<br>',$getLicensesAndSupport[1])."</td>";
                        print "<td>".read_oldassets($Childrenserial,$getChildrenData)."</td>";
                        print "</tr>";
                    }
                }
                print "</table>";
                ?>
            </div>
        </div>
    </div>
</div>
</body>
</html>

<?php

function read_licenses($serial){
    global $pandbRBAC;

    $tp="<img src='/resources/images/services/threat-prevention-gray.svg' width='35' height='35' alt='Threat Prevention License'>";
    $wf="<img src='/resources/images/services/wildfire-gray.svg' width='35' height='35' alt='Wildfire License'>";
    $dns="<img src='/resources/images/services/dns-gray.svg' width='35' height='35' alt='DNS Security License'>";
    $uf="<img src='/resources/images/services/url-filtering-gray.svg' width='35' height='35' alt='URL Filtering License'>";
    $af="<img src='/resources/images/services/autofocus-gray.svg' width='35' height='35' alt='AutoFocus License'>";
    $ls="<img src='/resources/images/services/logging-service-gray.svg' width='35' height='35' alt='Logging Service License'>";
    $gp="<img src='/resources/images/services/globalprotect-gray.svg' width='35' height='35' alt='Global Protect Licenses'>";
    $premium="<font color='gray'><b>[PS]</b>&nbsp</font>";

    $support= "<font color=red>No Support found</font>";

    $getLicenses=$pandbRBAC->query("SELECT * FROM licenses WHERE serial='$serial'");
    if ($getLicenses->num_rows>0){
        $element="";
        $support=[];
        while($data4=$getLicenses->fetch_object()){
            switch ($data4->feature){
                case "Threat Prevention":
                    if ($data4->expired=="no"){
                        $tp="<img src='/resources/images/services/threat-prevention-green.svg' width='35' height='35'>";
                    }
                    else{
                        $tp="<img src='/resources/images/services/threat-prevention-red.svg' width='35' height='35'>";
                    }
                    break;

                case "PAN-DB URL Filtering":
                case "BrightCloud URL Filtering":
                    if ($data4->expired=="no"){
                        $uf="<img src='/resources/images/services/url-filtering-green.svg' width='35' height='35'>";
                    }
                    else{
                        $uf="<img src='/resources/images/services/url-filtering-red.svg' width='35' height='35'>";
                    }
                    break;

                case "DNS Security":
                    if ($data4->expired=="no"){
                        $dns="<img src='/resources/images/services/dns-green.svg' width='35' height='35'>";
                    }
                    else{
                        $dns="<img src='/resources/images/services/dns-red.svg' width='35' height='35'>";
                    }
                    break;

                case "AutoFocus Device License":
                    if ($data4->expired=="no"){
                        $af="<img src='/resources/images/services/autofocus-green.svg' width='35' height='35'>";
                    }
                    else{
                        $af="<img src='/resources/images/services/autofocus-red.svg' width='35' height='35'>";
                    }
                    break;

                case "WildFire License":
                    if ($data4->expired=="no"){
                        $wf="<img src='/resources/images/services/wildfire-green.svg' width='35' height='35'>";
                    }
                    else{
                        $wf="<img src='/resources/images/services/wildfire-red.svg' width='35' height='35'>";
                    }
                    break;

                case "Logging Service":
                    if ($data4->expired=="no"){
                        $ls="<img src='/resources/images/services/logging-service-green.svg' width='35' height='35'>";
                    }
                    else{
                        $ls="<img src='/resources/images/services/logging-service-red.svg' width='35' height='35'>";
                    }
                    break;

                case "GlobalProtect Gateway":
                case "GlobalProtect Portal":
                    if ($data4->expired=="no"){
                        $gp="<img src='/resources/images/services/globalprotect-green.svg' width='35' height='35'>";
                    }
                    else{
                        $gp="<img src='/resources/images/services/globalprotect-red.svg' width='35' height='35'>";
                    }
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
        $element=$tp.'&nbsp;'.$wf.'&nbsp;'.$dns.'&nbsp;'.$uf.'&nbsp;'.$af.'&nbsp;'.$ls.'&nbsp;'.$gp;
    }
    else{
        //$element=$tp."<font color='gray'><b>[WF]</b>&nbsp</font><font color='gray'><b>[DNS]</b>&nbsp</font><font color='gray'><b>[UF]</b>&nbsp</font><font color='gray'><b>[AF]</b>&nbsp</font><font color='gray'><b>[LS]</b>&nbsp</font><font color='gray'><b>[GP]</b>&nbsp</font>";
        $element=$tp.'&nbsp;'.$wf.'&nbsp;'.$dns.'&nbsp;'.$uf.'&nbsp;'.$af.'&nbsp;'.$ls.'&nbsp;'.$gp;
        $support="Disconnected";
    }
    return [$element,$support];
}

function read_oldassets($serial,$data2){
    global $pandbRBAC;
    // Old Apps

    $getlic=$pandbRBAC->query("SELECT devicename,serial,appversion,appreleasedate FROM devices WHERE (appreleasedate < NOW() - INTERVAL 30 DAY) AND ( (appversion!=0) AND (appversion!='') ) AND connected='yes' AND serial='$serial';");
    if ($getlic->num_rows==1){
        $getlicData=$getlic->fetch_object();
        if ($getlicData->appreleasedate=="0000-00-00 00:00:00"){
            $appversion[]="AppID [".$getlicData->appversion. "] <font color=\"#cd383f\">Unknown</font>";
        }
        else{
            $appversion[]="AppID [".$getlicData->appversion. "] <font color=\"#cd383f\"> <i>".$data2['appreleasedate']."</i></font>";
        }

    }
    else{
        if ($data2['appreleasedate']=="0000-00-00 00:00:00"){
            $appversion[]="AppID [".$data2['appversion']. "] <font color=\"#cd383f\">Unknown</font>";
        }
        else{
            $appversion[]="AppID [".$data2['appversion']. "] <font color=\"#5fba7d\"> ".$data2['appreleasedate']."</font>";
        }

    }

    //Old Threats
    if ($data2['threatversion']==0){
        $appversion[]="<font color=\"#cd383f\">[No Threats]</font>";
    }
    else{
        $getlic=$pandbRBAC->query("SELECT devicename,serial,threatversion,threatreleasedate FROM devices WHERE (threatreleasedate < NOW() - INTERVAL 30 DAY) AND ( (threatversion!='0') AND (threatversion!='') ) AND connected='yes' AND serial='$serial';");
        if ($getlic->num_rows==1){
            $getlicData=$getlic->fetch_object();
            if ($getlicData->threatreleasedate=="0000-00-00 00:00:00"){
                $appversion[]="TP [".$getlicData->threatversion. "] <font color=\"#cd383f\">Unknown</font>";
            }
            else{
                $appversion[]="TP [".$getlicData->threatversion. "] <font color=\"#cd383f\"> <i>".$getlicData->threatreleasedate."</i></font>";
            }
        }
        else{
            if ($data2['threatreleasedate']=="0000-00-00 00:00:00"){
                $appversion[]="TP [".$data2['threatversion']. "] <font color=\"#cd383f\">Unknown</font>";
            }
            else{
                $appversion[]="TP [".$data2['threatversion']. "] <font color=\"#5fba7d\"> ".$data2['threatreleasedate']."</font>";
            }
        }
    }

    if (($data2['avversion']==0) OR ($data2['avversion']==NULL)){
        $appversion[]="<font color=\"#cd383f\">[No Anti-virus]</font>";
    }
    else{
        $appversion[]="AV [".$data2['avversion']. "]";
    }

    return implode("<br>",$appversion);
}
?>