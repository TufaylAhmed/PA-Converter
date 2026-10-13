<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

/* pChart library inclusions */
//include("../resources/pChart/class/pData.class.php");
//include("../resources/pChart/class/pDraw.class.php");
//include("../resources/pChart/class/pImage.class.php");

$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
$source = (string) (isset($_GET['source']) ? $_GET['source'] : '');

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

# Access Control
if(!checkProjectRights($project,'view')){
    echo 'You don\'t have rights to generate this report.';
    return;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$project = $projectdb->real_escape_string($project);
$source = $projectdb->real_escape_string($source);


require_once INC_ROOT.'/libs/tcpdf/tcpdf.php';
require_once(INC_ROOT.'/libs/tcpdf/config/tcpdf_config.php');



// create new PDF document
//$pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);
$pdf = new TCPDF('L', PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);

// set document information
$pdf->SetCreator(PDF_CREATOR);
$pdf->SetAuthor('Palo Alto Networks');
$pdf->SetTitle('Palo Alto Netoworks :: Migration Tool :: Report User-Id');

// set default header data
//$pdf->SetHeaderData(PDF_HEADER_LOGO, PDF_HEADER_LOGO_WIDTH, PDF_HEADER_TITLE, PDF_HEADER_STRING);
//$pdf->SetHeaderData(PDF_HEADER_LOGO, PDF_HEADER_LOGO_WIDTH, PDF_HEADER_TITLE, PDF_HEADER_STRING, array(0,64,255), array(0,64,128));
$pdf->SetHeaderData('../../resources/images/panlogoorange2.png', '35', '', '                                                                                            Migration Tool :: Report', array(51, 105, 136), array(51, 105, 136));
//array(51, 105, 136)
$pdf->setFooterData(array(51, 105, 136), array(51, 105, 136));

// set header and footer fonts
$pdf->setHeaderFont(Array(PDF_FONT_NAME_MAIN, '', PDF_FONT_SIZE_MAIN));
$pdf->setFooterFont(Array(PDF_FONT_NAME_DATA, '', PDF_FONT_SIZE_DATA));

// set default monospaced font
$pdf->SetDefaultMonospacedFont(PDF_FONT_MONOSPACED);

// set margins
//$pdf->SetMargins(PDF_MARGIN_LEFT, PDF_MARGIN_TOP, PDF_MARGIN_RIGHT);
$pdf->SetMargins(PDF_MARGIN_LEFT, '25', PDF_MARGIN_RIGHT);
//$pdf->SetHeaderMargin(PDF_MARGIN_HEADER);
$pdf->SetHeaderMargin('5');
//$pdf->SetFooterMargin(PDF_MARGIN_FOOTER);
$pdf->SetFooterMargin('10');

// set auto page breaks
$pdf->SetAutoPageBreak(TRUE, PDF_MARGIN_BOTTOM);

// set image scale factor
$pdf->setImageScale(PDF_IMAGE_SCALE_RATIO);

// set some language-dependent strings (optional)
if (@file_exists(dirname(__FILE__) . '/lang/eng.php')) {
    require_once(dirname(__FILE__) . '/lang/eng.php');
    $pdf->setLanguageArray($l);
}


// Get column users
$getRules = $projectdb->query("SELECT DISTINCT(rule_lid) FROM userid_from_log; ");
if ($getRules->num_rows > 0) {
    while ($dataR = $getRules->fetch_assoc()) {
        $rule_lid_u[] = $dataR['rule_lid'];
    }

    $getUsr = $projectdb->query("SELECT id FROM security_rules_usr WHERE rule_lid IN ('".implode(",", $rule_lid_u)."'); ");
    if ($getUsr->num_rows == 0) {
        $num_cols = "6";
    }else{
        $num_cols = "7";
    }
}



// add a page
$pdf->AddPage();

$html = '   
<style>
h2 {font-size:13px; color:#333; text-align: center;}
h1 {font-size:11px; color:#333; text-align: center; }
h3 {font-size:10px; color:#333; text-align: left; border-bottom: 1px solid #666; }
</style>

<h2>PALOALTO NETWORKS :: MIGRATION TOOL :: REPORT User-ID</h2>
<br /><br />
<h1>Report for project: <span style="color:#336699">' . $project . '</span></h1>

<h3>User-ID Adoption Statistics:</h3>

<h1></h1>
<table cellspacing="1" cellpadding="6" border=0 style="font-size:9px; ">
  <tr bgcolor="#c1d229">
    <td width="15%" colspan = "2"><b>NAME</b></td>
    <td width="20%"><b>SOURCE</b></td>
    <td width="20%"><b>DESTINATION</b></td>
    <td width="20%"><b>APPLICATION</b></td>
    <td width="25%"><b>USER-ID VIA LOG</b></td>
    
  </tr>';

$html .= '<tr bgcolor="#ccc" style="text-align: left;">
            <td colspan="6"><b>Rules with User-Id via LOG :</b></td>
        </tr>';

$i = 1;

$getRulesApp = $projectdb->query("SELECT DISTINCT(rule_lid) FROM userid_from_log; ");
if ($getRulesApp->num_rows > 0) {
    while ($dataRA = $getRulesApp->fetch_assoc()) {

        $rule_lid = $dataRA['rule_lid'];
        $html_user_from_log = array();
        $html_src = "";
        $html_dst = "";
        $html_app = "";
        $is_first = 1;
        $done = 0;

        if ($i % 2 != 0) {
            $row_color = "#eee";
        } else {
            $row_color = "#fff";
        }

        $getNameRule = $projectdb->query("SELECT name FROM security_rules WHERE id = '$rule_lid'; ");
        if ($getNameRule->num_rows > 0) {
            $dataNR = $getNameRule->fetch_assoc();
            $name_rule = $dataNR['name'];
        }

        //**********************//
        // SOURCES
        //**********************//

        $getSrc = $projectdb->query("SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid = '$rule_lid'; ");
        if ($getSrc->num_rows > 0) {

            $html_src = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';

            while ($dataSC = $getSrc->fetch_assoc()) {

                $member_lid_src = $dataSC['member_lid'];
                $table_name_src = $dataSC['table_name'];

                $image_address = getImage("address", $table_name_src, $member_lid_src);

                $getNameSrc = $projectdb->query("SELECT name FROM $table_name_src WHERE id = '$member_lid_src'; ");
                if ($getNameSrc->num_rows > 0) {

                    $dataNS = $getNameSrc->fetch_assoc();

                    $html_src .= '<tr><td width="8%"><img src="'.INC_ROOT.'/resources/images/rules/' . $image_address . '" height="10" width="10" align="top"></td>
                                    <td width="92%">' . $dataNS['name'] . '</td></tr>';
                }
            }
            $html_src .= '</table>';
        }

        //**********************//
        // DESTINATION
        //**********************//

        $getDst = $projectdb->query("SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid = '$rule_lid'; ");
        if ($getDst->num_rows > 0) {

            $html_dst = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';

            while ($dataDS = $getDst->fetch_assoc()) {

                $member_lid_dst = $dataDS['member_lid'];
                $table_name_dst = $dataDS['table_name'];

                $image_address = getImage("address", $table_name_dst, $member_lid_dst);

                $getNameDst = $projectdb->query("SELECT name FROM $table_name_dst WHERE id = '$member_lid_dst'; ");
                if ($getNameDst->num_rows > 0) {

                    $dataND = $getNameDst->fetch_assoc();

                    $html_dst .= '<tr><td width="8%"><img src="'.INC_ROOT.'/resources/images/rules/' . $image_address . '" height="10" width="10" align="top"></td>
                                    <td width="92%">' . $dataND['name'] . '</td></tr>';
                }
            }
            $html_dst .= '</table>';
        }


        //**********************//
        // APPLICATIONS
        //**********************//

        $getApp = $projectdb->query("SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid = '$rule_lid'; ");
        $total_app = $getApp->num_rows;

        if ($getApp->num_rows > 0) {

            $html_app = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';

            while ($dataA = $getApp->fetch_assoc()) {

                $member_lid_app = $dataA['member_lid'];
                $table_name_app = $dataA['table_name'];

                $getNameApp = $projectdb->query("SELECT name, risk FROM $table_name_app WHERE id = '$member_lid_app'; ");

                if ($getNameApp->num_rows > 0) {

                    $dataNA = $getNameApp->fetch_assoc();

                    $html_app .= '<tr><td width="8%"><img src="'.INC_ROOT.'/resources/images/rules/application.png" height="10" width="10" align="top"></td>
                                    <td width="92%">' . $dataNA['name'] . '</td></tr>';
                }
                
            }
            $html_app .= '</table>';
        }

        //**********************//
        // USERS ID FROM LOG
        //**********************//

        $html_user_from_log = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';

        $getUnknown = $projectdb->query("SELECT SUM(bytes) AS total_bytes, SUM(sessions) AS total_sessions, name FROM userid_from_log WHERE name = 'unknown' AND rule_lid = '$rule_lid';");

        if ($getUnknown->num_rows > 0) {
            while ($dataU = $getUnknown->fetch_assoc()) {
                $total_bytes = $dataU['total_bytes'];
                $total_sessions = $dataU['total_sessions'];
                if($total_bytes == ""){$format_total_bytes = 0;
                }else{$format_total_bytes = formatBytes($total_bytes, 2);}
                
                if($total_sessions == ""){$total_sessions = 0;}
            }
            $html_user_from_log .= '<tr><td colspan="2" style="border-bottom: 1px #ccc solid; "><b>UNKNOWN</b></td></tr>';
            $html_user_from_log .= '<tr><td width="35%">Total Bytes:</td><td width="65%">' . $format_total_bytes . '</td></tr>';
            $html_user_from_log .= '<tr><td width="35%">Total Sessions:</td><td width="65%">' . $total_sessions . '</td></tr>';

        }
        
        $getknown = $projectdb->query("SELECT SUM(bytes) AS total_bytes, SUM(sessions) AS total_sessions, name FROM userid_from_log WHERE name != 'unknown' AND rule_lid = '$rule_lid';");

        if ($getknown->num_rows > 0) {
            while ($dataK = $getknown->fetch_assoc()) {
                $total_bytes = $dataK['total_bytes'];
                $total_sessions = $dataK['total_sessions'];
                if($total_bytes == ""){$format_total_bytes = 0;
                }else{$format_total_bytes = formatBytes($total_bytes, 2);}
                
                if($total_sessions == ""){$total_sessions = 0;}
                
            }
            $html_user_from_log .= '<tr><td></td><td></td></tr><tr><td colspan="2" style="border-bottom: 1px #ccc solid; "><b>KNOWN</b></td></tr>';
            $html_user_from_log .= '<tr><td width="35%">Total Bytes:</td><td width="65%">' . $format_total_bytes . '</td></tr>';
            $html_user_from_log .= '<tr><td width="35%">Total Sessions:</td><td width="65%">' . $total_sessions . '</td></tr>';

        }
        
        $html_user_from_log .= '<tr><td></td><td></td></tr><tr><td colspan="2" style="border-bottom: 1px #ccc solid; "><b>RECOMMENDED GROUPS</b></td></tr>';
        
        $getUsers = $projectdb->query("SELECT DISTINCT(name) FROM userid_from_log WHERE rule_lid = '$rule_lid' ;");
        if($getUsers->num_rows == 1){
            while ($dataU = $getUsers->fetch_assoc()) {
                $user = addslashes($dataU['name']);
                if($user == "unknown"){
                    $done = 1;
                    $html_user_from_log .= '<tr><td width="8%"><img src="'.INC_ROOT.'/resources/images/rules/userp.png" width="11"></td>'
                            . '<td width="92%">' . $user . '</td></tr>';
                }
            } 
        }
        elseif($getUsers->num_rows == 2){
            while ($dataU = $getUsers->fetch_assoc()) {
                $user = addslashes($dataU['name']);
                if($user == "unknown"){
                    $are_unknown = 1;
                }
                else{
                    $user_no_unknown = addslashes($dataU['name']);
                }
            }
            if($are_unknown == 1){
                $image = getImageUser($user_no_unknown);
                $html_user_from_log .= '<tr><td width="8%"><img src="'.INC_ROOT.'/resources/images/rules/'.$image.'" width="11"></td>'
                            . '<td width="92%">' . $user_no_unknown . '</td></tr>';
                $done = 1;
            }
        }
        
        if($done == 0){
            list($groups_math_finish, $groups_math_finish_reco) = getRecommendedGroupsUserId($rule_lid, "all", $source);
            
            foreach ($groups_math_finish_reco as $key=>$user){
                if($user != "unknown"){
                    $image = getImageUser($user);
                    $html_user_from_log .= '<tr><td width="8%"><img src="'.INC_ROOT.'/resources/images/rules/'.$image.'" width="11"></td>'
                            . '<td width="92%">' . stripslashes($user) . '</td></tr>';
                    
                    
                }
                
            }
            
        }

        $html_user_from_log .= '</table>';

        $html .= '<tr bgcolor="' . $row_color . '" style="font-size:8px; ">
                    <td width="3%"><img src="'.INC_ROOT.'/resources/images/icons/security.png" height="12" width="12"></td>
                    <td width="12%" style="font-size:9px; "><b>' . $name_rule . '</b></td>
                    <td>' . $html_src . '</td>
                    <td>' . $html_dst . '</td>
                    <td>' . $html_app . '</td>
                    <td>' . $html_user_from_log . '</td>
                    
                    </tr>';

        $i ++;
    } // while rule_lid
}


$html .= '<tr bgcolor="#ccc" style="text-align: left;">
        <td colspan="6"></td>
        </tr>';

$html .= '</table>';

$pdf->writeHTML($html, true, false, true, false, '');

$pdf->Output('ReportUserId_' . $project . '.pdf', 'I');

function formatBytes($size, $precision = 2) {
    $base = log($size, 1024);
    $suffixes = array('', 'k', 'M', 'G', 'T');

    return round(pow(1024, $base - floor($base)), $precision) . $suffixes[floor($base)];
}

function formatBytes2($size, $precision = 2) {
    $base = log($size, 1024);
    return round(pow(1024, $base - floor($base)), $precision);
}

function getImageUser($name){

    global $projectdb;
    $isGroup = $projectdb->query("SELECT name FROM userid_group WHERE name = '$name' OR short_name = '$name';");
    if ($isGroup->num_rows > 0) {
        $image = 'user-groups.png';
    }else{
        $image = 'userp.png';
    }
    return $image;

}
