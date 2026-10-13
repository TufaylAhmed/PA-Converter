<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

if (isset($_GET['project'])){
    $project = $pandb->real_escape_string($_GET['project']);
}
else{
    $project = $pandb->real_escape_string($data['project']);
}

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

# Access Control
if(!checkProjectRights($project,'view')){
    echo 'You don\'t have rights to generate this report.';
    return;
}

require_once INC_ROOT.'/libs/projectdb.php';

$projectdb = selectDatabase($project);
global $pandb;

require_once INC_ROOT.'/libs/tcpdf/tcpdf.php';
require_once(INC_ROOT.'/libs/tcpdf/config/tcpdf_config.php');

// create new PDF document
$pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);

// set document information
$pdf->SetCreator(PDF_CREATOR);
$pdf->SetAuthor('Palo Alto Networks');
$pdf->SetTitle('Palo Alto Netoworks :: Migration Tool :: Report');

// set default header data
//$pdf->SetHeaderData(PDF_HEADER_LOGO, PDF_HEADER_LOGO_WIDTH, PDF_HEADER_TITLE, PDF_HEADER_STRING);
//$pdf->SetHeaderData(PDF_HEADER_LOGO, PDF_HEADER_LOGO_WIDTH, PDF_HEADER_TITLE, PDF_HEADER_STRING, array(0,64,255), array(0,64,128));
$pdf->SetHeaderData('../../resources/images/panlogoorange2.png', '35', '', '                                                                                  Migration Tool :: Monitor :: Logs ', array(51, 105, 136), array(51, 105, 136));
//array(51, 105, 136)
$pdf->setFooterData(array(51, 105, 136), array(51, 105, 136));

// set header and footer fonts
$pdf->setHeaderFont(Array(PDF_FONT_NAME_MAIN, '', PDF_FONT_SIZE_MAIN));
$pdf->setFooterFont(Array(PDF_FONT_NAME_DATA, '', PDF_FONT_SIZE_DATA));

// set default monospaced font
$pdf->SetDefaultMonospacedFont(PDF_FONT_MONOSPACED);

// set margins
//$pdf->SetMargins(PDF_MARGIN_LEFT, PDF_MARGIN_TOP, PDF_MARGIN_RIGHT);
$pdf->SetMargins(PDF_MARGIN_LEFT, '30', PDF_MARGIN_RIGHT);
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

// add a page
//$pdf->AddPage();
$html2="";
$html = '   
<style>
h2 {font-size:13px; color:#333; text-align: center;}
h1 {font-size:11px; color:#333; text-align: center; }
h3 {font-size:10px; color:#333; text-align: left; border-bottom: 1px solid #666; }
</style>

<h2>PALOALTO NETWORKS :: MIGRATION TOOL :: REPORT</h2>
<br /><br />
<h1>Report for project: <span style="color:#336699">' . $project . '</span></h1>
<h1></h1>

<h3>MIGRATION LOGS:</h3>
<h1></h1>
<table cellspacing="2" cellpadding="6" border=0 style="font-size:9px; ">
  <tr bgcolor="#f3713c">
    <td width="70" style="color:white;"><b>DATETIME</b></td>
    <td width="7%" style="color:white;"><b>LEVEL</b></td>
    <td width="58%" style="color:white;"><b>MESSAGE</b></td>
    <td width="20%" style="color:white;"><b>ACTION</b></td>
  </tr>';


$getTask = $projectdb->query("SELECT DISTINCT(task) FROM logs WHERE type = ''; ");
if ($getTask->num_rows > 0) {
    while ($data = $getTask->fetch_assoc()) {
        $task = $data['task'];

        $html .= '<tr bgcolor="#235585" style="text-align: left;color:white;">
        <td colspan="4"><b>Task: ' . $task . '</b></td>
        </tr>';

        $getTaskRecords = $projectdb->query("SELECT datetime, level, message, action,fixed FROM logs WHERE task = '$task'; ");
        if ($getTaskRecords->num_rows > 0) {
            $i = 1;
            while ($data = $getTaskRecords->fetch_assoc()) {
                $datetime = $data['datetime'];
                $level = $data['level'];
                $message = $data['message'];
                $action = $data['action'];
                $fixed= $data['fixed'];

                if ($i % 2 != 0) {
                    $row_color = "#eee";
                } else {
                    $row_color = "#fff";
                }

                if ($level == "4") {
                    $img = '<img src="'.INC_ROOT.'/resources/images/report/icon-error.png" height="10" width="10">';
                } elseif ($level == "3") {
                    $img = '<img src="'.INC_ROOT.'/resources/images/report/icon-warning.png" height="10" width="10">';
                } elseif ($level == "2") {
                    $img = '<img src="'.INC_ROOT.'/resources/images/report/icon-info.png" height="10" width="10">';
                } else {
                    $img = '<img src="'.INC_ROOT.'/resources/images/report/icon-ok.png" height="10" width="10">';
                }
                if ($fixed==1){$action="(Fixed)";}

                $html .= '<tr bgcolor="' . $row_color . '">
                    <td>' . $datetime . '</td>
                    <td align="center">' . $img . '</td>
                    <td>' . $message . '</td>
                    <td>' . $action . '</td>
                </tr>';
                $i ++;
            }
        }
    }
}

$html .= '</table>';

$getTaskAudit = $projectdb->query("SELECT DISTINCT(task) FROM logs WHERE type = '2'; ");
if ($getTaskAudit->num_rows > 0) {

    $html2 .= '
<style>
h2 {font-size:13px; color:#333; text-align: center;}
h1 {font-size:11px; color:#333; text-align: center; }
h3 {font-size:10px; color:#333; text-align: left; border-bottom: 1px solid #666; }
</style>
<h3>AUDIT LOGS:</h3>
<h1></h1>
<table cellspacing="2" cellpadding="6" border=0 style="font-size:9px; ">
  <tr bgcolor="#c1d229">
    <td width="20%"><b>DATETIME</b></td>
    <td width="7%"><b>LEVEL</b></td>
    <td width="40%"><b>MESSAGE</b></td>
    <td width="33%"><b>ACTION</b></td>
  </tr>';


    while ($data = $getTaskAudit->fetch_assoc()) {
        $task = $data['task'];

        $html2 .= '<tr bgcolor="#ccc" style="text-align: left;">
        <td colspan="4"><b>Task: ' . $task . '</b></td>
        </tr>';

        $getTaskRecords = $projectdb->query("SELECT datetime, level, message, action FROM logs WHERE task = '$task'; ");
        if ($getTaskRecords->num_rows > 0) {
            $i = 1;
            while ($data = $getTaskRecords->fetch_assoc()) {
                $datetime = $data['datetime'];
                $level = $data['level'];
                $message = $data['message'];
                $action = $data['action'];

                if ($i % 2 != 0) {
                    $row_color = "#eee";
                } else {
                    $row_color = "#fff";
                }

                if ($level == "4") {
                    $img = '<img src="'.INC_ROOT.'/resources/images/report/icon-error.png" height="10" width="10">';
                } elseif ($level == "3") {
                    $img = '<img src="'.INC_ROOT.'/resources/images/report/icon-warning.png" height="10" width="10">';
                } elseif ($level == "2") {
                    $img = '<img src="'.INC_ROOT.'/resources/images/report/icon-info.png" height="10" width="10">';
                } else {
                    $img = '<img src="'.INC_ROOT.'/resources/images/report/icon-ok.png" height="10" width="10">';
                }

                $html2 .= '<tr bgcolor="' . $row_color . '">
                    <td>' . $datetime . '</td>
                    <td align="center">' . $img . '</td>
                    <td>' . $message . '</td>
                    <td>' . $action . '</td>
                </tr>';
                $i ++;
            }
        }
    }
    $html2 .= '</table>';
}

$html1 = '
    <style>
        h2 {font-size:13px; color:#333; text-align: center;}
        h1 {font-size:11px; color:#333; text-align: center; }
        h3 {font-size:10px; color:#333; text-align: left; border-bottom: 1px solid #666; } 
    </style>
    <h3>DEVICE USAGE:</h3>
    <h1></h1>';


$pdf->AddPage();
$pdf->writeHTML($html, true, false, true, false, '');
$pdf->Output('Report_' . $project . '.pdf','D');

//$pdf->Output('Report_' . $project . '.pdf', 'I');

//$carpeta = '/home/userSpace/projects/' . $project . '/Reports';
//if (!file_exists($carpeta)) {
//    mkdir($carpeta, 0777, true);
//}

//$pdf->Output('/home/userSpace/projects/' . $project . '/Report_' . $project . '.pdf','FD');

//$buffer = file_get_contents('/home/userSpace/projects/' . $project . '/Report_' . $project . '.pdf');
//unlink('/home/userSpace/projects/' . $project . '/Report_' . $project . '.pdf');
//header("Content-type: application/pdf");
//header("Content-Length: " . strlen($buffer));
//header('Content-Disposition:attachment; filename="Report-'.$project.'.pdf"');


//$pdf->Output('Report_' . $project . '.pdf','FD');
//$pdf->Output('/var/www/html/Report_' . $project . '.pdf', 'D');
