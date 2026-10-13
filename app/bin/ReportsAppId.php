<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

/* pChart library inclusions */
include(INC_ROOT."/libs/pChart/class/pData.class.php");
include(INC_ROOT."/libs/pChart/class/pDraw.class.php");
include(INC_ROOT."/libs/pChart/class/pImage.class.php");

include INC_ROOT.'/bin/middleware_sanitizer.php';

$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
$project = check_sanitize($project);

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

# Access Control
if(!checkProjectRights($project,'view')){
    echo 'You don\'t have rights to generate this report.';
    return;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

require_once INC_ROOT.'/libs/tcpdf/tcpdf.php';
require_once(INC_ROOT.'/libs/tcpdf/config/tcpdf_config.php');


if (!file_exists(USERSPACE_PATH."/projects/$project/Reports")) {
    mkdir(USERSPACE_PATH."/projects/$project/Reports", 0755, true);
}
// create new PDF document
//$pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);
$pdf = new TCPDF('L', PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);

// set document information
$pdf->SetCreator(PDF_CREATOR);
$pdf->SetAuthor('Palo Alto Networks');
$pdf->SetTitle('Palo Alto Netoworks :: Expedition :: Report App-Id');

// set default header data
//$pdf->SetHeaderData(PDF_HEADER_LOGO, PDF_HEADER_LOGO_WIDTH, PDF_HEADER_TITLE, PDF_HEADER_STRING);
//$pdf->SetHeaderData(PDF_HEADER_LOGO, PDF_HEADER_LOGO_WIDTH, PDF_HEADER_TITLE, PDF_HEADER_STRING, array(0,64,255), array(0,64,128));
$pdf->SetHeaderData('../../resources/images/panlogoorange2.png', '35', '', '                                                                                Migration Tool :: Report', array(51, 105, 136), array(51, 105, 136));
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

/*
  $idind = array("y1","y2","y3","y4");
  $s1 = array("7","10","25","30");

  $grafico = new Graph(500,500,'auto');
  $grafico -> SetScale("textlin");
  $grafico -> title -> Set ("GRAFICA DE PRUEBA");
  $grafico -> yaxis -> title -> Set ("VALOR DE REFERENCIA");
  $grafico -> xaxis -> title -> Set ("INDICADORES");
  $grafico->xaxis->SetTickLabels($idind);

  $bp=new BarPlot($s1);
  $bp->SetFillColor("#00CC00");
  $bp->SetWidth(35);
  $bp->value->Show();

  $grafico->Add($bp);

  $grafico->Stroke(_IMG_HANDLER);

  $fileName = INC_ROOT."/resources/images/graphs/grafica3.png";
  $grafico->img->Stream($fileName);

  // Mandarlo al navegador
  //$grafico->img->Headers();
  //$grafico->img->Stream();
 */





//**********************//
// SUBCATEGORY APPLICATIONS FROM LOG
//**********************//

$name_rule="";
$html_src="";
$html_dst="";
$html_srv="";
$html_app="";
$html_app_from_log="";

$subcategory_all = array();
$total_bytes_array = array();

$getSubCat = $projectdb->query("SELECT DISTINCT(da.subcategory) FROM default_applications da, applications_from_log af WHERE af.app = da.name; ");
if ($getSubCat->num_rows > 0) {
    while ($dataSC = $getSubCat->fetch_assoc()) {
        if ($dataSC['subcategory'] == "") {
            $dataSC['subcategory'] = "unknown";
        }
        $subcategory_all[] = $dataSC['subcategory'];
    }
}

$getSubCat2 = $projectdb->query("SELECT DISTINCT(da.subcategory) FROM applications da, applications_from_log af WHERE af.app = da.name ; ");
if ($getSubCat2->num_rows > 0) {
    while ($dataSC2 = $getSubCat2->fetch_assoc()) {
        $sub = $dataSC2['subcategory'];
        if (!in_array($sub, $subcategory_all)) {
            $subcategory_all[] = $dataSC2['subcategory'];
        }
    }
}

//$getSubCat3 = $projectdb->query("SELECT DISTINCT(da.subcategory) FROM shared_applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid'; ");
//if ($getSubCat3->num_rows > 0) {
//    while ($dataSC3 = $getSubCat3->fetch_assoc()) {
//        $sub = $dataSC3['subcategory'];
//        if (!in_array($sub, $subcategory_all)) {
//            $subcategory_all[] = $dataSC3['subcategory'];
//        }
//    }
//}

foreach ($subcategory_all as $key => $value) {
    
    $getTotalBytes = $projectdb->query("SELECT SUM(af.bytes) AS total_bytes FROM default_applications da, applications_from_log af WHERE da.name = af.app AND da.subcategory = '$value';");

    if ($getTotalBytes->num_rows > 0) {
        $dataTB = $getTotalBytes->fetch_assoc();
        $total_bytes = $dataTB['total_bytes'];

        $format_total_bytes = formatBytes($total_bytes, 2);
    }

    $getTotalBytes2 = $projectdb->query("SELECT SUM(af.bytes) AS total_bytes FROM applications da, applications_from_log af WHERE da.name = af.app AND da.subcategory = '$value';");

    if ($getTotalBytes2->num_rows > 0) {
        $dataTB2 = $getTotalBytes2->fetch_assoc();
        $total_bytes = $dataTB2['total_bytes'] + $total_bytes;

        $format_total_bytes = formatBytes($total_bytes, 2);
    }

//    $getTotalBytes3 = $projectdb->query("SELECT SUM(af.bytes) AS total_bytes FROM shared_applications da, applications_from_log af WHERE da.name = af.app AND da.subcategory = '$value';");
//
//    if ($getTotalBytes3->num_rows > 0) {
//        $dataTB3 = $getTotalBytes3->fetch_assoc();
//        $total_bytes = $dataTB3['total_bytes'] + $total_bytes;
//
//        $format_total_bytes = formatBytes($total_bytes, 2);
//    }

    //$format_total_bytes = formatBytes($total_bytes, 2);
    //$total_bytes = $total_bytes / 1024;

    $total_bytes_array[] = $total_bytes;
}



//-----------------------------
$subcategory_all1 = array();
$subcategory_all2 = array();
$getSubCat2 = $projectdb->query("SELECT SUM(af.bytes) AS total_bytes, da.subcategory FROM default_applications da, applications_from_log af WHERE da.name = af.app GROUP BY da.subcategory ORDER BY total_bytes DESC; ");
if ($getSubCat2->num_rows > 0) {
    while ($dataSC2 = $getSubCat2->fetch_assoc()) {
        if ($dataSC2['subcategory'] == "") {
            $dataSC2['subcategory'] = "unknown";
        }
        $subcategory_all1[] = $dataSC2['subcategory'];

        $total_bytes = $dataSC2['total_bytes'] / 1024;
        $total_bytes_f = number_format($total_bytes, 2, '.', '');
        $subcategory_all2[] = $total_bytes_f;
        //$subcategory_all2[] = $dataSC2['total_bytes'];
    }
}

if ((count($subcategory_all2)>0) AND (count($subcategory_all1)>0)){
    /* Create and populate the pData object */
    $html_src="";
    $html_dst="";



    $MyData = new pData();
    $MyData->loadPalette(INC_ROOT."/libs/pChart/palettes/blind.color",TRUE);
//$MyData->addPoints($total_bytes_array,"Answers");
    $MyData->addPoints($subcategory_all2, "Answers");
//$MyData->setAxisName(0,"Total Bytes");
//$MyData->addPoints(array("I do agree  ","I disagree  ","No opinion  "), "Options");
//$MyData->addPoints($subcategory_all, "Options");
    $MyData->addPoints($subcategory_all1, "Options");
    $MyData->setAbscissa("Options");

    /* Create the pChart object */
//$myPicture = new pImage(500,220,$MyData);
    $myPicture = new pImage(1200, 600, $MyData);

    /* Write the chart title */
//$myPicture->setFontProperties(array("FontName" => INC_ROOT."/resources/pChart/fonts/calibri.ttf", "FontSize" => 10));
//$myPicture->setFontProperties(array("FontName" => INC_ROOT."/resources/pChart/fonts/Silkscreen.ttf", "FontSize" => 12));
//$myPicture->drawText(20,34,"Subcategory by Bytes",array("FontSize"=>15));

    /* Define the default font */
    $myPicture->setFontProperties(array("FontName" => INC_ROOT."/libs/pChart/fonts/verdana.ttf", "FontSize" => 9));

    /* Set the graph area */
//$myPicture->setGraphArea(70,60,480,400);
    $myPicture->setGraphArea(150, 0, 1100, 580);
//$myPicture->drawGradientArea(70,60,480,200,DIRECTION_HORIZONTAL,array("StartR"=>200,"StartG"=>200,"StartB"=>200,"EndR"=>255,"EndG"=>255,"EndB"=>255,"Alpha"=>30));
// Fondo verde
//$myPicture->drawGradientArea(120, 0, 1180, 580, DIRECTION_HORIZONTAL, array("StartR" => 233, "StartG" => 239, "StartB" => 198, "EndR" => 255, "EndG" => 255, "EndB" => 255, "Alpha" => 600));
    $myPicture->drawGradientArea(150, 0, 1100, 580, DIRECTION_HORIZONTAL, array("StartR" => 230, "StartG" => 230, "StartB" => 230, "EndR" => 255, "EndG" => 255, "EndB" => 255, "Alpha" => 600));


    /* Draw the chart scale */
//$scaleSettings = array("AxisAlpha" => 1000, "TickAlpha" => 100, "DrawXLines" => FALSE, "Mode" => SCALE_MODE_START0, "GridR" => 0, "GridG" => 0, "GridB" => 0, "GridAlpha" => 10, "Pos" => SCALE_POS_TOPBOTTOM);
    $scaleSettings = array("AxisAlpha" => 1000, "TickAlpha" => 100, "DrawXLines" => FALSE, "Mode" => SCALE_MODE_START0, "GridR" => 0, "GridG" => 0, "GridB" => 0, "GridAlpha" => 0, "Pos" => SCALE_POS_TOPBOTTOM);
//
    $myPicture->drawScale($scaleSettings);

    /* Turn on shadow computing */
//c1d229
//$myPicture->setShadow(TRUE, array("X" => 2, "Y" => 2, "R" => 0, "G" => 0, "B" => 0, "Alpha" => 10));
//$myPicture->setShadow(TRUE, array("X" => 1, "Y" => 1, "R" => 0, "G" => 0, "B" => 0, "Alpha" => 10));

    $Palette = array("0" => array("R" => 132, "G" => 177, "B" => 204, "Alpha" => 100),
        "1" => array("R" => 184, "G" => 221, "B" => 242, "Alpha" => 100),
        "2" => array("R" => 214, "G" => 217, "B" => 219, "Alpha" => 100),
        "3" => array("R" => 191, "G" => 153, "B" => 147, "Alpha" => 100),
        "4" => array("R" => 190, "G" => 229, "B" => 239, "Alpha" => 100),
        "5" => array("R" => 242, "G" => 207, "B" => 206, "Alpha" => 100),
        "6" => array("R" => 200, "G" => 224, "B" => 210, "Alpha" => 100),
        "7" => array("R" => 224, "G" => 176, "B" => 215, "Alpha" => 100),
        "8" => array("R" => 88, "G" => 143, "B" => 173, "Alpha" => 100),
        "9" => array("R" => 125, "G" => 183, "B" => 216, "Alpha" => 100),
        "10" => array("R" => 214, "G" => 217, "B" => 219, "Alpha" => 100),
        "11" => array("R" => 191, "G" => 153, "B" => 147, "Alpha" => 100),
        "12" => array("R" => 190, "G" => 229, "B" => 239, "Alpha" => 100),
        "13" => array("R" => 242, "G" => 207, "B" => 206, "Alpha" => 100),
        "14" => array("R" => 200, "G" => 224, "B" => 210, "Alpha" => 100),
        "15" => array("R" => 224, "G" => 176, "B" => 215, "Alpha" => 100),
        "16" => array("R" => 132, "G" => 177, "B" => 204, "Alpha" => 100),
        "17" => array("R" => 184, "G" => 221, "B" => 242, "Alpha" => 100),
        "18" => array("R" => 214, "G" => 217, "B" => 219, "Alpha" => 100),
        "19" => array("R" => 191, "G" => 153, "B" => 147, "Alpha" => 100),
        "20" => array("R" => 190, "G" => 229, "B" => 239, "Alpha" => 100),
        "21" => array("R" => 242, "G" => 207, "B" => 206, "Alpha" => 100),
        "14" => array("R" => 200, "G" => 224, "B" => 210, "Alpha" => 100),
        "15" => array("R" => 224, "G" => 176, "B" => 215, "Alpha" => 100),
        "16" => array("R" => 132, "G" => 177, "B" => 204, "Alpha" => 100),
        "17" => array("R" => 184, "G" => 221, "B" => 242, "Alpha" => 100),
        "18" => array("R" => 214, "G" => 217, "B" => 219, "Alpha" => 100),
        "19" => array("R" => 191, "G" => 153, "B" => 147, "Alpha" => 100),
        "20" => array("R" => 190, "G" => 229, "B" => 239, "Alpha" => 100),
        "21" => array("R" => 242, "G" => 207, "B" => 206, "Alpha" => 100));


    /* Draw the chart */
//$myPicture->drawBarChart(array("DisplayValues" => TRUE, "DisplayShadow" => TRUE, "DisplayPos" => LABEL_POS_INSIDE, "Rounded" => TRUE, "Surrounding" => 10, "OverrideColors" => $Palette));
    $myPicture->drawBarChart(array("DisplayValues" => TRUE, "DisplayShadow" => TRUE, "DisplayPos" => LABEL_POS_OUTSIDE, "Rounded" => TRUE, "Surrounding" => 100));

    /* Render the picture (choose the best way) */
    $myPicture->render(USERSPACE_PATH."/projects/$project/Reports/graph_app_id.png");
}

if (file_exists(USERSPACE_PATH.'/projects/' . $project . '/Reports/graph_app_id.png')) {
// add a page
    $pdf->AddPage();

//verde: c1d229

    $html = '   
<style>
h2 {font-size:13px; color:#333; text-align: center;}
h1 {font-size:11px; color:#333; text-align: center; }
h3 {font-size:10px; color:#333; text-align: left; border-bottom: 1px solid #666; }
</style>

<h2>PALOALTO NETWORKS :: MIGRATION TOOL :: REPORT App-ID</h2>
<br /><br />
<h1>Report for project: <span style="color:#3c6d8b">' . $project . '</span></h1>

<h3>Subcategory by MBytes:</h3>
<h1></h1>

<p><img src="'.USERSPACE_PATH.'/projects/' . $project . '/Reports/graph_app_id.png" width="1150" height="550"></p>

<h3>App-ID Adoption Statistics:</h3>

<h1></h1>
<table cellspacing="1" cellpadding="6" border=0 style="font-size:9px;">
  <tr bgcolor="#3c6d8b" style="font-size:9px; color:#fff;">
    <td width="15%" colspan = "2"><b>NAME</b></td>
    <td width="15%"><b>SOURCE</b></td>
    <td width="15%"><b>DESTINATION</b></td>
    <td width="15%"><b>SERVICE</b></td>
    <td width="20%"><b>APPLICATION</b></td>
    <td width="20%"><b>APP-ID VIA LOG</b></td>
    
  </tr>';

    $html .= '<tr bgcolor="#ccc" style="text-align: left;">
        <td colspan="7"><b>Rules with App-Id via LOG :</b></td>
        </tr>';

    $i = 1;

    $getRulesApp = $projectdb->query("SELECT DISTINCT(rule_lid) FROM applications_from_log; ");
    if ($getRulesApp->num_rows > 0) {
        while ($dataRA = $getRulesApp->fetch_assoc()) {

            $rule_lid = $dataRA['rule_lid'];
            $html_app_from_log = array();

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
            else{
                $html_src = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';
                $html_src .= '<tr><td width="8%">&nbsp;</td>
                                    <td width="92%">any</td></tr>';
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
            else{
                $html_dst = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';
                $html_dst .= '<tr><td width="8%">&nbsp;</td>
                                    <td width="92%">any</td></tr>';
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
            else{
                $html_app = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';
                $html_app .= '<tr><td width="8%">&nbsp;</td>
                                    <td width="92%">any</td></tr>';
                $html_app .= '</table>';
            }

            //**********************//
            // APPLICATIONS FROM LOG
            //**********************//

            $subcategory = array();
            $getSubCat = $projectdb->query("SELECT DISTINCT(da.subcategory) FROM default_applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid'; ");
            if ($getSubCat->num_rows > 0) {
                while ($dataSC = $getSubCat->fetch_assoc()) {
                    $subcategory[] = $dataSC['subcategory'];
                }
            }

            $getSubCat2 = $projectdb->query("SELECT DISTINCT(da.subcategory) FROM applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid'; ");
            if ($getSubCat2->num_rows > 0) {
                while ($dataSC2 = $getSubCat2->fetch_assoc()) {
                    $sub = $dataSC2['subcategory'];
                    if (!in_array($sub, $subcategory)) {
                        $subcategory[] = $dataSC2['subcategory'];
                    }
                }
            }

            $html_app_from_log = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';
            $is_first = 0;
            foreach ($subcategory as $key => $value) {
                if ($value == "") {
                    $title_value = "unknown";
                } else {
                    $title_value = $value;
                }
                if($is_first == 0){
                    $html_app_from_log .= '<tr><td colspan="2" style="border-bottom: 1px #ccc solid; "><b>' . $title_value . '</b></td></tr>';
                    $is_first = 1;
                }else{
                    $html_app_from_log .= '<tr><td></td><td></td></tr><tr><td colspan="2" style="border-bottom: 1px #ccc solid; "><b>' . $title_value . '</b></td></tr>';
                }

                $getDefaults = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.default_port, da.risk, af.app FROM default_applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.subcategory = '$value' GROUP BY da.subcategory, da.name;");

                if ($getDefaults->num_rows > 0) {
                    while ($data_defaults = $getDefaults->fetch_assoc()) {
                        $category = $data_defaults['category'];
                        $subcategory = $data_defaults['subcategory'];
                        $technology = $data_defaults['technology'];
                        $default_port = $data_defaults['default_port'];
                        $app_from_log = $data_defaults['app'];
                        $risk = $data_defaults['risk'];

                        if ($risk == "1") {
                            $icon_risk = "/resources/images/icons/risk_1.gif";
                        } elseif ($risk == "2") {
                            $icon_risk = "/resources/images/icons/risk_2.gif";
                        } elseif ($risk == "3") {
                            $icon_risk = "/resources/images/icons/risk_3.gif";
                        } elseif ($risk == "4") {
                            $icon_risk = "/resources/images/icons/risk_4.gif";
                        } elseif ($risk == "5") {
                            $icon_risk = "/resources/images/icons/risk_5.gif";
                        }

                        $getTotalBytes = $projectdb->query("SELECT SUM(bytes) AS total_bytes FROM applications_from_log WHERE app = '$app_from_log';");

                        if ($getTotalBytes->num_rows > 0) {
                            $dataTB = $getTotalBytes->fetch_assoc();
                            $total_bytes = $dataTB['total_bytes'];

                            $format_total_bytes = formatBytes($total_bytes, 2);
                        }

                        $html_app_from_log .= '<tr><td width="8%"><img src="' .INC_ROOT.'/'. $icon_risk . '" width="11"></td>
                                    <td width="92%">' . $app_from_log . ' (' . $format_total_bytes . ')</td></tr>';
                    }
                }

                $getDefaults2 = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.risk, af.app FROM applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.subcategory = '$value' GROUP BY da.subcategory, da.name;");
                if ($getDefaults2->num_rows > 0) {
                    while ($data_defaults2 = $getDefaults2->fetch_assoc()) {
                        $category = $data_defaults2['category'];
                        $subcategory = $data_defaults2['subcategory'];
                        $technology = $data_defaults2['technology'];
                        $risk = $data_defaults2['risk'];
                        $app_from_log = $data_defaults2['app'];
                        $default_port = "";

                        if ($risk == "1") {
                            $icon_risk = "/resources/images/icons/risk_1.gif";
                        } elseif ($risk == "2") {
                            $icon_risk = "/resources/images/icons/risk_2.gif";
                        } elseif ($risk == "3") {
                            $icon_risk = "/resources/images/icons/risk_3.gif";
                        } elseif ($risk == "4") {
                            $icon_risk = "/resources/images/icons/risk_4.gif";
                        } elseif ($risk == "5") {
                            $icon_risk = "/resources/images/icons/risk_5.gif";
                        }

                        $html_app_from_log .= '<tr><td width="8%"><img src="'.INC_ROOT.'/'. $icon_risk . '" width="11"></td>
                                    <td width="92%">' . $app_from_log . '</td></tr>';
                    }
                }

            }//foreach subcategory

            $html_app_from_log .= '</table>';

            //**********************//
            // SERVICES
            //**********************//

            $getSrv = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$rule_lid'; ");

            if ($getSrv->num_rows > 0) {

                $html_srv = '<table cellspacing="0" cellpadding="0" border=0 style="font-size:9px; ">';

                while ($dataS = $getSrv->fetch_assoc()) {

                    $member_lid_srv = $dataS['member_lid'];
                    $table_name_srv = $dataS['table_name'];

                    $image_services = getImage("services", $table_name_srv, $member_lid_srv);

                    $getNameSrv = $projectdb->query("SELECT name FROM $table_name_srv WHERE id = '$member_lid_srv'; ");

                    if ($getNameSrv->num_rows > 0) {

                        $dataNS = $getNameSrv->fetch_assoc();

                        $html_srv .= '<tr><td width="10%"><img src="'.INC_ROOT.'/resources/images/rules/' . $image_services . '" height="10" width="10" align="top"></td>
                                    <td width="90%">' . $dataNS['name'] . '</td></tr>';
                    }
                }

                $html_srv .= '</table>';
            }
            else{
                $html_srv = '<table cellspacing="0" cellpadding="1" border=0 style="font-size:9px; ">';
                $html_srv .= '<tr><td width="8%">&nbsp;</td>
                                    <td width="92%">any</td></tr>';
                $html_srv .= '</table>';
            }

            $html .= '<tr bgcolor="' . $row_color . '" style="font-size:8px; ">
                    <td width="3%"><img src="'.INC_ROOT.'/resources/images/icons/security.png" height="12" width="12"></td>
                    <td width="12%" style="font-size:9px; "><b>' . $name_rule . '</b></td>
                    <td>' . $html_src . '</td>
                    <td>' . $html_dst . '</td>
                    <td>' . $html_srv . '</td>
                    <td>' . $html_app . '</td>
                    <td>' . $html_app_from_log . '</td>
                    
                    </tr>';

            $i ++;
        } // while rule_lid
    }


    $html .= '<tr bgcolor="#ccc" style="text-align: left;">
        <td colspan="7"></td>
        </tr>';

    $html .= '</table>';
    $pdf->writeHTML($html, true, false, true, false, '');

    $pdf->Output('ReportAppId_' . $project . '.pdf', 'I');
}
else{
    echo "No Data";
}


function formatBytes($size, $precision = 2) {
    $base = log($size, 1024);
    $suffixes = array('', 'k', 'M', 'G', 'T');

    return round(pow(1024, $base - floor($base)), $precision) . $suffixes[floor($base)];
}

function formatBytes2($size, $precision = 2) {
    $base = log($size, 1024);
    return round(pow(1024, $base - floor($base)), $precision);
}
