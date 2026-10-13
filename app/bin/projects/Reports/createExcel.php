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
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';
require_once INC_ROOT.'/libs/common/bestpractices/bpat.php';

/** Set default timezone (will throw a notice otherwise) */
if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}else{
    date_default_timezone_set('Europe/Andorra');
}

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);
// include PHPExcel
require_once INC_ROOT.'/libs/Classes/PHPExcel.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

if (isset($_GET['project'])){
    $project = $pandb->real_escape_string($_GET['project']);
    $source = $pandb->real_escape_string($_GET['source']);
    $vsys = $pandb->real_escape_string($_GET['vsys']);
    $report = $pandb->real_escape_string($_GET['report']);

    if($report == "static_routes"){
        $vr_id = $pandb->real_escape_string($_GET['vr_id']);
    }
}
else{
    $project = $pandb->real_escape_string($data['project']);
    $source = $pandb->real_escape_string($data['source']);
    $vsys = $pandb->real_escape_string($data['vsys']);
    $report = $pandb->real_escape_string($data['report']);

    if($report == "static_routes"){
        $vr_id = $data['vr_id'];
    }
}

if(!checkProjectRights($project,'view')){
    $message = array();
    $message['code'] = false;
    $message['msg'] = 'Your account does not have the rights to see this project contents';
    echo json_encode($message);
    return $message;
}

$projectdb = selectDatabase($project);

switch ($report){
    case "unused":
        generateExcelUnused($projectdb, $source, $vsys);
        break;

    case "address":
        generateExcelAddress($projectdb, $source, $project, $vsys);
        break;

    case "address_groups":
        generateExcelAddressGroups($projectdb, $source, $project, $vsys);
        break;

    case "services":
        generateExcelServices($projectdb, $source, $project, $vsys);
        break;

    case "services_groups":
        generateExcelServicesGroups($projectdb, $source, $project, $vsys);
        break;

    case "applications":
        generateExcelApplications($projectdb, $source, $project, $vsys);
        break;

    case "applications_filters":
        generateExcelApplicationsFilters($projectdb, $source, $project, $vsys);
        break;

    case "applications_groups":
        generateExcelApplicationsGroups($projectdb, $source, $project, $vsys);
        break;

    case "regions":
        generateExcelRegions($projectdb, $source, $project, $vsys);
        break;

    case "tags":
        generateExcelTags($projectdb, $source, $project, $vsys);
        break;

    case "security_rules":
        generateExcelSecurityRules($projectdb, $source, $project, $vsys);
        break;

    case "security_rules_consolidation":
        generateExcelSecurityRulesConsolidation($projectdb, $source, $project, $vsys);
        break;

    case "security_rules_consolidation_complete":
        generateExcelSecurityRulesConsolidationComplete($projectdb, $source, $project, $vsys);
        break;

    case "nat_rules":
        generateExcelNatRules($projectdb, $source, $project, $vsys);
        break;

    case "nat_rules_consolidation":
        generateExcelNatRulesConsolidation($projectdb, $source, $project, $vsys);
        break;

    case "appoverride_rules":
        generateExcelAppoverrideRules($projectdb, $source, $project, $vsys);
        break;

    case "appoverride_rules_consolidation":
        generateExcelAppoverrideRulesConsolidation($projectdb, $source, $project, $vsys);
        break;

    case "bpat":
        generateExcelBpat($projectdb,$source,$project);
        break;

    case "rule_enrich":
        generateExcelRuleEnrichment($projectdb, $source, $project);
        break;

    case "interfaces":
        generateExcelInterfaces($projectdb, $source, $project);
        break;

    case "zones":
        generateExcelZones($projectdb, $source, $project);
        break;

    case "virtual_routers":
        generateExcelVirtualRouters($projectdb, $source, $project);
        break;

    case "static_routes":
        generateExcelStaticRouters($projectdb, $source, $project, $vr_id);
        break;

    case "virtual_wires":
        generateExcelVirtualWires($projectdb, $source, $project);
        break;

    case "vlan":
        generateExcelVlan($projectdb, $source, $project);
        break;

    case "ipsec_tunnels":
        generateExcelIpsecTunnels($projectdb, $source, $project);
        break;

    case "ike_crypto":
        generateExcelIkeCrypto($projectdb, $source, $project);
        break;

    case "ipsec_crypto":
        generateExcelIpsecCrypto($projectdb, $source, $project);
        break;

    case "global_protect_ipsec":
        generateExcelGlobalProtectIpsec($projectdb, $source, $project);
        break;

    case "monitor_profile":
        generateExcelMonitorProfile($projectdb, $source, $project);
        break;

    // FALTA
    case "ike_gateways":
        generateExcelIkeGatewaysProfile($projectdb, $source, $project);
        break;

    case "ml_servers":
        generateExcelMLServers($projectdb, $source, $project);
        break;

    case "ml_new_rules":
        generateExcelMLNewRules($projectdb, $source, $project);
        break;

    default:
        break;
}


function generateExcelBpat($projectdb,$source,$project){

    $objPHPExcel = new PHPExcel();

    // set default font
    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    // set default font size
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);
    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("Best Practices Assessment Tool")
        ->setSubject("Best Practices")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Best Practices paloalto")
        ->setCategory("Expedition Tool Reports");

    // Add Header
    $objDrawing = new PHPExcel_Worksheet_Drawing();
    $objDrawing->setName('test_img');
    $objDrawing->setDescription('test_img');
    $objDrawing->setPath('../../../resources/images/panlogoorange2.png');
    $objDrawing->setCoordinates('J2');
    //setOffsetX works properly
    $objDrawing->setOffsetX(5);
    $objDrawing->setOffsetY(5);
    //set width, height
    $objDrawing->setWidth(183);
    $objDrawing->setHeight(101);
    $objDrawing->setWorksheet($objPHPExcel->getActiveSheet());

    # Get Radar Chart Data
    $getRadar=list_bpat_radar($project);
    if (count($getRadar['msg'])>0){
        $RadarArray[]=array("Topic","Adoption %");
        foreach($getRadar['msg'] as $valueArray){
            $RadarArray[]=array($valueArray['topic'],$valueArray['adoption']);
        }
    }

    $objWorksheet = $objPHPExcel->getActiveSheet();
    //$objWorksheet->setTitle("Dashboard");
    $objWorksheet->fromArray($RadarArray,-1);



//	Set the Labels for each data series we want to plot
//		Datatype
//		Cell reference for data
//		Format Code
//		Number of datapoints in series
//		Data values
//		Data Marker
    $dataseriesLabels = array(
        new PHPExcel_Chart_DataSeriesValues('String', 'Worksheet!$C$1', NULL, 1),	//	2011
        //new PHPExcel_Chart_DataSeriesValues('String', 'Worksheet!$D$1', NULL, 1),	//	2012
    );
//	Set the X-Axis Labels
//		Datatype
//		Cell reference for data
//		Format Code
//		Number of datapoints in series
//		Data values
//		Data Marker
    $xAxisTickValues = array(
        new PHPExcel_Chart_DataSeriesValues('String', 'Worksheet!$A$2:$A$9', NULL, 8),	//	Jan to Dec
        //new PHPExcel_Chart_DataSeriesValues('String', 'Worksheet!$A$2:$A$13', NULL, 12),	//	Jan to Dec
    );
//	Set the Data values for each data series we want to plot
//		Datatype
//		Cell reference for data
//		Format Code
//		Number of datapoints in series
//		Data values
//		Data Marker
    $dataSeriesValues = array(
        new PHPExcel_Chart_DataSeriesValues('Number', 'Worksheet!$B$2:$B$9', NULL, 8),
        //new PHPExcel_Chart_DataSeriesValues('Number', 'Worksheet!$D$2:$D$13', NULL, 12),
    );
//	Build the dataseries
    $series = new PHPExcel_Chart_DataSeries(
        PHPExcel_Chart_DataSeries::TYPE_RADARCHART,				// plotType
        NULL,													// plotGrouping
        range(0, count($dataSeriesValues)-1),					// plotOrder
        $dataseriesLabels,										// plotLabel
        $xAxisTickValues,										// plotCategory
        $dataSeriesValues,										// plotValues
        NULL,													// smooth line
        PHPExcel_Chart_DataSeries::STYLE_MARKER					// plotStyle
    );
//	Set up a layout object for the Pie chart
    $layout = new PHPExcel_Chart_Layout();
//	Set the series in the plot area
    $plotarea = new PHPExcel_Chart_PlotArea($layout, array($series));
//	Set the chart legend
    $legend = new PHPExcel_Chart_Legend(PHPExcel_Chart_Legend::POSITION_RIGHT, NULL, false);
    $title = new PHPExcel_Chart_Title('BEST PRACTICES ADOPTION');
//	Create the chart
    $chart = new PHPExcel_Chart(
        'bpat_chart1',		// name
        $title,			// title
       // $legend,		// legend
       NULL,
        $plotarea,		// plotArea
        true,			// plotVisibleOnly
        0,				// displayBlanksAs
        NULL,			// xAxisLabel
        NULL			// yAxisLabel		- Radar charts don't have a Y-Axis
    );
//	Set the position where the chart should appear in the worksheet
    $chart->setTopLeftPosition('A1');
    $chart->setBottomRightPosition('I25');
//	Add the chart to the worksheet
    $objWorksheet->addChart($chart);

    # Create Styles
    $styleArrayPassed = array(
        'font'  => array(
            'bold' => false,
            'color' => array('rgb' => '336600')
        ));
    $styleArrayFail = array(
        'font'  => array(
            'bold' => false,
            'color' => array('rgb' => 'CC0000')
        ));
    $styleArrayWhite = array(
        'font'  => array(
            'bold' => true,
            'color' => array('rgb' => 'FFFFFF')
        )
    );
    $styleArrayBlack = array(
        'font'  => array(
            'bold' => true,
            'color' => array('rgb' => '000000'),
            'size' => 14
        )
    );

    $styleArrayBorders = array(
        'borders' => array(
            'allborders' => array(
                'style' => PHPExcel_Style_Border::BORDER_THIN,
                'color' => array('rgb' => 'cddae7')
            )
        )
    );


    # Consitional Change Color of Result to be applied to each sheet
    $objConditional1 = new PHPExcel_Style_Conditional();
    $objConditional1->setConditionType(PHPExcel_Style_Conditional::CONDITION_CONTAINSTEXT)
        ->setOperatorType(PHPExcel_Style_Conditional::OPERATOR_CONTAINSTEXT)
        ->setText('PASSED');
    $objConditional1->getStyle()->getFont()->getColor()->setRGB('ffffff');
    $objConditional1->getStyle()->getFont()->setBold(true);
    $objConditional1->getStyle()->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER)->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objConditional1->getStyle()->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getEndColor()->setRGB('24ac5c');

    $objConditional2 = new PHPExcel_Style_Conditional();
    $objConditional2->setConditionType(PHPExcel_Style_Conditional::CONDITION_CONTAINSTEXT)
        ->setOperatorType(PHPExcel_Style_Conditional::OPERATOR_CONTAINSTEXT)
        ->setText('FAILED');
    $objConditional2->getStyle()->getFont()->getColor()->setRGB('ffffff');
    $objConditional2->getStyle()->getFont()->setBold(true);
    $objConditional2->getStyle()->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER)->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objConditional2->getStyle()->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getEndColor()->setRGB('b81918');

    $objConditional3 = new PHPExcel_Style_Conditional();
    $objConditional3->setConditionType(PHPExcel_Style_Conditional::CONDITION_CONTAINSTEXT)
        ->setOperatorType(PHPExcel_Style_Conditional::OPERATOR_CONTAINSTEXT)
        ->setText('INFO');
    $objConditional3->getStyle()->getFont()->getColor()->setRGB('ffffff');
    $objConditional3->getStyle()->getFont()->setBold(true);
    $objConditional3->getStyle()->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER)->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objConditional3->getStyle()->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getEndColor()->setRGB('0095c8');

    $Topics=array("device","network","objects","policies","panorama");

    foreach ($Topics as $topic){
        $lastTopic="";
        $message = list_bpat_bpchecks($project,NULL,NULL,'',$topic);
        if (count($message['msg'])>0){
            $clonedSheet = $objPHPExcel->createSheet();
            // Rename cloned worksheet
            $clonedSheet->setTitle($topic);
            // write header
            $clonedSheet->getCell('A1')->setValue('RESULT');
            $clonedSheet->getCell('B1')->setValue('CHECK NAME');
            $clonedSheet->getCell('C1')->setValue('TOPIC');

            $clonedSheet->getCell('D1')->setValue('MESSAGE');
            $clonedSheet->getCell('E1')->setValue('RATIONALE');
            $clonedSheet->getCell('F1')->setValue('CONFIG');
            $clonedSheet->getCell('G1')->setValue('REFERENCES');
            $clonedSheet->getCell('H1')->setValue('VSYS-DG');
            $clonedSheet->getCell('I1')->setValue('TEMPLATE');


            $clonedSheet->getStyle('A1:I1')->getFont()->setBold(true)->setSize(12);
            $clonedSheet->getStyle('A1:I1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $clonedSheet->getStyle('A1:I1')->getFill()->getStartColor()->setARGB('204b7a');
            $clonedSheet->getStyle('A1:I1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
            $clonedSheet->getStyle('A1:I1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);
            $clonedSheet->getStyle('A1:I1')->applyFromArray($styleArrayWhite);

            $clonedSheet->freezePane('A2');

            $row=2;
            foreach($message['msg'] as $newTopic){
                if($row % 2 == 0){$color = "ffffff";
                }else{$color = "f1f1f1";}

                if ($lastTopic!=$newTopic['subtype']){
                    # ROW LABEL SUBTYPE
                    if ($lastTopic!=""){$row++;}
                    $cellA="A".$row;
                    $cellI="I".$row;
                    $clonedSheet->mergeCells($cellA.':'.$cellI);
                    $subtype=ucfirst(str_replace("_"," ",$newTopic['subtype']));
                    $clonedSheet->getCell($cellA)->setValue($subtype);
                    $clonedSheet->getStyle($cellA)->applyFromArray($styleArrayBlack);
                    $clonedSheet->getStyle($cellA.':'.$cellI)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
                    $clonedSheet->getStyle($cellA.':'.$cellI)->getFill()->getStartColor()->setARGB('d3dfea');

                    $clonedSheet
                        ->getRowDimension($row)
                        ->setOutlineLevel(0)
                        ->setVisible(true)
                        ->setCollapsed(true);

                    $clonedSheet->getRowDimension($row)->setRowHeight(30);

                    $row++;
                }


                $cellA="A".$row;
                if ($newTopic['result']=="1"){
                    $clonedSheet->getCell($cellA)->setValue("PASSED");
                }
                elseif ($newTopic['result']=="0"){
                    if ($newTopic['type']=="note"){
                        $clonedSheet->getCell($cellA)->setValue("INFO");
                    }
                    else{
                        $clonedSheet->getCell($cellA)->setValue("FAILED");
                    }

                }


                $cellB="B".$row;
                $clonedSheet->getCell($cellB)->setValue($newTopic['name']);
                $clonedSheet->getStyle($cellB)->getAlignment()->setWrapText(true);

                $cellC="C".$row;
                $clonedSheet->getCell($cellC)->setValue($newTopic['topic']);
                $clonedSheet->getStyle($cellC)->getAlignment()->setWrapText(true);

                $cellD="D".$row;
                $clonedSheet->getCell($cellD)->setValue($newTopic['message']);
                $clonedSheet->getStyle($cellD)->getAlignment()->setWrapText(true);

                if (isset($newTopic['rationale'])){
                    $cellE="E".$row;
                    $rationale = mb_convert_encoding($newTopic['rationale'], 'UTF-8', 'UTF-8');
                    $clonedSheet->getCell($cellE)->setValue($rationale);
                    $clonedSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
                }

                if ( (isset($newTopic['configuration'])) AND ($newTopic['configuration']!="")){
                    $cellF="F".$row;
                    $config=json_encode($newTopic['configuration']);
                    $config = str_replace("\\\"","\"",$config);
                    $clonedSheet->getCell($cellF)->setValue($config);
                    $clonedSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                }

                if (isset($newTopic['references'])){
                    $cellG="G".$row;
                    $links=explode(" ",$newTopic['references']);
                    foreach ($links as $referencesRaw){
                        $references = iconv("UTF-8", "UTF-8//IGNORE", $referencesRaw);
                        if (preg_match("/^https/",$references)){
                            $url = str_replace('https://', '', $references);
                            $clonedSheet->getCell($cellG)->getHyperlink()->setUrl('https://'.$url);
                            $clonedSheet->getCell($cellG)->setValue($references);
                        }
                        elseif(preg_match("/^http/",$references)){
                            $url = str_replace('http://', '', $references);
                            $clonedSheet->getCell($cellG)->getHyperlink()->setUrl('http://'.$url);
                            $clonedSheet->getCell($cellG)->setValue($references);
                        }
                        else{
                            $clonedSheet->getCell($cellG)->setValue($references);
                        }
                    }

                    $clonedSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                }

                $cellH="H".$row;
                $clonedSheet->getCell($cellH)->setValue($newTopic['vsys']);

                $cellI="I".$row;
                $clonedSheet->getCell($cellI)->setValue($newTopic['template_name']);

                $clonedSheet->getStyle($cellA.':'.$cellI)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
                $clonedSheet->getStyle($cellA.':'.$cellI)->getFill()->getStartColor()->setARGB($color);
                $clonedSheet->getStyle($cellA.':'.$cellI)->applyFromArray($styleArrayBorders);

                $lastTopic=$newTopic['subtype'];

                $clonedSheet
                    ->getRowDimension($row)
                    ->setOutlineLevel(1)
                    ->setVisible(false)
                    ->setCollapsed(true);

                $row++;
            }

            $clonedSheet->getRowDimension('1')->setRowHeight(30);
            $clonedSheet->getRowDimension('2')->setRowHeight(30);
            $clonedSheet->getColumnDimension('A')->setWidth(30);
            $clonedSheet->getColumnDimension('B')->setWidth(40);
            $clonedSheet->getColumnDimension('C')->setWidth(25);
            $clonedSheet->getColumnDimension('D')->setWidth(40);
            $clonedSheet->getColumnDimension('E')->setWidth(60);
            $clonedSheet->getColumnDimension('F')->setWidth(60);
            $clonedSheet->getColumnDimension('G')->setWidth(40);
            $clonedSheet->getColumnDimension('H')->setWidth(15);
            $clonedSheet->getColumnDimension('I')->setWidth(15);

            $conditionalStyles = $clonedSheet->getStyle('A2')->getConditionalStyles();
            array_push($conditionalStyles, $objConditional1);
            array_push($conditionalStyles, $objConditional2);
            array_push($conditionalStyles, $objConditional3);
            $clonedSheet->getStyle('A2')->setConditionalStyles($conditionalStyles);
            $clonedSheet->duplicateConditionalStyle(
                $clonedSheet->getStyle('A2')->getConditionalStyles(),
                'A3:A'.$row
            );

            $clonedSheet->getRowDimension($row)->setCollapsed(false);

            $clonedSheet->setAutoFilter($objPHPExcel->getActiveSheet()->calculateWorksheetDimension());
            // Set active filters
            $autoFilter = $clonedSheet->getAutoFilter();
            $autoFilter->showHideRows();

        }

    }

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="PaloAltoNetworksBestPractices.xlsx"');
    header('Cache-Control: max-age=0');
    $objPHPExcel->setActiveSheetIndex(0);
    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, 'Excel2007');
    $objWriter->setIncludeCharts(TRUE);
    $objWriter->save('php://output');
}

function generateExcelUnused($projectdb,$source, $vsys){
    // create new PHPExcel object
    $objPHPExcel = new PHPExcel;

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);


// set default font
    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
// set default font size
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

// create the writer
    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");
    /**
     * Define currency and number format.
     */
// currency format, € with < 0 being in red color
    $currencyFormat = '#,#0.## \€;[Red]-#,#0.## \€';
// number format, with thousands separator and two decimal points.
    $numberFormat = '#,#0.##;[Red]-#,#0.##';
// writer already created the first sheet for us, let's get it
    $objSheet = $objPHPExcel->getActiveSheet();

// let's bold and size the header font and write the header
// as you can see, we can specify a range of cells, like here: cells from A1 to A4
    $objSheet->getStyle('A1:D1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:D1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:D1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:D1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:D1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("Unused Objects")
        ->setSubject("Unused Objects")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Unused objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $getAddress=$projectdb->query("SELECT name,ipaddress,description,vsys FROM address WHERE source='$source' $vsys_query AND dummy=0 AND used=0;");
    if ($getAddress->num_rows>0){
        // rename the sheet
        $objSheet->setTitle('Unused Address Objects');
        // write header
        $objSheet->getCell('A1')->setValue('NAME');
        $objSheet->getCell('B1')->setValue('IP ADDRESS');
        $objSheet->getCell('C1')->setValue('DESCRIPTION');
        $objSheet->getCell('D1')->setValue('LOCATION');
        $row=2;
        while($address=$getAddress->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA="A".$row;
            $objSheet->getCell($cellA)->setValue($address['name']);
            $cellB="B".$row;
            $objSheet->getCell($cellB)->setValue($address['ipaddress']);
            $cellC="C".$row;
            $objSheet->getCell($cellC)->setValue($address['description']);
            $cellD="D".$row;
            $objSheet->getCell($cellD)->setValue($address['vsys']);

            $objSheet->getStyle($cellA.':'.$cellD)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellD)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }
        // autosize the columns
        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        //$objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setWidth(100);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
    }


    // Address Groups

    $getAddress=$projectdb->query("SELECT id,name,description,vsys FROM address_groups_id WHERE source='$source' $vsys_query AND used=0;");
    if ($getAddress->num_rows>0){
        $clonedSheet = $objPHPExcel->createSheet();
        // Rename cloned worksheet
        $clonedSheet->setTitle('Unused Address Groups');
        // write header
        $clonedSheet->getCell('A1')->setValue('NAME');
        $clonedSheet->getCell('B1')->setValue('MEMBERS');
        $clonedSheet->getCell('C1')->setValue('DESCRIPTION');
        $clonedSheet->getCell('D1')->setValue('LOCATION');

        $clonedSheet->getStyle('A1:D1')->getFont()->setBold(true)->setSize(12);
        $clonedSheet->getStyle('A1:D1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
        $clonedSheet->getStyle('A1:D1')->getFill()->getStartColor()->setARGB('d3dfea');
        $clonedSheet->getStyle('A1:D1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
        $clonedSheet->getStyle('A1:D1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

        $clonedSheet->freezePane('A2');

        $row=2;
        while($address=$getAddress->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA="A".$row;
            $clonedSheet->getCell($cellA)->setValue($address['name']);
            $cellB="B".$row;
            $grouplid=$address['id'];
            $getMembers=$projectdb->query("SELECT member_lid,table_name FROM address_groups WHERE lid='$grouplid';");
            if ($getMembers->num_rows>0){
                $members=array();
                while($getMembersData=$getMembers->fetch_assoc()){
                    $tablename=$getMembersData['table_name'];
                    $memberlid=$getMembersData['member_lid'];
                    $getMembersName=$projectdb->query("SELECT name FROM $tablename WHERE id='$memberlid';");
                    if ($getMembersName->num_rows==1){
                        $getMembersNameData=$getMembersName->fetch_assoc();
                        $members[]=$getMembersNameData['name'];
                    }
                }
                if (count($members)>0){
                    $members=implode("\n",$members);
                    $clonedSheet->getCell($cellB)->setValue($members);
                    $clonedSheet->getStyle($cellB)->getAlignment()->setWrapText(true);
                }
            }

            $cellC="C".$row;
            $clonedSheet->getCell($cellC)->setValue($address['description']);
            $cellD="D".$row;
            $clonedSheet->getCell($cellD)->setValue($address['vsys']);

            $clonedSheet->getStyle($cellA.':'.$cellD)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $clonedSheet->getStyle($cellA.':'.$cellD)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }
        // autosize the columns
        $clonedSheet->getRowDimension('1')->setRowHeight(30);
        $clonedSheet->getColumnDimension('A')->setAutoSize(true);
        $clonedSheet->getColumnDimension('B')->setAutoSize(true);
        //$clonedSheet->getColumnDimension('C')->setAutoSize(true);
        $clonedSheet->getColumnDimension('C')->setWidth(100);
        $clonedSheet->getColumnDimension('D')->setAutoSize(true);
    }


    // Services

    $getAddress=$projectdb->query("SELECT id,name,description,vsys,protocol,dport FROM services WHERE source='$source' $vsys_query AND dummy=0 AND used=0 AND devicegroup!='predefined';");
    if ($getAddress->num_rows>0){
        $clonedSheet = $objPHPExcel->createSheet();
        // Rename cloned worksheet
        $clonedSheet->setTitle('Unused Services Objects');
        // write header
        $clonedSheet->getCell('A1')->setValue('NAME');
        $clonedSheet->getCell('B1')->setValue('PROTOCOL');
        $clonedSheet->getCell('C1')->setValue('DESTINATION PORT');
        $clonedSheet->getCell('D1')->setValue('DESCRIPTION');
        $clonedSheet->getCell('E1')->setValue('LOCATION');

        $clonedSheet->getStyle('A1:E1')->getFont()->setBold(true)->setSize(12);
        $clonedSheet->getStyle('A1:E1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
        $clonedSheet->getStyle('A1:E1')->getFill()->getStartColor()->setARGB('d3dfea');
        $clonedSheet->getStyle('A1:E1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
        $clonedSheet->getStyle('A1:E1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

        $clonedSheet->freezePane('A2');

        $row=2;
        while($address=$getAddress->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA="A".$row;
            $clonedSheet->getCell($cellA)->setValue($address['name']);
            $cellB="B".$row;
            $clonedSheet->getCell($cellB)->setValue($address['protocol']);
            $cellC="C".$row;
            $clonedSheet->getCell($cellC)->setValue($address['dport']);
            $cellD="D".$row;
            $clonedSheet->getCell($cellD)->setValue($address['description']);
            $cellE="E".$row;
            $clonedSheet->getCell($cellE)->setValue($address['vsys']);

            $clonedSheet->getStyle($cellA.':'.$cellE)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $clonedSheet->getStyle($cellA.':'.$cellE)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }
        // autosize the columns
        $clonedSheet->getRowDimension('1')->setRowHeight(30);
        $clonedSheet->getColumnDimension('A')->setAutoSize(true);
        $clonedSheet->getColumnDimension('B')->setAutoSize(true);
        $clonedSheet->getColumnDimension('C')->setAutoSize(true);
        //$clonedSheet->getColumnDimension('D')->setAutoSize(true);
        $clonedSheet->getColumnDimension('D')->setWidth(100);
        $clonedSheet->getColumnDimension('E')->setAutoSize(true);
    }


    // Services Groups

    $getAddress=$projectdb->query("SELECT id,name,description,vsys FROM services_groups_id WHERE source='$source' $vsys_query AND used=0;");
    if ($getAddress->num_rows>0){
        $clonedSheet = $objPHPExcel->createSheet();
        // Rename cloned worksheet
        $clonedSheet->setTitle('Unused Services Groups');
        // write header
        $clonedSheet->getCell('A1')->setValue('NAME');
        $clonedSheet->getCell('B1')->setValue('MEMBERS');
        $clonedSheet->getCell('C1')->setValue('DESCRIPTION');
        $clonedSheet->getCell('D1')->setValue('LOCATION');

        $clonedSheet->getStyle('A1:D1')->getFont()->setBold(true)->setSize(12);
        $clonedSheet->getStyle('A1:D1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
        $clonedSheet->getStyle('A1:D1')->getFill()->getStartColor()->setARGB('d3dfea');
        $clonedSheet->getStyle('A1:D1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
        $clonedSheet->getStyle('A1:D1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

        $clonedSheet->freezePane('A2');

        $row=2;
        while($address=$getAddress->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA="A".$row;
            $clonedSheet->getCell($cellA)->setValue($address['name']);
            $cellB="B".$row;
            $grouplid=$address['id'];
            $getMembers=$projectdb->query("SELECT member_lid,table_name FROM services_groups WHERE lid='$grouplid';");
            if ($getMembers->num_rows>0){
                $members=array();
                while($getMembersData=$getMembers->fetch_assoc()){
                    $tablename=$getMembersData['table_name'];
                    $memberlid=$getMembersData['member_lid'];
                    $getMembersName=$projectdb->query("SELECT name FROM $tablename WHERE id='$memberlid';");
                    if ($getMembersName->num_rows==1){
                        $getMembersNameData=$getMembersName->fetch_assoc();
                        $members[]=$getMembersNameData['name'];
                    }
                }
                if (count($members)>0){
                    $members=implode("\n",$members);
                    $clonedSheet->getCell($cellB)->setValue($members);
                    $clonedSheet->getStyle($cellB)->getAlignment()->setWrapText(true);
                }
            }
            $cellC="C".$row;
            $clonedSheet->getCell($cellC)->setValue($address['description']);
            $cellD="D".$row;
            $clonedSheet->getCell($cellD)->setValue($address['vsys']);

            $clonedSheet->getStyle($cellA.':'.$cellD)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $clonedSheet->getStyle($cellA.':'.$cellD)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }
        // autosize the columns
        $clonedSheet->getRowDimension('1')->setRowHeight(30);
        $clonedSheet->getColumnDimension('A')->setAutoSize(true);
        $clonedSheet->getColumnDimension('B')->setAutoSize(true);
        //$clonedSheet->getColumnDimension('C')->setAutoSize(true);
        $clonedSheet->getColumnDimension('C')->setWidth(100);
        $clonedSheet->getColumnDimension('D')->setAutoSize(true);
    }

    // Applications

    $getAddress=$projectdb->query("SELECT name, description, vsys, risk FROM applications WHERE source='$source' $vsys_query AND dummy=0 AND used=0 AND devicegroup!='predefined';");
    if ($getAddress->num_rows>0){
        $clonedSheet = $objPHPExcel->createSheet();
        // Rename cloned worksheet
        $clonedSheet->setTitle('Unused Applications Objects');
        // write header
        $clonedSheet->getCell('A1')->setValue('NAME');
        $clonedSheet->getCell('B1')->setValue('RISK');
        $clonedSheet->getCell('C1')->setValue('DESCRIPTION');
        $clonedSheet->getCell('D1')->setValue('LOCATION');

        $clonedSheet->getStyle('A1:D1')->getFont()->setBold(true)->setSize(12);
        $clonedSheet->getStyle('A1:D1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
        $clonedSheet->getStyle('A1:D1')->getFill()->getStartColor()->setARGB('d3dfea');
        $clonedSheet->getStyle('A1:D1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
        $clonedSheet->getStyle('A1:D1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

        $clonedSheet->freezePane('A2');

        $row=2;
        while($address=$getAddress->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA="A".$row;
            $clonedSheet->getCell($cellA)->setValue($address['name']);
            $cellB="B".$row;
            $clonedSheet->getCell($cellB)->setValue($address['risk']);
            $cellC="C".$row;
            $clonedSheet->getCell($cellC)->setValue($address['description']);
            $cellD="D".$row;
            $clonedSheet->getCell($cellD)->setValue($address['vsys']);

            $clonedSheet->getStyle($cellA.':'.$cellD)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $clonedSheet->getStyle($cellA.':'.$cellD)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }
        // autosize the columns
        $clonedSheet->getRowDimension('1')->setRowHeight(30);
        $clonedSheet->getColumnDimension('A')->setAutoSize(true);
        $clonedSheet->getColumnDimension('B')->setAutoSize(true);
        //$clonedSheet->getColumnDimension('C')->setAutoSize(true);
        $clonedSheet->getColumnDimension('C')->setWidth(100);
        $clonedSheet->getColumnDimension('D')->setAutoSize(true);
    }

    // Applications Filters

    $getAddress=$projectdb->query("SELECT name, vsys FROM applications_filters WHERE source='$source' $vsys_query AND dummy=0 AND used=0 AND devicegroup!='predefined';");
    if ($getAddress->num_rows>0){
        $clonedSheet = $objPHPExcel->createSheet();
        // Rename cloned worksheet
        $clonedSheet->setTitle('Unused Applications Filters');
        // write header
        $clonedSheet->getCell('A1')->setValue('NAME');
        $clonedSheet->getCell('B1')->setValue('LOCATION');

        $clonedSheet->getStyle('A1:B1')->getFont()->setBold(true)->setSize(12);
        $clonedSheet->getStyle('A1:B1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
        $clonedSheet->getStyle('A1:B1')->getFill()->getStartColor()->setARGB('d3dfea');
        $clonedSheet->getStyle('A1:B1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
        $clonedSheet->getStyle('A1:B1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

        $clonedSheet->freezePane('A2');

        $row=2;
        while($address=$getAddress->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA="A".$row;
            $clonedSheet->getCell($cellA)->setValue($address['name']);
            $cellB="B".$row;
            $clonedSheet->getCell($cellB)->setValue($address['vsys']);

            $clonedSheet->getStyle($cellA.':'.$cellB)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $clonedSheet->getStyle($cellA.':'.$cellB)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }
        // autosize the columns
        $clonedSheet->getRowDimension('1')->setRowHeight(30);
        $clonedSheet->getColumnDimension('A')->setAutoSize(true);
        $clonedSheet->getColumnDimension('B')->setAutoSize(true);
    }


    // Applications Groups

    $getAddress=$projectdb->query("SELECT id,name,description,vsys FROM applications_groups_id WHERE source='$source' $vsys_query AND used=0;");
    if ($getAddress->num_rows>0){
        $clonedSheet = $objPHPExcel->createSheet();
        // Rename cloned worksheet
        $clonedSheet->setTitle('Unused Applications Groups');
        // write header
        $clonedSheet->getCell('A1')->setValue('NAME');
        $clonedSheet->getCell('B1')->setValue('MEMBERS');
        $clonedSheet->getCell('C1')->setValue('DESCRIPTION');
        $clonedSheet->getCell('D1')->setValue('LOCATION');

        $clonedSheet->getStyle('A1:D1')->getFont()->setBold(true)->setSize(12);
        $clonedSheet->getStyle('A1:D1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
        $clonedSheet->getStyle('A1:D1')->getFill()->getStartColor()->setARGB('d3dfea');
        $clonedSheet->getStyle('A1:D1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
        $clonedSheet->getStyle('A1:D1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

        $clonedSheet->freezePane('A2');

        $row=2;
        while($address=$getAddress->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA="A".$row;
            $clonedSheet->getCell($cellA)->setValue($address['name']);
            $cellB="B".$row;
            $grouplid=$address['id'];
            $getMembers=$projectdb->query("SELECT member_lid,table_name FROM applications_groups WHERE lid='$grouplid';");
            if ($getMembers->num_rows>0){
                $members=array();
                while($getMembersData=$getMembers->fetch_assoc()){
                    $tablename=$getMembersData['table_name'];
                    $memberlid=$getMembersData['member_lid'];
                    $getMembersName=$projectdb->query("SELECT name FROM $tablename WHERE id='$memberlid';");
                    if ($getMembersName->num_rows==1){
                        $getMembersNameData=$getMembersName->fetch_assoc();
                        $members[]=$getMembersNameData['name'];
                    }
                }
                if (count($members)>0){
                    $members=implode("\n",$members);
                    $clonedSheet->getCell($cellB)->setValue($members);
                    $clonedSheet->getStyle($cellB)->getAlignment()->setWrapText(true);
                }
            }
            $cellC="C".$row;
            $clonedSheet->getCell($cellC)->setValue($address['description']);
            $cellD="D".$row;
            $clonedSheet->getCell($cellD)->setValue($address['vsys']);

            $clonedSheet->getStyle($cellA.':'.$cellD)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $clonedSheet->getStyle($cellA.':'.$cellD)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }
        // autosize the columns
        $clonedSheet->getRowDimension('1')->setRowHeight(30);
        $clonedSheet->getColumnDimension('A')->setAutoSize(true);
        $clonedSheet->getColumnDimension('B')->setAutoSize(true);
        //$clonedSheet->getColumnDimension('C')->setAutoSize(true);
        $clonedSheet->getColumnDimension('C')->setWidth(100);
        $clonedSheet->getColumnDimension('D')->setAutoSize(true);
    }


// Set active sheet index to the first sheet, so Excel opens this as the first sheet
    $objPHPExcel->setActiveSheetIndex(0);
//Setting the header type
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_unused_objects.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelAddress($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:H1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:H1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:H1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:H1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:H1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("ADDRESS")
        ->setSubject("ADDRESS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Address objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "address", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, IF (used = '1', 'Used', 'Unused') AS used, name, ipaddress, cidr, description, vsys FROM address a $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('USED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('IP ADDRESS');
        $objSheet->getCell('E1')->setValue('CIDR');
        $objSheet->getCell('F1')->setValue('DESCRIPTION');
        $objSheet->getCell('G1')->setValue('TAG');
        $objSheet->getCell('H1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            //$color = "eaeff2";
            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $lid = $dataA['id'];

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['used']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['ipaddress']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['cidr']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['description']);

            $cellG = "G".$row;
            $getMembers = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$lid' AND table_name = 'address' ;");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){

                    $tag_id = $getMembersData['tag_id'];
                    $getMembersName = $projectdb->query("SELECT name FROM tag WHERE id = '$tag_id';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellG)->setValue($members);
                    $objSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                }
            }

            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellH)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellH)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        //$objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setWidth(100);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_address.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelAddressGroups($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");
    $currencyFormat = '#,#0.## \€;[Red]-#,#0.## \€';
    $numberFormat = '#,#0.##;[Red]-#,#0.##';

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:G1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:G1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:G1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:G1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:G1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("ADDRESS GROUPS")
        ->setSubject("ADDRESS GROUPS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Address Groups objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "address_groups_id", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, name, description, vsys, IF (used = '1', 'Used', 'Unused') AS used FROM address_groups_id a $conditions $orderby;");
    //echo "SELECT id, name, description, vsys, used FROM address_groups_id $conditions $orderby;";

    if ($getData->num_rows>0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('USED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('MEMBERS');
        $objSheet->getCell('E1')->setValue('DESCRIPTION');
        $objSheet->getCell('F1')->setValue('TAG');
        $objSheet->getCell('G1')->setValue('LOCATION');
        $objSheet->getStyle('A1:G1')->getFont()->setBold(true)->setSize(12);

        $row = 2;

        while($dataA = $getData->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $lid = $dataA['id'];

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['used']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $grouplid = $dataA['id'];

            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid = '$grouplid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellD)->setValue($members);
                    $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
                }
            }

            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['description']);

            $cellF = "F".$row;
            $getMembers = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$lid' AND table_name = 'address_groups_id' ;");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){

                    $tag_id = $getMembersData['tag_id'];
                    $getMembersName = $projectdb->query("SELECT name FROM tag WHERE id = '$tag_id';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellF)->setValue($members);
                    $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                }
            }

            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        //$objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setWidth(100);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_address_groups.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelServices($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:H1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:H1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:H1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:H1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:H1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("SERVICES")
        ->setSubject("SERVICES")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Services objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "services", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, IF (used = '1', 'Used', 'Unused') AS used, id, name, description, vsys, protocol, dport FROM services a $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('USED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('PROTOCOL');
        $objSheet->getCell('E1')->setValue('DESTINATION PORT');
        $objSheet->getCell('F1')->setValue('DESCRIPTION');
        $objSheet->getCell('G1')->setValue('TAG');
        $objSheet->getCell('H1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $lid = $dataA['id'];

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['used']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['protocol']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['dport']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['description']);

            $cellG = "G".$row;
            $getMembers = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$lid' AND table_name = 'services' ;");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){

                    $tag_id = $getMembersData['tag_id'];
                    $getMembersName = $projectdb->query("SELECT name FROM tag WHERE id = '$tag_id';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellG)->setValue($members);
                    $objSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                }
            }

            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellH)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellH)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        //$objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setWidth(100);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_services.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelServicesGroups($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:G1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:G1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:G1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:G1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:G1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("SERVICES GROUPS")
        ->setSubject("SERVICES GROUPS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Services Groups objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "services_groups_id", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, name, description, vsys, IF (used = '1', 'Used', 'Unused') AS used FROM services_groups_id a $conditions $orderby;");
    //echo "SELECT id, name, description, vsys, used FROM address_groups_id $conditions $orderby;";

    if ($getData->num_rows>0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('USED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('MEMBERS');
        $objSheet->getCell('E1')->setValue('DESCRIPTION');
        $objSheet->getCell('F1')->setValue('TAG');
        $objSheet->getCell('G1')->setValue('LOCATION');
        //$objSheet->getStyle('A1:G1')->getFont()->setBold(true)->setSize(12);

        $row = 2;

        while($dataA = $getData->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $lid = $dataA['id'];

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['used']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $grouplid = $dataA['id'];

            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM services_groups WHERE lid = '$grouplid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellD)->setValue($members);
                    $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
                }
            }

            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['description']);

            $cellF = "F".$row;
            $getMembers = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$lid' AND table_name = 'services_groups_id' ;");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){

                    $tag_id = $getMembersData['tag_id'];
                    $getMembersName = $projectdb->query("SELECT name FROM tag WHERE id = '$tag_id';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellF)->setValue($members);
                    $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                }
            }

            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        //$objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setWidth(100);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_services_groups.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelApplications($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:G1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:G1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:G1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:G1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:G1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("APPLICATIONS")
        ->setSubject("APPLICATIONS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Applications objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "applications", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, IF (used = '1', 'Used', 'Unused') AS used, risk, name, description, vsys FROM applications a $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('USED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('RISK');
        $objSheet->getCell('E1')->setValue('DESCRIPTION');
        $objSheet->getCell('F1')->setValue('TAG');
        $objSheet->getCell('G1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }
            else{$color = "f1f1f1";}

            $lid = $dataA['id'];

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['used']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['risk']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['description']);

            $cellF = "F".$row;
            $getMembers = $projectdb->query("SELECT tag_id FROM tag_relations WHERE member_lid = '$lid' AND table_name = 'applications' ;");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){

                    $tag_id = $getMembersData['tag_id'];
                    $getMembersName = $projectdb->query("SELECT name FROM tag WHERE id = '$tag_id';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellF)->setValue($members);
                    $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                }
            }

            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        //$objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setWidth(100);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_applications.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelApplicationsFilters($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:D1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:D1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:D1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:D1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:D1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("APPLICATIONS")
        ->setSubject("APPLICATIONS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Applications Filters objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "applications_filters", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, IF (used = '1', 'Used', 'Unused') AS used, name, vsys FROM applications_filters a $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('USED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['used']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellD)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellD)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_applications_filters.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelApplicationsGroups($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:F1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:F1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:F1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:F1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:F1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("APPLICATIONS GROUPS")
        ->setSubject("APPLICATIONS GROUPS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Applications Groups objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "applications_groups_id", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, name, description, vsys, IF (used = '1', 'Used', 'Unused') AS used FROM applications_groups_id a $conditions $orderby;");

    if ($getData->num_rows>0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('USED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('MEMBERS');
        $objSheet->getCell('E1')->setValue('DESCRIPTION');
        $objSheet->getCell('F1')->setValue('LOCATION');
        $objSheet->getStyle('A1:F1')->getFont()->setBold(true)->setSize(12);

        $row = 2;

        while($dataA = $getData->fetch_assoc()){

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['used']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $grouplid = $dataA['id'];

            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM applications_groups WHERE lid = '$grouplid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellD)->setValue($members);
                    $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
                }
            }

            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['description']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellF)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellF)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        //$objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setWidth(100);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_applications_groups.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelRegions($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:G1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:G1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:G1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:G1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:G1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("REGIONS")
        ->setSubject("REGIONS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Regions objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "regions", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, IF (used = '1', 'Used', 'Unused') AS used, name, address, latitude, longitude, vsys FROM regions a $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('USED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('IP');
        $objSheet->getCell('E1')->setValue('LATITUDE');
        $objSheet->getCell('F1')->setValue('LONGITUDE');
        $objSheet->getCell('G1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            //$color = "eaeff2";
            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['used']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['address']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['latitude']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['longitude']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_regions.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelTags($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:E1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:E1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:E1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:E1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:E1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("TAGS")
        ->setSubject("TAGS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Tags objects paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "tag", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, color, name, comments, vsys FROM tag a $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('COLOR');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('COMMENTS');
        $objSheet->getCell('E1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['color']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['comments']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellE)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellE)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_tags.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelSecurityRules($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");
    $currencyFormat = '#,#0.## \€;[Red]-#,#0.## \€';
    $numberFormat = '#,#0.##;[Red]-#,#0.##';

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:T1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:T1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:T1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:T1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:T1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);
    //$objSheet->getStyle('A1:K1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_PATTERN_MEDIUMGRAY);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("Expedition")
        ->setLastModifiedBy("Expedition")
        ->setTitle("SECURITY RULES")
        ->setSubject("SECURITY RULES")
        ->setDescription("Report generated by Expedition from Palo Alto Networks.")
        ->setKeywords("Expedition Tool security rules paloalto")
        ->setCategory("Expedition Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query";
    list($conditions, $orderby) = generateQueryFilters($project, "security_rules", "", $conditions, $source);

    $orderby = " ORDER BY position,preorpost ";

    $getData = $projectdb->query("SELECT id, name, action, description, IF (disabled = '1', 'True', 'False') AS disabled, vsys, target as chk_target, profile_type 
    FROM security_rules $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('DISABLED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('ACTION');
        $objSheet->getCell('E1')->setValue('DESCRIPTION');
        $objSheet->getCell('F1')->setValue('TAG');
        $objSheet->getCell('G1')->setValue('FROM');
        $objSheet->getCell('H1')->setValue('SOURCE');
        $objSheet->getCell('I1')->setValue('TO');
        $objSheet->getCell('J1')->setValue('DESTINATION');
        $objSheet->getCell('K1')->setValue('APPLICATION');
        $objSheet->getCell('L1')->setValue('SERVICE');
        $objSheet->getCell('M1')->setValue('APPLICATION FROM LOG');
        $objSheet->getCell('N1')->setValue('LOCATION');
        $objSheet->getCell('O1')->setValue('USER');
        $objSheet->getCell('P1')->setValue('CATEGORY');
        $objSheet->getCell('Q1')->setValue('PROFILE TYPE');
        $objSheet->getCell('R1')->setValue('PROFILE');
        $objSheet->getCell('S1')->setValue('TARGET');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()){

            $lid = $dataA['id'];

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['disabled']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['action']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['description']);

            $cellF = "F".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_tag WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellF)->setValue($members);
                    $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                }
            }

            $cellG = "G".$row;
            $getMembers = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $members[] = $getMembersData['name'];
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellG)->setValue($members);
                    $objSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                }
            }

            $cellH = "H".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellH)->setValue($members);
                    $objSheet->getStyle($cellH)->getAlignment()->setWrapText(true);
                }
            }

            $cellI = "I".$row;
            $getMembers = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $members[] = $getMembersData['name'];
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellI)->setValue($members);
                    $objSheet->getStyle($cellI)->getAlignment()->setWrapText(true);
                }
            }

            $cellJ = "J".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellJ)->setValue($members);
                    $objSheet->getStyle($cellJ)->getAlignment()->setWrapText(true);
                }
            }

            $cellK = "K".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellK)->setValue($members);
                    $objSheet->getStyle($cellK)->getAlignment()->setWrapText(true);
                }
            }

            $cellL = "L".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellL)->setValue($members);
                    $objSheet->getStyle($cellL)->getAlignment()->setWrapText(true);
                }
            }

            $cellM = "M".$row;
            $getMembers = $projectdb->query("SELECT app, dport, bytes , packets, proto FROM applications_from_log WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $app = $getMembersData['app'];
                    $dport = $getMembersData['dport'];
                    $proto = $getMembersData['proto'];
                    $members[] = $app." (".$proto."/".$dport.")";
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellM)->setValue($members);
                    $objSheet->getStyle($cellM)->getAlignment()->setWrapText(true);
                }
            }

            $cellN = "N".$row;
            $objSheet->getCell($cellN)->setValue($dataA['vsys']);

            $cellO = "O".$row;
            $getMembers = $projectdb->query("SELECT name FROM security_rules_usr WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $members[] = $getMembersData['name'];
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellO)->setValue($members);
                    $objSheet->getStyle($cellO)->getAlignment()->setWrapText(true);
                }
            }

            $cellP = "P".$row;
            $getMembers = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $members[] = $getMembersData['name'];
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellP)->setValue($members);
                    $objSheet->getStyle($cellP)->getAlignment()->setWrapText(true);
                }
            }

            $cellQ = "Q".$row;
            if($dataA['profile_type'] == "profiles"){

                $getMembers = $projectdb->query("SELECT type FROM security_rules_profiles WHERE rule_lid = '$lid';");

                if ($getMembers->num_rows>0){
                    $members = array();
                    while($getMembersData = $getMembers->fetch_assoc()){
                        $members[] = $getMembersData['type'];
                    }
                    if (count($members) > 0){
                        $members = implode("\n",$members);
                        $objSheet->getCell($cellQ)->setValue($members);
                        $objSheet->getStyle($cellQ)->getAlignment()->setWrapText(true);
                    }
                }
            }else{
                $objSheet->getCell($cellQ)->setValue($dataA['profile_type']);
            }
            
            $cellR = "R".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name, type FROM security_rules_profiles WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    //$type_profile = "";
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];

                    /*if($getMembersData['type'] != ""){
                        $type_profile = " (".$getMembersData['type'].") ";
                    }*/
                    if($memberlid != 0){
                        $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                        if ($getMembersName->num_rows == 1){
                            $getMembersNameData = $getMembersName->fetch_assoc();
                            //$members[] = $getMembersNameData['name'] . $type_profile;
                            $members[] = $getMembersNameData['name'];
                        }
                    }else{
                        $members[] = "None";
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellR)->setValue($members);
                    $objSheet->getStyle($cellR)->getAlignment()->setWrapText(true);
                }
            }

            $cellS = "S".$row;
            $getMembers = $projectdb->query("SELECT name,device_vsys FROM security_rules_target WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    if (($getMembersData['device_vsys']!="") OR ($getMembersData['device_vsys']!= null)){
                        $members[] = $getMembersData['name']."/".$getMembersData['device_vsys'];
                    }
                    else{
                        $members[] = $getMembersData['name'];
                    }

                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellS)->setValue($members);
                    $objSheet->getStyle($cellS)->getAlignment()->setWrapText(true);
                }
            }

            $cellT = "T".$row;
            $objSheet->getCell($cellT)->setValue($dataA['chk_target']);

            $objSheet->getStyle($cellA.':'.$cellT)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellT)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        //$objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setWidth(90);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
        $objSheet->getColumnDimension('M')->setAutoSize(true);
        $objSheet->getColumnDimension('N')->setAutoSize(true);
        $objSheet->getColumnDimension('O')->setAutoSize(true);
        $objSheet->getColumnDimension('P')->setAutoSize(true);
        $objSheet->getColumnDimension('Q')->setAutoSize(true);
        $objSheet->getColumnDimension('R')->setAutoSize(true);
        $objSheet->getColumnDimension('S')->setAutoSize(true);
        $objSheet->getColumnDimension('T')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_security_rules.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelSecurityRulesConsolidation($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");
    $currencyFormat = '#,#0.## \€;[Red]-#,#0.## \€';
    $numberFormat = '#,#0.##;[Red]-#,#0.##';

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:R1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:R1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:R1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:R1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:R1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);
    //$objSheet->getStyle('A1:K1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_PATTERN_MEDIUMGRAY);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("Expedition")
        ->setLastModifiedBy("Expedition")
        ->setTitle("SECURITY RULES CONSOLIDATION")
        ->setSubject("SECURITY RULES CONSOLIDATION")
        ->setDescription("Report generated by Expedition from Palo Alto Networks.")
        ->setKeywords("Expedition Tool security rules paloalto")
        ->setCategory("Expedition Reports");


    $getConsolidation = $projectdb->query("SELECT filter_hash, rules_lid FROM hash_rules WHERE source = '$source' AND table_name = 'security_rules';");

    if ($getConsolidation->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('DISABLED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('ACTION');
        $objSheet->getCell('E1')->setValue('DESCRIPTION');
        $objSheet->getCell('F1')->setValue('TAG');
        $objSheet->getCell('G1')->setValue('FROM');
        $objSheet->getCell('H1')->setValue('SOURCE');
        $objSheet->getCell('I1')->setValue('TO');
        $objSheet->getCell('J1')->setValue('DESTINATION');
        $objSheet->getCell('K1')->setValue('APPLICATION');
        $objSheet->getCell('L1')->setValue('SERVICE');
        $objSheet->getCell('M1')->setValue('APPLICATION FROM LOG');
        $objSheet->getCell('N1')->setValue('LOCATION');
        $objSheet->getCell('O1')->setValue('USER');
        $objSheet->getCell('P1')->setValue('CATEGORY');
        $objSheet->getCell('Q1')->setValue('TARGET');

        $row = 2;

        while ($dataCon = $getConsolidation->fetch_assoc()){

            $rules_lid = $dataCon['rules_lid'];

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataCon['filter_hash']);
            $objSheet->getStyle(''.$cellA.':R'.$row.'')->getFont()->setBold(true)->setSize(12);
            $objSheet->getStyle(''.$cellA.':R'.$row.'')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle(''.$cellA.':R'.$row.'')->getFill()->getStartColor()->setARGB('CCCCCC');

            $row++;

            $getData = $projectdb->query("SELECT id, name, action, description, IF (disabled = '1', 'True', 'False') AS disabled, vsys, target as chk_target 
              FROM security_rules WHERE id IN ($rules_lid) ORDER BY position,preorpost;");

            if ($getData->num_rows > 0){

                while ($dataA = $getData->fetch_assoc()){

                    $lid = $dataA['id'];

                    if($row % 2 == 0){$color = "ffffff";
                    }else{$color = "f1f1f1";}

                    $cellA = "A".$row;
                    $objSheet->getCell($cellA)->setValue($dataA['id']);
                    $cellB = "B".$row;
                    $objSheet->getCell($cellB)->setValue($dataA['disabled']);
                    $cellC = "C".$row;
                    $objSheet->getCell($cellC)->setValue($dataA['name']);
                    $cellD = "D".$row;
                    $objSheet->getCell($cellD)->setValue($dataA['action']);
                    $cellE = "E".$row;
                    $objSheet->getCell($cellE)->setValue($dataA['description']);

                    $cellF = "F".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_tag WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellF)->setValue($members);
                            $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellG = "G".$row;
                    $getMembers = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $members[] = $getMembersData['name'];
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellG)->setValue($members);
                            $objSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellH = "H".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellH)->setValue($members);
                            $objSheet->getStyle($cellH)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellI = "I".$row;
                    $getMembers = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $members[] = $getMembersData['name'];
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellI)->setValue($members);
                            $objSheet->getStyle($cellI)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellJ = "J".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellJ)->setValue($members);
                            $objSheet->getStyle($cellJ)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellK = "K".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellK)->setValue($members);
                            $objSheet->getStyle($cellK)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellL = "L".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellL)->setValue($members);
                            $objSheet->getStyle($cellL)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellM = "M".$row;
                    $getMembers = $projectdb->query("SELECT app, dport, bytes , packets, proto FROM applications_from_log WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $app = $getMembersData['app'];
                            $dport = $getMembersData['dport'];
                            $proto = $getMembersData['proto'];
                            $members[] = $app." (".$proto."/".$dport.")";
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellM)->setValue($members);
                            $objSheet->getStyle($cellM)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellN = "N".$row;
                    $objSheet->getCell($cellN)->setValue($dataA['vsys']);

                    $cellO = "O".$row;
                    $getMembers = $projectdb->query("SELECT name FROM security_rules_usr WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $members[] = $getMembersData['name'];
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellO)->setValue($members);
                            $objSheet->getStyle($cellO)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellP = "P".$row;
                    $getMembers = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $members[] = $getMembersData['name'];
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellP)->setValue($members);
                            $objSheet->getStyle($cellP)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellQ = "Q".$row;
                    $getMembers = $projectdb->query("SELECT name,device_vsys FROM security_rules_target WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            if (($getMembersData['device_vsys']!="") OR ($getMembersData['device_vsys']!= null)){
                                $members[] = $getMembersData['name']."/".$getMembersData['device_vsys'];
                            }
                            else{
                                $members[] = $getMembersData['name'];
                            }

                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellQ)->setValue($members);
                            $objSheet->getStyle($cellQ)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellR = "R".$row;
                    $objSheet->getCell($cellR)->setValue($dataA['chk_target']);

                    $objSheet->getStyle($cellA.':'.$cellR)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
                    $objSheet->getStyle($cellA.':'.$cellR)->getFill()->getStartColor()->setARGB($color);

                    $row++;
                }

            }

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        //$objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setWidth(90);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
        $objSheet->getColumnDimension('M')->setAutoSize(true);
        $objSheet->getColumnDimension('N')->setAutoSize(true);
        $objSheet->getColumnDimension('O')->setAutoSize(true);
        $objSheet->getColumnDimension('P')->setAutoSize(true);
        $objSheet->getColumnDimension('Q')->setAutoSize(true);
        $objSheet->getColumnDimension('R')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_security_rules_consolidation.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}

function generateExcelSecurityRulesConsolidationComplete($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");
    $currencyFormat = '#,#0.## \€;[Red]-#,#0.## \€';
    $numberFormat = '#,#0.##;[Red]-#,#0.##';

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:R1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:R1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:R1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:R1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:R1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);
    //$objSheet->getStyle('A1:K1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_PATTERN_MEDIUMGRAY);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("Expedition")
        ->setLastModifiedBy("Expedition")
        ->setTitle("SECURITY RULES CONSOLIDATION (contextualized)")
        ->setSubject("SECURITY RULES CONSOLIDATION (contextualized)")
        ->setDescription("Report generated by Expedition from Palo Alto Networks.")
        ->setKeywords("Expedition Tool security rules paloalto")
        ->setCategory("Expedition Reports");

    /* @var $projectdb mysqli */
    $mergeableIds = array();
    $mergeableRules = array();
    $mergeableCasesByID = array();
    $mergeableCasesByName = array();

    $getConsolidation = $projectdb->query("SELECT filter_hash, rules_lid FROM hash_rules WHERE source = '$source' AND table_name = 'security_rules';");
    if ($getConsolidation->num_rows > 0){
        while ($dataCon = $getConsolidation->fetch_assoc()) {
            $mergeableRules[] = $dataCon;
            $rules_lid = $dataCon['rules_lid'];
            foreach(explode(",",$rules_lid) as $rule_lid){
                $mergeableCasesByID[$rule_lid] = $dataCon['filter_hash'];
                $mergeableCasesByName[$dataCon['filter_hash']][]=$rule_lid;
            }
            $mergeableIds = array_merge($mergeableIds, explode(",",$rules_lid));
        }
    }
    if($vsys='all'){
        $query = "select vsys from security_rules where id in (SELECT rules_lid FROM hash_rules WHERE source = '$source' AND table_name = 'security_rules');";
        $vsysResult = $projectdb->query($query);
        $vsyses = array();
        if($vsysResult->num_rows>0){
            while($data = $vsysResult->fetch_assoc()){
                $vsyses[] = '"'.$data['vsys'].'"';
            }
        }
        else{
            $vsyses[] = '';
        }
    }

    $allTheRulesQuery = "SELECT id, name, action, description, IF (disabled = '1', 'True', 'False') AS disabled, vsys, target as chk_target 
              FROM security_rules WHERE source='$source' AND vsys in (".implode(",",$vsyses).") ORDER BY position,preorpost";

    $results= $projectdb->query($allTheRulesQuery);
    $allRules = array();
    if($results->num_rows > 0 ){
        while($data=$results->fetch_assoc()){
            $data['mergeable'] = in_array($data['id'], $mergeableIds)?1:0;
            $data['processed'] = 0;
            $allRules[$data['id']] = $data;
        }
    }

    $getConsolidation = $projectdb->query("SELECT filter_hash, rules_lid FROM hash_rules WHERE source = '$source' AND table_name = 'security_rules';");

    if ($getConsolidation->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('DISABLED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('ACTION');
        $objSheet->getCell('E1')->setValue('DESCRIPTION');
        $objSheet->getCell('F1')->setValue('TAG');
        $objSheet->getCell('G1')->setValue('FROM');
        $objSheet->getCell('H1')->setValue('SOURCE');
        $objSheet->getCell('I1')->setValue('TO');
        $objSheet->getCell('J1')->setValue('DESTINATION');
        $objSheet->getCell('K1')->setValue('APPLICATION');
        $objSheet->getCell('L1')->setValue('SERVICE');
        $objSheet->getCell('M1')->setValue('APPLICATION FROM LOG');
        $objSheet->getCell('N1')->setValue('LOCATION');
        $objSheet->getCell('O1')->setValue('USER');
        $objSheet->getCell('P1')->setValue('CATEGORY');
        $objSheet->getCell('Q1')->setValue('TARGET');

        $row = 2;
        $wasBeforeMerge = true;

        foreach($allRules as $rule_lid=>$rule){
            if($allRules[$rule_lid]['processed']==1){
                continue;
            }
            else {
                if ($rule['mergeable'] == 0) { //This is a not mergeable rule
                    if($wasBeforeMerge) {
                        $row++;
                        $cellA = "A" . $row;
                        $objSheet->getCell($cellA)->setValue("Not mergeable");
                        $objSheet->getStyle('' . $cellA . ':R' . $row . '')->getFont()->setBold(true)->setSize(12);
                        $objSheet->getStyle('' . $cellA . ':R' . $row . '')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
                        $objSheet->getStyle('' . $cellA . ':R' . $row . '')->getFill()->getStartColor()->setARGB('CCCCCC');
                        $row++;
                    }
                    if ($row % 2 == 0) $color = "ffefbb";
                    else             $color = "dece9e";
                    add_row($projectdb, $objSheet, $rule, $color, $row);
                    $rule['processed'] = 1;
                    $wasBeforeMerge=false;
                }
                else {
                    $row++;
                    $wasBeforeMerge=true;
                    $caseName = $mergeableCasesByID[$rule_lid];
                    $cellA = "A".$row;
                    $objSheet->getCell($cellA)->setValue($caseName);
                    $objSheet->getStyle(''.$cellA.':R'.$row.'')->getFont()->setBold(true)->setSize(12);
                    $objSheet->getStyle(''.$cellA.':R'.$row.'')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
                    $objSheet->getStyle(''.$cellA.':R'.$row.'')->getFill()->getStartColor()->setARGB('CCCCCC');
                    $row++;
                    foreach ($mergeableCasesByName[$caseName] as $ruleId){
                        if ($row % 2 == 0) $color = "ffffff";
                        else             $color = "fff1f1";
                        $mergeRule = $allRules[$ruleId];
                        add_row($projectdb, $objSheet, $mergeRule, $color, $row);
                        $allRules[$ruleId]['processed'] = 1;
                    }
                }
            }
        }


        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        //$objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setWidth(90);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
        $objSheet->getColumnDimension('M')->setAutoSize(true);
        $objSheet->getColumnDimension('N')->setAutoSize(true);
        $objSheet->getColumnDimension('O')->setAutoSize(true);
        $objSheet->getColumnDimension('P')->setAutoSize(true);
        $objSheet->getColumnDimension('Q')->setAutoSize(true);
        $objSheet->getColumnDimension('R')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_security_rules_consolidation.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}

function add_row($projectdb, $objSheet, $rule, $color, &$row){
    $cellA = "A".$row;
    $lid = $rule['id'];


    $objSheet->getCell("A".$row)->setValue($rule['id']);
    $objSheet->getCell("B".$row)->setValue($rule['disabled']);
    $objSheet->getCell("C".$row)->setValue($rule['name']);
    $objSheet->getCell("D".$row)->setValue($rule['action']);
    $objSheet->getCell("E".$row)->setValue($rule['description']);

    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_tag WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $tablename = $getMembersData['table_name'];
            $memberlid = $getMembersData['member_lid'];
            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
            if ($getMembersName->num_rows == 1){
                $getMembersNameData = $getMembersName->fetch_assoc();
                $members[] = $getMembersNameData['name'];
            }
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("F".$row)->setValue($members);
            $objSheet->getStyle("F".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $members[] = $getMembersData['name'];
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("G".$row)->setValue($members);
            $objSheet->getStyle("G".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $tablename = $getMembersData['table_name'];
            $memberlid = $getMembersData['member_lid'];
            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
            if ($getMembersName->num_rows == 1){
                $getMembersNameData = $getMembersName->fetch_assoc();
                $members[] = $getMembersNameData['name'];
            }
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("H".$row)->setValue($members);
            $objSheet->getStyle("H".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $members[] = $getMembersData['name'];
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("I".$row)->setValue($members);
            $objSheet->getStyle("I".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $tablename = $getMembersData['table_name'];
            $memberlid = $getMembersData['member_lid'];
            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
            if ($getMembersName->num_rows == 1){
                $getMembersNameData = $getMembersName->fetch_assoc();
                $members[] = $getMembersNameData['name'];
            }
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("J".$row)->setValue($members);
            $objSheet->getStyle("J".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $tablename = $getMembersData['table_name'];
            $memberlid = $getMembersData['member_lid'];
            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
            if ($getMembersName->num_rows == 1){
                $getMembersNameData = $getMembersName->fetch_assoc();
                $members[] = $getMembersNameData['name'];
            }
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("K".$row)->setValue($members);
            $objSheet->getStyle("K".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $tablename = $getMembersData['table_name'];
            $memberlid = $getMembersData['member_lid'];
            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
            if ($getMembersName->num_rows == 1){
                $getMembersNameData = $getMembersName->fetch_assoc();
                $members[] = $getMembersNameData['name'];
            }
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("L".$row)->setValue($members);
            $objSheet->getStyle("L".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT app, dport, bytes , packets, proto FROM applications_from_log WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $app = $getMembersData['app'];
            $dport = $getMembersData['dport'];
            $proto = $getMembersData['proto'];
            $members[] = $app." (".$proto."/".$dport.")";
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("M".$row)->setValue($members);
            $objSheet->getStyle("M".$row)->getAlignment()->setWrapText(true);
        }
    }

    $objSheet->getCell("N".$row)->setValue($rule['vsys']);

    $getMembers = $projectdb->query("SELECT name FROM security_rules_usr WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $members[] = $getMembersData['name'];
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("O".$row)->setValue($members);
            $objSheet->getStyle("O".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            $members[] = $getMembersData['name'];
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("P".$row)->setValue($members);
            $objSheet->getStyle("P".$row)->getAlignment()->setWrapText(true);
        }
    }

    $getMembers = $projectdb->query("SELECT name,device_vsys FROM security_rules_target WHERE rule_lid = '$lid';");
    if ($getMembers->num_rows>0){
        $members = array();
        while($getMembersData = $getMembers->fetch_assoc()){
            if (($getMembersData['device_vsys']!="") OR ($getMembersData['device_vsys']!= null)){
                $members[] = $getMembersData['name']."/".$getMembersData['device_vsys'];
            }
            else{
                $members[] = $getMembersData['name'];
            }
        }
        if (count($members) > 0){
            $members = implode("\n",$members);
            $objSheet->getCell("Q".$row)->setValue($members);
            $objSheet->getStyle("Q".$row)->getAlignment()->setWrapText(true);
        }
    }

    $objSheet->getCell("R".$row)->setValue($rule['chk_target']);

    $objSheet->getStyle("A".$row.':'."R".$row)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle("A".$row.':'."R".$row)->getFill()->getStartColor()->setARGB($color);

    $row++;
}

function generateExcelNatRules($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:Q1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:Q1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:Q1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:Q1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:Q1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("NAT RULES")
        ->setSubject("NAT RULES")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool nat rules paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "nat_rules", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, name, description, IF (disabled = '1', 'True', 'False') AS disabled, vsys, op_zone_to, tp_dat_port, IF (tp_sat_bidirectional = '1', 'True', 'False') AS tp_sat_bidirectional, op_to_interface, tp_sat_type 
        FROM nat_rules $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('DISABLED');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('DESCRIPTION');
        $objSheet->getCell('E1')->setValue('TAG');
        $objSheet->getCell('F1')->setValue('FROM');
        $objSheet->getCell('G1')->setValue('SOURCE');
        $objSheet->getCell('H1')->setValue('TO');
        $objSheet->getCell('I1')->setValue('DESTINATION');
        $objSheet->getCell('J1')->setValue('SERVICE');
        $objSheet->getCell('K1')->setValue('INTERFACE');
        $objSheet->getCell('L1')->setValue('[TP] SOURCE');
        $objSheet->getCell('M1')->setValue('TRANSLATION TYPE');
        $objSheet->getCell('N1')->setValue('[TP] DESTINATION');
        $objSheet->getCell('O1')->setValue('[TP] PORT');
        $objSheet->getCell('P1')->setValue('BI-DIR');
        $objSheet->getCell('Q1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()){

            $lid = $dataA['id'];

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['disabled']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['description']);

            $cellE = "E".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_tag WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellE)->setValue($members);
                    $objSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
                }
            }

            $cellF = "F".$row;
            $getMembers = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $members[] = $getMembersData['name'];
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellF)->setValue($members);
                    $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                }
            }

            $cellG = "G".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellG)->setValue($members);
                    $objSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                }
            }

            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['op_zone_to']);

            $cellI = "I".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellI)->setValue($members);
                    $objSheet->getStyle($cellI)->getAlignment()->setWrapText(true);
                }
            }

            $cellJ = "J".$row;
            $getMembers = $projectdb->query("SELECT op_service_lid as member_lid, op_service_table as table_name FROM nat_rules WHERE id = '$lid' AND op_service_table != '';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellJ)->setValue($members);
                    $objSheet->getStyle($cellJ)->getAlignment()->setWrapText(true);
                }
            }

            $cellK = "K".$row;
            $objSheet->getCell($cellK)->setValue($dataA['op_to_interface']);

            $cellL = "L".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellL)->setValue($members);
                    $objSheet->getStyle($cellL)->getAlignment()->setWrapText(true);
                }
            }

            if (($dataA['tp_sat_type'] == "") || ($dataA['tp_sat_type'] == "None") || ($dataA['tp_sat_type'] == "none") || ($dataA['tp_sat_type'] == NULL)){
                $tp_sat_type_format = "None";
            }elseif($dataA['tp_sat_type'] == "static-ip"){
                $tp_sat_type_format = "Static";
            }elseif($dataA['tp_sat_type'] == "dynamic-ip"){
                $tp_sat_type_format = "Dynamic Ip";
            }elseif($dataA['tp_sat_type'] == "dynamic-ip-and-port"){
                $tp_sat_type_format = "Dynamic Ip and Port";
            }else{
                $tp_sat_type_format = "None";
            }

            $cellM = "M".$row;
            $objSheet->getCell($cellM)->setValue($tp_sat_type_format);

            $cellN = "N".$row;
            $getMembers = $projectdb->query("SELECT tp_dat_address_lid as member_lid, tp_dat_address_table as table_name FROM nat_rules WHERE id = '$lid' AND tp_dat_address_table != '';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellN)->setValue($members);
                    $objSheet->getStyle($cellN)->getAlignment()->setWrapText(true);
                }
            }

            $cellO = "O".$row;
            $objSheet->getCell($cellO)->setValue($dataA['tp_dat_port']);

            $cellP = "P".$row;
            $objSheet->getCell($cellP)->setValue($dataA['tp_sat_bidirectional']);

            $cellQ = "Q".$row;
            $objSheet->getCell($cellQ)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellQ)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellQ)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        //$objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setWidth(90);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
        $objSheet->getColumnDimension('M')->setAutoSize(true);
        $objSheet->getColumnDimension('N')->setAutoSize(true);
        $objSheet->getColumnDimension('O')->setAutoSize(true);
        $objSheet->getColumnDimension('P')->setAutoSize(true);
        $objSheet->getColumnDimension('Q')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_nat_rules.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');

}


function generateExcelNatRulesConsolidation($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:O1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:O1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:O1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:O1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:O1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("NAT RULES CONSOLIDATION")
        ->setSubject("NAT RULES CONSOLIDATION")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool nat rules paloalto")
        ->setCategory("Expedition Tool Reports");


    $getConsolidation = $projectdb->query("SELECT filter_hash, rules_lid FROM hash_rules WHERE source = '$source' AND table_name = 'nat_rules';");

    if ($getConsolidation->num_rows > 0) {

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('DISABLED');
        $objSheet->getCell('C1')->setValue('ID) NAME');
        $objSheet->getCell('D1')->setValue('DESCRIPTION');
        $objSheet->getCell('E1')->setValue('TAG');
        $objSheet->getCell('F1')->setValue('FROM');
        $objSheet->getCell('G1')->setValue('SOURCE');
        $objSheet->getCell('H1')->setValue('TO');
        $objSheet->getCell('I1')->setValue('DESTINATION');
        $objSheet->getCell('J1')->setValue('SERVICE');
        $objSheet->getCell('K1')->setValue('[TP] SOURCE');
        $objSheet->getCell('L1')->setValue('[TP] DESTINATION');
        $objSheet->getCell('M1')->setValue('[TP] PORT');
        $objSheet->getCell('N1')->setValue('BI-DIR');
        $objSheet->getCell('O1')->setValue('LOCATION');

        $row = 2;

        while ($dataCon = $getConsolidation->fetch_assoc()) {

            $rules_lid = $dataCon['rules_lid'];

            $cellA = "A" . $row;
            $objSheet->getCell($cellA)->setValue($dataCon['filter_hash']);
            $objSheet->getStyle('' . $cellA . ':O' . $row . '')->getFont()->setBold(true)->setSize(12);
            $objSheet->getStyle('' . $cellA . ':O' . $row . '')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle('' . $cellA . ':O' . $row . '')->getFill()->getStartColor()->setARGB('CCCCCC');

            $row++;

            $getData = $projectdb->query("SELECT id, name, description, IF (disabled = '1', 'True', 'False') AS disabled, vsys, op_zone_to, tp_dat_port, IF (tp_sat_bidirectional = '1', 'True', 'False') AS tp_sat_bidirectional 
                FROM nat_rules WHERE id IN ($rules_lid) ;");

            if ($getData->num_rows > 0){

                while ($dataA = $getData->fetch_assoc()){

                    $lid = $dataA['id'];

                    if($row % 2 == 0){$color = "ffffff";
                    }else{$color = "f1f1f1";}

                    $cellA = "A".$row;
                    $objSheet->getCell($cellA)->setValue($dataA['id']);
                    $cellB = "B".$row;
                    $objSheet->getCell($cellB)->setValue($dataA['disabled']);
                    $cellC = "C".$row;
                    $objSheet->getCell($cellC)->setValue($dataA['id'].") ".$dataA['name']);
                    $cellD = "D".$row;
                    $objSheet->getCell($cellD)->setValue($dataA['description']);

                    $cellE = "E".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_tag WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellE)->setValue($members);
                            $objSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellF = "F".$row;
                    $getMembers = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $members[] = $getMembersData['name'];
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellF)->setValue($members);
                            $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellG = "G".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellG)->setValue($members);
                            $objSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellH = "H".$row;
                    $objSheet->getCell($cellH)->setValue($dataA['op_zone_to']);

                    $cellI = "I".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellI)->setValue($members);
                            $objSheet->getStyle($cellI)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellJ = "J".$row;
                    $getMembers = $projectdb->query("SELECT op_service_lid as member_lid, op_service_table as table_name FROM nat_rules WHERE id = '$lid' AND op_service_table != '';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellJ)->setValue($members);
                            $objSheet->getStyle($cellJ)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellK = "K".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellK)->setValue($members);
                            $objSheet->getStyle($cellK)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellL = "L".$row;
                    $getMembers = $projectdb->query("SELECT tp_dat_address_lid as member_lid, tp_dat_address_table as table_name FROM nat_rules WHERE id = '$lid' AND tp_dat_address_table != '';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellL)->setValue($members);
                            $objSheet->getStyle($cellL)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellM = "M".$row;
                    $objSheet->getCell($cellM)->setValue($dataA['tp_dat_port']);

                    $cellN = "N".$row;
                    $objSheet->getCell($cellN)->setValue($dataA['tp_sat_bidirectional']);

                    $cellO = "O".$row;
                    $objSheet->getCell($cellO)->setValue($dataA['vsys']);

                    $objSheet->getStyle($cellA.':'.$cellO)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
                    $objSheet->getStyle($cellA.':'.$cellO)->getFill()->getStartColor()->setARGB($color);

                    $row++;
                }

            }
            $row++;

        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        //$objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setWidth(90);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
        $objSheet->getColumnDimension('M')->setAutoSize(true);
        $objSheet->getColumnDimension('N')->setAutoSize(true);
        $objSheet->getColumnDimension('O')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_nat_rules_consolidation.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');

}


function generateExcelAppoverrideRules($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");
    $currencyFormat = '#,#0.## \€;[Red]-#,#0.## \€';
    $numberFormat = '#,#0.##;[Red]-#,#0.##';

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:M1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:M1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:M1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:M1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:M1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);
    //$objSheet->getStyle('A1:K1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_PATTERN_MEDIUMGRAY);

    $objSheet->freezePane('A2');
    
    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("APPOVERRIDE RULES")
        ->setSubject("APPOVERRIDE RULES")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool appoverride rules paloalto")
        ->setCategory("Expedition Tool Reports");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $conditions = " WHERE source = '$source' $vsys_query ";
    list($conditions, $orderby) = generateQueryFilters($project, "appoverride_rules", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, name, description, IF (disabled = '1', 'True', 'False') AS disabled, vsys, protocol, port FROM appoverride_rules $conditions $orderby;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('DISABLED');
        $objSheet->getCell('C1')->setValue('ID) NAME');
        $objSheet->getCell('D1')->setValue('DESCRIPTION');
        $objSheet->getCell('E1')->setValue('TAG');
        $objSheet->getCell('F1')->setValue('FROM');
        $objSheet->getCell('G1')->setValue('SOURCE');
        $objSheet->getCell('H1')->setValue('TO');
        $objSheet->getCell('I1')->setValue('DESTINATION');
        $objSheet->getCell('J1')->setValue('PROTOCOL');
        $objSheet->getCell('K1')->setValue('PORT');
        $objSheet->getCell('L1')->setValue('APPLICATION');
        $objSheet->getCell('M1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()){

            $lid = $dataA['id'];

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['disabled']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['id'].") ".$dataA['name']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['description']);

            $cellE = "E".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM appoverride_rules_tag WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellE)->setValue($members);
                    $objSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
                }
            }

            $cellF = "F".$row;
            $getMembers = $projectdb->query("SELECT name FROM appoverride_rules_from WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $members[] = $getMembersData['name'];
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellF)->setValue($members);
                    $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                }
            }

            $cellG = "G".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM appoverride_rules_src WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellG)->setValue($members);
                    $objSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                }
            }

            $cellH = "H".$row;
            $getMembers = $projectdb->query("SELECT name FROM appoverride_rules_to WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $members[] = $getMembersData['name'];
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellH)->setValue($members);
                    $objSheet->getStyle($cellH)->getAlignment()->setWrapText(true);
                }
            }

            $cellI = "I".$row;
            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM appoverride_rules_dst WHERE rule_lid = '$lid';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellI)->setValue($members);
                    $objSheet->getStyle($cellI)->getAlignment()->setWrapText(true);
                }
            }

            $cellJ = "J".$row;
            $objSheet->getCell($cellJ)->setValue($dataA['protocol']);

            $cellK = "K".$row;
            $objSheet->getCell($cellK)->setValue($dataA['port']);

            $cellL = "L".$row;
            $getMembers = $projectdb->query("SELECT app_id as member_lid, app_table as table_name FROM appoverride_rules WHERE id = '$lid' AND app_table != '';");

            if ($getMembers->num_rows>0){
                $members = array();
                while($getMembersData = $getMembers->fetch_assoc()){
                    $tablename = $getMembersData['table_name'];
                    $memberlid = $getMembersData['member_lid'];
                    $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                    if ($getMembersName->num_rows == 1){
                        $getMembersNameData = $getMembersName->fetch_assoc();
                        $members[] = $getMembersNameData['name'];
                    }
                }
                if (count($members) > 0){
                    $members = implode("\n",$members);
                    $objSheet->getCell($cellL)->setValue($members);
                    $objSheet->getStyle($cellL)->getAlignment()->setWrapText(true);
                }
            }

            $cellM = "M".$row;
            $objSheet->getCell($cellM)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellM)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellM)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        //$objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setWidth(90);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
        $objSheet->getColumnDimension('M')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_appoverride_rules.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelAppoverrideRulesConsolidation($projectdb, $source, $project, $vsys){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");
    $currencyFormat = '#,#0.## \€;[Red]-#,#0.## \€';
    $numberFormat = '#,#0.##;[Red]-#,#0.##';

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:M1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:M1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:M1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:M1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:M1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);
    //$objSheet->getStyle('A1:K1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_PATTERN_MEDIUMGRAY);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("APPOVERRIDE RULES CONSOLIDATION")
        ->setSubject("APPOVERRIDE RULES CONSOLIDATION")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool appoverride rules paloalto")
        ->setCategory("Expedition Tool Reports");


    $getConsolidation = $projectdb->query("SELECT filter_hash, rules_lid FROM hash_rules WHERE source = '$source' AND table_name = 'appoverride_rules';");

    if ($getConsolidation->num_rows > 0) {

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('DISABLED');
        $objSheet->getCell('C1')->setValue('ID) NAME');
        $objSheet->getCell('D1')->setValue('DESCRIPTION');
        $objSheet->getCell('E1')->setValue('TAG');
        $objSheet->getCell('F1')->setValue('FROM');
        $objSheet->getCell('G1')->setValue('SOURCE');
        $objSheet->getCell('H1')->setValue('TO');
        $objSheet->getCell('I1')->setValue('DESTINATION');
        $objSheet->getCell('J1')->setValue('PROTOCOL');
        $objSheet->getCell('K1')->setValue('PORT');
        $objSheet->getCell('L1')->setValue('APPLICATION');
        $objSheet->getCell('M1')->setValue('LOCATION');

        $row = 2;

        while ($dataCon = $getConsolidation->fetch_assoc()) {

            $rules_lid = $dataCon['rules_lid'];

            $cellA = "A" . $row;
            $objSheet->getCell($cellA)->setValue($dataCon['filter_hash']);
            $objSheet->getStyle('' . $cellA . ':M' . $row . '')->getFont()->setBold(true)->setSize(12);
            $objSheet->getStyle('' . $cellA . ':M' . $row . '')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle('' . $cellA . ':M' . $row . '')->getFill()->getStartColor()->setARGB('CCCCCC');

            $row++;

            $getData = $projectdb->query("SELECT id, name, description, IF (disabled = '1', 'True', 'False') AS disabled, vsys, protocol, port 
                FROM appoverride_rules WHERE id IN ($rules_lid);");

            if ($getData->num_rows > 0){

                while ($dataA = $getData->fetch_assoc()){

                    $lid = $dataA['id'];

                    if($row % 2 == 0){$color = "ffffff";
                    }else{$color = "f1f1f1";}

                    $cellA = "A".$row;
                    $objSheet->getCell($cellA)->setValue($dataA['id']);
                    $cellB = "B".$row;
                    $objSheet->getCell($cellB)->setValue($dataA['disabled']);
                    $cellC = "C".$row;
                    $objSheet->getCell($cellC)->setValue($dataA['id'].") ".$dataA['name']);
                    $cellD = "D".$row;
                    $objSheet->getCell($cellD)->setValue($dataA['description']);

                    $cellE = "E".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM appoverride_rules_tag WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellE)->setValue($members);
                            $objSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellF = "F".$row;
                    $getMembers = $projectdb->query("SELECT name FROM appoverride_rules_from WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $members[] = $getMembersData['name'];
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellF)->setValue($members);
                            $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellG = "G".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM appoverride_rules_src WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellG)->setValue($members);
                            $objSheet->getStyle($cellG)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellH = "H".$row;
                    $getMembers = $projectdb->query("SELECT name FROM appoverride_rules_to WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $members[] = $getMembersData['name'];
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellH)->setValue($members);
                            $objSheet->getStyle($cellH)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellI = "I".$row;
                    $getMembers = $projectdb->query("SELECT member_lid, table_name FROM appoverride_rules_dst WHERE rule_lid = '$lid';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellI)->setValue($members);
                            $objSheet->getStyle($cellI)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellJ = "J".$row;
                    $objSheet->getCell($cellJ)->setValue($dataA['protocol']);

                    $cellK = "K".$row;
                    $objSheet->getCell($cellK)->setValue($dataA['port']);

                    $cellL = "L".$row;
                    $getMembers = $projectdb->query("SELECT app_id as member_lid, app_table as table_name FROM appoverride_rules WHERE id = '$lid' AND app_table != '';");

                    if ($getMembers->num_rows>0){
                        $members = array();
                        while($getMembersData = $getMembers->fetch_assoc()){
                            $tablename = $getMembersData['table_name'];
                            $memberlid = $getMembersData['member_lid'];
                            $getMembersName = $projectdb->query("SELECT name FROM $tablename WHERE id = '$memberlid';");
                            if ($getMembersName->num_rows == 1){
                                $getMembersNameData = $getMembersName->fetch_assoc();
                                $members[] = $getMembersNameData['name'];
                            }
                        }
                        if (count($members) > 0){
                            $members = implode("\n",$members);
                            $objSheet->getCell($cellL)->setValue($members);
                            $objSheet->getStyle($cellL)->getAlignment()->setWrapText(true);
                        }
                    }

                    $cellM = "M".$row;
                    $objSheet->getCell($cellM)->setValue($dataA['vsys']);

                    $objSheet->getStyle($cellA.':'.$cellM)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
                    $objSheet->getStyle($cellA.':'.$cellM)->getFill()->getStartColor()->setARGB($color);

                    $row++;
                }

            }
            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        //$objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setWidth(90);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
        $objSheet->getColumnDimension('M')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_appoverride_rules_consolidation.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelRuleEnrichment($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:J1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:J1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:J1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:J1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:J1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    //$objSheet->getStyle('A1:J1')->getAlignment()->setWrapText(true);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("RULE ENRICHEMENT")
        ->setSubject("RULE ENRICHEMENT")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Rule Enrichment objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $getData = $projectdb->query("SELECT * FROM ML_RuleEnrichment ORDER BY RuleID;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('NAME');
        $objSheet->getCell('B1')->setValue('SOURCES ZONES');
        $objSheet->getCell('C1')->setValue('SOURCES');
        $objSheet->getCell('D1')->setValue('SOURCES REGIONS');
        $objSheet->getCell('E1')->setValue('USERS');
        $objSheet->getCell('F1')->setValue('DESTINATIONS');
        $objSheet->getCell('G1')->setValue('DESTINATIONS REGIONS');
        $objSheet->getCell('H1')->setValue('DESTINATIONS ZONES');
        $objSheet->getCell('I1')->setValue('APPLICATIONS');
        $objSheet->getCell('J1')->setValue('SERVICES');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['RuleName']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['SourcesZones']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['Sources']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['SourcesRegions']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['Users']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['Destinations']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['DestinationRegions']);
            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['DestinationZones']);
            $cellI = "I".$row;
            $objSheet->getCell($cellI)->setValue($dataA['Application']);
            $cellJ = "J".$row;

            if(($dataA['ServicesTCP'] == "application-default") && ($dataA['ServicesUDP'] == "application-default")){
                $dataA['Services'] = $dataA['ServicesTCP'];
            }else{
                $dataA['Services'] = $dataA['ServicesTCP'].",". $dataA['ServicesUDP'];

            }
            $objSheet->getCell($cellJ)->setValue($dataA['Services']);

            $objSheet->getStyle($cellA.':'.$cellJ)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellJ)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);

        $objSheet->getColumnDimension('A')->setAutoSize(true);
        //$objSheet->getStyle('A1:A'.$objPHPExcel->getActiveSheet()->getHighestRow())
        //    ->getAlignment()->setWrapText(true);
        $objSheet->getStyle('B1:B'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);
        $objSheet->getStyle('C1:C'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);

        $objSheet->getStyle('D1:D'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);
        $objSheet->getStyle('E1:E'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);
        $objSheet->getStyle('F1:F'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);

        $objSheet->getStyle('G1:G'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);
        $objSheet->getStyle('H1:H'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);
        $objSheet->getStyle('I1:I'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);

        $objSheet->getStyle('J1:J'.$objPHPExcel->getActiveSheet()->getHighestRow())
            ->getAlignment()->setWrapText(true);

        /*$objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(false);
        $objSheet->getColumnDimension('D')->setAutoSize(false);
        $objSheet->getColumnDimension('E')->setAutoSize(false);
        $objSheet->getColumnDimension('F')->setAutoSize(false);
        $objSheet->getColumnDimension('G')->setAutoSize(false);
        $objSheet->getColumnDimension('H')->setAutoSize(false);
        $objSheet->getColumnDimension('I')->setAutoSize(false);
        $objSheet->getColumnDimension('J')->setAutoSize(false);*/
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_rule_enrichment.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelInterfaces($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:L1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:L1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:L1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:L1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:L1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("INTERFACES")
        ->setSubject("INTERFACES")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Interfaces objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "interfaces", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, unitname, media, type, unitipaddress, vr_id, unittag, zone, interface_management_profile, comment, template, vsys 
                FROM interfaces a $conditions ORDER BY unitname;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('MEDIA');
        $objSheet->getCell('D1')->setValue('TYPE');
        $objSheet->getCell('E1')->setValue('IP ADDRESS');
        $objSheet->getCell('F1')->setValue('VIRTUAL ROUTER');
        $objSheet->getCell('G1')->setValue('TAG');
        $objSheet->getCell('H1')->setValue('ZONE');
        $objSheet->getCell('I1')->setValue('MANAGEMENT PROFILE');
        $objSheet->getCell('J1')->setValue('COMMENT');
        $objSheet->getCell('K1')->setValue('TEMPLATE');
        $objSheet->getCell('L1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            //$color = "eaeff2";
            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $vrid = $dataA['vr_id'];

            if (intval($vrid) > 0) {
                $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source = '$source' AND id = '$vrid';");
                if ($getVR->num_rows == 1) {
                    $theData = $getVR->fetch_assoc();
                    $dataA['vr'] = $theData['name'];
                }
            }else{
                $dataA['vr'] = "None";
            }

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source = '$source' AND id = '$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['unitname']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['media']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['type']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['unitipaddress']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['vr']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['unittag']);
            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['zone']);
            $cellI = "I".$row;
            $objSheet->getCell($cellI)->setValue($dataA['interface_management_profile']);
            $cellJ = "J".$row;
            $objSheet->getCell($cellJ)->setValue($dataA['comment']);
            $cellK = "K".$row;
            $objSheet->getCell($cellK)->setValue($dataA['template']);
            $cellL = "L".$row;
            $objSheet->getCell($cellL)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellL)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellL)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_interfaces.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelZones($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:L1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:L1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:L1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:L1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:L1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("ZONES")
        ->setSubject("ZONES")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Zones objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "zones", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, type, name, interfaces, zone_protection_profile, enable_packet_buffer_protection, log_setting_id, log_setting_table_name, enable_user_identification, include_list, exclude_list, template, vsys 
                FROM zones a $conditions ORDER BY type, name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('TYPE');
        $objSheet->getCell('C1')->setValue('NAME');
        $objSheet->getCell('D1')->setValue('INTERFACES');
        $objSheet->getCell('E1')->setValue('PROTECTION PROFILE');
        $objSheet->getCell('F1')->setValue('PACKET BUFFER PROTECTION');
        $objSheet->getCell('G1')->setValue('LOG SETTINGS');
        $objSheet->getCell('H1')->setValue('ENABLE USER IDENTIFICATION');
        $objSheet->getCell('I1')->setValue('INCLUDE LIST');
        $objSheet->getCell('J1')->setValue('EXCLUDE LIST');
        $objSheet->getCell('K1')->setValue('TEMPLATE');
        $objSheet->getCell('L1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            //$color = "eaeff2";
            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            if (($dataA['log_setting_id'] != "") AND ($dataA['log_setting_table_name'] != "")) {
                $id = $dataA['log_setting_id'];
                $table = $dataA['log_setting_table_name'];
                $getLS = $projectdb->query("SELECT name FROM $table WHERE id = '$id';");
                if ($getLS->num_rows == 1) {
                    $getLSdata = $getLS->fetch_assoc();
                    $dataA['log_setting'] = $getLSdata['name'];
                }
            }else{
                $dataA['log_setting'] = "None";
            }

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }



            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['type']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['name']);

            $cellD = "D".$row;
            $interfaces = explode(",", $dataA['interfaces']);
            if (count($interfaces) > 0){
                $interfaces = implode("\n",$interfaces);
                $objSheet->getCell($cellD)->setValue($interfaces);
                $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
            }

            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['zone_protection_profile']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['enable_packet_buffer_protection']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['log_setting']);
            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['enable_user_identification']);
            $cellI = "I".$row;
            $objSheet->getCell($cellI)->setValue($dataA['include_list']);
            $cellJ = "J".$row;
            $objSheet->getCell($cellJ)->setValue($dataA['exclude_list']);
            $cellK = "K".$row;
            $objSheet->getCell($cellK)->setValue($dataA['template']);
            $cellL = "L".$row;
            $objSheet->getCell($cellL)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellL)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellL)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
        $objSheet->getColumnDimension('L')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_zones.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelVirtualRouters($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:F1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:F1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:F1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:F1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:F1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("VIRTUAL ROUTERS")
        ->setSubject("VIRTUAL ROUTERS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Virtual Routers objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "virtual_routers", "", $conditions, $source);

    $getData = $projectdb->query("SELECT 'Static Routes: 0' as configuration, id, name, interfaces, template, vsys 
                FROM virtual_routers a $conditions ORDER BY id,name;");

    //admin_dist_static, admin_dist_ospf_int, admin_dist_ospf_ext, admin_dist_ibgp, admin_dist_ebgp, admin_dist_rip, admin_dist_static_ipv6, admin_dist_ospfv3_int, admin_dist_ospfv3_ext

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('INTERFACES');
        $objSheet->getCell('D1')->setValue('CONFIGURATION');
        $objSheet->getCell('E1')->setValue('TEMPLATE');
        $objSheet->getCell('F1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $vrid = $dataA['id'];
            $getStatic = $projectdb->query("SELECT id FROM routes_static WHERE source='$source' AND vr_id='$vrid';");
            if ($getStatic->num_rows > 0) {
                $dataA['configuration'] = "Static Routes: " . $getStatic->num_rows;
            }

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);

            $cellC = "C".$row;
            $interfaces = explode(",", $dataA['interfaces']);
            if (count($interfaces) > 0){
                $interfaces = implode("\n",$interfaces);
                $objSheet->getCell($cellC)->setValue($interfaces);
                $objSheet->getStyle($cellC)->getAlignment()->setWrapText(true);
            }

            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['configuration']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['template']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellF)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellF)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_virtual_routers.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelStaticRouters($projectdb, $source, $project, $vr_id){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:H1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:H1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:H1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:H1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:H1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("STATIC ROUTERS")
        ->setSubject("STATIC ROUTERS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Static Routers objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $getData = $projectdb->query("SELECT id, name, destination, nexthop_value, tointerface, metric, template, vsys FROM routes_static WHERE source='$source' AND vr_id='$vr_id';");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('DESTINATION');
        $objSheet->getCell('D1')->setValue('NEXTHOP');
        $objSheet->getCell('E1')->setValue('INTERFACE');
        $objSheet->getCell('F1')->setValue('METRIC');
        $objSheet->getCell('G1')->setValue('TEMPLATE');
        $objSheet->getCell('H1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['destination']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['nexthop_value']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['tointerface']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['metric']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['template']);
            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellH)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellH)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_routes_static.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelVirtualWires($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:G1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:G1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:G1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:G1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:G1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("VIRTUAL WIRES")
        ->setSubject("VIRTUAL WIRES")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Virtual Wires objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "virtual_wires", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, name, interface1, interface2, tag_allowed, template, vsys 
                FROM virtual_wires a $conditions ORDER BY id,name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('INTERFACE1');
        $objSheet->getCell('D1')->setValue('INTERFACE2');
        $objSheet->getCell('E1')->setValue('TAG ALLOWED');
        $objSheet->getCell('F1')->setValue('TEMPLATE');
        $objSheet->getCell('G1')->setValue('LOCATION');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['interface1']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['interface2']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['tag_allowed']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['template']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['vsys']);

            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_virtual_wires.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelVlan($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:G1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:G1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:G1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:G1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:G1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("VLANs")
        ->setSubject("VLANs")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool VLANs objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "vlans", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, name, interface, mac, mac_interfaces, virtual_interface, template 
                FROM vlans a $conditions ORDER BY id,name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('INTERFACES');
        $objSheet->getCell('D1')->setValue('MAC');
        $objSheet->getCell('E1')->setValue('MAC INTERFACE');
        $objSheet->getCell('F1')->setValue('VLAN INTERFACE');
        $objSheet->getCell('G1')->setValue('TEMPLATE');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);

            $cellC = "C".$row;
            $interfaces = explode(",", $dataA['interface']);
            if (count($interfaces) > 0){
                $interfaces = implode("\n",$interfaces);
                $objSheet->getCell($cellC)->setValue($interfaces);
                $objSheet->getStyle($cellC)->getAlignment()->setWrapText(true);
            }

            $cellD = "D".$row;
            $mac = explode(",", $dataA['mac']);
            if (count($mac) > 0){
                $mac = implode("\n",$mac);
                $objSheet->getCell($cellD)->setValue($mac);
                $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
            }

            $cellE = "E".$row;
            $mac = explode(",", $dataA['mac_interfaces']);
            if (count($mac) > 0){
                $mac = implode("\n",$mac);
                $objSheet->getCell($cellE)->setValue($mac);
                $objSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
            }

            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['virtual_interface']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['template']);

            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellG)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_vlans.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelIpsecTunnels($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:K1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:K1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:K1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:K1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:K1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("IPSEC TUNNELS")
        ->setSubject("IPSEC TUNNELS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Ipsec Tunnels objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "ipsec_tunnels", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, source, vsys, template, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, key_auth AS key_auth_confirm, encryption, key_encry, key_encry AS key_encry_confirm, local_address_ip, local_address_ip AS local_address_ip2, interface, interface AS interface2, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, local_certificate, publish_connected_routes, portal_address
                FROM ipsec_tunnel a $conditions ORDER BY id,name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('TYPE');
        $objSheet->getCell('D1')->setValue('INTERFACE');
        $objSheet->getCell('E1')->setValue('LOCAL IP');
        $objSheet->getCell('F1')->setValue('PEER IP');
        $objSheet->getCell('G1')->setValue('TUNNEL INTERFACE');
        $objSheet->getCell('H1')->setValue('VIRTUAL ROUTER');
        $objSheet->getCell('I1')->setValue('VIRTUAL SYSTEM');
        $objSheet->getCell('J1')->setValue('SECURITY ZONE');
        $objSheet->getCell('K1')->setValue('TEMPLATE');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $dataA['unitipaddress'] = "";
            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            if($dataA['type_tunnel'] == "auto-key") {
                $ike_gateway = $dataA['ike_gateway'];
                $getIKE = $projectdb->query("SELECT interface, peer_ip_address, local_address_ip AS unitipaddress FROM ike_gateways_profiles WHERE name = '$ike_gateway' AND source = '$source' AND template = '$template_id';");

                if ($getIKE->num_rows > 0) {
                    while ($dataIKE = $getIKE->fetch_object()) {
                        $dataA['interface'] = $dataIKE->interface;
                        $dataA['peer_ip_address'] = $dataIKE->peer_ip_address;
                        $dataA['unitipaddress'] = $dataIKE->unitipaddress;
                    }
                }
            }

            $tunnel_interface = $dataA['tunnel_interface'];
            $getInterfaceTunnel = $projectdb->query("SELECT vsys, zone, vr_id FROM interfaces WHERE unitname = '$tunnel_interface' AND source = '$source' AND template = '$template_id';");

            if ($getInterfaceTunnel->num_rows > 0) {
                while ($dataTunnel = $getInterfaceTunnel->fetch_object()) {
                    $dataA['vsys'] = $dataTunnel->vsys;
                    $dataA['zone'] = $dataTunnel->zone;
                    $dataA['vr_id'] = $dataTunnel->vr_id;

                    if($dataA['vr_id'] != 0){
                        $vr_id = $dataA['vr_id'];
                        $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE id = '$vr_id' AND source = '$source';");
                        if ($getVR->num_rows > 0) {
                            $dataVR = $getVR->fetch_object();
                            $dataA['name_vr'] = $dataVR->name;
                        }
                    }else{
                        $dataA['name_vr'] = "";
                    }
                }
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['type_tunnel']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['interface']);
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['unitipaddress']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['peer_ip_address']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['tunnel_interface']);
            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['name_vr']);
            $cellI = "I".$row;
            $objSheet->getCell($cellI)->setValue($dataA['vsys']);
            $cellJ = "J".$row;
            $objSheet->getCell($cellJ)->setValue($dataA['zone']);
            $cellK = "K".$row;
            $objSheet->getCell($cellK)->setValue($dataA['template']);

            $objSheet->getStyle($cellA.':'.$cellK)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellK)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_ipsec_tunnels.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelIkeCrypto($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:H1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:H1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:H1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:H1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:H1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("IKE CRYPTO")
        ->setSubject("IKE CRYPTO")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Ike Crypto objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "ike_crypto_profiles", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, source, vsys, template, name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple
                FROM ike_crypto_profiles a $conditions ORDER BY id,name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('ENCRYPTION');
        $objSheet->getCell('D1')->setValue('AUTHENTICATION');
        $objSheet->getCell('E1')->setValue('DH GROUP');
        $objSheet->getCell('F1')->setValue('LIFETIME');
        $objSheet->getCell('G1')->setValue('IKEv2 AUTHENTICATION MULTIPLE');
        $objSheet->getCell('H1')->setValue('TEMPLATE');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $template_id =  $dataA['template'];
            $lifetime = "";
            $lifesize = "";

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            if($dataA['seconds'] != "0"){
                $lifetime = $dataA['seconds'] . " Seconds";
            }elseif($dataA['minutes'] != "0"){
                $lifetime = $dataA['minutes'] . " Minutes";
            }elseif($dataA['hours'] != "0"){
                $lifetime = $dataA['hours'] . " Hours";
            }elseif($dataA['days'] != "0"){
                $lifetime = $dataA['days'] . " Days";
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);

            $cellC = "C".$row;
            $encryption = explode(",", $dataA['encryption']);
            if (count($encryption) > 0){
                $encryption = implode("\n",$encryption);
                $objSheet->getCell($cellC)->setValue($encryption);
                $objSheet->getStyle($cellC)->getAlignment()->setWrapText(true);
            }

            $cellD = "D".$row;
            $hash = explode(",", $dataA['hash']);
            if (count($hash) > 0){
                $hash = implode("\n",$hash);
                $objSheet->getCell($cellD)->setValue($hash);
                $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
            }

            $cellE = "E".$row;
            $dh_group = explode(",", $dataA['dh_group']);
            if (count($dh_group) > 0){
                $dh_group = implode("\n",$dh_group);
                $objSheet->getCell($cellE)->setValue($dh_group);
                $objSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
            }

            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($lifetime);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($dataA['authentication_multiple']);
            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($dataA['template']);

            $objSheet->getStyle($cellA.':'.$cellH)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellH)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_ike_crypto.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelGlobalProtectIpsec($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:E1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:E1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:E1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:E1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:E1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("GLOBAL PROTECT IPSEC CRYPTO")
        ->setSubject("GLOBAL PROTECT IPSEC CRYPTO")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Global Protect Ipsec Crypto objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "global_protect_app_ipsec_crypto_profiles", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, source, vsys, template, name, encryption, hash
                FROM global_protect_app_ipsec_crypto_profiles a $conditions ORDER BY id,name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('ENCRYPTION');
        $objSheet->getCell('D1')->setValue('AUTHENTICATION');
        $objSheet->getCell('E1')->setValue('TEMPLATE');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);

            $cellC = "C".$row;
            $encryption = explode(",", $dataA['encryption']);
            if (count($encryption) > 0){
                $encryption = implode("\n",$encryption);
                $objSheet->getCell($cellC)->setValue($encryption);
                $objSheet->getStyle($cellC)->getAlignment()->setWrapText(true);
            }

            $cellD = "D".$row;
            $hash = explode(",", $dataA['hash']);
            if (count($hash) > 0){
                $hash = implode("\n",$hash);
                $objSheet->getCell($cellD)->setValue($hash);
                $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
            }

            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['template']);

            $objSheet->getStyle($cellA.':'.$cellE)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellE)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_globalprotect_ipsec_crypto.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelIpsecCrypto($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:I1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:I1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:I1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:I1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:I1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("IPSEC CRYPTO")
        ->setSubject("IPSEC CRYPTO")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool IPSec Crypto objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "ipsec_crypto_profiles", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, source, vsys, template, name, protocol, encryption, hash, dh_group, seconds, minutes, 
                hours, days, kb, mb, gb, tb
                FROM ipsec_crypto_profiles a $conditions ORDER BY id,name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('ESP/AH');
        $objSheet->getCell('D1')->setValue('ENCRYPTION');
        $objSheet->getCell('E1')->setValue('AUTHENTICATION');
        $objSheet->getCell('F1')->setValue('DH GROUP');
        $objSheet->getCell('G1')->setValue('LIFETIME');
        $objSheet->getCell('H1')->setValue('LIFESIZE');
        $objSheet->getCell('I1')->setValue('TEMPLATE');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $template_id =  $dataA['template'];
            $lifetime = "";
            $lifesize = "";

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            if($dataA['seconds'] != "0"){
                $lifetime = $dataA['seconds'] . " Seconds";
            }elseif($dataA['minutes'] != "0"){
                $lifetime = $dataA['minutes'] . " Minutes";
            }elseif($dataA['hours'] != "0"){
                $lifetime = $dataA['hours'] . " Hours";
            }elseif($dataA['days'] != "0"){
                $lifetime = $dataA['days'] . " Days";
            }

            if($dataA['kb'] != "0"){
                $lifesize = $dataA['kb'] . " KB";
            }elseif($dataA['mb'] != "0"){
                $lifesize = $dataA['mb'] . " MB";
            }elseif($dataA['gb'] != "0"){
                $lifesize = $dataA['gb'] . " GB";
            }elseif($dataA['tb'] != "0"){
                $lifesize = $dataA['tb'] . " TB";
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);

            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['protocol']);

            $cellD = "D".$row;
            $encryption = explode(",", $dataA['encryption']);
            if (count($encryption) > 0){
                $encryption = implode("\n",$encryption);
                $objSheet->getCell($cellD)->setValue($encryption);
                $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
            }

            $cellE = "E".$row;
            $hash = explode(",", $dataA['hash']);
            if (count($hash) > 0){
                $hash = implode("\n",$hash);
                $objSheet->getCell($cellE)->setValue($hash);
                $objSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
            }

            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['dh_group']);
            $cellG = "G".$row;
            $objSheet->getCell($cellG)->setValue($lifetime);
            $cellH = "H".$row;
            $objSheet->getCell($cellH)->setValue($lifesize);
            $cellI = "I".$row;
            $objSheet->getCell($cellI)->setValue($dataA['template']);

            $objSheet->getStyle($cellA.':'.$cellI)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellI)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_ipsec_crypto.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelMonitorProfile($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:F1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:F1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:F1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:F1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:F1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("MONITOR PROFILE")
        ->setSubject("MONITOR PROFILE")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Monitor Profile objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "monitor_profile", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, source, vsys, template, name, m_action, interva, threshold 
                FROM monitor_profile a $conditions ORDER BY id,name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('ACTION');
        $objSheet->getCell('D1')->setValue('INTERVAL');
        $objSheet->getCell('E1')->setValue('THRESHOLD');
        $objSheet->getCell('F1')->setValue('TEMPLATE');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['m_action']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['interva']." sec");
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['threshold']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['template']);

            $objSheet->getStyle($cellA.':'.$cellF)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellF)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_monitor_profile.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelIkeGatewaysProfile($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:F1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:F1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:F1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:F1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:F1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("IKE GATEWAYS")
        ->setSubject("IKE GATEWAYS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Monitor Profile objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $conditions = " WHERE source = '$source' ";
    list($conditions, $orderby) = generateQueryFilters($project, "monitor_profile", "", $conditions, $source);

    $getData = $projectdb->query("SELECT id, source, vsys, template, name, m_action, interva, threshold 
                FROM monitor_profile a $conditions ORDER BY id,name;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('ID');
        $objSheet->getCell('B1')->setValue('NAME');
        $objSheet->getCell('C1')->setValue('ACTION');
        $objSheet->getCell('D1')->setValue('INTERVAL');
        $objSheet->getCell('E1')->setValue('THRESHOLD');
        $objSheet->getCell('F1')->setValue('TEMPLATE');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $template_id =  $dataA['template'];

            $getTemplate = $projectdb->query("SELECT name FROM templates_mapping WHERE source='$source' AND id='$template_id';");
            if ($getTemplate->num_rows == 1) {
                $theData = $getTemplate->fetch_assoc();
                $dataA['template'] = $theData['name'];
            }

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['id']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['name']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['m_action']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['interva']." sec");
            $cellE = "E".$row;
            $objSheet->getCell($cellE)->setValue($dataA['threshold']);
            $cellF = "F".$row;
            $objSheet->getCell($cellF)->setValue($dataA['template']);

            $objSheet->getStyle($cellA.':'.$cellF)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellF)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_monitor_profile.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelMLServers($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:D1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:D1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:D1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:D1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:D1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("ML SERVERS")
        ->setSubject("ML SERVERS")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool ML Servers objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $getData = $projectdb->query("SELECT DISTINCT ml.serverAddress, INET_ATON(serverAddress) AS serverAddressLong, ml.application, app.category AS categories, app.subcategory AS subcategories
          FROM ML_Servers ml, default_applications app
          WHERE	ml.application = app.name AND
          ml.timestamp IN (SELECT MAX(timestamp) FROM ML_Servers ) ORDER BY ml.application;");

    if ($getData->num_rows > 0){

        $objSheet->getCell('A1')->setValue('SERVER IP ADDRESS');
        $objSheet->getCell('B1')->setValue('APPLICATION');
        $objSheet->getCell('C1')->setValue('CATEGORY');
        $objSheet->getCell('D1')->setValue('SUBCATEGORY');

        $row = 2;

        while ($dataA = $getData->fetch_assoc()) {

            if($row % 2 == 0){$color = "ffffff";
            }else{$color = "f1f1f1";}

            $cellA = "A".$row;
            $objSheet->getCell($cellA)->setValue($dataA['serverAddress']);
            $cellB = "B".$row;
            $objSheet->getCell($cellB)->setValue($dataA['application']);
            $cellC = "C".$row;
            $objSheet->getCell($cellC)->setValue($dataA['categories']);
            $cellD = "D".$row;
            $objSheet->getCell($cellD)->setValue($dataA['subcategories']);

            $objSheet->getStyle($cellA.':'.$cellD)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle($cellA.':'.$cellD)->getFill()->getStartColor()->setARGB($color);

            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);

    }

    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_ml_servers.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}


function generateExcelMLNewRules($projectdb, $source, $project){

    $objPHPExcel = new PHPExcel;

    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);

    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, "Excel2007");

    $objSheet = $objPHPExcel->getActiveSheet();

    $objSheet->getStyle('A1:K1')->getFont()->setBold(true)->setSize(12);
    $objSheet->getStyle('A1:K1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
    $objSheet->getStyle('A1:K1')->getFill()->getStartColor()->setARGB('d3dfea');
    $objSheet->getStyle('A1:K1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
    $objSheet->getStyle('A1:K1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);

    $objSheet->freezePane('A2');

    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("DISCOVERED RULES")
        ->setSubject("DISCOVERED RULES")
        ->setDescription("Report generated by Paloalto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool Discovered Rules objects paloalto")
        ->setCategory("Expedition Tool Reports");

    $query = "SELECT id, timestamp from ML_NewRules ORDER BY id DESC LIMIT 1;";
    $result = $projectdb->query($query);
    if($result->num_rows == 1){
        $data = $result->fetch_assoc();
        $lastDate = $data['timestamp'];
    }


    $getConsolidation = $projectdb->query("SELECT application FROM ML_NewRules WHERE timestamp ='$lastDate' GROUP BY application ASC;");

    if ($getConsolidation->num_rows > 0) {

        $objSheet->getCell('A1')->setValue('FLOW');
        $objSheet->getCell('B1')->setValue('APPLICATION');
        $objSheet->getCell('C1')->setValue('FROM');
        $objSheet->getCell('D1')->setValue('USER');
        $objSheet->getCell('E1')->setValue('SOURCE');
        $objSheet->getCell('F1')->setValue('SOURCE REGIONS');
        $objSheet->getCell('G1')->setValue('TO');
        $objSheet->getCell('H1')->setValue('DESTINATION');
        $objSheet->getCell('I1')->setValue('DESTINATION REGIONS');
        $objSheet->getCell('J1')->setValue('SERVICE');
        $objSheet->getCell('K1')->setValue('TAG');

        $row = 2;

        while ($dataCon = $getConsolidation->fetch_assoc()) {

            $application = $dataCon['application'];

            $cellA = "A" . $row;
            $objSheet->getCell($cellA)->setValue("Application: " . $dataCon['application']);
            $objSheet->getStyle('' . $cellA . ':K' . $row . '')->getFont()->setBold(true)->setSize(12);
            $objSheet->getStyle('' . $cellA . ':K' . $row . '')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $objSheet->getStyle('' . $cellA . ':K' . $row . '')->getFill()->getStartColor()->setARGB('CCCCCC');

            $row++;


            $getData = $projectdb->query("SELECT communicationType, application, Source_Zone, sourceUser, source, seenSourceRegions, Destination_Zone,
              destination, seenDestinationRegions, service, tag FROM ML_NewRules WHERE timestamp ='$lastDate' AND application = '$application' ;");

            if ($getData->num_rows > 0) {

                while ($dataA = $getData->fetch_assoc()) {

                    if($row % 2 == 0){$color = "ffffff";
                    }else{$color = "f1f1f1";}

                    if ($dataA['destination']==''){$dataA['destination']="any";}
                    if ($dataA['source']==''){$dataA['source']="any";}
                    if ($dataA['sourceUser']==''){$dataA['sourceUser']="any";}
                    if ($dataA['service']==''){$dataA['service']="any";}
                    if ($dataA['application']==''){$dataA['application']="any";}

                    $cellA = "A".$row;
                    $objSheet->getCell($cellA)->setValue($dataA['communicationType']);
                    $cellB = "B".$row;
                    $objSheet->getCell($cellB)->setValue($dataA['application']);
                    $cellC = "C".$row;
                    $objSheet->getCell($cellC)->setValue($dataA['Source_Zone']);

                    $cellD = "D".$row;
                    $sourceUser = explode(",", $dataA['sourceUser']);
                    if (count($sourceUser) > 0){
                        $sourceUser = implode("\n",$sourceUser);
                        $objSheet->getCell($cellD)->setValue($sourceUser);
                        $objSheet->getStyle($cellD)->getAlignment()->setWrapText(true);
                    }

                    $cellE = "E".$row;
                    $source = explode(",", $dataA['source']);
                    if (count($source) > 0){
                        $source = implode("\n",$source);
                        $objSheet->getCell($cellE)->setValue($source);
                        $objSheet->getStyle($cellE)->getAlignment()->setWrapText(true);
                    }

                    $cellF = "F".$row;
                    $source = explode(",", $dataA['seenSourceRegions']);
                    if (count($source) > 0){
                        $source = implode("\n",$source);
                        $objSheet->getCell($cellF)->setValue($source);
                        $objSheet->getStyle($cellF)->getAlignment()->setWrapText(true);
                    }

                    $cellG = "G".$row;
                    $objSheet->getCell($cellG)->setValue($dataA['Destination_Zone']);

                    $cellH = "H".$row;
                    $destination = explode(",", $dataA['destination']);
                    if (count($destination) > 0){
                        $destination = implode("\n",$destination);
                        $objSheet->getCell($cellH)->setValue($destination);
                        $objSheet->getStyle($cellH)->getAlignment()->setWrapText(true);
                    }

                    $cellI = "I".$row;
                    $source = explode(",", $dataA['seenDestinationRegions']);
                    if (count($source) > 0){
                        $source = implode("\n",$source);
                        $objSheet->getCell($cellI)->setValue($source);
                        $objSheet->getStyle($cellI)->getAlignment()->setWrapText(true);
                    }

                    $cellJ = "J".$row;
                    $service = explode(",", $dataA['service']);
                    if (count($service) > 0){
                        $service = implode("\n",$service);
                        $objSheet->getCell($cellJ)->setValue($service);
                        $objSheet->getStyle($cellJ)->getAlignment()->setWrapText(true);
                    }

                    $cellK = "K".$row;
                    $objSheet->getCell($cellK)->setValue($dataA['tag']);

                    $objSheet->getStyle($cellA.':'.$cellK)->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
                    $objSheet->getStyle($cellA.':'.$cellK)->getFill()->getStartColor()->setARGB($color);

                    $row++;
                }
            }
            $row++;
        }

        $objSheet->getRowDimension('1')->setRowHeight(30);
        $objSheet->getColumnDimension('A')->setAutoSize(true);
        $objSheet->getColumnDimension('B')->setAutoSize(true);
        $objSheet->getColumnDimension('C')->setAutoSize(true);
        $objSheet->getColumnDimension('D')->setAutoSize(true);
        $objSheet->getColumnDimension('E')->setAutoSize(true);
        $objSheet->getColumnDimension('F')->setAutoSize(true);
        $objSheet->getColumnDimension('G')->setAutoSize(true);
        $objSheet->getColumnDimension('H')->setAutoSize(true);
        $objSheet->getColumnDimension('I')->setAutoSize(true);
        $objSheet->getColumnDimension('J')->setAutoSize(true);
        $objSheet->getColumnDimension('K')->setAutoSize(true);
    }


    $objPHPExcel->setActiveSheetIndex(0);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Ex_discovered_rules.xlsx"');
    header('Cache-Control: max-age=0');

    $objWriter->save('php://output');
}
?>