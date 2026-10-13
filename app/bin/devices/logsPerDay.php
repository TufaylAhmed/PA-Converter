<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 3/11/19 2:59 PM
 ******************************************************************************/

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/objects/Response.php';

require_once INC_ROOT.'/libs/Classes/PHPExcel.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

$request_body   = file_get_contents('php://input');
//print_r($request_body);
$data           = json_decode($request_body, true);

require_once INC_ROOT.'/libs/database.php';

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type =  $pandb->real_escape_string($post_vars['type']);
}
else {
    $mode           = $pandb->real_escape_string((string)(isset($_GET['mode'])                 ? $_GET['mode'] : ''));
    $page           = $pandb->real_escape_string((string)(isset($_GET['page'])                 ? $_GET['page']: ''));
    $start          = $pandb->real_escape_string((string)(isset($_GET['start'])                ? $_GET['start']: ''));
    $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])                ? $_GET['limit']: ''));

    $type           = $pandb->real_escape_string((string)(isset($_GET['type'])                 ? $_GET['type']: ''));
    $device         = $pandb->real_escape_string((string)(isset($_GET['device'])               ? $_GET['device']: ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $data = [
            'mode'          => $mode,
            'page'          => $page,
            'start'         => $start,
            'limit'         => $limit,
            'type'          => $type,
            'device'        => $device,
        ];
        $message = list_logsPerDay($data);
        echo json_encode(array('success'=>$message->success ,'data' => $message->getMessages()));
        break;
    case 'POST':
        $data['report'] = $pandb->real_escape_string(isset($_POST['report'])?$_POST['report']:isset($_GET['report'])?$_GET['report']:'');
        $data['device'] = $pandb->real_escape_string(isset($_POST['device'])?$_POST['device']:isset($_GET['device'])?$_GET['device']:'');

        $message = list_logsPerDay($data);
        echo json_encode(array('success'=>$message->success ,'data' => $message->getMessages()));
        break;

    case 'PUT':
    case 'DELETE':
    default:
        break;
}

function list_logsPerDay(array $params): Response{
    global $app;
    if(!isset($params['device'])){
        return new Response(false,-1, new Messages([]));
    }


    require_once INC_ROOT.'/libs/projectdb.php';
    $pandbRBAC = selectDatabase("pandbRBAC");
    $data = array();
    $serial = $params['device'];

    if($device = $app->device->where('serial', $serial)->get(['serialHA'])->first()){
        $haserial = ($device->serialHA != '')?$device->serialHA:$serial;
    }
    else{
        $haserial = $serial;
    }


    //Whether we want to present the data on the chart or to download the data in Excel format
    if(isset($params['report']) && $params['report']=='excel'){
        $logsQuery = "SELECT DATE_FORMAT(date, '%Y-%m-%d') as date, serial, rule, serial_vsys, typology, sum(hits) as hits FROM device_logsPerDay WHERE serial='$serial' OR serial='$haserial' GROUP BY date, rule ";
        $logResults = $pandbRBAC->query($logsQuery);
        if ($logResults->num_rows > 0) {
            while ($logData = $logResults->fetch_assoc()) {
                $data[] = $logData;
            }
        }
        generateExcelLogsPerDay($serial, $data);
    }
    else {
        $logsQuery = "SELECT DATE_FORMAT(date, '%Y-%m-%d') as date, serial, serial_vsys, typology, sum(hits) as hits FROM device_logsPerDay WHERE serial='$serial' OR serial='$haserial' GROUP BY date, typology ";
        $logResults = $pandbRBAC->query($logsQuery);
        if ($logResults->num_rows > 0) {
            while ($logData = $logResults->fetch_assoc()) {
                switch ($logData['typology']) {
                    case 'global':
                        $data[$logData['date']]['Global'] = $logData['hits'];
                        break;
                    case 'common':
                        $data[$logData['date']]['Common'] = $logData['hits'];
                        break;
                    case 'cloud':
                        $data[$logData['date']]['Cloud'] = $logData['hits'];
                        break;
                    case 'peer-to-peer':
                        $data[$logData['date']]['Peer-to-Peer'] = $logData['hits'];
                        break;
                    case 'unknown':
                        $data[$logData['date']]['Unknown'] = $logData['hits'];
                        break;
                }
            }
        }
    }

    foreach ($data as $key => &$dataEntry){
        $dataEntry['date'] = $key;
    }
    $data = array_values($data);

    return new Response(true, 0, new Messages($data));
}

function generateExcelLogsPerDay($device, $data){

    if (function_exists('mb_internal_encoding')) {
        $oldEncoding=mb_internal_encoding();
        mb_internal_encoding('latin1');
    }
    $objPHPExcel = new PHPExcel();
//    print_r($data);

    // set default font
    $objPHPExcel->getDefaultStyle()->getFont()->setName('Calibri');
    // set default font size
    $objPHPExcel->getDefaultStyle()->getFont()->setSize(10);
//    $objPHPExcel->getDefaultStyle()->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_TOP);
    $objPHPExcel->getProperties()->setCreator("ExpeditionTool")
        ->setLastModifiedBy("ExpeditionTool")
        ->setTitle("Logs per Day reported by Device $device")
        ->setSubject("Logs per Day")
        ->setDescription("Report generated by Palo Alto Networks Expedition Tool.")
        ->setKeywords("Expedition Tool CSVLogs Analysis")
        ->setCategory("Expedition Tool Reports");


    # Create Styles
    $styleArrayWhite = array(
        'font'  => array(
            'bold' => true,
            'color' => array('rgb' => 'FFFFFF')
        )
    );


//    # Consitional Change Color of Result to be applied to each sheet
//    $objConditional1 = new PHPExcel_Style_Conditional();
//    $objConditional1->setConditionType(PHPExcel_Style_Conditional::CONDITION_CONTAINSTEXT)
//        ->setOperatorType(PHPExcel_Style_Conditional::OPERATOR_CONTAINSTEXT)
//        ->setText('PASSED');
//    $objConditional1->getStyle()->getFont()->getColor()->setRGB('ffffff');
//    $objConditional1->getStyle()->getFont()->setBold(true);
//    $objConditional1->getStyle()->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER)->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
//    $objConditional1->getStyle()->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getEndColor()->setRGB('24ac5c');
//
//    $objConditional2 = new PHPExcel_Style_Conditional();
//    $objConditional2->setConditionType(PHPExcel_Style_Conditional::CONDITION_CONTAINSTEXT)
//        ->setOperatorType(PHPExcel_Style_Conditional::OPERATOR_CONTAINSTEXT)
//        ->setText('FAILED');
//    $objConditional2->getStyle()->getFont()->getColor()->setRGB('ffffff');
//    $objConditional2->getStyle()->getFont()->setBold(true);
//    $objConditional2->getStyle()->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER)->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
//    $objConditional2->getStyle()->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getEndColor()->setRGB('b81918');
//
//    $objConditional3 = new PHPExcel_Style_Conditional();
//    $objConditional3->setConditionType(PHPExcel_Style_Conditional::CONDITION_CONTAINSTEXT)
//        ->setOperatorType(PHPExcel_Style_Conditional::OPERATOR_CONTAINSTEXT)
//        ->setText('INFO');
//    $objConditional3->getStyle()->getFont()->getColor()->setRGB('ffffff');
//    $objConditional3->getStyle()->getFont()->setBold(true);
//    $objConditional3->getStyle()->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER)->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
//    $objConditional3->getStyle()->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID)->getEndColor()->setRGB('0095c8');


        $lastTopic="";
        if (count($data)>0){
            $clonedSheet = $objPHPExcel->getActiveSheet();
//            $clonedSheet = $objPHPExcel->createSheet();
            // Rename cloned worksheet
            $clonedSheet->setTitle('Logs');
            // write header
            $clonedSheet->getCell('A1')->setValue('Device');
            $clonedSheet->getCell('B1')->setValue('Vsys');
            $clonedSheet->getCell('C1')->setValue('Date');
            $clonedSheet->getCell('D1')->setValue('Rule Name');
            $clonedSheet->getCell('E1')->setValue('Typology');
            $clonedSheet->getCell('F1')->setValue('Hits');


            $clonedSheet->getStyle('A1:F1')->getFont()->setBold(true)->setSize(12);
            $clonedSheet->getStyle('A1:F1')->getFill()->setFillType(PHPExcel_Style_Fill::FILL_SOLID);
            $clonedSheet->getStyle('A1:F1')->getFill()->getStartColor()->setARGB('204b7a');
            $clonedSheet->getStyle('A1:F1')->getAlignment()->setVertical(PHPExcel_Style_Alignment::VERTICAL_CENTER);
            $clonedSheet->getStyle('A1:F1')->getAlignment()->setHorizontal(PHPExcel_Style_Alignment::HORIZONTAL_CENTER);
            $clonedSheet->getStyle('A1:F1')->applyFromArray($styleArrayWhite);

            $clonedSheet->freezePane('A2');

            $row=2;
            foreach($data as $entry){
                $cellB="A".$row;
                $clonedSheet->getCell($cellB)->setValue($entry['serial']);
//                $clonedSheet->getStyle($cellB)->getAlignment()->setWrapText(true);

                $cellB="B".$row;
                $clonedSheet->getCell($cellB)->setValue($entry['serial_vsys']);
//                $clonedSheet->getStyle($cellB)->getAlignment()->setWrapText(true);

                $cellC="C".$row;
                $clonedSheet->getCell($cellC)->setValue($entry['date']);
//                $clonedSheet->getStyle($cellC)->getAlignment()->setWrapText(true);

                $cellD="D".$row;
                $clonedSheet->getCell($cellD)->setValue($entry['rule']);
//                $clonedSheet->getStyle($cellD)->getAlignment()->setWrapText(true);

                $cellD="E".$row;
                $clonedSheet->getCell($cellD)->setValue($entry['typology']);
//                $clonedSheet->getStyle($cellD)->getAlignment()->setWrapText(true);

                $cellD="F".$row;
                $clonedSheet->getCell($cellD)->setValue($entry['hits']);
//                $clonedSheet->getStyle($cellD)->getAlignment()->setWrapText(true);

//                $clonedSheet
//                    ->getRowDimension($row)
//                    ->setOutlineLevel(1)
//                    ->setVisible(false)
//                    ->setCollapsed(false);
                $row++;
            }

            $clonedSheet->getRowDimension('1')->setRowHeight(30);
            $clonedSheet->getColumnDimension('A')->setWidth(30);
            $clonedSheet->getColumnDimension('B')->setWidth(40);
            $clonedSheet->getColumnDimension('C')->setWidth(25);
            $clonedSheet->getColumnDimension('D')->setWidth(40);
            $clonedSheet->getColumnDimension('E')->setWidth(60);
            $clonedSheet->getColumnDimension('F')->setWidth(60);

//            $conditionalStyles = $clonedSheet->getStyle('A2')->getConditionalStyles();
//            array_push($conditionalStyles, $objConditional1);
//            array_push($conditionalStyles, $objConditional2);
//            array_push($conditionalStyles, $objConditional3);
//            $clonedSheet->getStyle('A2')->setConditionalStyles($conditionalStyles);
//            $clonedSheet->duplicateConditionalStyle(
//                $clonedSheet->getStyle('A2')->getConditionalStyles(),
//                'A3:A'.$row
//            );

            //$clonedSheet->getRowDimension($row)->setCollapsed(false);

            $clonedSheet->setAutoFilter($objPHPExcel->getActiveSheet()->calculateWorksheetDimension());
            // Set active filters
            $autoFilter = $clonedSheet->getAutoFilter();
            $autoFilter->showHideRows();



    }

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="Machine_Learning_Analysis.xlsx"');
    header('Cache-Control: max-age=0');
    //$objPHPExcel->setActiveSheetIndex(0);
    $objWriter = PHPExcel_IOFactory::createWriter($objPHPExcel, 'Excel2007');
    //$objWriter->setIncludeCharts(TRUE);
    $objWriter->save('php://output');
    if (function_exists('mb_internal_encoding'))
        mb_internal_encoding($oldEncoding);

    exit(0); //It is important not to continue writing after the Excel is created
}

