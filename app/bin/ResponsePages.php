<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename']) ? $_GET['devicename'] : '');
        $template   = (string)  (isset($_GET['template'])   ? $_GET['template'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$devicename = (string) (isset($_POST['devicename']) ? $_POST['devicename'] : $_GET['devicename']);
//$template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
//$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
//$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);

#DEBUG
//$project="Cisco";
//$action="set";
//$type="save_position";
//$start=0;
//$limit=100;
#DEBUG
# Access Control
if(!checkProjectRights($project,'view')){
    echo '{"total":"0","pages":[]}';
    return;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);

if ($action == "get") {
    if ($type == "response_pages") {
        $query = generate_query("template");
//        $getAll = $projectdb->query("SELECT id as idx,type,template,source,html,vsys,'response_pages' as table_name  "
//                . "FROM response_pages $query "
//                . "UNION SELECT id as idx,type,template,source,html,'shared' as vsys,'shared_response_pages' as table_name "
//                . "FROM shared_response_pages $query;");
        $getAll = $projectdb->query("SELECT id as idx,type,template,source,html,vsys,'response_pages' as table_name  "
                . "FROM response_pages $query ;");
        
        //$count = $getAll->num_rows;
        //$getLimit = $projectdb->query("SELECT id as idx,type,template,source,html,vsys,'response_pages' as table_name  "
        //        . "FROM response_pages $query UNION SELECT id as idx,type,template,source,html,'shared' as vsys,'shared_response_pages' as table_name "
        //        . "FROM shared_response_pages $query ORDER BY type ASC LIMIT $start, $limit;");
        $getLimit = $projectdb->query("SELECT id as idx,type,template,source,html,vsys,'response_pages' as table_name  "
                . "FROM response_pages $query ORDER BY type ASC LIMIT $start, $limit;");
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->id = $x++;
            $data->html = base64_decode($data->html);
            $myData[] = $data;
        }
        if ($getAll->num_rows == 0) {
            $myData = "";
        }
        echo '{"total":"' . $getAll->num_rows . '","pages":' . json_encode($myData) . '}';
    }
}
elseif ($action == "update") {
    switch($_SERVER['REQUEST_METHOD'])
    {
        case 'GET':
            $template   = (string)  (isset($_GET['template'])  ? $_GET['template'] : '');
            $html       = (string)  (isset($_GET['html'])      ? $_GET['html'] :'');
            $table_name = (string)  (isset($_GET['table_name'])? $_GET['table_name'] : '');
            $idx        = (string)  (isset($_GET['idx'])       ? $_GET['idx'] : '');
            $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : '');
            break;
        case 'POST':
            $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
            $html       = (string)  (isset($_POST['html'])      ? $_POST['html'] :'');
            $table_name = (string)  (isset($_POST['table_name'])? $_POST['table_name'] : '');
            $idx        = (string)  (isset($_POST['idx'])       ? $_POST['idx'] : '');
            $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : '');
            break;
        default:
            $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
            $html       = (string)  (isset($_POST['html'])      ? $_POST['html'] :'');
            $table_name = (string)  (isset($_POST['table_name'])? $_POST['table_name'] : '');
            $idx        = (string)  (isset($_POST['idx'])       ? $_POST['idx'] : '');
            $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : '');
            break;
    }

    $template = $projectdb->real_escape_string($template);
    $html = $projectdb->real_escape_string($html);
    $table_name = $projectdb->real_escape_string($table_name);
    $idx = $projectdb->real_escape_string($idx);
    $type = $projectdb->real_escape_string($type);

//    $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
//    $html = (string) (isset($_POST['html']) ? $_POST['html'] : $_GET['html']);
//    $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
//    $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
//    $type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']);

    if($type == "application-block-page"){
        $html = str_replace("<user>", "", $html);
        $html = str_replace("</user>", "<user/>", $html);
        $html = str_replace("<appname>", "", $html);
        $html = str_replace("</appname>", "<appname/>", $html);
    }elseif($type == "captive-portal-text"){
        $html = str_replace("<pan_form>", "", $html);
        $html = str_replace("</pan_form>", "<pan_form/>", $html); 
    }elseif($type == "file-block-continue-page"){
        $html = str_replace("<fname>", "", $html);
        $html = str_replace("</fname>", "<fname/>", $html); 
    }elseif($type == "file-block-page"){
        $html = str_replace("<certname>", "", $html);
        $html = str_replace("</certname>", "<certname/>", $html);
        $html = str_replace("<url>", "", $html);
        $html = str_replace("</url>", "<url/>", $html);
        $html = str_replace("<issuer>", "", $html);
        $html = str_replace("</issuer>", "<issuer/>", $html);
        $html = str_replace("<status>", "", $html);
        $html = str_replace("</status>", "<status/>", $html);
        $html = str_replace("<reason>", "", $html);
        $html = str_replace("</reason>", "<reason/>", $html);   
    }elseif($type == "ssl-cert-status-page"){
        $html = str_replace("<certname>", "", $html);
        $html = str_replace("</certname>", "<certname/>", $html);
        $html = str_replace("<url>", "", $html);
        $html = str_replace("</url>", "<url/>", $html);
        $html = str_replace("<issuer>", "", $html);
        $html = str_replace("</issuer>", "<issuer/>", $html);
        $html = str_replace("<status>", "", $html);
        $html = str_replace("</status>", "<status/>", $html);
        $html = str_replace("<reason>", "", $html);
        $html = str_replace("</reason>", "<reason/>", $html);
    }elseif($type == "ssl-optout-text"){
        $html = str_replace("<url>", "", $html);
        $html = str_replace("</url>", "<url/>", $html);
        $html = str_replace("<category>", "", $html);
        $html = str_replace("</category>", "<category/>", $html);  
    }elseif($type == "url-block-page"){
        $html = str_replace("<user>", "", $html);
        $html = str_replace("</user>", "<user/>", $html);
        $html = str_replace("<url>", "", $html);
        $html = str_replace("</url>", "<url/>", $html);
        $html = str_replace("<category>", "", $html);
        $html = str_replace("</category>", "<category/>", $html);  
    }elseif($type == "url-coach-text"){
        $html = str_replace("<user>", "", $html);
        $html = str_replace("</user>", "<user/>", $html);
        $html = str_replace("<url>", "", $html);
        $html = str_replace("</url>", "<url/>", $html);
        $html = str_replace("<category>", "", $html);
        $html = str_replace("</category>", "<category/>", $html);
        $html = str_replace("<pan_form>", "", $html);
        $html = str_replace("</pan_form>", "<pan_form/>", $html);  
    }elseif($type == "virus-block-page"){
        $html = str_replace("<fname>", "", $html);
        $html = str_replace("</fname>", "<fname/>", $html); 
    }elseif($type == "safe-search-block-page"){
        $html = str_replace("<user>", "", $html);
        $html = str_replace("</user>", "<user/>", $html);
        $html = str_replace("<ssurl>", "", $html);
        $html = str_replace("</ssurl>", "<ssurl/>", $html);
    }    
    
    $newhtml = base64_encode($html);
    //echo "Html: " .$html. "\n";
    // Quitar del html los tags que añade el ExtJs
    
    //echo "New html: " .$newhtml. "\n";
    
    if (strlen($newhtml) > 21845) {
        echo json_encode(array("success" => false, "msg" => "Max lenght is 21845 the website lenght is [" . strlen($newhtml) . "]"));
    } else {
        $projectdb->query("UPDATE $table_name SET html='$newhtml' WHERE id='$idx';");
        echo json_encode(array("success" => true));
    }
}
?>