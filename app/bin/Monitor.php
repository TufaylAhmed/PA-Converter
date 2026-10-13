<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        $type_log   = (string)  (isset($_GET['type_log'])  ? $_GET['type_log'] : '');
        $log_search_action = (string) (isset($_GET['log_search_action'])   ? $_GET['log_search_action'] : '');
        $log_search_message = (string) (isset($_GET['log_search_message']) ? $_GET['log_search_message'] : '');
        $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
        $lid        = (integer) (isset($_GET['obj_id'])     ? $_GET['obj_id'] : 0);
        $obj_table  = (string) (isset($_GET['obj_table'])  ? $_GET['obj_table'] : '');
        $obj_type   = (string) (isset($_GET['obj_type'])   ? $_GET['obj_type'] : '');
        $ids        = (string) (isset($_GET['ids'])        ? $_GET['ids'] : '');
        $hide_fixed = (string) (isset($_GET['hide_fixed'])        ? $_GET['hide_fixed'] : '');


        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $type_log   = (string)  (isset($_POST['type_log'])  ? $_POST['type_log'] : '');
        $log_search_action = (string) (isset($_POST['log_search_action'])   ? $_POST['log_search_action'] : '');
        $log_search_message = (string) (isset($_POST['log_search_message']) ? $_POST['log_search_message'] : '');

        $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
        $lid        = (integer) (isset($_POST['obj_id'])     ? $_POST['obj_id'] : 0);
        $obj_table  = (string) (isset($_POST['obj_table'])  ? $_POST['obj_table'] : '');
        $obj_type   = (string) (isset($_POST['obj_type'])   ? $_POST['obj_type'] : '');
        $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
        $hide_fixed = (string) (isset($_POST['hide_fixed'])        ? $_POST['hide_fixed'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $type_log   = (string)  (isset($_POST['type_log'])  ? $_POST['type_log'] : '');
        $log_search_action = (string) (isset($_POST['log_search_action'])   ? $_POST['log_search_action'] : '');
        $log_search_message = (string) (isset($_POST['log_search_message']) ? $_POST['log_search_message'] : '');
        $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
        $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
        $lid        = (integer) (isset($_POST['obj_id'])     ? $_POST['obj_id'] : 0);
        $obj_table  = (string) (isset($_POST['obj_table'])  ? $_POST['obj_table'] : '');
        $obj_type   = (string) (isset($_POST['obj_type'])   ? $_POST['obj_type'] : '');
        $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
        $hide_fixed = (string) (isset($_POST['hide_fixed'])        ? $_POST['hide_fixed'] : '');
        break;
}
//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
//$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);
#DEBUG
//$project="test";
//$action="generate";
//$type="XML";
#DEBUG

# Access Control
if(!checkProjectRights($project,'view')){
    echo '{"total":"0","rows":' . json_encode(array()) . '}';
    return;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = (integer) $projectdb->real_escape_string($start);
$limit = (integer) $projectdb->real_escape_string($limit);
$type_log = $projectdb->real_escape_string($type_log);
$log_search_action = $projectdb->real_escape_string($log_search_action);
$log_search_message = $projectdb->real_escape_string($log_search_message);
$vsys = $projectdb->real_escape_string($vsys);
$source = $projectdb->real_escape_string($source);
$lid = (integer) $projectdb->real_escape_string($lid);
$obj_table = $projectdb->real_escape_string($obj_table);
$obj_type = $projectdb->real_escape_string($obj_type);
$ids = $projectdb->real_escape_string($ids);
$hide_fixed = $projectdb->real_escape_string($hide_fixed);


if ($action == "get") {
    if ($type == "logs") {




//        $type_log = (string) (isset($_POST['type_log']) ? $_POST['type_log'] : $_GET['type_log']);
//        $log_search_action = (string) (isset($_POST['log_search_action']) ? $_POST['log_search_action'] : $_GET['log_search_action']);
//        $log_search_message = (string) (isset($_POST['log_search_message']) ? $_POST['log_search_message'] : $_GET['log_search_message']);
        
        // Hasta que no actualicemos todas las consultas con type = 1, de momento lo hago así
        if($type_log == "2"){
            $sql = " WHERE type = '2' ";
        }else{
            $sql = " WHERE type in ('',1,2) ";
        }

        if($hide_fixed == "true"){
            $sql .= " AND fixed = '0' ";
        }

        if(($log_search_message != "") || ($log_search_action != "")){
            $sql .= " AND ( message LIKE :log_search_message AND action LIKE :log_search_action ) ";
        }

        $conn = get_pdo($project);
        $stmt = $conn->prepare("SELECT id FROM logs $sql GROUP BY type,source,level,task,message,action ORDER BY datetime DESC;");

        if(($log_search_message != "") || ($log_search_action != "")) {
            $log_search_message= "%".$log_search_message."%";
            $log_search_action= "%".$log_search_action."%";
            $stmt->bindParam(":log_search_message", $log_search_message);
            $stmt->bindParam(":log_search_action", $log_search_action);
        }

        $stmt->execute();
        // Fetch all the rows from the result set
        $countLogs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $count = count($countLogs);

        //$countLogs = $result = $projectdb->query("SELECT id FROM logs $sql GROUP BY type,source,level,task,message,action ORDER BY datetime DESC;");
        //$count = $countLogs->num_rows;
        
        if($type_log == "2"){

            $conn2 = get_pdo("pandb");

            $stmt = $conn2->prepare("SELECT id FROM logs $sql GROUP BY type,source,level,task,message,action ORDER BY datetime DESC;");

            if(($log_search_message != "") || ($log_search_action != "")) {
                $stmt->bindParam(":log_search_message", $log_search_message);
                $stmt->bindParam(":log_search_action", $log_search_action);
            }
            $stmt->execute();

            $countLogs2 = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $count += count($countLogs2);

            //$countLogs2 = $result = $pandb->query("SELECT id FROM logs $sql GROUP BY type,level,task,message,action ORDER BY datetime DESC;");
            //$count = $count + $countLogs2->num_rows;
        }

        $conn = get_pdo($project);
        $stmt = $conn->prepare("SELECT id,datetime,type,source,level,task,message,action,fixed,obj_type,obj_id,obj_table FROM logs $sql ORDER BY task ASC LIMIT :start, :limit ");

        if(($log_search_message != "") || ($log_search_action != "")) {
            $stmt->bindParam(":log_search_message", $log_search_message);
            $stmt->bindParam(":log_search_action", $log_search_action);
        }

        $stmt->bindParam(':start', $start,1);
        $stmt->bindParam(':limit', $limit, 1);

        //$result = $projectdb->query("SELECT id,datetime,type,source,level,task,message,action,fixed,obj_type,obj_id,obj_table "
        //        . " FROM logs $sql ORDER BY task ASC LIMIT $start,$limit;");

        $stmt->execute();
        // Fetch all the rows from the result set
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $data = array();
        if(count($rows) > 0){
            foreach ($rows as $row) {
                $data [] = $row;
            }
        }

        if($type_log == "2"){

            $conn2 = get_pdo("pandb");
            $stmt = $conn2->prepare("SELECT id,datetime,type,source,level,task,message,action,fixed,obj_type,obj_id,obj_table FROM logs $sql ORDER BY task ASC LIMIT :start,:limit;");

            if(($log_search_message != "") || ($log_search_action != "")) {
                $stmt->bindParam(":log_search_message", $log_search_message);
                $stmt->bindParam(":log_search_action", $log_search_action);
            }
            $stmt->bindParam(":start", $start);
            $stmt->bindParam(":limit", $limit);


            //$result = $pandb->query("SELECT id,datetime,type,level,task,message,action,fixed,obj_type,obj_id,obj_table "
            //    . " FROM logs $sql ORDER BY task ASC LIMIT $start,$limit;");

            $stmt->execute();
            // Fetch all the rows from the result set
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $data = array();
            if(count($rows) > 0){
                foreach ($rows as $row) {
                    $data [] = $row;
                }
            }

        }
        echo '{"total":"' . $count . '","rows":' . json_encode($data) . '}';
    
        
    } 
    elseif ($type == "logs_by_rulelid") {

        $data = array();
        $rows = 0;
        $count = 0;

        if ($lid != "" || $lid != 0) {

            $conn = get_pdo($project);
            $stmt = $conn->prepare("SELECT id,datetime,type,source,level,task,message,action,fixed,obj_type,obj_id,obj_table 
            FROM logs WHERE obj_id IN (:lid) AND obj_type=:obj_type AND obj_table=:obj_table ORDER BY task DESC;");

            $stmt->bindParam(':lid', $lid);
            $stmt->bindParam(':obj_type', $obj_type);
            $stmt->bindParam(':obj_table', $obj_table);

            $stmt->execute();

            //$result = $projectdb->query("SELECT id,datetime,type,source,level,task,message,action,fixed,obj_type,obj_id,obj_table
            //FROM logs WHERE obj_id IN ($lid) AND obj_type='$obj_type' AND obj_table='$obj_table' ORDER BY task DESC;");

            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $count = count($rows);

            //$count = $result->num_rows;
            $data = array();
            foreach($rows as $row) {
                $data[] = $row;
            }
        }

        echo '{"total":"' . $count . '","rows":' . json_encode($data) . '}';
    }
}
elseif ($action == "fixed"){
    # Access Control Delete
    if(!checkProjectRights($project,"update")){
        echo '{"success":"fail","msg":"You do not have rights in this project"}';
        return;
    }
//    $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
    if ($ids!=""){
        take_snapshot_last($project);
        $conn = get_pdo($project);
        $stmt = $conn->prepare("UPDATE logs SET fixed=1 WHERE id IN ($ids);");
        $stmt->bindParam(':lid', $lid);
        $stmt->execute();

        //$projectdb->query("UPDATE logs SET fixed=1 WHERE id IN ($ids);");
    }
    
    
}
elseif ($action == "remove"){
    # Access Control Delete
    if(!checkProjectRights($project,"delete")){
        echo '{"success":"fail","msg":"You do not have rights in this project"}';
        return;
    }
//    $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
    if ($ids!=""){
        take_snapshot_last($project);
        $conn = get_pdo($project);
        $stmt = $conn->prepare("DELETE FROM logs WHERE id IN ($ids);");
        $stmt->bindParam(':lid', $lid);
        $stmt->execute();

        //$projectdb->query("DELETE FROM logs WHERE id IN ($ids);");
    }
}
?>