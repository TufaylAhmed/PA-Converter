<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

$request_body     = file_get_contents('php://input');
$params           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':

        $params['project'] = $pandb->real_escape_string(isset($_GET['project']) ? $_GET['project']: '');
        $params['mode'] = $pandb->real_escape_string(isset($_GET['mode']) ? $_GET['mode']: '');
        $params['tools_where_id'] = $pandb->real_escape_string(isset($_GET['tools_where_id']) ? $_GET['tools_where_id']: '');
        $params['source'] = $pandb->real_escape_string(isset($_GET['source']) ? $_GET['source']: '');

        $params['start'] = $pandb->real_escape_string(isset($_GET['start']) ? $_GET['start']: '');
        $params['limit'] = $pandb->real_escape_string(isset($_GET['limit']) ? $_GET['limit']: '');

        if ((isset($params['project'] )) AND ($params['project'] !='')) {

            $message = list_filters($params);
            //print_r($message);

            if ($message['code'] == true) {

                if ($params['mode'] == "where") {
                    echo json_encode(array('total' => $message['count'], 'where' => $message['msg']));
                } elseif (($params['mode'] == "columns") || ($params['mode'] == "advanced_options") || ($params['mode'] == "operator") || ($params['mode'] == "columns_predefined")) {
                    echo json_encode(array('total' => $message['count'], 'columns' => $message['msg']));
                } elseif ($params['mode'] == "results_filters") {
                    echo json_encode(array('total' => $message['count'], 'results' => $message['msg']));
                } elseif ($params['mode'] == "sql_tree" || $params['mode'] == "filters_tree"){
                    echo json_encode($message['msg']);
                }
                else {
                    echo json_encode($message);
                }
            }
            else {
                echo json_encode(array('code' => $message['code'], 'msg' => $message['msg']));
            }

        }else{
            echo '{"total":"0","filters":[]}';
        }
        break;

    case 'POST':

        $message = register_filters($params);

        echo json_encode(array('success' => $message['code']));
        break;

    case 'PUT':

        $message = update_filters($params);

        echo json_encode(array('success' => $message['code']));
        break;


    case 'DELETE':

        $message = delete_filter($params);

        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_filters(ARRAY $params){

    $project = $params['project'];

    if(!checkProjectRights($project,'view')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'where':
            $message = getWhere($project,'');
            break;

        case 'columns':
            $message = getColumns($project, $params);
            break;

        case 'columns_predefined':
            $message = getColumnsPredefined($project, $params);
            break;

        case 'advanced_options':
            $message = getAdvancedOptions($project, $params);
            break;

        case 'operator':
            $message = getOperator($project, $params);
            break;

        case 'filters_tree':
            $message = getFiltersTree($project, $params);
            break;

        case 'sql_tree':
            $message = getSQLTree($project, $params);
            break;

        case 'results_filters':
            $message = getResultsFilters($project, $params);
            break;

        case 'check_exist_filter':
            $message = getExistFilter($project, $params);
            break;

        default:
            $message = [
                'code'  => false,
                'msg'   => 'Option not defined'
            ];
            break;
    }

//    print_r($message);

    return $message;

}

function register_filters(ARRAY $params){

    $project = $params['project'];

    if(!checkProjectRights($project,'update')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'set_filter': //Register a filter (Used from Front-End and ...)
            $message = setFilter($project, $params, "");
            break;

        case 'set_filter_multi_selection':
            $message = setFilterMultiSelection($project, $params, "");
            break;

        case 'set_sql':
            $message = setSQL($project, $params);
            break;

        case 'set_sql_filter': //Activate filter (Used from Front-End and ...)
            $message = setSQLFilter($project, $params, "no");
            break;

        case 'execute_sql': //Apply the filter to show the results (Used from Front-End and ...)
            $message = executeSQL($project, $params);
            break;

        case 'exist_filters':
            $message = existFilters($project,'');
            break;

        default:
            break;
    }

    return $message;


}


function update_filters(ARRAY $params){

    $project = $params['project'];

    if(!checkProjectRights($project,'update')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'update_filter':
            $message = updateFilter($project, $params);
            break;

        case 'update_sql':
            $message = updateSQL($project, $params);
            break;

        default:
            break;
    }

    return $message;


}

function delete_filter(ARRAY $params){

    global $projectdb;

    $project = $params['project'];

    if(!checkProjectRights($project,'update')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $source = $params['source'];

    $projectdb = selectDatabase($project);

    if($params['type'] == "filter"){
        if($params['mode'] == "selected"){
            $filter_id = $params['filter_id'];
            if($filter_id == "root"){
                $query = "DELETE FROM tools_filters WHERE source = '$source';";
            }else{
                $query = "DELETE FROM tools_filters WHERE id = '$filter_id';";
            }
            $projectdb->query($query);
        }
        elseif ($params['mode'] == "all"){
            $projectdb->query("DELETE FROM tools_filters WHERE source = '$source' ;");
            $projectdb->query("DELETE FROM tools_sql WHERE source = '$source';");
            $projectdb->query("DELETE FROM tools_results WHERE source = '$source';");

            //checkExistFilterAndRemove($params['project'], 'address');
            //checkExistFilterAndRemove($params['project'], 'services');
            //checkExistFilterAndRemove($params['project'], 'applications');
        }
        elseif($params['mode'] == "selected_filter_id"){
            checkExistFilterFromWhereColumnsId($params['project'], $params['tools_where_id'], $params['tools_where_columns_id'], "yes", $source);
            //$filter_id = checkExistFilterFromWhereColumnsId($params['project'], $params['tools_where_id'], $params['tools_where_columns_id'], "yes");
            //if($filter_id != ""){
            //    removeFilterId($params['project'], $filter_id);
            //}
        }
        elseif($params['mode'] == "selected_where_id"){
            checkExistFilterFromWhereId($params['project'], $params['tools_where_id'], "yes", $source);
            //$filter_id = checkExistFilterFromWhereId($params['project'], $params['tools_where_id']);
            //if($filter_id != ""){
            //    removeFilterId($params['project'], $filter_id);
            //}
        }

    }
    elseif($params['type'] == "tree"){
        if($params['mode'] == "selected"){

            $id = $params['id'];
            $table_name = $params['table_name'];
            $tools_sql_id = $params['tools_sql_id'];

            if($table_name == "tools_sql"){
                $getExistsFilter = $projectdb->query("SELECT filter_id FROM tools_sql WHERE id = '$id';");
                if ($getExistsFilter->num_rows > 0) {
                    $dataEF = $getExistsFilter->fetch_assoc();
                    $projectdb->query("UPDATE tools_filters SET active = '1', tools_sql_id = '0' WHERE id IN (".$dataEF['filter_id']."); ");
                }
                $query = "DELETE FROM tools_sql WHERE id = '$id';";
                $projectdb->query($query);

                // Check if parent_id
                $getExistsFilter = $projectdb->query("SELECT filter_id FROM tools_sql WHERE parent_id = '$id';");
                if ($getExistsFilter->num_rows > 0) {
                    while($dataEF = $getExistsFilter->fetch_assoc()){
                        $projectdb->query("UPDATE tools_filters SET active = '1', tools_sql_id = '0' WHERE id IN (".$dataEF['filter_id']."); ");
                    }

                }
                $query = "DELETE FROM tools_sql WHERE parent_id = '$id';";
                $projectdb->query($query);
            }
            elseif($table_name == "tools_filters"){
                $getFilter = $projectdb->query("SELECT filter_id FROM tools_sql WHERE id = '$tools_sql_id';");
                //echo "SELECT filter_id FROM tools_sql WHERE id = '$tools_sql_id';\n";
                if ($getFilter->num_rows > 0) {
                    $dataF = $getFilter->fetch_assoc();
                    $filter_id_old = explode(",", $dataF['filter_id']);
                    if (($key = array_search($id, $filter_id_old)) !== false) {
                        unset($filter_id_old[$key]);
                        $projectdb->query("UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$tools_sql_id'");
                        //echo "UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$tools_sql_id'\n";
                    }
                    $projectdb->query("UPDATE tools_filters SET active = '1', tools_sql_id = '0' WHERE id = '$id'; ");
                    //echo "UPDATE tools_filters SET active = '1', tools_sql_id = '0' WHERE id = '$id'; \n";
                }
            }
        }
        elseif ($params['mode'] == "all"){

            //$getFilter = $projectdb->query("SELECT filter_id FROM tools_sql;");
            //if ($getFilter->num_rows > 0) {
            //    while($dataF = $getFilter->fetch_assoc()){
            //        $projectdb->query("UPDATE tools_filters SET active = '1' WHERE id IN (".$dataF['filter_id']."); ");
            //    }
            //}

            $projectdb->query("UPDATE tools_filters SET active = '1', tools_sql_id = '0' WHERE source = '$source'; ");

            $projectdb->query("DELETE FROM tools_sql WHERE source = '$source';");
            $projectdb->query("DELETE FROM tools_results WHERE source = '$source';");

        }
    }

    //executeSQL($project, '');

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Filter Removed';
    return $message;

}
