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
require_once INC_ROOT.'/libs/common/tools/tools.php';
require_once INC_ROOT.'/libs/common/tools/tools-rules.php';

$request_body     = file_get_contents('php://input');
$params           = json_decode($request_body, true);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':

        $params['project'] = $pandb->real_escape_string(isset($_GET['project']) ? $_GET['project']: '');
        $params['mode'] = $pandb->real_escape_string(isset($_GET['mode']) ? $_GET['mode']: '');
        $params['table_name'] = $pandb->real_escape_string(isset($_GET['table_name']) ? $_GET['table_name']: '');

        $message = list_tools($params);

        if($message['code']==true) {
            if ($params['mode'] == "get_consolidation"){
                echo json_encode(array('code' => $message['code'], 'total' => $message['count'], 'search' => $message['msg']));
            }
            else {
                echo json_encode($message);
            }
        }
        else{
            echo json_encode(array('code' => $message['code'], 'msg' => $message['msg']));
        }

        break;

    case 'POST':

        $message = register_tools($params);

        if(($params['mode'] == "get_found_in_groups") || ($params['mode'] == "get_found_in_security") || ($params['mode'] == "get_found_in_nat") || ($params['mode'] == "get_found_in_appoverride") || ($params['mode'] == "get_objects_to_replace")){
            echo json_encode(array('total' => $message['count'], 'search' => $message['msg']));
        }
        elseif(($params['mode'] == "set_merge_nat_rules") || ($params['mode'] == "set_merge_security_rules") || ($params['mode'] == "set_merge_appoverride_rules")){
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }
        else{
            echo json_encode(array('success' => $message['code']));
        }

        break;

    case 'PUT':

        $message = update_tools($params);

        echo json_encode(array('success' => $message['code']));
        break;


    case 'DELETE':

        $message = delete_tools($params);

        echo json_encode(array('success' => $message['code']));
        break;

    default:
        break;
}

function list_tools(ARRAY $params){

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view', 'project.create'])){
        $message =[
            'code'  => false,
            'msg'   => 'Your account does not have the rights to view this project contents'
            ];
        return $message;
    }
    switch ($params['mode']){

        case 'get_consolidation':
            $message = getConsolidationHash($project, $params);
            break;

        default:
            $message = [
                'code'  => true,
                'count' => 0,
                'msg'   => ''
            ];
            break;
    }

    return $message;

}

function register_tools(ARRAY $params){

    $project = $params['project'];
    $message = "";

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }
    take_snapshot_last($project);
    switch ($params['mode']){

        case 'get_found_in_groups':
            $message = getFoundInGroups($project, $params);
            break;

        case 'get_found_in_security':
            $message = getFoundInSecurity($project, $params);
            break;

        case 'get_found_in_nat':
            $message = getFoundInNat($project, $params);
            break;

        case 'get_found_in_appoverride':
            $message = getFoundInAppOverride($project, $params);
            break;

        case 'get_objects_to_replace':
            $message = getObjectsToReplace($project, $params);
            break;

        case 'add_prefix_suffix':
            $message = setPrefixSuffix($project, $params);
            break;

        case 'rename':
            $message = setRename($project, $params);
            break;

        case 'set_objects_to_replace':
            $message = setObjectsToReplace($project, $params);
            break;

        case 'set_replace':
            $message = setReplace($project, $params);
            break;

        case 'get_consolidation_rules':
            $message = getConsolidationRules($project, $params);
            break;

        case 'set_merge_objects':
            $message = setMergeObjects($project, $params);
            break;

        case 'set_merge_security_rules':
            $message = setMergeSecurityRules($project, $params,'yes');
            break;

        case 'set_merge_nat_rules':
            $message = setMergeNatRules($project, $params);
            break;

        case 'set_merge_appoverride_rules':
            $message = setMergeAppoverrideRules($project, $params);
            break;

        case 'set_visible_hash':
            $message = setVisibleHash($project, $params);
            break;

        case 'set_merge_as_primary':
            $message = setMergeAsPrimary($project, $params);
            break;

        case 'set_objects_to_group':
            $message = setObjectsToGroup($project, $params);
            break;

        case 'set_members_to_group':
            $message = setMembersToGroup($project, $params);
            break;

        case 'set_replace_by_group':
            $message = setReplaceByGroup($project, $params);
            break;

        case 'deselect_merge_as_primary':
            $message = deselectMergeAsPrimary($project, $params);
            break;

        case 'deselect_all_merge_as_primary':
            $message = deselectAllMergeAsPrimary($project, $params);
            break;

        case 'transform_objects_to_ipaddress':
            $message = transformObjectsToIPaddress($project, $params);
            break;

        case 'transform_ipaddress_to_objects':
            $message = transformIPaddressToObjects($project, $params);
            break;

        case 'set_protocol':
            $message = setProtocol($project, $params);
            break;

        case 'set_options_rules':
            $message = setOptionsRules($project, $params);
            break;

        case 'set_options_rules_relations':
            $message = setOptionsRulesRelations($project, $params);
            break;

        case 'unset_options_rules_relations':
            $message = unsetOptionsRulesRelations($project, $params);
            break;

        case 'rule_names':
            $message = setRuleNames($project, $params);
            break;

        case 'rule_address_groups_by_member':
            $message = setRuleAddressGroupsByMember($project, $params);
            break;

        case 'rule_services_groups_by_member':
            $message = setRuleServicesGroupsByMember($project, $params);
            break;

        case 'set_options_objects_relations':
            $message = setOptionsObjectsRelations($project, $params);
            break;

        case 'unset_options_objects_relations':
            $message = unsetOptionsObjectsRelations($project, $params);
            break;

        default:
            break;
    }

    return $message;


}


function update_tools(ARRAY $params){

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }
    switch ($params['mode']){

        default:
            break;
    }

    //return $message;

}

function delete_tools(ARRAY $params){

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }
    take_snapshot_last($project);
    switch ($params['mode']){

        case 'remove_replace':
            $message = removeReplace($project, $params);
            break;

        case 'remove_consolidation':
            $message = removeConsolidation($project, $params);
            break;


        default:
            break;
    }

    return $message;

}
