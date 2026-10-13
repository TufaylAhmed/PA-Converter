<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 8/7/16 - 16:02
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

use PaloaltoNetworks\Policy\Objects\MemberObject;

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $post_vars['type'];
}
else {
    $type       = (string)(isset($_GET['type']) ? $_GET['type'] : '');
}
$project    = (string)(isset($_GET['project'])  ? $_GET['project'] : '');
$vsys       = (string)(isset($_GET['vsys'])     ? $_GET['vsys'] : '');
$source     = (string)(isset($_GET['source'])   ? $_GET['source'] : '');

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        fixDuplicated( $project,  $source,  $vsys);
//        $message = list_Duplicated($project, $source, $vsys);
//        if($message['code']) {
//            $totalDevices = count($message['msg']);
//            echo json_encode(array('total' => count($message['msg']), 'addresses' => $message['msg']));
//        }
//        else{
//            echo '{"success":"false","message":""}';
//        }
        break;

    case 'POST':
        $source = $data['source'];
        $svys = $data['vsys'];
        $message = fixDuplicated($project,  $source,  $vsys);  //vsys, source,
        echo json_encode(array('success' => $message['code'], 'message' => $message['msg']));
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}

function fixDuplicated(STRING $project, STRING $source, STRING $vsys){
    global $projectdb;
    $projectdb = selectDatabase($project);

    $memberAssociation = array();

    //Sanitize the input info
    $source = $projectdb->real_escape_string($source);
    $vsys   = $projectdb->real_escape_string($vsys);

    // IP/CIDR
    $query = "SELECT * FROM address_groups_id WHERE  vsys='$vsys' AND source='$source' AND type='static' GROUP BY name HAVING count(*)>1";
    $duplicatedReference=$projectdb->query($query);

    $query = "SELECT * FROM address_groups_id WHERE  vsys='$vsys' AND source='$source' AND type='static'";
    $explodedGroups=$projectdb->query($query);
    //Get the explodedgroups

    $processedGroups = array();
    while($row = $explodedGroups->fetch_assoc()) {
        $memberReference = array();
        $memberReference[] = new MemberObject($row['id'],'address_groups_id');
        $membersInReference =explodeGroups2Members($memberReference, $projectdb, $source, $vsys, 0, $processedGroups);
        $memberAssociation[$row['id'].'address_groups_id']['name'] = $row['name'];
        $memberAssociation[$row['id'].'address_groups_id']['members'] = $membersInReference;


//        //Init variables
//        $newDescFound = $newTagFound = false;
//        $description = $tag = $replaceable = $deletable = array();
//
//        if ($row['description'] != '') {
//            $descriptionSample = explode('.',$row['description']);
//            $description = array_merge($description, $descriptionSample);
//        }
//
//        if ($row['tag'] != ''){
//            $tagsFromSample = explode (',',$row['tag']);
//            $tag = array_merge($tag, $tagsFromSample);
//        }
//
//        $duplicated = "SELECT a.id,a.description, a.tag
//          FROM address a, address b
//          WHERE a.vsys='$vsys' AND a.source='$source' AND (a.type='ip-netmask' OR a.type='ip-range') AND
//            a.name = b.name AND
//            a.ipaddress = b.ipaddress AND
//            a.cidr = b.cidr AND
//            b.id = ".$row['id']." AND
//            a.id != ".$row['id'];
//        $data = $projectdb->query($duplicated);
//        while($rowDup = $data->fetch_assoc()){
//            $memberToReplace = new MemberObject($rowDup['id'], 'address');
//            $deletable[] = $rowDup['id'];
//            $replaceable[] = $memberToReplace;
//            if ($rowDup['description'] != '') {
//                $description[] = $rowDup['description'];
//                $newDescFound = true;
//            }
//            if ($rowDup['tag'] != '') {
//                $tagsFromDup = explode (',',$rowDup['tag']);
//                $tag = array_merge($tag, $tagsFromDup);
//                $newTagFound = true;
//            }
//        }
//
//        if($newDescFound){
//            add_log2(
//                "warning",
//                'AutoMerge Duplicated Address',
//                'Address Object['.$row['name'].']: Description has been extended with information from multiple duplicated addresses',
//                $source,
//                'AutoMerge',
//                'address',
//                $row['id'],
//                'address');
//        }
//        if($newTagFound){
//            add_log2(
//                "warning",
//                'AutoMerge Duplicated Address',
//                'Address Object['.$row['name'].']: Tags have been extended with information from multiple duplicated addresses',
//                $source,
//                'AutoMerge',
//                'address',
//                $row['id'],
//                'address');
//        }
//
//        $description = array_unique($description);
//        $tag = array_unique($tag);
//
//        $queryUpdate = "UPDATE address SET description = '".implode('.',$description)."', tag='".implode(',',$tag)."' WHERE id = ".$row['id'];
//        $projectdb->query($queryUpdate);
//
//        //Redirect all references from this address object to the Reference
//        $member = new MemberObject($row['id'], 'address');
//        $message = redirectReferences($project, $member, $replaceable);
//
//        //Delete the duplicateds
//        $deleteQuery = "DELETE FROM address WHERE id in (".implode(',',$deletable).")";
//        $projectdb->query($deleteQuery);
    }

    echo "Final<br>";
    var_dump(htmlspecialchars($memberAssociation));

    $message = array();
    $message['code'] = true;

    return $message;
}

function redirectReferences(STRING $project, MemberObject $member, ARRAY $replaceables){
    $projectdb = selectDatabase($project);

    foreach($replaceables as $replaceable){
        $conditions[]    = "member_lid='$replaceable->name'           AND table_name='$replaceable->location'";
        $conditionsNat[] = "tp_dat_address_lid='$replaceable->name'   AND tp_dat_address_table='$replaceable->location'";
        $conditionsLog[] = "obj_id='$replaceable->name'               AND obj_table='$replaceable->location'";
    }

    if(count($conditions)>0) {
        $query = "UPDATE address_groups SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        //$query = "UPDATE shared_address_groups SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        //$projectdb->query($query);
        $query = "UPDATE security_rules_src SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        $query = "UPDATE security_rules_dst SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        $query = "UPDATE nat_rules_src SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        $query = "UPDATE nat_rules_dst SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        $query = "UPDATE nat_rules_translated_address SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        $query = "UPDATE nat_rules_translated_address_fallback SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        $query = "UPDATE appoverride_rules_src SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        $query = "UPDATE appoverride_rules_dst SET member_lid='$member->name', table_name='$member->location' WHERE (" . implode(') OR (', $conditions) . ")";
        $projectdb->query($query);
        $query = "UPDATE nat_rules SET tp_dat_address_lid='$member->name', tp_dat_address_table='$member->location' WHERE (" . implode(') OR (', $conditionsNat) . ")";
        $projectdb->query($query);
        $query = "UPDATE logs SET obj_id='$member->name', obj_table='$member->location' WHERE (" . implode(') OR (', $conditionsLog) . ")";
        $projectdb->query($query);
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = "";
    return $message;
}

function list_Duplicated(STRING $project, STRING $source, STRING $vsys){
    global $projectdb;
    //Select the database;
    $projectdb = selectDatabase($project);

    $query = "SELECT * FROM address_groups_id WHERE  vsys='$vsys' AND source='$source' AND type='static' GROUP BY name HAVING count(*)>1";
    $getisPanorama=$projectdb->query($query);
    $message = array();
    $message['code'] = true;
    $message['msg'] = array();

    while($row = $getisPanorama->fetch_assoc()){
        $message['msg'][]=$row;
    }
    return $message;
}

function fixDuplicatedNames(STRING $project, ARRAY $data){
    global $pandb;

    foreach ($data as $address){
        $memberID  = $address['id'];
        $tableName = $address['tablename'];

        //get all fields that are blank in the selected entry
        $getisPanorama=$pandb->query("SELECT source, vsys, name FROM $tableName WHERE id='$memberID'");

        //Delete all duplicated addresses

    }

}