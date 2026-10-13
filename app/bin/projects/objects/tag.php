<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/7/16 - 14:42
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/userManager/API/devices/list.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';

require_once INC_ROOT . '/libs/common/tag/tag.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

if(isset($post_vars['type'])){
    $type = $post_vars['type'];
}
else {
    $mode           = $pandb->real_escape_string((string)(isset($_GET['mode'])         ? $_GET['mode'] : ''));
    $type           = $pandb->real_escape_string((string)(isset($_GET['type'])         ? $_GET['type'] : ''));
    $projectName    = $pandb->real_escape_string((string)(isset($_GET['project'])      ? $_GET['project']: ''));
    $source         = $pandb->real_escape_string((string)(isset($_GET['source'])       ? $_GET['source']: ''));
    $vsys           = $pandb->real_escape_string((string)(isset($_GET['vsys'])         ? $_GET['vsys']: ''));
    $table_name     = $pandb->real_escape_string((string)(isset($_GET['table_name'])   ? $_GET['table_name']: ''));
    $id             = $pandb->real_escape_string((string)(isset($_GET['id'])           ? $_GET['id']: ''));
    $objsearch      = $pandb->real_escape_string((string)(isset($_GET['objsearch'])    ? $_GET['objsearch']: ''));
    $objfilter      = $pandb->real_escape_string((string)(isset($_GET['objfilter'])    ? $_GET['objfilter']: 'none'));
    $hide_shared    = $pandb->real_escape_string((string)(isset($_GET['hide_shared'])  ? $_GET['hide_shared']: 'false'));
    $version        = $pandb->real_escape_string((string)(isset($_GET['version'])         ? $_GET['version'] : ''));
    $page           = $pandb->real_escape_string((string)(isset($_GET['page'])         ? $_GET['page']: ''));
    $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])        ? $_GET['limit']: ''));
    $start          = $pandb->real_escape_string((string)(isset($_GET['start'])        ? $_GET['start']: ''));

    $params = [
        'mode'          => $mode,
        'type'          => $type,
        'projectName'   => $projectName,
        'project'       => $projectName,
        'source'        => $source,
        'vsys'          => $vsys,
        'table_name'    => $table_name,
        'id'            => $id,
        'objfilter'     => $objfilter,
        'objsearch'     => $objsearch,
        'hide_shared'   => $hide_shared,
        'version'       => $version,
        'page'          => $page,
        'limit'         => $limit,
        'start'         => $start
    ];}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_tag($params);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'tags' => $message['msg']));
        }
        else{
            echo '{"total":"0","tags":[]}';
        }
        break;

    case 'POST':
        $message = register_tag($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;
        
    case 'PUT':
        $message = update_tag($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_tag($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_tag(ARRAY $params){

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'tags':
            $message = get_tags($params);
            break;

        case 'tags_all':
            $message = get_tagsAll($params);
            break;

        case 'grouptags_all':
            $message = get_grouptagsAll($params);
            break;


        case 'tags_colors':
            $message = get_tagsColors($params);
            break;

        default:
            break;
    }

    return $message;


}

function update_tag(ARRAY $data){
    global $app;
    global $projectdb;

    $project = $data['project'];
    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);
    $modified = 1;
    $dummy = 0;
    $vtype = '';
    $name = mysqli_real_escape_string($projectdb, $data['name']);
    $name = normalizeTagNames($name);
    $source = mysqli_real_escape_string($projectdb, $data['source']);
    $vsys = mysqli_real_escape_string($projectdb, $data['vsys']);
    //$vtype = mysqli_real_escape_string($projectdb, $data['vtype']);
    $comments = mysqli_real_escape_string($projectdb, $data['comments']);
    //$devicegroup = mysqli_real_escape_string($projectdb, $data['devicegroup']);
    $color = mysqli_real_escape_string($projectdb, $data['color_name']);
    $id = mysqli_real_escape_string($projectdb, $data['id']);

    if($vsys == "all"){
        $query = "UPDATE tag SET name='$name', color='$color',
              comments='$comments', modified='$modified', dummy='$dummy'
              WHERE id=$id";
        $projectdb->query($query);
    }
    else{
        if(is_numeric($id)){
            $query = "UPDATE tag SET name='$name', vsys='$vsys', color='$color',
                comments='$comments', source='$source', modified='$modified', dummy='$dummy'
                WHERE id=$id";
            $projectdb->query($query);
        }
        else{
            $getTags = $projectdb->query("SELECT id FROM tag WHERE vsys = '$vsys' AND source = '$source' AND BINARY name = '$name';");
            if ($getTags->num_rows == 0) {
                $query = "INSERT INTO tag (name, vsys, source, color, comments, modified, dummy) 
                           VALUES ('$name', '$vsys', '$source', '$color', '$comments','$modified', '$dummy')";
                $projectdb->query($query);
                $id = $projectdb->insert_id;
            }
        }
    }

    $getOldTags = $projectdb->query("SELECT name FROM tag WHERE id = '$id';");
    if ($getOldTags->num_rows == 1) {
        $getOldTagsData = $getOldTags->fetch_assoc();
        $old_name = $getOldTagsData['name'];
    }

    // Update tag on Address, AddressGroups, Services, ServicesGroups
    $tables_name = array("address", "address_groups_id", "services", "services_groups_id");

    foreach ($tables_name as $table) {
        
        $getTags = $projectdb->query("SELECT id, tag FROM $table WHERE vsys = '$vsys' AND source = '$source' AND tag != '';");
        if ($getTags->num_rows > 0) {
            while($getTagsData = $getTags->fetch_assoc()){
                $tag = $getTagsData['tag'];
                $idx = $getTagsData['id'];
                $tag_array = explode(",", $tag);
                if (in_array($name, $tag_array)) {
                } else {
                    $replace = str_replace($old_name, $name, $tag);
                    $projectdb->query("UPDATE $table SET tag = '$replace' WHERE id='$idx';");
                }
            }
        }
    }
    
    $message = array();
    $message['code'] = true;
    $message['msg']['warning'] = false;
    $message['msg']['content'] = '';

    return $message;
}

function register_tag(ARRAY $data){
    global $app;
    global $projectdb;
    
    $project = $data['project'];
    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);
    $name = mysqli_real_escape_string($projectdb, $data['name']);
    $name = normalizeTagNames($name);
    $source = mysqli_real_escape_string($projectdb, $data['source']);
    $vsys = mysqli_real_escape_string($projectdb, $data['vsys']);
    $comments = mysqli_real_escape_string($projectdb, $data['comments']);
    $color = mysqli_real_escape_string($projectdb, $data['color']);
    
    $modified = 1;
    $dummy = 0;
    
    if($source <=0 || $vsys==''){
        $message = array();
        $message['code'] = false;
        $message['msg'] = "The specified target is not correct";
        return $message;
    }

    else{
        if($name != ""){
            
            $getTags = $projectdb->query("SELECT id FROM tag WHERE vsys = '$vsys' AND source = '$source' AND BINARY name = '$name';");
            if ($getTags->num_rows == 0) {
                $query = "INSERT INTO tag (name, vsys, source, color, comments, modified, dummy) 
                           VALUES ('$name', '$vsys', '$source', '$color', '$comments','$modified', '$dummy')";
                $projectdb->query($query);
                $id = $projectdb->insert_id;
            }
        }
    }

    $message = array();
    $message['code'] = true;
    
    $message['msg']['warning'] = false;
    $message['msg']['content'] = '';


    return $message;
}

function delete_tag(ARRAY $data){
    global $app;
    $project = $data['project'];

    take_snapshot_last($project);
    
    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $ids = mysqli_real_escape_string($projectdb, $data['ids']);

    $projectdb->query("DELETE FROM tag WHERE id in (".$ids.");");

    $projectdb->query("DELETE FROM security_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM nat_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM appoverride_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM authentication_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM captiveportal_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM decryption_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM dos_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM pbf_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM qos_rules_tag WHERE member_lid IN (".$ids.");");
    $projectdb->query("DELETE FROM tunnel_inspect_rules_tag WHERE member_lid IN (".$ids.");");

    $projectdb->query("UPDATE security_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");
    $projectdb->query("UPDATE nat_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");
    $projectdb->query("UPDATE appoverride_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");
    $projectdb->query("UPDATE authentication_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");
    $projectdb->query("UPDATE decryption_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");
    $projectdb->query("UPDATE dos_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");
    $projectdb->query("UPDATE pbf_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");
    $projectdb->query("UPDATE qos_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");
    $projectdb->query("UPDATE tunnel_inspect_rules SET group_tag_id = '0' WHERE group_tag_id IN (".$ids.");");

    $projectdb->query("DELETE FROM tag_relations WHERE tag_id IN (".$ids.");");

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    return $message;
}