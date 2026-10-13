<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

require_once INC_ROOT.'/libs/common/MemberObject.php';
use PaloaltoNetworks\Policy\Objects\MemberObject;

require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";

function addNameConfig($text_suffix, $name){

    $name_fin = $name;

    $name = $name_fin;
    $name_fin = $name_fin."_".$text_suffix;
    if (strlen($name_fin) > 63){
        $total_name_fin = strlen($name_fin);
        $total_subs = $total_name_fin - 63;
        $name = substr($name, 0, -$total_subs);
        $name_fin = $name.$text_suffix;
    }

    return $name_fin;
}

function export_merge($project, $params){

    global $projectdb;

    $projectdb = selectDatabase($project);

    $message = array();

    $getAll = $projectdb->query("SELECT id,action,filename,vsys,type,element,map_filename,map_vsys,template,map_template 
          FROM pending_tasks WHERE map_filename!='' AND (map_vsys!='' OR map_template!='');");

    $query = "INSERT INTO project_status (datetime,project,percentage,message) values (NOW(),'$project','0.00','Initializing')";
    $projectdb->query($query);
    $jobid = $projectdb->insert_id;
    //echo "Job ID: " .$jobid. "\n";
    //echo json_encode(array("success"=>true,"jobid"=>$jobid));
    if ($getAll->num_rows > 0) {
        take_snapshot_last($project);
        //$projectdb->query("TRUNCATE TABLE project_status;");
        //add_progress($project, '0.00', 'Moving All Objects');

        while ($data = $getAll->fetch_object()) {
            #Define Arrays
            $address = array();
            $address_groups_id = array();
            $address_groups = array();
            $services = array();
            $regions = array();
            $rules_other = array();
            $services_groups_id = array();
            $services_groups = array();
            $tasks = array();
            $rules_security = array();
            $rules_appoverride = array();
            $rules_nat = array();
            $rules_authentication = array();
            $rules_captiveportal = array();
            $rules_decryption = array();
            $rules_dos = array();
            $rules_pbf = array();
            $rules_qos = array();
            $rules_tunnel = array();

            $applications = array();
            $applications_filters = array();
            $applications_groups = array();
            $tags = array();
            $interfaces = array();
            $zones = array();
            $profiles= array();
            $profiles_groups = array();
            $applications_groups_id = array();
            $shared_tag = array();
            $shared_log_settings = array();
            $log_settings = array();
            $schedules = array();
            $shared_schedules = array();
            $shared_applications_groups_id = array();

            $reports = array();
            $shared_reports= array();

            $shared_address = array();
            $shared_address_groups_id = array();
            $shared_address_groups = array();
            $shared_services = array();
            $shared_regions = array();
            $shared_services_groups_id = array();
            $shared_services_groups = array();
            $shared_applications = array();
            $shared_applications_filters = array();
            $shared_applications_groups = array();
            $shared_tags = array();
            $shared_response_pages = array();
            $shared_profiles = array();
            $shared_profiles_groups = array();

            $virtual_routers = array();
            $interface_management_profile = array();
            $ipsec_tunnel = array();
            $ike_gateways_profiles = array();
            $ipsec_crypto_profiles = array();
            $ike_crypto_profiles = array();
            $monitor_profile = array();
            $global_protect_app_ipsec_crypto_profiles = array();
            $vlans = array();
            $virtual_wires = array();

            $map_template = $data->map_template;
            #Get Source IN
            $getSource = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$data->filename' GROUP BY filename;");
            if ($getSource->num_rows == 1) {
                $getSourceData = $getSource->fetch_object();
                $sourceIN = $getSourceData->id;
            }
            #Get Source OUT
            $getSource = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$data->map_filename' GROUP BY filename;");
            if ($getSource->num_rows == 1) {
                $getSourceData = $getSource->fetch_object();
                $sourceOUT = $getSourceData->id;
            }
            # Process Elements
            if ($data->type == "interfaces") {
                $getUnique = $projectdb->query("SELECT id FROM interfaces WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $interfaces[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "interface_management_profile") {
                $getUnique = $projectdb->query("SELECT id FROM interface_management_profile WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $interface_management_profile[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "ipsec_tunnel") {
                $getUnique = $projectdb->query("SELECT id FROM ipsec_tunnel WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $ipsec_tunnel[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "ike_gateways_profiles") {
                $getUnique = $projectdb->query("SELECT id FROM ike_gateways_profiles WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $ike_gateways_profiles[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "ipsec_crypto_profiles") {
                $getUnique = $projectdb->query("SELECT id FROM ipsec_crypto_profiles WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $ipsec_crypto_profiles[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "ike_crypto_profiles") {
                $getUnique = $projectdb->query("SELECT id FROM ike_crypto_profiles WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $ike_crypto_profiles[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "monitor_profile") {
                $getUnique = $projectdb->query("SELECT id FROM monitor_profile WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $monitor_profile[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "global_protect_app_ipsec_crypto_profiles") {
                $getUnique = $projectdb->query("SELECT id FROM global_protect_app_ipsec_crypto_profiles WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $global_protect_app_ipsec_crypto_profiles[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "vlans") {
                $getUnique = $projectdb->query("SELECT id FROM vlans WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $vlans[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "virtual_wires") {
                $getUnique = $projectdb->query("SELECT id FROM virtual_wires WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $virtual_wires[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "zones") {
                $getUnique = $projectdb->query("SELECT id FROM zones WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $zones[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if ($data->type == "virtual_router") {
                $getUnique = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$data->template' AND source='$sourceIN' AND name='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $virtual_routers[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }

            if (($data->type == "object") AND ( $data->element == "shared_applications")) {
                //$getUnique = $projectdb->query("SELECT id FROM shared_applications WHERE (source='$sourceIN');");
                $getUnique = $projectdb->query("SELECT id FROM applications WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_applications[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "object") AND ( $data->element == "applications")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM applications WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $applications[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                } elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id, 'applications' AS table_name, name FROM applications WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            //$applications[] = $getUniqueData->id.";".$getUniqueData->table_name.";".$getUniqueData->name;
                            $applications[] = $getUniqueData->id;
                        }
                    }

                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM applications WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_applications[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }
            }
            if (($data->type == "object") AND ( $data->element == "shared_applications_filters")) {
                $getUnique = $projectdb->query("SELECT id FROM applications_filters WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_applications_filters[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "object") AND ( $data->element == "applications_filters")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM applications_filters WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $applications_filters[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                } elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id, 'applications_filters' AS table_name, name FROM applications_filters WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            //$applications_filters[] = $getUniqueData->id.";".$getUniqueData->table_name.";".$getUniqueData->name;
                            $applications_filters[] = $getUniqueData->id;
                        }
                    }

                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM applications_filters WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_applications_filters[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }
            }
            if (($data->type == "object") AND ( $data->element == "shared_applications_groups")) {

                $getUnique = $projectdb->query("SELECT id FROM applications_groups_id WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_applications_groups_id[] = $getUniqueData->id;
                        $shared_applications_groups[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;

            }
            if (($data->type == "object") AND ( $data->element == "applications_groups")) {

                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM applications_groups_id WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $applications_groups_id[] = $getUniqueData->id;
                            $applications_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                }
                elseif($data->map_vsys == "shared"){

                    $getUnique = $projectdb->query("SELECT id, 'applications_groups' AS table_name, name FROM applications_groups_id WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $applications_groups_id[] = $getUniqueData->id;
                            $applications_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM applications_groups_id WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_applications_groups_id[] = $getUniqueData->id;
                            $shared_applications_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "object") AND ( $data->element == "shared_schedules")) {
                $getUnique = $projectdb->query("SELECT id FROM schedules WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_schedules[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "object") AND ( $data->element == "schedules")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM schedules WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $schedules[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM schedules WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_schedules[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "object") AND ( $data->element == "shared_reports")) {
                $getUnique = $projectdb->query("SELECT id FROM reports WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_reports[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "object") AND ( $data->element == "reports")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM reports WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $reports[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM schedules WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_schedules[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "object") AND ( $data->element == "shared_address")) {
                $getUnique = $projectdb->query("SELECT id FROM address WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_address[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "object") AND ( $data->element == "address")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM address WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $address[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                }
                elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id, 'address' AS table_name, name FROM address WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            //$address[] = $getUniqueData->id.";".$getUniqueData->table_name.";".$getUniqueData->name;
                            $address[] = $getUniqueData->id;
                        }
                    }

                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM address WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_address[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }
            }
            if (($data->type == "object") AND ( $data->element == "shared_services")) {
                $getUnique = $projectdb->query("SELECT id FROM services WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_services[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "object") AND ( $data->element == "services")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM services WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $services[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }
                elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id, 'services' AS table_name, name FROM services WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            //$services[] = $getUniqueData->id.";".$getUniqueData->table_name.";".$getUniqueData->name;
                            $services[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM services WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_services[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "object") AND ( $data->element == "shared_regions")) {
                $getUnique = $projectdb->query("SELECT id FROM regions WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_regions[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "object") AND ( $data->element == "regions")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM regions WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $regions[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }
                elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id, 'regions' AS table_name, name FROM regions WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            //$regions[] = $getUniqueData->id.";".$getUniqueData->table_name.";".$getUniqueData->name;
                            $regions[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM regions WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_regions[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "object") AND ( $data->element == "shared_address_groups")) {

                $getUnique = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_address_groups_id[] = $getUniqueData->id;
                        $shared_address_groups[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;

            }
            if (($data->type == "object") AND ( $data->element == "address_groups")) {

                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM address_groups_id WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $address_groups_id[] = $getUniqueData->id;
                            $address_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                }
                elseif($data->map_vsys == "shared"){

                    $getUnique = $projectdb->query("SELECT id, 'address_groups' AS table_name, name FROM address_groups_id WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $address_groups_id[] = $getUniqueData->id;
                            $address_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_address_groups_id[] = $getUniqueData->id;
                            $shared_address_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "object") AND ( $data->element == "shared_services_groups")) {

                $getUnique = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_services_groups_id[] = $getUniqueData->id;
                        $shared_services_groups[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;

            }
            if (($data->type == "object") AND ( $data->element == "services_groups")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM services_groups_id WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $services_groups_id[] = $getUniqueData->id;
                            $services_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }elseif($data->map_vsys == "shared"){

                    $getUnique = $projectdb->query("SELECT id, 'services_groups' AS table_name, name FROM services_groups_id WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $services_groups_id[] = $getUniqueData->id;
                            $services_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_services_groups_id[] = $getUniqueData->id;
                            $shared_services_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "object") AND ( $data->element == "shared_tag")) {
                $getUnique = $projectdb->query("SELECT id FROM tag WHERE source='$sourceIN' AND vsys = 'shared';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_tag[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "object") AND ( $data->element == "tag")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM tag WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $tags[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }elseif($data->map_vsys == "shared"){

                    $getUnique = $projectdb->query("SELECT id, 'tag' AS table_name, name FROM tag WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            //$tags[] = $getUniqueData->id.";".$getUniqueData->table_name.";".$getUniqueData->name;
                            $tags[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM tag WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_tags[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }

            if (($data->type == "shared_response_pages") AND ( $data->map_vsys == "shared")) {
                $getUnique = $projectdb->query("SELECT id FROM response_pages WHERE template='$data->template' AND source='$sourceIN' AND vsys = 'shared' AND type='$data->element';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $shared_response_pages[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "profiles") AND ( $data->element == "profiles")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM profiles WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $profiles[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id, 'profiles' AS table_name, name FROM profiles WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $profiles[] = $getUniqueData->id.";".$getUniqueData->table_name.";".$getUniqueData->name;
                        }
                    }
                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM profiles WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_profiles[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "shared_profiles") AND ( $data->element == "shared_profiles")) {
                if($data->map_vsys != "shared"){
                    #move to non Shared

                }elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM profiles WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_profiles[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "shared_profiles_groups") AND ( $data->element == "shared_profiles_groups")) {
                if($data->map_vsys != "shared"){
                    #Migrate to non Shared

                }elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM profiles_groups WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_profiles_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "profiles_groups") AND ( $data->element == "profiles_groups")) {
                if($data->map_vsys != "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM profiles_groups WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $profiles_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id, 'profiles_groups' AS table_name, name FROM profiles_groups WHERE (vsys='$data->vsys' AND source='$sourceIN');");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $profiles_groups[] = $getUniqueData->id.";".$getUniqueData->table_name.";".$getUniqueData->name;
                        }
                    }
                    $tasks[] = $data->id;

                    $getUnique = $projectdb->query("SELECT id FROM profiles_groups WHERE source='$sourceIN' AND vsys = 'shared';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_profiles_groups[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "shared_log_settings") AND ( $data->element == "shared_log_settings")) {
                if($data->map_vsys != "shared"){
                    #Move shared to no shared

                }elseif($data->map_vsys == "shared"){
                    $getUnique = $projectdb->query("SELECT id FROM log_settings WHERE source='$sourceIN' AND vsys = 'shared' AND type='profiles';");
                    if ($getUnique->num_rows > 0) {
                        while ($getUniqueData = $getUnique->fetch_object()) {
                            $shared_log_settings[] = $getUniqueData->id;
                        }
                    }
                    $tasks[] = $data->id;
                }

            }
            if (($data->type == "log_settings") AND ( $data->element == "log_settings")) {
                $getUnique = $projectdb->query("SELECT id FROM log_settings WHERE source='$sourceIN' AND vsys = '$data->vsys' AND type='profiles';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $log_settings[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;

            }
            # Rules
            if (($data->type == "policy") AND ( $data->element == "nat")) {
                $getUnique = $projectdb->query("SELECT id FROM nat_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM nat_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_nat_new_position = intval($getPositionData->pos);
                        if ($rules_nat_new_position == "") {
                            $rules_nat_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_nat[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "policy") AND ( $data->element == "security")) {
                $getUnique = $projectdb->query("SELECT id FROM security_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM security_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_security_new_position = intval($getPositionData->pos);
                        if ($rules_security_new_position == "") {
                            $rules_security_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_security[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            if (($data->type == "policy") AND ( $data->element == "appoverride")) {
                $getUnique = $projectdb->query("SELECT id FROM appoverride_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM appoverride_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_appoverride_new_position = intval($getPositionData->pos);
                        if ($rules_appoverride_new_position == "") {
                            $rules_appoverride_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_appoverride[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }
            /*if (($data->type == "policy") AND ( $data->element == "others")) {
                $getUnique = $projectdb->query("SELECT id FROM other_rules WHERE vsys='$data->vsys' AND source='$sourceIN';");
                if ($getUnique->num_rows > 0) {
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_other[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }*/
            if (($data->type == "policy") AND ( $data->element == "authentication")) {
                $getUnique = $projectdb->query("SELECT id FROM authentication_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM authentication_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_authentication_new_position = intval($getPositionData->pos);
                        if ($rules_authentication_new_position == "") {
                            $rules_authentication_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_authentication[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }

            if (($data->type == "policy") AND ( $data->element == "captiveportal")) {
                $getUnique = $projectdb->query("SELECT id FROM captiveportal_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM captiveportal_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_captiveportal_new_position = intval($getPositionData->pos);
                        if ($rules_captiveportal_new_position == "") {
                            $rules_captiveportal_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_captiveportal[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }

            if (($data->type == "policy") AND ( $data->element == "decryption")) {
                $getUnique = $projectdb->query("SELECT id FROM decryption_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM decryption_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_decryption_new_position = intval($getPositionData->pos);
                        if ($rules_decryption_new_position == "") {
                            $rules_decryption_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_decryption[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }

            if (($data->type == "policy") AND ( $data->element == "dos")) {
                $getUnique = $projectdb->query("SELECT id FROM dos_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM dos_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_dos_new_position = intval($getPositionData->pos);
                        if ($rules_dos_new_position == "") {
                            $rules_dos_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_dos[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }

            if (($data->type == "policy") AND ( $data->element == "pbf")) {
                $getUnique = $projectdb->query("SELECT id FROM pbf_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM pbf_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_pbf_new_position = intval($getPositionData->pos);
                        if ($rules_pbf_new_position == "") {
                            $rules_pbf_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_pbf[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }

            if (($data->type == "policy") AND ( $data->element == "qos")) {
                $getUnique = $projectdb->query("SELECT id FROM qos_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM qos_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_qos_new_position = intval($getPositionData->pos);
                        if ($rules_qos_new_position == "") {
                            $rules_qos_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_qos[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }

            if (($data->type == "policy") AND ( $data->element == "tunnel_inspect")) {
                $getUnique = $projectdb->query("SELECT id FROM tunnel_inspect_rules WHERE vsys='$data->vsys' AND source='$sourceIN' ORDER BY preorpost,position;");

                if ($getUnique->num_rows > 0) {
                    $getPosition = $projectdb->query("SELECT max(position) as pos FROM tunnel_inspect_rules WHERE vsys='$data->map_vsys' AND source='$sourceOUT';");
                    if ($getPosition->num_rows == 1) {
                        $getPositionData = $getPosition->fetch_object();
                        $rules_tunnel_new_position = intval($getPositionData->pos);
                        if ($rules_tunnel_new_position == "") {
                            $rules_tunnel_new_position = 0;
                        }
                    }
                    while ($getUniqueData = $getUnique->fetch_object()) {
                        $rules_tunnel[] = $getUniqueData->id;
                    }
                }
                $tasks[] = $data->id;
            }


            #Update
            if (count($shared_response_pages) > 0) {
                //$projectdb->query("UPDATE shared_response_pages SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_response_pages) . ");");
                $projectdb->query("UPDATE response_pages SET source='$sourceOUT', vsys='$data->map_vsys', template='$data->map_template' WHERE id IN (" . implode(",", $shared_response_pages) . ");");
            }
            if (count($interfaces) > 0) {
                $projectdb->query("UPDATE interfaces SET source='$sourceOUT', template='$data->map_template' WHERE id IN (" . implode(",", $interfaces) . ");");
            }
            if (count($interface_management_profile) > 0) {
                foreach($interface_management_profile as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, permitted_ip, http, https, http_ocsp, ssh, snmp, userid_service, "
                        . "userid_syslog_listener_ssl, userid_syslog_listener_udp, ping, response_pages, telnet FROM interface_management_profile WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $permitted_ip_in = $dataN['permitted_ip'];
                        $http_in = $dataN['http'];
                        $https_in = $dataN['https'];
                        $http_ocsp_in = $dataN['http_ocsp'];
                        $ssh_in = $dataN['ssh'];
                        $snmp_in = $dataN['snmp'];
                        $userid_service_in = $dataN['userid_service'];
                        $userid_syslog_listener_ssl_in = $dataN['userid_syslog_listener_ssl'];
                        $userid_syslog_listener_udp_in = $dataN['userid_syslog_listener_udp'];
                        $ping_in = $dataN['ping'];
                        $response_pages_in = $dataN['response_pages'];
                        $telnet_in = $dataN['telnet'];

                        $getDuplicated = $projectdb->query("SELECT id, name, permitted_ip, http, https, http_ocsp, ssh, snmp, userid_service, "
                            . "userid_syslog_listener_ssl, userid_syslog_listener_udp, ping, response_pages, telnet FROM interface_management_profile WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $permitted_ip_out = $dataD['permitted_ip'];
                            $http_out = $dataD['http'];
                            $https_out = $dataD['https'];
                            $http_ocsp_out = $dataD['http_ocsp'];
                            $ssh_out = $dataD['ssh'];
                            $snmp_out = $dataD['snmp'];
                            $userid_service_out = $dataD['userid_service'];
                            $userid_syslog_listener_ssl_out = $dataD['userid_syslog_listener_ssl'];
                            $userid_syslog_listener_udp_out = $dataD['userid_syslog_listener_udp'];
                            $ping_out = $dataD['ping'];
                            $response_pages_out = $dataD['response_pages'];
                            $telnet_out = $dataD['telnet'];

                            if(($name_ike_in == $name_ike_out) && ($permitted_ip_in == $permitted_ip_out) && ($http_in == $http_out) && ($https_in == $https_out)
                                && ($http_ocsp_in == $http_ocsp_out) && ($ssh_in == $ssh_out) && ($snmp_in == $snmp_out) && ($userid_service_in == $userid_service_out)
                                && ($userid_syslog_listener_ssl_in == $userid_syslog_listener_ssl_out) && ($userid_syslog_listener_udp_in == $userid_syslog_listener_udp_out)
                                && ($ping_in == $ping_out) && ($response_pages_in == $response_pages_out) && ($telnet_in == $telnet_out)){
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM interface_management_profile WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                $filename_normalize = normalizeNames($data->filename);
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                $projectdb->query("UPDATE interface_management_profile SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE interface_management_profile SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                        }
                    }
                }
            }
            if (count($ipsec_tunnel) > 0) {
                foreach($ipsec_tunnel as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, "
                        . "tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, "
                        . "encryption, key_encry, local_address_ip, interface, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, "
                        . "local_certificate, publish_connected_routes, portal_address FROM ipsec_tunnel WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $anti_replay_in = $dataN['anti_replay'];
                        $copy_tos_in = $dataN['copy_tos'];
                        $tunnel_monitor_in = $dataN['tunnel_monitor'];
                        $destination_ip_in = $dataN['destination_ip'];
                        $tunnel_monitor_profile_in = $dataN['tunnel_monitor_profile'];
                        $tunnel_interface_in = $dataN['tunnel_interface'];
                        $address_type_in = $dataN['address_type'];
                        $type_tunnel_in = $dataN['type_tunnel'];
                        $ike_gateway_in = $dataN['ike_gateway'];
                        $ipsec_crypto_profile_in = $dataN['ipsec_crypto_profile'];
                        $protocol_in = $dataN['protocol'];
                        $authentication_in = $dataN['authentication'];
                        $key_auth_in = $dataN['key_auth'];
                        $encryption_in = $dataN['encryption'];
                        $key_encry_in = $dataN['key_encry'];
                        $local_address_ip_in = $dataN['local_address_ip'];
                        $interface_in = $dataN['interface'];
                        $peer_ip_address_in = $dataN['peer_ip_address'];
                        $local_spi_in = $dataN['local_spi'];
                        $remote_spi_in = $dataN['remote_spi'];
                        $external_ca_in = $dataN['external_ca'];
                        $certificate_profile_in = $dataN['certificate_profile'];
                        $local_certificate_in = $dataN['local_certificate'];
                        $publish_connected_routes_in = $dataN['publish_connected_routes'];
                        $portal_address_in = $dataN['portal_address'];

                        $getDuplicated = $projectdb->query("SELECT id, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, "
                            . "tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, "
                            . "encryption, key_encry, local_address_ip, interface, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, "
                            . "local_certificate, publish_connected_routes, portal_address FROM ipsec_tunnel WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $anti_replay_out = $dataD['anti_replay'];
                            $copy_tos_out = $dataD['copy_tos'];
                            $tunnel_monitor_out = $dataD['tunnel_monitor'];
                            $destination_ip_out = $dataD['destination_ip'];
                            $tunnel_monitor_profile_out = $dataD['tunnel_monitor_profile'];
                            $tunnel_interface_out = $dataD['tunnel_interface'];
                            $address_type_out = $dataD['address_type'];
                            $type_tunnel_out = $dataD['type_tunnel'];
                            $ike_gateway_out = $dataD['ike_gateway'];
                            $ipsec_crypto_profile_out = $dataD['ipsec_crypto_profile'];
                            $protocol_out = $dataD['protocol'];
                            $authentication_out = $dataD['authentication'];
                            $key_auth_out = $dataD['key_auth'];
                            $encryption_out = $dataD['encryption'];
                            $key_encry_out = $dataD['key_encry'];
                            $local_address_ip_out = $dataD['local_address_ip'];
                            $interface_out = $dataD['interface'];
                            $peer_ip_address_out = $dataD['peer_ip_address'];
                            $local_spi_out = $dataD['local_spi'];
                            $remote_spi_out = $dataD['remote_spi'];
                            $external_ca_out = $dataD['external_ca'];
                            $certificate_profile_out = $dataD['certificate_profile'];
                            $local_certificate_out = $dataD['local_certificate'];
                            $publish_connected_routes_out = $dataD['publish_connected_routes'];
                            $portal_address_out = $dataD['portal_address'];

                            if(($name_ike_in == $name_ike_out) && ($anti_replay_in == $anti_replay_out) && ($copy_tos_in == $copy_tos_out) && ($tunnel_monitor_in == $tunnel_monitor_out)
                                && ($destination_ip_in == $destination_ip_out) && ($tunnel_monitor_profile_in == $tunnel_monitor_profile_out) && ($tunnel_interface_in == $tunnel_interface_out)
                                && ($address_type_in == $address_type_out) && ($type_tunnel_in == $type_tunnel_out) && ($ike_gateway_in == $ike_gateway_out)
                                && ($ipsec_crypto_profile_in == $ipsec_crypto_profile_out) && ($protocol_in == $protocol_out) && ($authentication_in == $authentication_out)
                                && ($key_auth_in == $key_auth_out) && ($encryption_in == $encryption_out) && ($key_encry_in == $key_encry_out)
                                && ($local_address_ip_in == $local_address_ip_out) && ($interface_in == $interface_out) && ($peer_ip_address_in == $peer_ip_address_out)
                                && ($local_spi_in == $local_spi_out) && ($remote_spi_in == $remote_spi_out) && ($external_ca_in == $external_ca_out) && ($certificate_profile_in == $certificate_profile_out)
                                && ($local_certificate_in == $local_certificate_out) && ($publish_connected_routes_in == $publish_connected_routes_out) && ($portal_address_in == $portal_address_out)){
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM ipsec_tunnel WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                $filename_normalize = normalizeNames($data->filename);
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                $projectdb->query("UPDATE ipsec_tunnel SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                                $projectdb->query("UPDATE proxy_id_ipsec_tunnel SET source='$sourceOUT', template='$data->map_template' WHERE ipsec_tunnel_id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE ipsec_tunnel SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                            $projectdb->query("UPDATE proxy_id_ipsec_tunnel SET source='$sourceOUT', template='$data->map_template' WHERE ipsec_tunnel_id = '$id_ike_in';");
                        }
                    }
                }
            }
            if (count($ike_gateways_profiles) > 0) {
                foreach($ike_gateways_profiles as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, "
                        . "ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, "
                        . "require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, allow_id_payload_mismatch, "
                        . "certificate_profile, strict_validation_revocation, local_certificate, hash_and_url, base_url, nat_traversal, passive_mode, "
                        . "fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type FROM ike_gateways_profiles WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $version_in = $dataN['version'];
                        $dpd_ikev1_in = $dataN['dpd_ikev1'];
                        $ike_interval_ikev1_in = $dataN['ike_interval_ikev1'];
                        $retry_ikev1_in = $dataN['retry_ikev1'];
                        $ike_crypto_profile_ikev1_in = $dataN['ike_crypto_profile_ikev1'];
                        $exchange_mode_ikev1_in = $dataN['exchange_mode_ikev1'];
                        $dpd_ikev2_in = $dataN['dpd_ikev2'];
                        $ike_interval_ikev2_in = $dataN['ike_interval_ikev2'];
                        $ike_crypto_profile_ikev2_in = $dataN['ike_crypto_profile_ikev2'];
                        $require_cookie_ikev2_in = $dataN['require_cookie_ikev2'];
                        $local_address_ip_in = $dataN['local_address_ip'];
                        $interface_in = $dataN['interface'];
                        $type_authentication_in = $dataN['type_authentication'];
                        $pre_shared_key_in = $dataN['pre_shared_key'];
                        $allow_id_payload_mismatch_in = $dataN['allow_id_payload_mismatch'];
                        $certificate_profile_in = $dataN['certificate_profile'];
                        $strict_validation_revocation_in = $dataN['strict_validation_revocation'];
                        $local_certificate_in = $dataN['local_certificate'];
                        $hash_and_url_in = $dataN['hash_and_url'];
                        $base_url_in = $dataN['base_url'];
                        $nat_traversal_in = $dataN['nat_traversal'];
                        $passive_mode_in = $dataN['passive_mode'];
                        $fragmentation_in = $dataN['fragmentation'];
                        $peer_ip_type_in = $dataN['peer_ip_type'];
                        $peer_ip_address_in = $dataN['peer_ip_address'];
                        $local_id_in = $dataN['local_id'];
                        $local_id_type_in = $dataN['local_id_type'];
                        $peer_id_in = $dataN['peer_id'];
                        $peer_id_type_in = $dataN['peer_id_type'];
                        $peer_id_matching_in = $dataN['peer_id_matching'];
                        $address_type_in = $dataN['address_type'];

                        $getDuplicated = $projectdb->query("SELECT id, name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, allow_id_payload_mismatch, certificate_profile, strict_validation_revocation, local_certificate, hash_and_url, base_url, nat_traversal, passive_mode, fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type FROM ike_gateways_profiles WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $version_out = $dataD['version'];
                            $dpd_ikev1_out = $dataD['dpd_ikev1'];
                            $ike_interval_ikev1_out = $dataD['ike_interval_ikev1'];
                            $retry_ikev1_out = $dataD['retry_ikev1'];
                            $ike_crypto_profile_ikev1_out = $dataD['ike_crypto_profile_ikev1'];
                            $exchange_mode_ikev1_out = $dataD['exchange_mode_ikev1'];
                            $dpd_ikev2_out = $dataD['dpd_ikev2'];
                            $ike_interval_ikev2_out = $dataD['ike_interval_ikev2'];
                            $ike_crypto_profile_ikev2_out = $dataD['ike_crypto_profile_ikev2'];
                            $require_cookie_ikev2_out = $dataD['require_cookie_ikev2'];
                            $local_address_ip_out = $dataD['local_address_ip'];
                            $interface_out = $dataD['interface'];
                            $type_authentication_out = $dataD['type_authentication'];
                            $pre_shared_key_out = $dataD['pre_shared_key'];
                            $allow_id_payload_mismatch_out = $dataD['allow_id_payload_mismatch'];
                            $certificate_profile_out = $dataD['certificate_profile'];
                            $strict_validation_revocation_out = $dataD['strict_validation_revocation'];
                            $local_certificate_out = $dataD['local_certificate'];
                            $hash_and_url_out = $dataD['hash_and_url'];
                            $base_url_out = $dataD['base_url'];
                            $nat_traversal_out = $dataD['nat_traversal'];
                            $passive_mode_out = $dataD['passive_mode'];
                            $fragmentation_out = $dataD['fragmentation'];
                            $peer_ip_type_out = $dataD['peer_ip_type'];
                            $peer_ip_address_out = $dataD['peer_ip_address'];
                            $local_id_out = $dataD['local_id'];
                            $local_id_type_out = $dataD['local_id_type'];
                            $peer_id_out = $dataD['peer_id'];
                            $peer_id_type_out = $dataD['peer_id_type'];
                            $peer_id_matching_out = $dataD['peer_id_matching'];
                            $address_type_out = $dataD['address_type'];

                            if(($name_ike_in == $name_ike_out) && ($version_in == $version_out) && ($dpd_ikev1_in == $dpd_ikev1_out) && ($ike_interval_ikev1_in == $ike_interval_ikev1_out)
                                && ($retry_ikev1_in == $retry_ikev1_out) && ($ike_crypto_profile_ikev1_in == $ike_crypto_profile_ikev1_out) && ($exchange_mode_ikev1_in == $exchange_mode_ikev1_out)
                                && ($dpd_ikev2_in == $dpd_ikev2_out) && ($ike_interval_ikev2_in == $ike_interval_ikev2_out) && ($ike_crypto_profile_ikev2_in == $ike_crypto_profile_ikev2_out)
                                && ($require_cookie_ikev2_in == $require_cookie_ikev2_out) && ($local_address_ip_in == $local_address_ip_out) && ($interface_in == $interface_out)
                                && ($type_authentication_in == $type_authentication_out) && ($pre_shared_key_in == $pre_shared_key_out) && ($allow_id_payload_mismatch_in == $allow_id_payload_mismatch_out)
                                && ($certificate_profile_in == $certificate_profile_out) && ($strict_validation_revocation_in == $strict_validation_revocation_out) && ($local_certificate_in == $local_certificate_out)
                                && ($hash_and_url_in == $hash_and_url_out) && ($base_url_in == $base_url_out) && ($nat_traversal_in == $nat_traversal_out) && ($passive_mode_in == $passive_mode_out)
                                && ($fragmentation_in == $fragmentation_out) && ($peer_ip_type_in == $peer_ip_type_out) && ($peer_ip_address_in == $peer_ip_address_out) && ($local_id_in == $local_id_out)
                                && ($local_id_type_in == $local_id_type_out) && ($peer_id_in == $peer_id_out) && ($peer_id_type_in == $peer_id_type_out) && ($peer_id_matching_in == $peer_id_matching_out) && ($address_type_in == $address_type_out)){
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM ike_gateways_profiles WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                $filename_normalize = normalizeNames($data->filename);
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                $projectdb->query("UPDATE ike_gateways_profiles SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE ike_gateways_profiles SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                        }
                    }
                }
            }
            if (count($ipsec_crypto_profiles) > 0) {
                foreach($ipsec_crypto_profiles as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, encryption, hash, dh_group, protocol, seconds, minutes, hours, days, kb, mb, gb, tb FROM ipsec_crypto_profiles WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $encryption_in = $dataN['encryption'];
                        $hash_in = $dataN['hash'];
                        $dh_group_in = $dataN['dh_group'];
                        $seconds_in = $dataN['seconds'];
                        $minutes_in = $dataN['minutes'];
                        $hours_in = $dataN['hours'];
                        $days_in = $dataN['days'];
                        $protocol_in = $dataN['protocol'];
                        $kb_in = $dataN['kb'];
                        $mb_in = $dataN['mb'];
                        $gb_in = $dataN['gb'];
                        $tb_in = $dataN['tb'];

                        $getDuplicated = $projectdb->query("SELECT id, name, encryption, hash, dh_group, protocol, seconds, minutes, hours, days, kb, mb, gb, tb FROM ipsec_crypto_profiles WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $encryption_out = $dataD['encryption'];
                            $hash_out = $dataD['hash'];
                            $dh_group_out = $dataD['dh_group'];
                            $seconds_out = $dataD['seconds'];
                            $minutes_out = $dataD['minutes'];
                            $hours_out = $dataD['hours'];
                            $days_out = $dataD['days'];
                            $protocol_out = $dataD['protocol'];
                            $kb_out = $dataD['kb'];
                            $mb_out = $dataD['mb'];
                            $gb_out = $dataD['gb'];
                            $tb_out = $dataD['tb'];

                            if(($name_ike_in == $name_ike_out) && ($encryption_in == $encryption_out) && ($hash_in == $hash_out) && ($dh_group_in == $dh_group_out) && ($seconds_in == $seconds_out) && ($minutes_in == $minutes_out) && ($hours_in == $hours_out) && ($days_in == $days_out) && ($protocol_in == $protocol_out) && ($kb_in == $kb_out) && ($mb_in == $mb_out) && ($gb_in == $gb_out) && ($tb_in == $tb_out)){
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM ipsec_crypto_profiles WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                $filename_normalize = normalizeNames($data->filename);
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                $projectdb->query("UPDATE ipsec_crypto_profiles SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE ipsec_crypto_profiles SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                        }
                    }
                }
            }
            if (count($ike_crypto_profiles) > 0) {
                // Comprobar que no se llaman igual.
                // Si es así, si tienen los mismos valores, no hacer el update y hacer delete de éste.
                // Si no tiene los mismos valores, añadir detrás del name el nombre de la config para diferenciarlos
                foreach($ike_crypto_profiles as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple FROM ike_crypto_profiles WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $encryption_in = $dataN['encryption'];
                        $hash_in = $dataN['hash'];
                        $dh_group_in = $dataN['dh_group'];
                        $seconds_in = $dataN['seconds'];
                        $minutes_in = $dataN['minutes'];
                        $hours_in = $dataN['hours'];
                        $days_in = $dataN['days'];
                        $authentication_multiple_in = $dataN['authentication_multiple'];

                        $getDuplicated = $projectdb->query("SELECT id, name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple FROM ike_crypto_profiles WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $encryption_out = $dataD['encryption'];
                            $hash_out = $dataD['hash'];
                            $dh_group_out = $dataD['dh_group'];
                            $seconds_out = $dataD['seconds'];
                            $minutes_out = $dataD['minutes'];
                            $hours_out = $dataD['hours'];
                            $days_out = $dataD['days'];
                            $authentication_multiple_out = $dataD['authentication_multiple'];

                            if(($name_ike_in == $name_ike_out) && ($encryption_in == $encryption_out) && ($hash_in == $hash_out) && ($dh_group_in == $dh_group_out) && ($seconds_in == $seconds_out) && ($minutes_in == $minutes_out) && ($hours_in == $hours_out) && ($days_in == $days_out) && ($authentication_multiple_in == $authentication_multiple_out)){
                                //echo "THE SAME: " .$name_ike_out. "\n";
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM ike_crypto_profiles WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                //echo "NOT THE SAME: " .$name_ike_out. "\n";
                                $filename_normalize = normalizeNames($data->filename);
                                //echo "Filename normalize: " .$filename_normalize. "\n";
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                //echo "The name con config: " .$name_with_config. "\n";
                                $projectdb->query("UPDATE ike_crypto_profiles SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE ike_crypto_profiles SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                        }
                    }
                }

            }
            if (count($monitor_profile) > 0) {
                foreach($monitor_profile as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, m_action, interva, threshold, vtype, dummy FROM monitor_profile WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $m_action_in = $dataN['m_action'];
                        $interva_in = $dataN['interva'];
                        $threshold_in = $dataN['threshold'];
                        $vtype_in = $dataN['vtype'];
                        $dummy_in = $dataN['dummy'];

                        $getDuplicated = $projectdb->query("SELECT id, name, m_action, interva, threshold, vtype, dummy FROM monitor_profile WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $m_action_out = $dataD['m_action'];
                            $interva_out = $dataD['interva'];
                            $threshold_out = $dataD['threshold'];
                            $vtype_out = $dataD['vtype'];
                            $dummy_out = $dataD['dummy'];

                            if(($name_ike_in == $name_ike_out) && ($m_action_in == $m_action_out) && ($interva_in == $interva_out) && ($threshold_in == $threshold_out) && ($vtype_in == $vtype_out) && ($dummy_in == $dummy_out)){
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM monitor_profile WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                $filename_normalize = normalizeNames($data->filename);
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                $projectdb->query("UPDATE monitor_profile SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE monitor_profile SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                        }
                    }
                }
            }
            if (count($global_protect_app_ipsec_crypto_profiles) > 0) {
                foreach($global_protect_app_ipsec_crypto_profiles as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, encryption, hash FROM global_protect_app_ipsec_crypto_profiles WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $encryption_in = $dataN['encryption'];
                        $hash_in = $dataN['hash'];

                        $getDuplicated = $projectdb->query("SELECT id, name, encryption, hash FROM global_protect_app_ipsec_crypto_profiles WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $encryption_out = $dataD['encryption'];
                            $hash_out = $dataD['hash'];

                            if(($name_ike_in == $name_ike_out) && ($encryption_in == $encryption_out) && ($hash_in == $hash_out)){
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM global_protect_app_ipsec_crypto_profiles WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                $filename_normalize = normalizeNames($data->filename);
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                $projectdb->query("UPDATE global_protect_app_ipsec_crypto_profiles SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE global_protect_app_ipsec_crypto_profiles SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                        }
                    }
                }
            }
            if (count($vlans) > 0) {
                foreach($vlans as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, interface, mac, mac_interfaces, virtual_interface FROM vlans WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $interface_in = $dataN['interface'];
                        $mac_in = $dataN['mac'];
                        $mac_interfaces_in = $dataN['mac_interfaces'];
                        $virtual_interface_in = $dataN['virtual_interface'];

                        $getDuplicated = $projectdb->query("SELECT id, name, interface, mac, mac_interfaces, virtual_interface FROM vlans WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $interface_out = $dataD['interface'];
                            $mac_out = $dataD['mac'];
                            $mac_interfaces_out = $dataD['mac_interfaces'];
                            $virtual_interface_out = $dataD['virtual_interface'];

                            if(($name_ike_in == $name_ike_out) && ($interface_in == $interface_out) && ($mac_in == $mac_out) && ($mac_interfaces_in == $mac_interfaces_out) && ($virtual_interface_in == $virtual_interface_out)){
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM vlans WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                $filename_normalize = normalizeNames($data->filename);
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                $projectdb->query("UPDATE vlans SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE vlans SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                        }
                    }
                }
            }
            if (count($virtual_wires) > 0) {
                foreach($virtual_wires as $id_ike_in){
                    $getName = $projectdb->query("SELECT id, name, multicast_firewalling, tag_allowed, link_state_pass_through, interface1, interface2 FROM virtual_wires WHERE id = '$id_ike_in';");
                    if ($getName->num_rows == 1) {
                        $dataN = $getName->fetch_assoc();
                        $name_ike_in = $dataN['name'];
                        $multicast_firewalling_in = $dataN['multicast_firewalling'];
                        $tag_allowed_in = $dataN['tag_allowed'];
                        $link_state_pass_through_in = $dataN['link_state_pass_through'];
                        $interface1_in = $dataN['interface1'];
                        $interface2_in = $dataN['interface2'];

                        $getDuplicated = $projectdb->query("SELECT id, name, multicast_firewalling, tag_allowed, link_state_pass_through, interface1, interface2 FROM virtual_wires WHERE name = '$name_ike_in' AND id != '$id_ike_in';");
                        if ($getDuplicated->num_rows > 0) {
                            $dataD = $getDuplicated->fetch_assoc();
                            $name_ike_out = $dataD['name'];
                            $multicast_firewalling_out = $dataD['multicast_firewalling'];
                            $tag_allowed_out = $dataD['tag_allowed'];
                            $link_state_pass_through_out = $dataD['link_state_pass_through'];
                            $interface1_out = $dataD['interface1'];
                            $interface2_out = $dataD['interface2'];

                            if(($name_ike_in == $name_ike_out) && ($multicast_firewalling_in == $multicast_firewalling_out) && ($tag_allowed_in == $tag_allowed_out) && ($link_state_pass_through_in == $link_state_pass_through_out) && ($interface1_in == $interface1_out) && ($interface2_in == $interface2_out)){
                                // Delete del SourceIN because is the same
                                $projectdb->query("DELETE FROM virtual_wires WHERE id = '$id_ike_in';");
                            }
                            else{
                                // Make update, Add with the name config to differentiate
                                $filename_normalize = normalizeNames($data->filename);
                                $name_with_config = addNameConfig($filename_normalize, $name_ike_out);
                                $projectdb->query("UPDATE virtual_wires SET source='$sourceOUT', template='$data->map_template', name = '$name_with_config' WHERE id = '$id_ike_in';");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE virtual_wires SET source='$sourceOUT', template='$data->map_template' WHERE id = '$id_ike_in';");
                        }
                    }
                }
            }
            if (count($zones) > 0) {
                $projectdb->query("UPDATE zones SET source='$sourceOUT', template='$data->map_template', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $zones) . ");");
            }
            if (count($virtual_routers) > 0) {
                $projectdb->query("UPDATE virtual_routers SET source='$sourceOUT', template='$data->map_template' WHERE id IN (" . implode(",", $virtual_routers) . ");");
                $projectdb->query("UPDATE routes_static SET template='$data->map_template',source='$sourceOUT' WHERE vr_id IN (" . implode(",", $virtual_routers) . ");");
            }

            //--------------------------------------------------------------

            if (count($address_groups_id) > 0) {
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE address_groups_id SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $address_groups_id) . ");");
                    $projectdb->query("UPDATE address_groups SET source='$sourceOUT', vsys='$data->map_vsys' WHERE lid IN (" . implode(",", $address_groups) . ");");
                }
                elseif($data->map_vsys == "shared"){
//                        $data_function = implode(",", $address_groups_id);
//                        convertAddressGroupsToShared($sourceOUT, $data_function, "all");
                    convertAddressGroupsToShared($sourceOUT, $address_groups_id, "all");
                    $projectdb->query("UPDATE address_groups_id SET source='$sourceOUT' WHERE id IN (" . implode(",", $address_groups_id) . ");");
                    $projectdb->query("UPDATE address_groups SET source='$sourceOUT' WHERE lid IN (" . implode(",", $address_groups) . ");");
                }

            }
            if (count($address) > 0) {
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE address SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $address) . ");");
                }
                elseif($data->map_vsys == "shared"){
                    convertAddressToSharedExport($sourceOUT, $address, "all");
                    $projectdb->query("UPDATE address SET source='$sourceOUT' WHERE id IN (" . implode(",", $address) . ");");
                }
            }
            if (count($services_groups_id) > 0) {
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE services_groups_id SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $services_groups_id) . ");");
                    $projectdb->query("UPDATE services_groups SET source='$sourceOUT', vsys='$data->map_vsys' WHERE lid IN (" . implode(",", $services_groups) . ");");
                }elseif($data->map_vsys == "shared"){
//                            $data_function = implode(",", $services_groups_id);
//                            convertServicesGroupsToShared($sourceOUT, $data_function, "all");
                    convertServicesGroupsToShared($sourceOUT, $services_groups_id, "all");
                    $projectdb->query("UPDATE services_groups_id SET source='$sourceOUT' WHERE id IN (" . implode(",", $services_groups_id) . ");");
                    $projectdb->query("UPDATE services_groups SET source='$sourceOUT' WHERE lid IN (" . implode(",", $services_groups) . ");");
                }

            }
            if (count($services) > 0) {
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE services SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $services) . ");");
                }
                elseif($data->map_vsys == "shared"){
//                  $data_function = implode(",", $services);
                    convertServicesToShared($sourceOUT, $services, "all");
                    $projectdb->query("UPDATE services SET source='$sourceOUT' WHERE id IN (" . implode(",", $services) . ");");
                }

                // Update references id's defaults services objects
                $getDefaultServicesIN = $projectdb->query("SELECT id, name FROM services WHERE source='$sourceIN' AND vsys = 'shared' AND name IN ('application-default', 'service-http', 'service-https')  ;");

                if ($getDefaultServicesIN->num_rows > 0) {
                    while ($dataIN = $getDefaultServicesIN->fetch_object()) {
                        $member_lid_in = $dataIN->id;
                        $name_default_service = $dataIN->name;

                        $getDefaultServicesOUT = $projectdb->query("SELECT id FROM services WHERE source='$sourceOUT' AND vsys = 'shared' AND name = '$name_default_service' ;");

                        if ($getDefaultServicesOUT->num_rows > 0) {
                            $dataOUT = $getDefaultServicesOUT->fetch_object();
                            $member_lid_out = $dataOUT->id;

                            updateMemberLid("", $member_lid_out, $member_lid_in, "services");
                        }
                        //$remove_objects[] = $member_lid_in;
                    }
                }

                //if (count($remove_objects) > 0) {
                //    $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
                //}
            }
            if (count($regions) > 0) {
                //echo "PASA 2\n";
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE regions SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $regions) . ");");
                }elseif($data->map_vsys == "shared"){
//                        $data_function = implode(",", $regions);
//                        convertRegionsToShared($sourceOUT, $data_function, "all");
                    convertRegionsToShared($sourceOUT, $regions, "all");
                    $projectdb->query("UPDATE regions SET source='$sourceOUT' WHERE id IN (" . implode(",", $regions) . ");");
                }

            }

            //--------------------------------------------------------------

            if (count($applications) > 0) {
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE applications SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $applications) . ");");
                }elseif($data->map_vsys == "shared"){
//                        $data_function = implode(",", $applications);
//                        convertApplicationsToShared($sourceOUT, $data_function, "all");
                    convertApplicationsToShared($sourceOUT, $applications, "all");
                    $projectdb->query("UPDATE applications SET source='$sourceOUT' WHERE id IN (" . implode(",", $applications) . ");");
                }
            }
            if (count($applications_filters) > 0) {
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE applications_filters SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $applications_filters) . ");");
                }elseif($data->map_vsys == "shared"){
//                        $data_function = implode(",", $applications_filters);
//                        convertApplicationsFiltersToShared($sourceOUT, $data_function, "all");
                    convertApplicationsFiltersToShared($sourceOUT, $applications_filters, "all");
                    $projectdb->query("UPDATE applications_filters SET source='$sourceOUT' WHERE id IN (" . implode(",", $applications_filters) . ");");
                }
            }
            if (count($applications_groups_id) > 0) {
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE applications_groups_id SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $applications_groups_id) . ");");
                    $projectdb->query("UPDATE applications_groups SET source='$sourceOUT', vsys='$data->map_vsys' WHERE lid IN (" . implode(",", $applications_groups) . ");");

                }elseif($data->map_vsys == "shared"){
//                        $data_function = implode(",", $applications_groups_id);
//                        convertApplicationsGroupsToShared($sourceOUT, $data_function, "all");
                    convertApplicationsGroupsToShared($sourceOUT, $applications_groups_id, "all");
                    $projectdb->query("UPDATE applications_groups_id SET source='$sourceOUT' WHERE id IN (" . implode(",", $applications_groups_id) . ");");
                    $projectdb->query("UPDATE applications_groups SET source='$sourceOUT' WHERE lid IN (" . implode(",", $applications_groups) . ");");
                }

            }
            if (count($tags) > 0) {
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE tag SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $tags) . ");");
                }elseif($data->map_vsys == "shared"){
//                        $data_function = implode(",", $tags);
//                        convertTagToShared($sourceOUT, $data_function, "all");
                    convertTagToShared($sourceOUT, $tags, "all");
                    $projectdb->query("UPDATE tag SET source='$sourceOUT' WHERE id IN (" . implode(",", $tags) . ");");
                }
            }
            if (count($shared_tag)>0){
                //$projectdb->query("UPDATE shared_tag SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_tag) . ");");
                $projectdb->query("UPDATE tag SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_tag) . ");");
            }
            # Profiles and Groups
            if (count($profiles)>0){
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE profiles SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $profiles) . ");");
                }elseif($data->map_vsys == "shared"){
//                        $data_function = implode(",", $profiles);
//                        convertProfilesToShared($sourceOUT, $data_function, "all");
                    convertProfilesToShared($sourceOUT, $profiles, "all");
                }
            }
            if (count($shared_profiles)>0){
                //$projectdb->query("UPDATE shared_profiles SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_profiles) . ");");
                $projectdb->query("UPDATE profiles SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_profiles) . ");");
            }
            if (count($profiles_groups)>0){
                if($data->map_vsys != "shared"){
                    $projectdb->query("UPDATE profiles_groups SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $profiles_groups) . ");");
                }elseif($data->map_vsys == "shared"){
//                        $data_function = implode(",", $profiles_groups);
//                        convertProfilesGroupsToShared($sourceOUT, $data_function, "all");
                    convertProfilesGroupsToShared($sourceOUT, $profiles_groups, "all");
                }
            }
            if (count($shared_profiles_groups)>0){
                $projectdb->query("UPDATE profiles_groups SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_profiles_groups) . ");");
            }
            if (count($shared_log_settings)>0){
                $projectdb->query("UPDATE log_settings SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_log_settings) . ");");
            }
            if(count($log_settings)>0){
                $projectdb->query("UPDATE log_settings SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $log_settings) . ");");
            }
            //--------------------------------------------------------------
            if (count($shared_address) > 0) {
                $projectdb->query("UPDATE address SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_address) . ");");
            }
            if (count($shared_address_groups_id) > 0) {
                $projectdb->query("UPDATE address_groups_id SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_address_groups_id) . ");");
                $projectdb->query("UPDATE address_groups SET source='$sourceOUT', vsys='$data->map_vsys' WHERE lid IN (" . implode(",", $shared_address_groups) . ");");
            }
            if (count($shared_services) > 0) {
                $remove_objects = array();

                $getDefaultServicesIN = $projectdb->query("SELECT id, name FROM services WHERE source='$sourceIN' AND vsys = 'shared' AND (name IN ('application-default', 'service-http', 'service-https') AND id IN (".implode(',',$shared_services)."))  ;");

                if ($getDefaultServicesIN->num_rows > 0) {
                    while ($dataIN = $getDefaultServicesIN->fetch_object()) {
                        $member_lid_in = $dataIN->id;
                        $name_default_service = $dataIN->name;

                        $getDefaultServicesOUT = $projectdb->query("SELECT id FROM services WHERE source='$sourceOUT' AND vsys = 'shared' AND name = '$name_default_service' ;");

                        if ($getDefaultServicesOUT->num_rows > 0) {
                            $dataOUT = $getDefaultServicesOUT->fetch_object();
                            $member_lid_out = $dataOUT->id;

                            updateMemberLid("", $member_lid_out, $member_lid_in, "services");
                        }
                        $remove_objects[] = $member_lid_in;
                    }
                }

                if (count($remove_objects) > 0) {
                    $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
                }

                $projectdb->query("UPDATE services SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_services) . ");");
            }
            if (count($shared_services_groups_id) > 0) {
                $projectdb->query("UPDATE services_groups_id SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_services_groups_id) . ");");
                $projectdb->query("UPDATE services_groups SET source='$sourceOUT', vsys='$data->map_vsys' WHERE lid IN (" . implode(",", $shared_services_groups) . ");");
            }
            if (count($shared_regions) > 0) {
                $projectdb->query("UPDATE regions SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_regions) . ");");
            }
            if (count($schedules)>0){
                $projectdb->query("UPDATE schedules SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $schedules) . ");");
            }
            if (count($shared_schedules) > 0) {
                $projectdb->query("UPDATE schedules SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_schedules) . ");");
            }

            if (count($reports)>0){
                $projectdb->query("UPDATE reports SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $reports) . ");");
            }
            if (count($shared_reports) > 0) {
                $projectdb->query("UPDATE reports SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_reports) . ");");
            }

            if (count($shared_applications) > 0) {
                $projectdb->query("UPDATE applications SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_applications) . ");");
            }
            if (count($shared_applications_filters) > 0) {
                $projectdb->query("UPDATE applications_filters SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_applications_filters) . ");");
            }
            if (count($shared_applications_groups_id) > 0) {
                $projectdb->query("UPDATE applications_groups_id SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_applications_groups_id) . ");");
                $projectdb->query("UPDATE applications_groups SET source='$sourceOUT', vsys='$data->map_vsys' WHERE lid IN (" . implode(",", $shared_applications_groups) . ");");
            }
            if (count($shared_tags) > 0) {
                $projectdb->query("UPDATE tag SET source='$sourceOUT', vsys='$data->map_vsys' WHERE id IN (" . implode(",", $shared_tags) . ");");
            }

            if ((count($rules_security) > 0) AND ( is_numeric($rules_security_new_position))) {
                foreach ($rules_security as $key => $value) {
                    $rules_security_new_position++;
                    $projectdb->query("UPDATE security_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_security_new_position' WHERE id='$value';");
                }
            }
            if ((count($rules_nat) > 0) AND ( is_numeric($rules_nat_new_position))) {
                foreach ($rules_nat as $key => $value) {
                    $rules_nat_new_position++;
                    $projectdb->query("UPDATE nat_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_nat_new_position' WHERE id='$value';");
                }
            }
            if ((count($rules_appoverride) > 0) AND ( is_numeric($rules_appoverride_new_position))) {
                foreach ($rules_appoverride as $key => $value) {
                    $rules_appoverride_new_position++;
                    $projectdb->query("UPDATE appoverride_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_appoverride_new_position' WHERE id='$value';");
                }
            }
            /*if (count($rules_other) > 0) {
                foreach ($rules_other as $key => $value) {
                    $projectdb->query("UPDATE other_rules SET vsys='$data->map_vsys', source='$sourceOUT' WHERE id='$value';");
                }
            }*/
            if ((count($rules_authentication) > 0) AND ( is_numeric($rules_authentication_new_position))) {
                foreach ($rules_authentication as $key => $value) {
                    $rules_authentication_new_position++;
                    $projectdb->query("UPDATE authentication_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_authentication_new_position' WHERE id='$value';");
                }
            }

            if ((count($rules_captiveportal) > 0) AND ( is_numeric($rules_captiveportal_new_position))) {
                foreach ($rules_captiveportal as $key => $value) {
                    $rules_captiveportal_new_position++;
                    $projectdb->query("UPDATE captiveportal_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_captiveportal_new_position' WHERE id='$value';");

                    //echo "El update: UPDATE captiveportal_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_captiveportal_new_position' WHERE id='$value';";
                }
            }

            if ((count($rules_decryption) > 0) AND ( is_numeric($rules_decryption_new_position))) {
                foreach ($rules_decryption as $key => $value) {
                    $rules_decryption_new_position++;
                    $projectdb->query("UPDATE decryption_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_decryption_new_position' WHERE id='$value';");
                }
            }

            if ((count($rules_dos) > 0) AND ( is_numeric($rules_dos_new_position))) {
                foreach ($rules_dos as $key => $value) {
                    $rules_dos_new_position++;
                    $projectdb->query("UPDATE dos_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_dos_new_position' WHERE id='$value';");
                }
            }

            if ((count($rules_pbf) > 0) AND ( is_numeric($rules_pbf_new_position))) {
                foreach ($rules_pbf as $key => $value) {
                    $rules_pbf_new_position++;
                    $projectdb->query("UPDATE pbf_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_pbf_new_position' WHERE id='$value';");
                }
            }

            if ((count($rules_qos) > 0) AND ( is_numeric($rules_qos_new_position))) {
                foreach ($rules_qos as $key => $value) {
                    $rules_qos_new_position++;
                    $projectdb->query("UPDATE qos_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_qos_new_position' WHERE id='$value';");
                }
            }

            if ((count($rules_tunnel) > 0) AND ( is_numeric($rules_tunnel_new_position))) {
                foreach ($rules_tunnel as $key => $value) {
                    $rules_tunnel_new_position++;
                    $projectdb->query("UPDATE tunnel_inspect_rules SET vsys='$data->map_vsys', source='$sourceOUT', position='$rules_tunnel_new_position' WHERE id='$value';");
                }
            }

            if (count($tasks) > 0) {
                $projectdb->query("DELETE FROM pending_tasks WHERE id IN (" . implode(",", $tasks) . ");");
            }
        }

        clean_duplicated_members("security_rules_src");
        clean_duplicated_members("security_rules_dst");
        clean_duplicated_members("security_rules_srv");
        clean_duplicated_members("security_rules_app");
        clean_duplicated_members("security_rules_tag");
        clean_duplicated_members("nat_rules_src");
        clean_duplicated_members("nat_rules_dst");
        clean_duplicated_members("nat_rules_tag");
        clean_duplicated_members("nat_rules_translated_address");
        clean_duplicated_members("nat_rules_translated_address_fallback");
        clean_duplicated_members("nat_rules_tag");
        clean_duplicated_members("appoverride_rules_dst");
        clean_duplicated_members("appoverride_rules_src");
        clean_duplicated_members("appoverride_rules_tag");
        clean_duplicated_members("authentication_rules_src");
        clean_duplicated_members("authentication_rules_dst");
        clean_duplicated_members("authentication_rules_srv");
        clean_duplicated_members("authentication_rules_tag");
        clean_duplicated_members("captiveportal_rules_src");
        clean_duplicated_members("captiveportal_rules_dst");
        clean_duplicated_members("captiveportal_rules_srv");
        clean_duplicated_members("captiveportal_rules_tag");
        clean_duplicated_members("decryption_rules_dst");
        clean_duplicated_members("decryption_rules_src");
        clean_duplicated_members("decryption_rules_srv");
        clean_duplicated_members("decryption_rules_tag");
        clean_duplicated_members("dos_rules_dst");
        clean_duplicated_members("dos_rules_src");
        clean_duplicated_members("dos_rules_srv");
        clean_duplicated_members("dos_rules_tag");
        clean_duplicated_members("pbf_rules_src");
        clean_duplicated_members("pbf_rules_dst");
        clean_duplicated_members("pbf_rules_app");
        clean_duplicated_members("pbf_rules_srv");
        clean_duplicated_members("pbf_rules_tag");
        clean_duplicated_members("qos_rules_dst");
        clean_duplicated_members("qos_rules_src");
        clean_duplicated_members("qos_rules_srv");
        clean_duplicated_members("qos_rules_app");
        clean_duplicated_members("qos_rules_tag");
        clean_duplicated_members("tunnel_inspect_rules_dst");
        clean_duplicated_members("tunnel_inspect_rules_src");
        clean_duplicated_members("tunnel_inspect_rules_app");
        clean_duplicated_members("tunnel_inspect_rules_tag");
        clean_duplicated_members("address_groups");
        clean_duplicated_members("services_groups");
        clean_duplicated_members("applications_groups");
        clean_duplicated_members("tag_relations");

    }
    else{

    }

    $message['msg'] = "Finish.";
    $message['code'] = true;


    return $message;

}

