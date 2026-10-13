<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

require_once INC_ROOT.'/libs/common/MemberObject.php';
use PaloaltoNetworks\Policy\Objects\MemberObject;

require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

function import_rule_enrichment_all($project, $params){

    global $projectdb;

    $projectdb = selectDatabase($project);
    $source = $params['source'];
    $vsys = $params['vsys'];
    $update_to = $params['update_to'];
    $created_objects = $params['created_objects'];
    $template = $params['template'];

    $combo_src = $params['combo_src'];
    $combo_dst = $params['combo_dst'];
    $combo_srv = $params['combo_srv'];

    $import_from = ($params['from'] == "on")?1:0;
    $import_to = ($params['to'] == "on")?1:0;
    $import_src = ($params['src'] == "on")?1:0;
    $import_dst = ($params['dst'] == "on")?1:0;
    $import_usr = ($params['users'] == "on")?1:0;
    $import_apps = ($params['apps'] == "on")?1:0;
    $import_srv = ($params['services'] == "on")?1:0;

    $message = array();

    if ($source != 0){

        if ($params['selection'] == "all"){
            $conditions = " WHERE 1=1 ";
        }
        else{
            if ($params['ids'] != ""){
                $conditions = " WHERE id IN (".$params['ids'].") ";
            }
            else{
                $message['msg'] = "No Rules Selected";
                $message['code'] = false;
                return $message;
            }
        }

        $getRE = $projectdb->query("SELECT id, RuleID, RuleName, Application, ServicesTCP, ServicesUDP, SourcesZones, DestinationZones, Sources, SourcesRegions,
            Destinations, DestinationRegions, Users
            FROM ML_RuleEnrichment $conditions ORDER BY RuleName, ServicesTCP;");

        //echo "1. SELECT id, RuleID, RuleName, Application, ServicesTCP, ServicesUDP, SourcesZones, DestinationZones, Sources, SourcesRegions,
        //    Destinations, DestinationRegions, Users
        //     FROM ML_RuleEnrichment $conditions;\n";


        if ($getRE->num_rows > 0){

            $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');

            $enrichedRules = array();
            while($dataA = $getRE->fetch_assoc()){
                //$id_re = $dataA['id'];
                $rule_lid_origin = $dataA['RuleID'];
                $enrichedRules[] = $rule_lid_origin;

                $getRuleID = $projectdb->query("SELECT id, position, name, vsys, source, devicegroup FROM security_rules WHERE id = '$rule_lid_origin' AND source = '$source' AND vsys = '$vsys' ;");
                //echo "2. SELECT id, position, name, vsys, source, devicegroup FROM security_rules WHERE id = '$rule_lid_origin' AND source = '$source' AND vsys = '$vsys' ;\n";
                if ($getRuleID->num_rows > 0){
                    $dataRI = $getRuleID->fetch_assoc();
                    $initial_position = $dataRI['position'];
                    $rule_name = $dataRI['name'];
                }

                $final_position = $initial_position - 1;

                // Primero se tiene que mirar si ya existe alguna clonada antiguamente con re_users, re_app_default
                /*
                 * Section commented because it generates 4 queries per learnt Rule that can be removed
                 *
                if((    hasUsersOriginRE($id_re) === TRUE) && (hasApplicationDefaultOriginRE($id_re) === TRUE)){
                    $case_re = "has_re_UA";
                }
                elseif((hasUsersOriginRE($id_re) === FALSE) && (hasApplicationDefaultOriginRE($id_re) === TRUE)){
                    $case_re = "has_re_uA";
                }
                elseif((hasUsersOriginRE($id_re) === TRUE) && (hasApplicationDefaultOriginRE($id_re) === FALSE)){
                    $case_re = "has_re_Ua";
                }
                elseif((hasUsersOriginRE($id_re) === FALSE) && (hasApplicationDefaultOriginRE($id_re) === FALSE)){
                    $case_re = "has_re_ua";
                }
                */

                if((        $dataA['Users'] != '') && ( $dataA['ServicesTCP'] == 'application-default')){ $case_re = "has_re_UA"; }
                elseif((    $dataA['Users'] == '') && ( $dataA['ServicesTCP'] == 'application-default')){ $case_re = "has_re_uA"; }
                elseif((    $dataA['Users'] != '') && ( $dataA['ServicesTCP'] != 'application-default')){ $case_re = "has_re_Ua"; }
                elseif((    $dataA['Users'] == '') && ( $dataA['ServicesTCP'] != 'application-default')){ $case_re = "has_re_ua"; }

                switch($case_re){
                    case "has_re_UA":
                        list($rule_lid_re, $is_first_cloned) = checkExistRuleWithTypeAndCloned($rule_name, $vsys, $source, $initial_position, $final_position, $rule_lid_origin, $project, 'UA', '1', '1');
                        break;

                    case "has_re_Ua":
                        list($rule_lid_re, $is_first_cloned) = checkExistRuleWithTypeAndCloned($rule_name, $vsys, $source, $initial_position, $final_position, $rule_lid_origin, $project, 'Ua', '1', '0');
                        break;

                    case "has_re_uA":
                        list($rule_lid_re, $is_first_cloned) = checkExistRuleWithTypeAndCloned($rule_name, $vsys, $source, $initial_position, $final_position, $rule_lid_origin, $project, 'uA', '0', '1');
                        break;

                    case "has_re_ua":
                        list($rule_lid_re, $is_first_cloned) = checkExistRuleWithTypeAndCloned($rule_name, $vsys, $source, $initial_position, $final_position, $rule_lid_origin, $project, 'ua', '0', '0');
                        break;

                    default:
                }

//                if($update_to == "replace_rule"){
//                    // Disabled rule origin
//                    $projectdb->query("UPDATE security_rules SET disabled = '1' WHERE id = '$rule_lid_origin'; ");
//                }

                # Imported Applications
                if($import_apps == 1){
                    if($is_first_cloned == 1){
                        $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid = '$rule_lid_re';");
                    }
                    import_rule_enrichment_apps($project, $rule_lid_re, $dataA['Application'], $source, $vsys);
                }

                # Importes Services
                if($import_srv == 1){
                    if($is_first_cloned == 1){
                        $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$rule_lid_re';");
                    }
                    import_rule_enrichment_services($project, $rule_lid_re, $dataA['ServicesTCP'], $dataA['ServicesUDP'], $source, $vsys, $combo_srv);
                }

                # Imported Zones
                if(($import_from == 1) || ($import_to == 1)){
                    if($is_first_cloned == 1){
                        if($import_from == 1){
                            $projectdb->query("DELETE FROM security_rules_from WHERE rule_lid = '$rule_lid_re';");
                        }
                        if($import_to == 1){
                            $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid = '$rule_lid_re';");
                        }
                    }
                    import_rule_enrichment_zones($project, $rule_lid_re, $dataA['SourcesZones'], $dataA['DestinationZones'], $source, $vsys, $template, $created_objects);
                }

                # Imported Source
                if($import_src == 1){
                    if($is_first_cloned == 1){
                        $projectdb->query("DELETE FROM security_rules_src WHERE rule_lid = '$rule_lid_re';");
                    }
                    import_rule_enrichment_sources($project, $rule_lid_re, $dataA['Sources'], $dataA['SourcesRegions'], $source, $vsys, $combo_src);
                }

                # Imported Destinations
                if($import_dst == 1){
                    if($is_first_cloned == 1){
                        $projectdb->query("DELETE FROM security_rules_dst WHERE rule_lid = '$rule_lid_re';");
                    }
                    import_rule_enrichment_destinations($project, $rule_lid_re, $dataA['Destinations'], $dataA['DestinationRegions'], $source, $vsys, $combo_dst);
                }

                # Imported Users
                if($import_usr == 1){
                    if($is_first_cloned == 1){
                        $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid = '$rule_lid_re';");
                    }
                    import_rule_enrichment_users($project, $rule_lid_re, $dataA['Users'], $source, $vsys);
                }


                # add tag to the sec rule
                $projectdb->query("INSERT INTO security_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) SELECT '$source',$tag_id,'tag','$vsys','$rule_lid_re','M.Learning' FROM DUAL WHERE NOT EXISTS (SELECT source,member_lid,table_name,vsys,rule_lid,devicegroup FROM security_rules_tag WHERE source='$source' AND member_lid='$tag_id' AND table_name='tag' AND vsys='$vsys' AND rule_lid='$rule_lid_re' AND devicegroup='M.Learning' LIMIT 1);");

            }

            if($update_to == "replace_rule"){
                // Disabled rule origin
                $enrichedRules = array_unique($enrichedRules);
                if (count($enrichedRules)>0)
                    $projectdb->query("UPDATE security_rules SET disabled = '1' WHERE id in (".implode(",",$enrichedRules)."); ");
            }

            $message['msg'] = "Imported into Project successfuly";
            $message['code'] = true;
        }

    }
    else{
        $message['msg'] = "Select SOURCE, VSYS or TEMPLATE.";
        $message['code'] = false;
    }

    //check_used_objects_new();

    return $message;


}


function import_rule_enrichment_zones($project, $rule_lid_re, $sourcesZones, $destinationZones, $source, $vsys, $template, $created_objects){

    if (($sourcesZones != "any") || ($sourcesZones != "")){

        $raw = explode(",", $sourcesZones);

        foreach($raw as $zone){
            add_zone($project, $zone, "security_rules_from", $rule_lid_re, $source, $vsys, $template, $created_objects);
        }
    }

    if (($destinationZones != "any") || ($destinationZones != "")){

        $raw = explode(",", $destinationZones);

        foreach($raw as $zone){
            add_zone($project, $zone, "security_rules_to", $rule_lid_re, $source, $vsys, $template, $created_objects);
        }
    }

}

function import_rule_enrichment_apps($project, $rule_lid_re, $applications, $source, $vsys){

    if (($applications != "any") || ($applications != "")){

        $raw = explode(",", $applications);

        foreach($raw as $application){
            add_app($project, $application, $rule_lid_re, $source, $vsys);
        }
    }
}

function import_rule_enrichment_services($project, $rule_lid_re, $servicesTCP, $servicesUDP, $source, $vsys, $use_highPorts='All'){
    global $projectdb;

    $compactPorts = $use_highPorts=='compact'?true:false;

    $projectdb = selectDatabase($project);

    if (($servicesTCP != "any") || ($servicesTCP != "")) {
        $raw = explode(",", $servicesTCP);

        if ($compactPorts) {
            $raw2 = [
                'tcp' => [
                    'low' => [
                        'members' => array(),
                    ],
                    'high' => [
                        'members' => array(),
                        'number' => 0
                    ]
                ],
            ];
            foreach ($raw as $services) {
                if ($services != "") {
                    if ($services == "application-default") {
                        $raw2['tcp']['low']['members'][] = "application-default";
                        $raw2['tcp']['low']['number'] = 1;
                    } else {
                        list($protocol, $port) = explode("/", $services);
                        $portArray = explode("-", $port);
                        if (isset($portArray[1])) {
                            $number = $portArray[1] - $portArray[0] + 1;
                        } else {
                            $number = 1;
                        }

                        if ($port > 1024) {
                            $raw2[$protocol]['high']['members'][] = $services;
                            $raw2[$protocol]['high']['number'] += $number;
                        } else {
                            $raw2[$protocol]['low']['members'][] = $services;
                        }
                    }
                }
            }

            if ($raw2['tcp']['high']['number'] > 10) {
                $raw2['tcp']['high']['members'] = ['tcp/1025-65535'];
            }

            $raw3 = array_merge(array_filter($raw2['tcp']['low']['members']), array_filter($raw2['tcp']['high']['members']));
        }
        else{
            $raw3 = $raw;
        }
        foreach($raw3 as $services){
            if($services != "") {
                add_services($project, $services, "tcp", $rule_lid_re, $source, $vsys);
            }
        }
    }

    if (($servicesUDP != "any") || ($servicesUDP != "")){
        $raw = explode(",", $servicesUDP);
        if ($compactPorts) {
            $raw2 = [
                'udp' => [
                    'low' => [
                        'members' => array(),
                    ],
                    'high' => [
                        'members' => array(),
                        'number' => 0
                    ]
                ],
            ];
            foreach ($raw as $services) {
                if ($services != "") {
                    if ($services == "application-default") {
                        $raw2['udp']['low']['members'][] = "application-default";
                        $raw2['udp']['low']['number'] = 1;
                    } else {
                        list($protocol, $port) = explode("/", $services);
                        $portArray = explode("-", $port);
                        if (isset($portArray[1])) {
                            $number = $portArray[1] - $portArray[0] + 1;
                        } else {
                            $number = 1;
                        }

                        if ($portArray[0] > 1024) {
                            $raw2[$protocol]['high']['members'][] = $services;
                            $raw2[$protocol]['high']['number'] += $number;
                        } else {
                            $raw2[$protocol]['low']['members'][] = $services;
                        }
                    }
                }
            }

            if ($raw2['udp']['high']['number'] > 10) {
                $raw2['udp']['high']['members'] = ['udp/1025-65535'];
            }

            $raw3 = array_merge(array_filter($raw2['udp']['low']['members']), array_filter($raw2['udp']['high']['members']));
        }
        else{
            $raw3 = $raw;
        }

        foreach($raw3 as $services){
            if($services != ""){
                add_services($project, $services, "udp", $rule_lid_re, $source, $vsys);
            }
        }
    }

    #Clean Application-Default from Services if there are more than one
    $getAppDefault = $projectdb->query("SELECT id FROM services WHERE name = 'application-default' AND vsys = 'shared' AND source = '$source';");
    if ($getAppDefault->num_rows == 1){
        $data = $getAppDefault->fetch_assoc();
        $app_default_id = $data['id'];
    }
    $getSecRulesServ = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid_re';");
    if ($getSecRulesServ->num_rows > 1){
        $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$rule_lid_re' AND table_name = 'services' AND member_lid = '$app_default_id';");
    }

}

function import_rule_enrichment_sources($project, $rule_lid_re, $sources, $sourcesRegions, $source, $vsys, $combo_src){

    if(($combo_src == "IPs") || ($combo_src == "ips")){
        if (($sources != "any") || ($sources != "")){
            add_address($project, $sources, "security_rules_src", $rule_lid_re, $source, $vsys);
        }
    }
    elseif($combo_src == "regions"){
        if (($sourcesRegions != "any") || ($sourcesRegions != "")){

            $raw = explode(",", $sourcesRegions);

            foreach($raw as $address){
                add_regions($project, $address, "security_rules_src", $rule_lid_re, $source, $vsys);
            }
        }
    }
    elseif($combo_src == "networks"){
        if (($sources != "any") || ($sources != "")){

            $raw = explode(",", $sources);

            foreach($raw as $address){
                add_networks($project, $address, "security_rules_src", $rule_lid_re, $source, $vsys);
            }
        }
    }

}

function import_rule_enrichment_destinations($project, $rule_lid_re, $destinations, $destinationRegions, $source, $vsys, $combo_dst){

    if(($combo_dst == "IPs") || ($combo_dst == "ips")){
        if (($destinations != "any") || ($destinations != "")){
            add_address($project, $destinations, "security_rules_dst", $rule_lid_re, $source, $vsys);
        }
    }
    elseif($combo_dst == "regions"){
        if (($destinationRegions != "any") || ($destinationRegions != "")){

            $raw = explode(",", $destinationRegions);

            foreach($raw as $address){
                add_regions($project, $address, "security_rules_dst", $rule_lid_re, $source, $vsys);
            }
        }
    }
    elseif($combo_dst == "networks"){
        if (($destinations != "any") || ($destinations != "")){

            $raw = explode(",", $destinations);

            foreach($raw as $address){
                add_networks($project, $address, "security_rules_dst", $rule_lid_re, $source, $vsys);
            }
        }
    }
}

function import_rule_enrichment_users($project, $rule_lid_re, $users, $source, $vsys){

    if (($users != "any") || ($users != "")){

        $raw = explode(",", $users);

        foreach($raw as $user){
            if($user != ""){
                add_users($project, $user, $rule_lid_re, $source, $vsys);
            }
        }
    }
}

function add_zone($project, $zone, $table, $rule_lid, $source, $vsys, $template, $created_objects){

    global $projectdb;

    $projectdb = selectDatabase($project);

    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($created_objects == "on"){
        $getExistZone = $projectdb->query("SELECT id FROM zones WHERE name = '$zone' AND source = '$source' AND vsys = '$vsys' AND template = '$template';");
        if ($getExistZone->num_rows == 0){
            $projectdb->query("INSERT INTO zones (name, source, vsys, template, type) VALUES ('$zone', '$source', '$vsys', '$template', 'layer3');");
            $member_lid = $projectdb->insert_id;
            // get M.Learning tag id
            $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');
            // add M.Learning tag to the new address created
            $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) SELECT 'zones', '$member_lid', '$tag_id' FROM DUAL WHERE NOT EXISTS (SELECT table_name,member_lid,tag_id FROM tag_relations WHERE table_name='zones' AND member_lid='$member_lid' AND tag_id='$tag_id' LIMIT 1);");
        }
    }

    $getExistZoneInRule = $projectdb->query("SELECT id FROM $table WHERE name = '$zone' AND rule_lid = '$rule_lid';");
    if ($getExistZoneInRule->num_rows == 0){
        $projectdb->query("INSERT INTO $table (name, source, vsys, rule_lid, from_log) VALUES ('$zone', '$source', '$vsys', '$rule_lid', 'false');");
    }

}

function add_app($project, $app2, $rule_lid, $source, $vsys){

    global $projectdb;

    $projectdb = selectDatabase($project);

    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $getExistDefApp = $projectdb->query("SELECT id FROM default_applications WHERE name = '$app2';");
    if ($getExistDefApp->num_rows == 0){

        $getExistApp = $projectdb->query("SELECT id FROM applications WHERE name = '$app2' AND source = '$source' $vsys_query;");
        if ($getExistApp->num_rows == 0){

            $getExistAppGroup = $projectdb->query("SELECT id FROM applications_groups_id WHERE name = '$app2' AND source = '$source' $vsys_query;");
            if ($getExistAppGroup->num_rows == 0){

                $getExistAppFilters = $projectdb->query("SELECT id FROM applications_filters WHERE name = '$app2' AND source = '$source' $vsys_query;");
                if ($getExistAppFilters->num_rows == 0){
                    $projectdb->query("INSERT INTO applications (name, source, vsys) VALUES ('$app2', '$source', '$vsys');");
                    $member_lid = $projectdb->insert_id;
                    $table_name = "applications";

                    // get M.Learning tag id
                    $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');
                    // add M.Learning tag to the new address create
                    $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) SELECT '$table_name', '$member_lid', '$tag_id' FROM DUAL WHERE NOT EXISTS (SELECT table_name,member_lid,tag_id FROM tag_relations WHERE table_name='$table_name' AND member_lid='$member_lid' AND tag_id='$tag_id' LIMIT 1);");

                }
                else{
                    while($dataEAF = $getExistAppFilters->fetch_assoc()){
                        $member_lid = $dataEAF['id'];
                        $table_name = "applications_filters";
                    }
                }
            }
            else{
                while($dataEAG = $getExistAppGroup->fetch_assoc()){
                    $member_lid = $dataEAG['id'];
                    $table_name = "applications_groups_id";
                }
            }
        }
        else{
            while($dataEA = $getExistApp->fetch_assoc()){
                $member_lid = $dataEA['id'];
                $table_name = "applications";
            }
        }
    }
    else{
        while($dataEDA = $getExistDefApp->fetch_assoc()){
            $member_lid = $dataEDA['id'];
            $table_name = "default_applications";
        }
    }

    $getExistAppRule = $projectdb->query("SELECT id FROM security_rules_app WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';");
    if ($getExistAppRule->num_rows == 0){
        $projectdb->query("INSERT INTO security_rules_app (member_lid, table_name, source, vsys, rule_lid) VALUES ('$member_lid', '$table_name', '$source', '$vsys', '$rule_lid');");
    }

}

function add_services($project, $services, $protocol, $rule_lid, $source, $vsys){

    global $projectdb;

    $projectdb = selectDatabase($project);

    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($services == "application-default"){

        $getExistService = $projectdb->query("SELECT id FROM services WHERE name = 'application-default' AND source = '$source' AND vsys = 'shared';");
        //echo "3. SELECT id FROM services WHERE name = 'application-default' AND source = '$source' AND vsys = 'shared';\n";
        if ($getExistService->num_rows == 1){

            $dataES = $getExistService->fetch_assoc();
            $member_lid = $dataES['id'];
            $table_name = "services";

            $getExistAppRule = $projectdb->query("SELECT id FROM security_rules_srv WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';");
            //echo "4. SELECT id FROM security_rules_srv WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';\n";
            if ($getExistAppRule->num_rows == 0){
                // If exist, delete all services from rule and add application-default
                $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$rule_lid';");
                $projectdb->query("INSERT INTO security_rules_srv (member_lid, table_name, source, vsys, rule_lid) VALUES ('$member_lid', '$table_name', '$source', '$vsys', '$rule_lid');");
                //echo "5. INSERT INTO security_rules_srv (member_lid, table_name, source, vsys, rule_lid) VALUES ('$member_lid', '$table_name', '$source', '$vsys', '$rule_lid');\n";
            }
        }

    }
    else{

        //echo "El services: " .$services. "\n";
        // Chequear que existe un servicio con rango que pueda contener el servicio visto
        list($protocol, $port) = explode("/", $services);

        $probability_name = truncate_names($protocol."-".$port);

        $getExistService = $projectdb->query("SELECT id FROM services WHERE protocol = '$protocol' AND dport = '$port' AND sport = '' AND timeout = '' AND source = '$source' $vsys_query;");
        //echo "1. SELECT id FROM services WHERE protocol = '$protocol' AND dport = '$port' AND sport = '' AND timeout = '' AND source = '$source' $vsys_query;\n";
        if ($getExistService->num_rows == 0){

            $projectdb->query("INSERT INTO services (source, vsys, name, protocol, dport, sport, tag, timeout, override,used)  
                                    VALUES ('$source', '$vsys', '$probability_name', '$protocol', '$port', '', '', '', 'no',1);");

            //echo "2. INSERT INTO services (source, vsys, name, protocol, dport, sport, tag, timeout, override)
            //                        VALUES ('$source', '$vsys', '$probability_name', '$protocol', '$port', '', '', '', 'no');\n";

            $member_lid = $projectdb->insert_id;
            $table_name = "services";

            // get M.Learning tag id
            $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');
            // add M.Learning tag to the new service created
            $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) SELECT '$table_name', '$member_lid', '$tag_id' FROM DUAL WHERE NOT EXISTS (SELECT table_name,member_lid,tag_id FROM tag_relations WHERE table_name='$table_name' AND member_lid='$member_lid' AND tag_id='$tag_id' LIMIT 1);");
        }
        else{
            while($dataES = $getExistService->fetch_assoc()){
                $member_lid = $dataES['id'];
                $table_name = "services";
            }
        }

        // Check if A in B with services on rule
        $getMemberLidSRV = $projectdb->query("SELECT member_lid, table_name FROM security_rules_srv WHERE rule_lid = '$rule_lid';");

        if ($getMemberLidSRV->num_rows > 0) {
            while ($dataML = $getMemberLidSRV->fetch_assoc()) {

                $member_lid_srv = $dataML['member_lid'];
                $table_name_srv = $dataML['table_name'];

                $is_port_in_the_rule = checkPortsAreInNewServiceClean($rule_lid, $member_lid_srv, $table_name_srv, $port, $protocol);

            }
            if($is_port_in_the_rule == "false"){
                $getExistAppRule = $projectdb->query("SELECT id FROM security_rules_srv WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';");
                if ($getExistAppRule->num_rows == 0){
                    $projectdb->query("INSERT INTO security_rules_srv (member_lid, table_name, source, vsys, rule_lid) VALUES ('$member_lid', '$table_name', '$source', '$vsys', '$rule_lid');");
                }
            }
        }
        else{
            // No hay members, por lu tant, añadir sin más ya que no hace falta hacer el A is B de los ports
            $projectdb->query("INSERT INTO security_rules_srv (member_lid, table_name, source, vsys, rule_lid) VALUES ('$member_lid', '$table_name', '$source', '$vsys', '$rule_lid');");
        }
    }

}

function add_address($project, $data_address, $table_name_rule, $rule_lid, $source, $vsys){

    global $projectdb;
    $projectdb = selectDatabase($project);

    $members = array();
    $sources_sec_rule = array();

    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $raw = explode(",", $data_address);

    foreach($raw as $address){

        if (strpos($address, '-') != FALSE){
            $ip = $address;
            $cidr = "";
            $type = "ip-range";
        }
        else{
            if (strpos($address, '/') === FALSE){
                $ip = $address;
                $cidr = "32";
                $type = "ip-netmask";
            }
            else{
                list($ip, $cidr) = explode("/", $address);
                $type = "ip-netmask";
            }
        }

        $version0 = ip_version($ip);
        if($version0 == 'v6'){
            $v4 = 0;
            $v6 = 1;
        }
        else{
            $v4 = 1;
            $v6 = 0;
        }

        // get M.Learning tag id
        $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');

        $getExistAddress = $projectdb->query("SELECT id FROM address WHERE name = '$address' AND type = '$type' AND ipaddress = '$ip' AND cidr = '$cidr' AND source = '$source' $vsys_query;");
        //echo "SELECT id FROM address WHERE name = '$address' AND type = '$type' AND ipaddress = '$ip' AND cidr = '$cidr' AND source = '$source' $vsys_query;";
        if ($getExistAddress->num_rows == 0){

            $query = "INSERT INTO address (name,name_ext,type,ipaddress,cidr,description,devicegroup,source,tag,vsys,v4,v6,disable_override,used) VALUES ('$address', '$address', '$type', '$ip', '$cidr', '','','$source','','$vsys','$v4','$v6','','1');";
            $projectdb->query($query);

            $member_lid = $projectdb->insert_id;

            // add M.Learning tag to the new address created
            $table_name = 'address';
            $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) SELECT '$table_name', '$member_lid', '$tag_id' FROM DUAL WHERE NOT EXISTS (SELECT table_name,member_lid,tag_id FROM tag_relations WHERE table_name='$table_name' AND member_lid='$member_lid' AND tag_id='$tag_id' LIMIT 1);");

        }
        else{
            while($dataEA = $getExistAddress->fetch_assoc()){
                $member_lid = $dataEA['id'];
            }
        }

        $member = new MemberObject($member_lid, 'address', $ip, $cidr);
        $members[] = $member;

    }

    //echo "Los members NEWS son: \n";
    //print_r($members);

    $getValuesOnRule = $projectdb->query("SELECT id FROM $table_name_rule WHERE rule_lid = '$rule_lid';");
    //echo "SELECT id FROM $table_name_rule WHERE rule_lid = '$rule_lid';\n";
    if ($getValuesOnRule->num_rows == 0){

        foreach($members as $member){

            $getExistOnRule = $projectdb->query("SELECT id FROM $table_name_rule WHERE member_lid = '$member->name' AND table_name = '$member->location' AND rule_lid = '$rule_lid';");
            //echo "SELECT id FROM security_rules_src WHERE member_lid = '$member->name' AND table_name = '$member->location' AND rule_lid = '$rule_lid';\n";
            if ($getExistOnRule->num_rows == 0){
                $projectdb->query("INSERT INTO $table_name_rule (member_lid, table_name, source, vsys, rule_lid) 
                          VALUES ('$member->name', '$member->location', '$source', '$vsys', '$rule_lid');");
                //echo "INSERT INTO security_rules_src (member_lid, table_name, source, vsys, rule_lid)
                //          VALUES ('$member->name', '$member->location', '$source', '$vsys', '$rule_lid');\n";
            }
        }

    }
    else{

        $sources_sec_rule = getMembersSourceDestination($rule_lid, $table_name_rule);
        // Si hay valores en la security_rules que toca, parsear si a in b, sino, hacer insert de todos los que se han visto
        $exploded_childMembers = explodeGroups2Members($members, $projectdb, $source, $vsys, 0);
        //echo "Hijos";
        //print_r($childMembers);
        //print_r($exploded_childMembers);
        $exploded_parentMembers = explodeGroups2Members($sources_sec_rule, $projectdb, $source, $vsys, 0);
        //echo "Parents";
        //print_r($exploded_parentMembers);

        foreach ($exploded_childMembers as $childNode){
            //echo "ChildNode: \n";
            //print_r($childNode);
            foreach ($exploded_parentMembers as $parentMember){
                $way = -1;
                $result = netMatchObjects2Ways($childNode, $parentMember, $way);
                //echo "WAY: " .$way. "\n";
                //echo "ParentNode: \n";
                //print_r($parentMember);
                //echo "------->RESULT: \n";
                //print_r($result);
                if(isset($result)){
                    $tmp_Members[] = $result;
                    if($way == 1){
                        break 1;
                    }
                }
                else{
                    // Add news address from rule enrichment
                    if(strcmp($childNode->name, "ANY") != 0){
                        //$security_rules_src[] = "('$source', '$vsys', '$childNode->location', '$childNode->name', '$rule_lid')";
                        $getExistOnRule = $projectdb->query("SELECT id FROM $table_name_rule WHERE member_lid = '$childNode->name' AND table_name = '$childNode->location' AND rule_lid = '$rule_lid';");
                        //echo "SELECT id FROM $table_name_rule WHERE member_lid = '$childNode->name' AND table_name = '$childNode->location' AND rule_lid = '$rule_lid';\n";
                        if ($getExistOnRule->num_rows == 0){
                            $projectdb->query("INSERT INTO $table_name_rule (member_lid, table_name, source, vsys, rule_lid) 
                              VALUES ('$childNode->name', '$childNode->location', '$source', '$vsys', '$rule_lid');");
                            //echo "INSERT INTO $table_name_rule (member_lid, table_name, source, vsys, rule_lid)
                            //VALUES ('$childNode->name', '$childNode->location', '$source', '$vsys', '$rule_lid');\n";
                        }
                    }
                }
            }
        }
    }
}

function add_networks($project, $data_address, $table_name_rule, $rule_lid, $source, $vsys){

    global $projectdb;
    $projectdb = selectDatabase($project);

    $members = array();
    $sources_sec_rule = array();

    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $raw = explode(",", $data_address);

    foreach($raw as $address){
        if (strpos($address, '-') === TRUE){
            $startRange = explode("-", $address);
            $addressArray = explode(".", $startRange[0]);
            $ip = $addressArray[0].".".$addressArray[1].".".$addressArray[2].".0";
            $addressArray = explode(".", $startRange[1]);
            $ip2 = $addressArray[0].".".$addressArray[1].".".$addressArray[2].".0";
            if($ip == $ip2){
                $cidr = "24";
                $type = "ip-netmask";
            }
            else{
                $ip = $address;
                $cidr = "";
                $type = "ip-range";
            }
        }
        else{
            if (strpos($address, '/') === FALSE){
                $addressArray = explode(".", $address);
                $ip = $addressArray[0].".".$addressArray[1].".".$addressArray[2].".0";
                $cidr = "24";
                $type = "ip-netmask";

            }
            else{
                list($ip, $cidr) = explode("/", $address);
                if($cidr > "24") {
                    $addressArray = explode(".", $ip);
                    $ip = $addressArray[0] . "." . $addressArray[1] . "." . $addressArray[2] . ".0";
                    $cidr = "24";
                }
                $type = "ip-netmask";
            }
        }

        $version0 = ip_version($ip);
        if($version0 == 'v6'){
            $v4 = 0;
            $v6 = 1;
        }
        else{
            $v4 = 1;
            $v6 = 0;
        }

        // get M.Learning tag id
        $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');

        $getExistAddress = $projectdb->query("SELECT id FROM address WHERE name = '$ip-$cidr' AND type = '$type' AND ipaddress = '$ip' AND cidr = '$cidr' AND source = '$source' $vsys_query;");
        if ($getExistAddress->num_rows == 0){

            $projectdb->query("INSERT INTO address (name,name_ext,type,ipaddress,cidr,description,devicegroup,source,tag,vsys,v4,v6,disable_override) 
          VALUES ('$ip-$cidr', '$ip-$cidr', '$type', '$ip', '$cidr', '','','$source','','$vsys','$v4','$v6','');");

            $member_lid = $projectdb->insert_id;

            // add M.Learning tag to the new address created
            $table_name = 'address';
            $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) SELECT '$table_name', '$member_lid', '$tag_id' FROM DUAL WHERE NOT EXISTS (SELECT table_name,member_lid,tag_id FROM tag_relations WHERE table_name='$table_name' AND member_lid='$member_lid' AND tag_id='$tag_id' LIMIT 1);");
        }
        else{
            while($dataEA = $getExistAddress->fetch_assoc()){
                $member_lid = $dataEA['id'];
            }
        }

        $member = new MemberObject($member_lid, 'address', $ip, $cidr);
        $members[] = $member;

    }

    //echo "Los members NEWS son: \n";
    //print_r($members);

    $getValuesOnRule = $projectdb->query("SELECT id FROM $table_name_rule WHERE rule_lid = '$rule_lid';");
    //echo "SELECT id FROM $table_name_rule WHERE rule_lid = '$rule_lid';\n";
    if ($getValuesOnRule->num_rows == 0){

        foreach($members as $member){

            $getExistOnRule = $projectdb->query("SELECT id FROM $table_name_rule WHERE member_lid = '$member->name' AND table_name = '$member->location' AND rule_lid = '$rule_lid';");
            //echo "SELECT id FROM security_rules_src WHERE member_lid = '$member->name' AND table_name = '$member->location' AND rule_lid = '$rule_lid';\n";
            if ($getExistOnRule->num_rows == 0){
                $projectdb->query("INSERT INTO $table_name_rule (member_lid, table_name, source, vsys, rule_lid) 
                          VALUES ('$member->name', '$member->location', '$source', '$vsys', '$rule_lid');");
                //echo "INSERT INTO security_rules_src (member_lid, table_name, source, vsys, rule_lid)
                //          VALUES ('$member->name', '$member->location', '$source', '$vsys', '$rule_lid');\n";
            }
        }

    }
    else{

        $sources_sec_rule = getMembersSourceDestination($rule_lid, $table_name_rule);
        // Si hay valores en la security_rules que toca, parsear si a in b, sino, hacer insert de todos los que se han visto
        $exploded_childMembers = explodeGroups2Members($members, $projectdb, $source, $vsys, 0);
        //echo "Hijos";
        //print_r($childMembers);
        //print_r($exploded_childMembers);
        $exploded_parentMembers = explodeGroups2Members($sources_sec_rule, $projectdb, $source, $vsys, 0);
        //echo "Parents";
        //print_r($exploded_parentMembers);

        foreach ($exploded_childMembers as $childNode){
            //echo "ChildNode: \n";
            //print_r($childNode);
            foreach ($exploded_parentMembers as $parentMember){
                $way = -1;
                $result = netMatchObjects2Ways($childNode, $parentMember, $way);
                //echo "WAY: " .$way. "\n";
                //echo "ParentNode: \n";
                //print_r($parentMember);
                //echo "------->RESULT: \n";
                //print_r($result);
                if(isset($result)){
                    $tmp_Members[] = $result;
                    if($way == 1){
                        break 1;
                    }
                }
                else{
                    // Add news address from rule enrichment
                    if(strcmp($childNode->name, "ANY") != 0){
                        //$security_rules_src[] = "('$source', '$vsys', '$childNode->location', '$childNode->name', '$rule_lid')";
                        $getExistOnRule = $projectdb->query("SELECT id FROM $table_name_rule WHERE member_lid = '$childNode->name' AND table_name = '$childNode->location' AND rule_lid = '$rule_lid';");
                        //echo "SELECT id FROM $table_name_rule WHERE member_lid = '$childNode->name' AND table_name = '$childNode->location' AND rule_lid = '$rule_lid';\n";
                        if ($getExistOnRule->num_rows == 0){
                            $projectdb->query("INSERT INTO $table_name_rule (member_lid, table_name, source, vsys, rule_lid) 
                              VALUES ('$childNode->name', '$childNode->location', '$source', '$vsys', '$rule_lid');");
                            //echo "INSERT INTO $table_name_rule (member_lid, table_name, source, vsys, rule_lid)
                            //VALUES ('$childNode->name', '$childNode->location', '$source', '$vsys', '$rule_lid');\n";
                        }
                    }
                }
            }
        }
    }
}

function add_regions($project, $region, $table_name_rule, $rule_lid, $source, $vsys){

    global $projectdb;

    $projectdb = selectDatabase($project);

    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    // get M.Learning tag id
    $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');

    $getExistDefRegion = $projectdb->query("SELECT id FROM default_regions WHERE name = '$region';");
    if ($getExistDefRegion->num_rows == 0){

        $getExistRegions = $projectdb->query("SELECT id FROM regions WHERE name = '$region' AND source = '$source' $vsys_query;");
        if ($getExistRegions->num_rows == 0){

            //Insert regions
            $projectdb->query("INSERT INTO regions (name, source, vsys) VALUES ('$region', '$source', '$vsys');");
            $member_lid = $projectdb->insert_id;
            $table_name = "regions";

            // add M.Learning tag to the new address created
            $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) SELECT '$table_name', '$member_lid', '$tag_id' FROM DUAL WHERE NOT EXISTS (SELECT table_name,member_lid,tag_id FROM tag_relations WHERE table_name='$table_name' AND member_lid='$member_lid' AND tag_id='$tag_id' LIMIT 1);");
        }
        else{
            while($dataER = $getExistRegions->fetch_assoc()){
                $member_lid = $dataER['id'];
                $table_name = "regions";
            }
        }
    }
    else{
        $dataEDR = $getExistDefRegion->fetch_assoc();
        $member_lid = $dataEDR['id'];
        $table_name = "default_regions";
    }

    $getExistAppRule = $projectdb->query("SELECT id FROM $table_name_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$rule_lid';");
    if ($getExistAppRule->num_rows == 0){
        $projectdb->query("INSERT INTO $table_name_rule (member_lid, table_name, source, vsys, rule_lid) 
            VALUES ('$member_lid', '$table_name', '$source', '$vsys', '$rule_lid');");
    }

}

function add_users($project, $user, $rule_lid, $source, $vsys){

    global $projectdb;
    $user=addslashes($user);

    $projectdb = selectDatabase($project);

    $getExistUserInRule = $projectdb->query("SELECT id FROM security_rules_usr WHERE name = '$user' AND rule_lid = '$rule_lid';");
    if ($getExistUserInRule->num_rows == 0){
        $projectdb->query("INSERT INTO security_rules_usr (name, source, vsys, rule_lid, from_log) VALUES ('$user', '$source', '$vsys', '$rule_lid', 'false');");
    }

}

function checkPortsAreInNewServiceClean($rule_lid_sec, $member_lid, $table_name, $parent_ports_item, $parent_protocol){

    global $projectdb;

    if($table_name == "services"){

        $getServicesPorts = $projectdb->query("SELECT protocol, dport  FROM services WHERE id = '$member_lid' ;");
        if ($getServicesPorts->num_rows > 0) {
            while ($dataSP = $getServicesPorts->fetch_assoc()) {

                $dport = $dataSP['dport'];
                $protocol = $dataSP['protocol'];
                $portsArr = explode("-",$dport);
                $start_child = $portsArr[0];
                $end_child = isset($portsArr[1])?$portsArr[1]:$portsArr[0];

                $portsArr2 = explode("-",$parent_ports_item);
                $start_parent = $portsArr2[0];
                $end_parent = isset($portsArr2[1])?$portsArr2[1]:$portsArr2[0];

                if($protocol == $parent_protocol){
                    $is_match_port_partial = matchPortsRang($start_parent, $end_parent, $start_child, $end_child);
                }else{
                    $is_match_port_partial = "false";
                }

            }
        }
    }
    elseif($table_name == "services_groups_id"){

        $getMemeberLid = $projectdb->query("SELECT member_lid, table_name FROM services_groups WHERE lid = '$member_lid';");
        if ($getMemeberLid->num_rows > 0) {
            while ($dataML = $getMemeberLid->fetch_assoc()) {

                $member_lid_group = $dataML['member_lid'];
                $table_name_group = $dataML['table_name'];

                checkPortsAreInNewServiceClean($rule_lid_sec, $member_lid_group, $table_name_group, $parent_ports_item, $parent_protocol);

            }
        }
    }

    return $is_match_port_partial;
}

function matchPortsRang($childStart, $childEnd, $parentStart, $parentEnd){

    if (($childStart >= $parentStart) && ($childEnd <= $parentEnd)) {
        return "true";
    }
    else{
        return "false";
    }
}

function getMembersSourceDestination($rule_lid, $table_name){

    global $projectdb;

    $members = array();
    //unset($members);

    // Get Members security rules origin
    $getSec = $projectdb->query("SELECT member_lid, table_name FROM $table_name WHERE rule_lid = '$rule_lid';");
    if ($getSec->num_rows > 0) {
        while ($dataSS = $getSec->fetch_assoc()) {

            $member_lid = $dataSS['member_lid'];
            $table_name = $dataSS['table_name'];

            if($table_name == "address"){
                $getAddress = $projectdb->query("SELECT id, ipaddress, cidr FROM address WHERE id = '$member_lid';");
                if ($getAddress->num_rows > 0) {
                    $myData = $getAddress->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member_ip = $myData['ipaddress'];
                    $member_cidr = $myData['cidr'];
                    $member = new MemberObject($member_lid, 'address', $member_ip, $member_cidr);
                    $members[] = $member;
                }
            }
            elseif($table_name == "address_groups_id"){
                $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'address_groups_id');
                    $members[] = $member;
                }
            }
            elseif($table_name == "default_regions"){
                $getGRP = $projectdb->query("SELECT id FROM default_regions WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'default_regions');
                    $members[] = $member;
                }
            }
            elseif($table_name == "regions"){
                $getGRP = $projectdb->query("SELECT id FROM regions WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'regions');
                    $members[] = $member;
                }
            }
            elseif($table_name == "external_list"){
                $getGRP = $projectdb->query("SELECT id FROM external_list WHERE id = '$member_lid';");
                if ($getGRP->num_rows == 1) {
                    $myData = $getGRP->fetch_assoc();
                    $member_lid = $myData['id'];
                    $member = new MemberObject($member_lid, 'external_list');
                    $members[] = $member;
                }
            }
        }
    }
    else{
        $member = new MemberObject("ANY", '', '0.0.0.0', '0');
        $members[] = $member;
    }

    return $members;

}


/*function hasUsers($rule_lid){

    global $projectdb;

    $getUsers = $projectdb->query("SELECT id FROM security_rules_usr WHERE rule_lid = '$rule_lid';");

    if ($getUsers->num_rows > 0) {
        return true;
    }else{
        return false;
    }

}*/

/*function hasServices($rule_lid){

    global $projectdb;

    $getUsers = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid';");

    if ($getUsers->num_rows > 0) {
        return true;
    }else{
        return false;
    }

}*/

/*function hasApplicationDefault($rule_lid, $source){

    global $projectdb;

    $getIdAppDef = $projectdb->query("SELECT id FROM services WHERE name LIKE '%application-default%' AND source = '$source' AND vsys = 'shared' LIMIT 1; ");

    if ($getIdAppDef->num_rows > 0) {
        $dataIAD = $getIdAppDef->fetch_assoc();
        $id_app_default = $dataIAD['id'];

        $getAppDefaultOnRule = $projectdb->query("SELECT id FROM security_rules_srv WHERE member_lid = '$id_app_default' AND table_name = 'services' AND rule_lid = '$rule_lid';");

        if ($getAppDefaultOnRule->num_rows > 0) {
            return true;
        }else{
            return false;
        }

    }

}*/


function hasApplicationDefaultOriginRE($id){

    global $projectdb;

    $getIdAppDef = $projectdb->query("SELECT ServicesTCP FROM ML_RuleEnrichment WHERE id = '$id' AND ServicesTCP LIKE '%application-default%'; ");

    if ($getIdAppDef->num_rows > 0) {
        return true;
    }else{
        return false;
    }

}


function hasUsersOriginRE($id){

    global $projectdb;

    $getIdAppDef = $projectdb->query("SELECT Users FROM ML_RuleEnrichment WHERE id = '$id' AND Users != ''; ");

    if ($getIdAppDef->num_rows > 0) {
        return true;
    }else{
        return false;
    }

}


function checkPortsAreInNewService($is_match_port, $member_lid, $table_name, $parent_ports, $app_id, $app_table){

    global $projectdb;

    if($is_match_port == "true"){

        if($table_name == "services"){

            $getServicesPorts = $projectdb->query("SELECT name, dport FROM services WHERE id = '$member_lid' ;");

            if ($getServicesPorts->num_rows > 0) {
                while ($dataSP = $getServicesPorts->fetch_assoc()) {

                    $dports = $dataSP['dport'];
                    $name = $dataSP['name'];

                    if($name == "application-default"){
                        //$is_match_port = "true";

                        //Check if the app's ports have the same ports from appoverride rules
                        $getPortsFromApp = $projectdb->query("SELECT id, value FROM $app_table WHERE id = '$app_id' ;");

                        if ($getPortsFromApp->num_rows == 1){
                            $dataPFA = $getPortsFromApp->fetch_assoc();
                            $value_ports = $dataPFA['value'];

                            if($value_ports != ""){

                                $value_ports_explode = explode(",", $value_ports);

                                foreach ($value_ports_explode as $value_ports_item){

                                    $valueArr = explode("/", $value_ports_item);
                                    $portsArr = explode("-",$valueArr[1]);
                                    $start_child = $portsArr[0];
                                    $end_child = isset($portsArr[1])?$portsArr[1]:$portsArr[0];
                                    $protocol = $valueArr[0];

                                    $is_match_port_partial = "false";

                                    foreach ($parent_ports as $parent_ports_item){
                                        $portsArr2 = explode("-",$parent_ports_item);
                                        $start_parent = $portsArr2[0];
                                        $end_parent = isset($portsArr2[1])?$portsArr2[1]:$portsArr2[0];

                                        if($is_match_port_partial != "true"){
                                            $is_match_port_partial = matchPortsRang($start_child, $end_child, $start_parent, $end_parent);

                                            if($is_match_port_partial == "true"){
                                                $is_match_port = "true";
                                                break;
                                            }elseif($is_match_port_partial == "false"){
                                                $is_match_port = "false";
                                            }
                                        }

                                        //echo "Is match port partial: " .$is_match_port_partial. "\n";
                                        //echo "Start Child: " .$start_child. "\n";
                                        //echo "End Child: " .$end_child. "\n";
                                        //echo "Start Parent: " .$start_parent. "\n";
                                        //echo "End Parent: " .$end_parent. "\n";

                                    }
                                }
                            }
                        }
                    }
                    else{
                        $dport_explode = explode(",", $dports);

                        foreach($dport_explode as $dport){
                            if (in_array($dport, $parent_ports)) {
                            }else{
                                $is_match_port = "false";
                            }
                        }
                    }
                }
            }
        }
        elseif($table_name == "services_groups_id"){

            $getMemeberLid = $projectdb->query("SELECT member_lid, table_name FROM services_groups WHERE lid = '$member_lid';");
            if ($getMemeberLid->num_rows > 0) {
                while ($dataML = $getMemeberLid->fetch_assoc()) {

                    $member_lid_group = $dataML['member_lid'];
                    $table_name_group = $dataML['table_name'];

                    $is_match_port = checkPortsAreInNewService($is_match_port, $member_lid_group, $table_name_group, $parent_ports, $app_id, $app_table);

                }
            }
        }
    }

    return $is_match_port;

}

function checkExistRuleWithTypeAndCloned($rule_name, $vsys, $source, $initial_position, $final_position, $rule_lid, $project, $type, $re_users, $re_app_default){

    global $projectdb;

    #type can be Ua UA ua uA where uU means has or not Users and aA has or not App-default
    $getNameRuleCl = $projectdb->query("SELECT id, name FROM security_rules WHERE BINARY name = 'CL-$type-$rule_name' 
        AND disabled = '0' AND vsys = '$vsys' AND source = '$source' AND re_users = '$re_users' AND re_app_default = '$re_app_default' ;");

    if ($getNameRuleCl->num_rows == 0) {
        $rule_lid = clone_security_rule($initial_position, $final_position, $vsys, $source, $rule_lid, "CL-".$type."-", $project);
        $is_first_cloned = 1;
        $projectdb->query("UPDATE security_rules SET re_users = '$re_users', re_app_default = '$re_app_default', re='0', ml='0' WHERE id = '$rule_lid'; ");
    }
    else {
        $is_first_cloned = 0;
        $dataNRC = $getNameRuleCl->fetch_assoc();
        $rule_lid = $dataNRC['id'];
    }

    return array($rule_lid, $is_first_cloned);

}



