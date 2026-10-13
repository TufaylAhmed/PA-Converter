<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
//require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

function load_csv_description(){
    $description=false;

    if (file_exists(INC_ROOT.'/libs/best_practice_assessment/bpat_documentation.csv')){
        ini_set('auto_detect_line_endings',TRUE);
        $handle = fopen(INC_ROOT.'/libs/best_practice_assessment/bpat_documentation.csv','r');
        $description=array();
        while ( ($data = fgetcsv($handle,0,';') ) !== FALSE ) {
            $description[$data[0]]['title']=$data[4];
            $description[$data[0]]['description']=$data[6];
        }
        ini_set('auto_detect_line_endings',FALSE);
    }

    return $description;
}


function load_csv_description_from_www(){
    $description=false;

    if (file_exists(INC_ROOT.'/libs/best_practice_assessment_ngfw_pano/best_practice_assessment/BestPracticeDocumentation.csv')){
        ini_set('auto_detect_line_endings',TRUE);
        $handle = fopen(INC_ROOT.'/libs/best_practice_assessment_ngfw_pano/best_practice_assessment/BestPracticeDocumentation.csv','r');
        $description=array();
        while ( ($data = fgetcsv($handle,0,';') ) !== FALSE ) {
            $description[$data[0]]['title']=$data[1];
            $description[$data[0]]['description']=addslashes($data[5]);
            $description[$data[0]]['rationale']=addslashes($data[6]);
            if ($data[9]!="None"){
                $data[9]="";
            }
            $description[$data[0]]['references']=$data[9];
        }
        ini_set('auto_detect_line_endings',FALSE);
    }

    return $description;
}

function map_bpat_with_ruleid($source,$ispanorama){
    global $projectdb;
    $rulesInMemory=array();
    $getRules=$projectdb->query("SELECT * FROM security_rules WHERE source='$source'");
    if ($getRules->num_rows>0){
        while($getRulesData=$getRules->fetch_assoc()){
            $preorpost=$getRulesData['preorpost'];
            $vsys=$getRulesData['vsys'];
            $rule_name=$getRulesData['name'];
            if ($preorpost==1){$rulebase="post-rulebase";}
            else{
                if ($ispanorama==1){
                    $rulebase="pre-rulebase";
                }
                else{
                    $rulebase="rulebase";
                }
            }
            $rulesInMemory[$rule_name][$vsys][$rulebase]["id"]=$getRulesData['id'];
        }
    }
    return $rulesInMemory;
}

function add_bp_checks_to_tree($collector, $xpath, $bp_checks) {

    $location_arr = array('children');
    $result=array();
    for ($i = 0; $i < count($xpath); $i++) {
        $filter = array($xpath[$i]);

        if ($i == 0){
            $result = array_filter($collector['children'], function($e) use ($filter){
                return in_array($e['topic'], $filter);
            });
        }else {
            $index = $location_arr[count($location_arr)-2];
            $current_location =  $result[$index];


            $result = array_filter($current_location['children'], function($e) use ($filter){
                return in_array($e['topic'], $filter);
            });
        }

        if ( empty($result) ){

            $temp = &$collector;
            foreach($location_arr as $key) {
                $temp = &$temp[$key];
            }
            array_push($temp, array('topic' => $xpath[$i], 'children' => array() ) );

            $result = array_filter($temp, function($e) use ($filter){
                return in_array($e['topic'], $filter);
            });

            unset($temp);

        }
        array_push($location_arr, key($result), "children");

        if ($i == count($xpath)-1 ){
            $temp = &$collector;
            foreach($location_arr as $key) {
                $temp = &$temp[$key];
            }
            $temp = $bp_checks;
            unset($temp);
        }
    }
    return $collector;
}

function list_bpat_bpchecks($project,$vsys,$template,$subtype,$topic){
    if(!checkProjectRights($project,'view')){
        $message = [
            'code' => true,
            'count' => 0,
            'msg' => array()
        ];
        return $message;
    }

    global $projectdb;
    $projectdb = selectDatabase($project);

    $getSource=$projectdb->query("SELECT id,ispanorama FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
    if ($getSource->num_rows==1){
        $getSourceData=$getSource->fetch_assoc();
        $source=$getSourceData['id'];
        $ispanorama=$getSourceData['ispanorama'];
    }
    else{
        return $message["msg"]="There is NO Base-Config selected.";
    }

    $csv=load_csv_description_from_www();

    $Data=array();
    $addTopic="";
    $addSubtype="";

    if ($topic=="Root"){
        $addTopic=" AND topic='$subtype' ";
    }
    else{
        if ($topic!=""){
            $addTopic=" AND topic='$topic' ";
        }
        if ($subtype!=""){
            $subtype=uncamelize($subtype);
            $addSubtype=" AND subtype='$subtype' ";
        }
    }
    $getTopic=$projectdb->query("SELECT * FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND source='$source' $addTopic $addSubtype;");
    if ($getTopic->num_rows>0){
        $count=1;
        while($getTopicData=$getTopic->fetch_assoc()){
            $topic_id=$getTopicData['id'];
            $configuration=json_decode($getTopicData['configuration'],true);
            $getBPcheck=$projectdb->query("SELECT * FROM bpat_bpcheck WHERE topic_id='$topic_id';");
            if ($getBPcheck->num_rows>0){
                while($getBPcheckData=$getBPcheck->fetch_assoc()){
                    $getTopicData['message']=$getBPcheckData['message'];
                    $getTopicData['name']=$getBPcheckData['name'];
                    $getTopicData['result']=($getBPcheckData['result']=="pass") ? '1':'0';
                    $getTopicData['type']=$getBPcheckData['type'];
                    $getTopicData['bpcheck_id']=$getBPcheckData['check_id'];
                    $getTopicData['id']=$count;$count++;
                    $getTopicData['remediation']=$getBPcheckData['remediation'];
                    if (isset($csv[$getTopicData['bpcheck_id']])){
                        $getTopicData['topic']=$csv[$getTopicData['bpcheck_id']]['description'];
                        if (isset($csv[$getTopicData['bpcheck_id']]['rationale'])){
                            $getTopicData['rationale']=$csv[$getTopicData['bpcheck_id']]['rationale'];
                        }
                        if (isset($csv[$getTopicData['bpcheck_id']]['references'])){
                            if ($csv[$getTopicData['bpcheck_id']]['references']!="None"){
                                $getTopicData['references']=$csv[$getTopicData['bpcheck_id']]['references'];
                            }
                            else{
                                $getTopicData['references']="";
                            }

                        }
                        if (isset($csv[$getTopicData['bpcheck_id']]['description'])){
                            $getTopicData['description']=$csv[$getTopicData['bpcheck_id']]['description'];
                        }
                    }
                    else{
                        $getTopicData['topic']="";
                    }

                    switch($getBPcheckData['check_id']) {
                        case "31":
                            if (empty($configuration['threat_exceptions'])){$configuration['threat_exceptions']="None";}
                            $getTopicData['configuration']=array("name"=>$configuration['name'],"threat_exceptions"=>$configuration['threat_exceptions']);
                            break;
                        case "32":
                            if (empty($configuration['application_exceptions'])){$configuration['application_exceptions']="None";}
                            $getTopicData['configuration']=array("name"=>$configuration['name'],"application_exceptions"=>$configuration['application_exceptions']);
                            break;
                        case "33":
                            $getTopicData['configuration']=array("name"=>$configuration['name'],"decoders"=>json_encode($configuration['decoders']),true);
                            foreach ($configuration['decoders'] as $key=>$value){
                               // $getTopicData['configuration']="Action: ".$value['action'];
                            }
                            break;
                        case "34":
                            $getTopicData['configuration']['name']=$configuration['name'];
                            foreach ($configuration['decoders'] as $key=>$value){
                                $getTopicData['configuration'][$value['name']]="Action: ".$value['wildfire_action'];
                            }
                            break;
                        case "35":
                            $getTopicData['configuration']=array("name"=>$configuration['name'],"packet_capture_enabled"=>$configuration['packet_capture_enabled']);
                            break;
                        case "36":
                            $getTopicData['configuration'] = array("spyware_threat_exceptions" => $configuration['spyware_threat_exceptions']);
                            break;
                        case "38":
                            $getTopicData['configuration'] = array("dns_sinkhole_enabled" => $configuration['dns_sinkhole_enabled']);
                            break;
                        case "39":
                            $getTopicData['configuration'] = array("passive_dns_monitoring_enabled" => $configuration['passive_dns_monitoring_enabled']);
                            break;
                        case "41":
                            if (empty($configuration['threat_exceptions'])){$configuration['threat_exceptions']="None";}
                            $getTopicData['configuration']=array("name"=>$configuration['name'],"threat_exceptions"=>$configuration['threat_exceptions']);
                            break;
                        case "42":
                            if (empty($configuration['rules'])){$configuration['rules']="None";}
                            $getTopicData['configuration']=array("name"=>$configuration['name'],"rules"=>json_encode($configuration['rules']));
                            break;
                        case "43":
                            if (empty($configuration['block_categories'])){$configuration['block_categories']="None";}
                            $getTopicData['configuration']=array("name"=>$configuration['name'],"block_categories"=>$configuration['block_categories']);
                            break;
                        case "44":
                            if (empty($configuration['x_forwarded_for_enabled'])){$configuration['x_forwarded_for_enabled']="false";}
                            if (empty($configuration['user_agent_enabled'])){$configuration['user_agent_enabled']="false";}
                            if (empty($configuration['referer_enabled'])){$configuration['referer_enabled']="false";}
                            if (empty($configuration['log_container_page_only_enabled'])){$configuration['log_container_page_only_enabled']="false";}
                            $getTopicData['configuration']=array("name"=>$configuration['name'],
                                "user_agent_enabled"=>$configuration['user_agent_enabled'],
                                "x_forwarded_for_enabled"=>$configuration['x_forwarded_for_enabled'],
                                "referer_enabled"=>$configuration['referer_enabled'],
                                "log_container_page_only_enabled"=>$configuration['log_container_page_only_enabled']
                            );
                            break;
                        case "88":
                            $getTopicData['configuration'] = array("auto_acquire_commit_lock_enabled" => $configuration['auto_acquire_commit_lock_enabled']);
                            break;
                        case "89":
                            $getTopicData['configuration'] = array("cert_expiration_check_enabled" => $configuration['cert_expiration_check_enabled']);
                            break;
                        case "90":
                            $getTopicData['configuration'] = array("hostname" => $configuration['hostname']);
                            break;
                        case "91":
                            $getTopicData['configuration'] = array("login_banner_enabled" => $configuration['login_banner_enabled']);
                            break;
                        case "92":
                            $getTopicData['configuration'] = array("authentication_profile" => $configuration['authentication_profile']);
                            break;
                        case "93":
                            $getTopicData['configuration'] = array("certificate_profile" => $configuration['certificate_profile']);
                            break;
                        case "94":
                            $getTopicData['configuration'] = array("idle_timeout" => $configuration['idle_timeout']);
                            break;
                        case "95":
                            $getTopicData['configuration'] = array("failed_attempts" => $configuration['failed_attempts']);
                            break;
                        case "96":
                            $getTopicData['configuration'] = array("lockout_time" => $configuration['lockout_time']);
                            break;
                        case "97":
                            $getTopicData['configuration'] = array("log_on_high_dp_load_enabled" => $configuration['log_on_high_dp_load_enabled']);
                            break;
                        case "98":
                            $getTopicData['configuration'] = array("log_forwarding_from_device_enabled" => $configuration['log_forwarding_from_device_enabled']);
                            break;
                        case "99":
                            $getTopicData['configuration'] = array("certification_type" => $configuration['certification_type']);
                            break;
                        case "100":
                            if (empty($configuration['disabled_services'])){$configuration['disabled_services']="false";}
                            $getTopicData['configuration'] = array("permitted_ip_address_enabled" => (isset($configuration['permitted_ip_address_enabled'])?$configuration['permitted_ip_address_enabled']:''),"management_ip_address"=>$configuration['management_ip_address'],
                                "speed"=>$configuration['speed'],"disabled_services"=>$configuration['disabled_services']);
                            break;
                        case "101":
                            $getTopicData['configuration'] = array("speed" => $configuration['speed']);
                            break;
                        case "102":
                            if (empty($configuration['disabled_services'])){$configuration['disabled_services']="false";}
                            $getTopicData['configuration'] = array("disabled_services" => $configuration['disabled_services']);
                            break;
                        case "104":
                            $getTopicData['configuration'] = array("verify_update_server_identity_enabled" => $configuration['verify_update_server_identity_enabled']);
                            break;
                        case "105":
                            $getTopicData['configuration'] = array("primary_ntp_server_address" => $configuration['primary_ntp_server_address'],"secondary_ntp_server_address" => $configuration['secondary_ntp_server_address'],);
                            break;
                        case "106":
                            $getTopicData['configuration'] = array("primary_ntp_server_auth_type" => $configuration['primary_ntp_server_auth_type'],"secondary_ntp_server_auth_type" => $configuration['secondary_ntp_server_auth_type'],);
                            break;
                        case "107":
                            $getTopicData['configuration'] = array("use_x_forwarded_for_enabled" => $configuration['use_x_forwarded_for_enabled']);
                            break;
                        case "108":
                            $getTopicData['configuration'] = array("strip_x_forwarded_for_enabled" => $configuration['strip_x_forwarded_for_enabled']);
                            break;

                        case "109":
                            $getTopicData['configuration']=array("pe_size_limit"=>$configuration['pe_size_limit']);
                            break;
                        case "110":
                            $getTopicData['configuration']=array("apk_size_limit"=>$configuration['apk_size_limit']);
                            break;
                        case "111":
                            $getTopicData['configuration']=array("pdf_size_limit"=>$configuration['pdf_size_limit']);
                            break;
                        case "112":
                            $getTopicData['configuration']=array("ms_office_size_limit"=>$configuration['ms_office_size_limit']);
                            break;
                        case "113":
                            $getTopicData['configuration']=array("jar_size_limit"=>$configuration['jar_size_limit']);
                            break;
                        case "114":
                            $getTopicData['configuration']=array("flash_size_limit"=>$configuration['flash_size_limit']);
                            break;
                        case "115":
                            $getTopicData['configuration']=array("macosx_size_limit"=>$configuration['macosx_size_limit']);
                            break;
                        case "116":
                            $getTopicData['configuration']=array("report_benign_files_enabled"=>$configuration['report_benign_files_enabled']);
                            break;
                        case "117":
                            $getTopicData['configuration']=array("report_grayware_files_enabled"=>$configuration['report_grayware_files_enabled']);
                            break;
                        case "118":
                            $enabled=$configuration;
                            foreach($enabled as $i=>$v){
                                if (!preg_match("/enabled/",$i)){
                                    unset($enabled[$i]);
                                }
                            }
                            $getTopicData['configuration']=$enabled;

                            break;
                        case "119":
                            $getTopicData['configuration']=array("wildfire_public_cloud"=>$configuration['wildfire_public_cloud']);
                            break;

                        case "120":
                            $getTopicData['configuration'] = array("rematch_sessions_enabled" => $configuration['rematch_sessions_enabled']);
                            break;
                        case "121":
                            $getTopicData['configuration'] = array("accelerated_aging_enabled" => $configuration['accelerated_aging_enabled']);
                            break;
                        case "122":
                            $getTopicData['configuration'] = array("timeout_default" => $configuration['timeout_default']);
                            break;
                        case "123":
                            $getTopicData['configuration'] = array("timeout_discard_default" => $configuration['timeout_discard_default']);
                            break;
                        case "124":
                            $getTopicData['configuration'] = array("timeout_discard_tcp" => $configuration['timeout_discard_tcp']);
                            break;
                        case "125":
                            $getTopicData['configuration'] = array("timeout_discard_udp" => $configuration['timeout_discard_udp']);
                            break;
                        case "126":
                            $getTopicData['configuration'] = array("timeout_icmp" => $configuration['timeout_icmp']);
                            break;
                        case "127":
                            $getTopicData['configuration'] = array("timeout_scan" => $configuration['timeout_scan']);
                            break;
                        case "128":
                            $getTopicData['configuration'] = array("timeout_tcp" => $configuration['timeout_tcp']);
                            break;
                        case "129":
                            $getTopicData['configuration'] = array("timeout_tcp_handshake" => $configuration['timeout_tcp_handshake']);
                            break;
                        case "130":
                            $getTopicData['configuration'] = array("timeout_tcp_init" => $configuration['timeout_tcp_init']);
                            break;
                        case "131":
                            $getTopicData['configuration'] = array("timeout_tcp_half_closed" => $configuration['timeout_tcp_half_closed']);
                            break;
                        case "132":
                            $getTopicData['configuration'] = array("timeout_tcp_time_wait" => $configuration['timeout_tcp_time_wait']);
                            break;
                        case "133":
                            $getTopicData['configuration'] = array("timeout_unverified_rst" => $configuration['timeout_unverified_rst']);
                            break;
                        case "134":
                            $getTopicData['configuration'] = array("timeout_udp" => $configuration['timeout_udp']);
                            break;
                        case "135":
                            $getTopicData['configuration'] = array("timeout_captive_portal" => $configuration['timeout_captive_portal']);
                            break;

                        case "152":
                            $getTopicData['configuration'] = null;
                            break;
                        case "153":
                            $getTopicData['configuration'] = array("users" => json_encode($configuration['users']));
                            break;

                        case "161":
                            $getTopicData['configuration']=array("include_networks"=>$configuration['include_networks']);
                            break;
                        case "162":
                            $getTopicData['configuration']=array("security_log_enabled"=>$configuration['security_log_enabled']);
                            break;
                        case "163":
                            $getTopicData['configuration']=array("server_log_monitor_frequency"=>$configuration['server_log_monitor_frequency']);
                            break;
                        case "164":
                            $getTopicData['configuration']=array("probing_enabled"=>$configuration['probing_enabled']);
                            break;
                        case "165":
                            $getTopicData['configuration']=array("user_id_timeout_enabled"=>$configuration['user_id_timeout_enabled']);
                            break;
                        case "166":
                            $getTopicData['configuration']=array("user_id_timeout"=>$configuration['user_id_timeout']);
                            break;
                        case "167":
                            $getTopicData['configuration']=array("server_monitors"=>$configuration['server_monitors']);
                            break;
                        case "168":
                            $getTopicData['configuration']=array("ldap_proxy_agents"=>$configuration['ldap_proxy_agents']);
                            break;
                        case "169":
                            $getTopicData['configuration']=array("group_mappings"=>$configuration['group_mappings']);
                            break;
                        case "170":
                            $getTopicData['configuration']=array("group_mappings"=>$configuration['group_mappings']);
                            break;
                        case "171":
                            $getTopicData['configuration']=array("captive_portal_settings_enabled"=>$configuration['captive_portal_settings']['enabled']);
                            break;
                        case "172":
                            $getTopicData['configuration']=array("captive_portal_settings_mode"=>$configuration['captive_portal_settings']['mode']);
                            break;
                        case "173":
                            $getTopicData['configuration']=array("captive_portal_settings_session_cookie_timeout"=>$configuration['captive_portal_settings']['session_cookie_timeout']);
                            break;
                        case "174":
                            $getTopicData['configuration']=array("captive_portal_settings_ssl_tls_service_profile_min_version"=>$configuration['captive_portal_settings']['ssl_tls_service_profile_min_version']);
                            break;
                        case "175":
                            $getTopicData['configuration']=array("captive_portal_settings_auth_profile"=>$configuration['captive_portal_settings']['auth_profile'],"captive_portal_settings_cert_profile"=>$configuration['captive_portal_settings']['cert_profile']);
                            break;
                        case "176":
                            $getTopicData['configuration']="";
                            break;
                        case "177":
                            $getTopicData['configuration']=array("log_send_to_info"=>$configuration['log_send_to_info']);
                            break;
                        case "178":
                            $getTopicData['configuration']=array("log_send_to_low"=>$configuration['log_send_to_low']);
                            break;
                        case "179":
                            $getTopicData['configuration']=array("log_send_to_medium"=>$configuration['log_send_to_medium']);
                            break;
                        case "180":
                            $getTopicData['configuration']=array("log_send_to_high"=>$configuration['log_send_to_high']);
                            break;
                        case "181":
                            $getTopicData['configuration']=array("log_send_to_critical"=>$configuration['log_send_to_critical']);
                            break;


                        case "188":
                            $getTopicData['configuration']=$configuration['anti_virus'];
                            break;
                        case "189":
                            $getTopicData['configuration']=$configuration['apps_threats'];
                            break;
                        case "190":
                            $getTopicData['configuration']=$configuration['wildfire'];
                            break;
                        case "194":
                            $getTopicData['configuration']=$configuration['global_protect'];
                            break;
                        case "195":
                            $getTopicData['configuration']=$configuration['gp_clientless_vpn'];
                            break;
                        case "196":
                            if (empty($configuration['url_categories_allowed'])){$configuration['url_categories_allowed']="false";}
                            $getTopicData['configuration']=array("name"=>$configuration['name'],"url_categories_allowed"=>$configuration['url_categories_allowed']);
                            break;

                        case "204":
                            $getTopicData['configuration']=array("archive_size_limit"=>$configuration['archive_size_limit']);
                            break;
                        case "205":
                            $getTopicData['configuration']=array("linux_size_limit"=>$configuration['linux_size_limit']);
                            break;

                        default:
                            if ($subtype=="wildfire"){
                                $getTopicData['configuration']=null;
//                                unset($configuration['report_grayware_files_enabled']);
//                                unset($configuration['pe_size_limit']);
//                                unset($configuration['apk_size_limit']);
//                                unset($configuration['pdf_size_limit']);
//                                unset($configuration['ms_office_size_limit']);
//                                unset($configuration['jar_size_limit']);
//                                unset($configuration['flash_size_limit']);
//                                unset($configuration['macosx_size_limit']);
//                                unset($configuration['report_benign_files_enabled']);
//                                unset($configuration['template_name']);
//                                //unset($configuration['wildfire_public_cloud']);
//                                unset($configuration['rules']);
//                                $getTopicData['configuration']=$configuration;
                            }
                            else{
                                $getTopicData['configuration']=$configuration;
                                //echo "ID ".$getBPcheckData['check_id']."\n";
                            }
                    }

                    if (($getTopicData['template_name']=="") AND ($getTopicData['template']=="0")){
                        $getTopicData['template']=$getTopicData['vsys'];
                        $getTopicData['template_name']=$getTopicData['vsys'];
                    }

                    #Test


                    $Data[]=$getTopicData;
                }

            }
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = count($Data);
    $message['msg'] = $Data;
    return $message;

}

function uncamelize($input, $separator = ' ')
{
    $lowercase=strtolower($input);
    return str_replace($separator, '_', $lowercase);
}

# Statistics
function list_bpat_radar($project){
    if(!checkProjectRights($project,'view')){
        $message = [
            'code' => true,
            'count' => 0,
            'msg' => array()
        ];
        return $message;
    }

    global $projectdb;
    $projectdb = selectDatabase($project);
    $Data=array();
    $chart=array();

    # high Availability
    $getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE '%high_availability%';");
    $userID=0;
    $ha=0;
    if ($getWF->num_rows > 0){
        $ids=array();
        while($getWFData=$getWF->fetch_assoc()){
            $ids[]=$getWFData['id'];
        }
        if (count($ids)>0){
            #Calc Fail
            $failed=0;
            $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $failed=$getFailData['fail'];
            }

            #Calc Pass
            $pass=0;
            $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $pass=$getFailData['pass'];
            }
            $totalWF=$failed+$pass;
            if ($totalWF!=0){
                $calc=($pass*100)/$totalWF;
            }
            else{
                $calc=0;
            }

            $ha=round($calc);
        }

    }
    $chart[]=array("topic" => "High Availability", "adoption" => $ha, "icon" => "xf021@FontAwesome");

    # Decryption
    $getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE '%decryption%';");
    $decryption=0;
    $calc=0;
    if ($getWF->num_rows > 0){
        $ids=array();
        while($getWFData=$getWF->fetch_assoc()){
            $ids[]=$getWFData['id'];
        }
        if (count($ids)>0){
            #Calc Fail
            $failed=0;
            $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $failed=$getFailData['fail'];
            }

            #Calc Pass
            $pass=0;
            $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $pass=$getFailData['pass'];
            }
            $totalWF=$failed+$pass;
            if ($totalWF!=0){
                $calc=($pass*100)/$totalWF;
            }
            else{
                $calc=0;
            }

            $decryption=round($calc);
        }

    }
    $chart[]=array("topic" => "Decryption", "adoption" => $decryption, "icon" => "xf021@FontAwesome");

    # Wildfire
    $getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE '%wildfire%';");
    $wildfire=0;
    $calc=0;
    if ($getWF->num_rows > 0){
        $ids=array();
        while($getWFData=$getWF->fetch_assoc()){
            $ids[]=$getWFData['id'];
        }
        if (count($ids)>0){
            #Calc Fail
            $failed=0;
            $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $failed=$getFailData['fail'];
            }

            #Calc Pass
            $pass=0;
            $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $pass=$getFailData['pass'];
            }
            $totalWF=$failed+$pass;
            if ($totalWF!=0){
                $calc=($pass*100)/$totalWF;
            }
            else{
                $calc=0;
            }

            $wildfire=round($calc);
        }
    }
    $chart[]=array("topic" => "Wildfire", "adoption" => $wildfire, "icon" => "");

    # Device Setup without Wildfire
    //$getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE 'device/%' AND xpath NOT LIKE '%dynamic_updates%' AND xpath NOT LIKE '%wildfire%';");
    $getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE 'device/%' ;");
    $deviceSetup=0;
    $calc=0;
    if ($getWF->num_rows > 0){
        $ids=array();
        while($getWFData=$getWF->fetch_assoc()){
            $ids[]=$getWFData['id'];
        }
        if (count($ids)>0){
            #Calc Fail
            $failed=0;
            $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $failed=$getFailData['fail'];
            }

            #Calc Pass
            $pass=0;
            $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $pass=$getFailData['pass'];
            }
            $totalWF=$failed+$pass;
            if ($totalWF!=0){
                $calc=($pass*100)/$totalWF;
            }
            else{
                $calc=0;
            }

            $deviceSetup=round($calc);
        }

    }
    $chart[]=array("topic" => "Device Setup", "adoption" => $deviceSetup, "icon" => "xf021@FontAwesome");

    # Security Policies
    $getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE '%security_rule%';");
    $security=0;
    $calc=0;
    if ($getWF->num_rows > 0){
        $ids=array();
        while($getWFData=$getWF->fetch_assoc()){
            $ids[]=$getWFData['id'];
        }
        if (count($ids)>0){
            #Calc Fail
            $failed=0;
            $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $failed=$getFailData['fail'];
            }

            #Calc Pass
            $pass=0;
            $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $pass=$getFailData['pass'];
            }
            $totalWF=$failed+$pass;
            if ($totalWF!=0){
                $calc=($pass*100)/$totalWF;
            }
            else{
                $calc=0;
            }
            $security=round($calc);
        }

    }
    $chart[]=array("topic" => "Security Policies", "adoption" => $security, "icon" => "xf021@FontAwesome");

    # Dynamic Updates
    $getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE '%dynamic_updates%';");
    $dynUpdates=0;
    $calc=0;
    if ($getWF->num_rows > 0){
        $ids=array();
        while($getWFData=$getWF->fetch_assoc()){
            $ids[]=$getWFData['id'];
        }
        if (count($ids)>0){
            #Calc Fail
            $failed=0;
            $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $failed=$getFailData['fail'];
            }

            #Calc Pass
            $pass=0;
            $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $pass=$getFailData['pass'];
            }
            $totalWF=$failed+$pass;
            if ($totalWF!=0){
                $calc=($pass*100)/$totalWF;
            }
            else{
                $calc=0;
            }
            $dynUpdates=round($calc);
        }

    }
    $chart[]=array("topic" => "Dynamic Updates", "adoption" => $dynUpdates, "icon" => "xf021@FontAwesome");

    # Security Profiles
    $getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE 'objects/%profiles%';");
    $secProfiles=0;
    $calc=0;
    if ($getWF->num_rows > 0){
        $ids=array();
        while($getWFData=$getWF->fetch_assoc()){
            $ids[]=$getWFData['id'];
        }
        if (count($ids)>0){
            #Calc Fail
            $failed=0;
            $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $failed=$getFailData['fail'];
            }

            #Calc Pass
            $pass=0;
            $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $pass=$getFailData['pass'];
            }
            $totalWF=$failed+$pass;
            if ($totalWF!=0){
                $calc=($pass*100)/$totalWF;
            }
            else{
                $calc=0;
            }

            $secProfiles=round($calc);
        }

    }
    $chart[]=array("topic" => "Security Profiles", "adoption" => $secProfiles, "icon" => "xf021@FontAwesome");

    # User Identification
    $getWF=$projectdb->query("SELECT id FROM bpat_topic WHERE timestamp in (SELECT MAX(timestamp) from bpat_topic) AND xpath LIKE '%user_identification%';");
    $userID=0;
    $calc=0;
    if ($getWF->num_rows > 0){
        $ids=array();
        while($getWFData=$getWF->fetch_assoc()){
            $ids[]=$getWFData['id'];
        }
        if (count($ids)>0){
            #Calc Fail
            $failed=0;
            $getFail=$projectdb->query("SELECT count(id) as fail FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='fail';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $failed=$getFailData['fail'];
            }

            #Calc Pass
            $pass=0;
            $getFail=$projectdb->query("SELECT count(id) as pass FROM bpat_bpcheck WHERE topic_id IN (".implode(',',$ids).") AND result='pass';");
            if ($getFail->num_rows==1){
                $getFailData=$getFail->fetch_assoc();
                $pass=$getFailData['pass'];
            }
            $totalWF=$failed+$pass;
            if ($totalWF!=0){
                $calc=($pass*100)/$totalWF;
            }
            else{
                $calc=0;
            }

            $userID=round($calc);
        }

    }
    $chart[]=array("topic" => "User Identification", "adoption" => $userID, "icon" => "xf021@FontAwesome");

    $message = array();
    $message['code'] = true;
    $message['count'] = count($chart);
    $message['msg'] = $chart;
    return $message;
}