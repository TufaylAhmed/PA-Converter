<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/device/device.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';

//require_once INC_ROOT.'/libs/common/xml/panosxml.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = $pandb->real_escape_string((string)(isset($_GET['type']) ? $_GET['type'] : ''));
}
$objfilter      = $pandb->real_escape_string((string) (isset($_GET['objfilter']) ? $_GET['objfilter'] : ''));
$objsearch      = $pandb->real_escape_string((string) (isset($_GET['objsearch']) ? $_GET['objsearch'] : ''));
$project        = $pandb->real_escape_string((string) (isset($_GET['project'])   ? $_GET['project'] : ''));
$action         = $pandb->real_escape_string((string) (isset($_GET['action'])    ? $_GET['action'] : ''));

$api_call       = $pandb->real_escape_string((string) (isset($_GET['api_call'])  ? $_GET['api_call'] : ''));
$modified       = $pandb->real_escape_string((string) (isset($_GET['modified'])  ? $_GET['modified'] : ''));
$device         = $pandb->real_escape_string((string) (isset($_GET['device'])    ? $_GET['device'] : ''));

$start       = $pandb->real_escape_string((string) (isset($_GET['start'])    ? $_GET['start'] : ''));
$limit       = $pandb->real_escape_string((string) (isset($_GET['limit'])    ? $_GET['limit'] : ''));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

#PHP VARS
ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit",PARSER_max_execution_memory);


switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = get_api_calls($project, $objfilter, $objsearch, '','',$start, $limit);

        if($message['code']){
            echo json_encode(["total" => $message['total'], "rows"  => $message['msg'], ]);
        }
        else{
            echo json_encode([ "total" => 0, "rows"  => '',]);
        }
        break;

    case 'POST':
//        $data = ['project'=>$_POST['project'], 'modified'=>$_POST['modified'], 'api_call' => $_POST['api_call']];
        $message = generate_api_calls($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = send_api_calls($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = detach_Key($devicename, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function generate_api_calls(ARRAY $data){
    global $projectdb;

    $project = $data['project'];
    $api_call = $data['api_call'];

    $projectdb= selectDatabase($project);

    $modified = $data['modified'];

    if (($modified == "") || ($modified == "Full config")) {
        $sql_modified = "";
    }
    elseif ($modified == "Only changes") {  //TODO: This should be applied only in subatomic calls
        $sql_modified = " AND modified = '1' ";
    }

    $projectdb->query("TRUNCATE TABLE output_mapping;");
    $getBC = $projectdb->query("SELECT id,ispanorama,version,filename FROM device_mapping WHERE active=1 AND baseconfig=1 GROUP BY filename;");
    if ($getBC->num_rows == 1) {

        $dataBC = $getBC->fetch_assoc();
        $version = $dataBC['version'];

        if (preg_match("/^6\.0/", $version)) {
            $version = 6;
        }
        elseif (preg_match("/^6\.1/", $version)) {
            $version = 6.1;
        }
        elseif (preg_match("/^5\./", $version)) {
            $version = 5;
        }
        elseif (preg_match("/^7\./", $version)) {
            $version = 7;
        }

        $ispanorama = $dataBC['ispanorama'];
        $filename = $dataBC['filename'];
        $source = $dataBC['id'];
        //$projectdb->query("TRUNCATE TABLE project_status;");
        update_progress($project, '0.00', 'Generating the Base Config');

        # Network
        if ($ispanorama == 0) {
            #DEviceConfig

            if ($api_call=="single"){
                # Login Banner
                $getBanner=$projectdb->query("SELECT xml FROM deviceconfig WHERE source='$source' AND template=0;");
                if ($getBanner->num_rows==1){
                    $getBannerData=$getBanner->fetch_assoc();

                    if ($getBannerData['xml']!=""){
                        $myBannerRaw=simplexml_load_string($getBannerData['xml']);
                        if (isset($myBannerRaw->system->{'login-banner'})){
                            $myBanner=$myBannerRaw->system->{'login-banner'}->asXML();
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/deviceconfig/system/login-banner";
                            $xml_final = addslashes($myBanner);
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Login Banner','DeviceConfig','deviceconfig','$xml_final','$xpath','edit');");
                        }
                        if (isset($myBannerRaw->setting->wildfire)){
                            $myBanner=$myBannerRaw->setting->wildfire->asXML();
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/deviceconfig/setting/wildfire";
                            $xml_final = addslashes($myBanner);
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Wildfire','DeviceConfig','deviceconfig','$xml_final','$xpath','edit');");
                        }
                        if (isset($myBannerRaw->setting->management)){
                            $myBanner=$myBannerRaw->setting->management->asXML();
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/deviceconfig/setting/management";
                            $xml_final = addslashes($myBanner);
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Management','DeviceConfig','deviceconfig','$xml_final','$xpath','edit');");
                        }
                    }
                }
            }
            else{
                $getBanner=$projectdb->query("SELECT xml FROM deviceconfig WHERE source='$source' AND template=0;");
                if ($getBanner->num_rows==1){
                    $getBannerData=$getBanner->fetch_assoc();
                    if ($getBannerData['xml']!=""){
                        $myBannerRaw=addslashes($getBannerData['xml']);
                        $myBanner=$myBannerRaw;
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/deviceconfig";
                        $xml_final = addslashes($myBanner);
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('DeviceConfig','DeviceConfig','deviceconfig','$xml_final','$xpath','edit');");
                    }
                }
            }


            # networking
            $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE source='$source';");
            if ($getTemplate->num_rows == 1) {
                $getTemplateData = $getTemplate->fetch_assoc();
                $template = $getTemplateData['id'];
            }
            if ($template != "") {
                #DHCP
                $getDHCP = $projectdb->query("SELECT name,dhcp_type,xml FROM dhcp WHERE source='$source' AND template='$template';");
                if ($getDHCP->num_rows > 0) {
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><dhcp></dhcp></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/dhcp");
                    $xml = $xml1[0];
                    $xml->addChild("interface");

                    while ($getDHCPData = $getDHCP->fetch_assoc()) {
                        $myname = $getDHCPData['name'];
                        $xmlfield = $getDHCPData['xml'];
                        $xml_append = simplexml_load_string($xmlfield);
                        $mgmprofile = $xml->interface;
                        if ($xml->interface->xpath("//entry[@name='$myname']") != null) {
                            add_log('warning', 'Exporting Schedules [' . $vsys . ']', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                        } else {
                            SimpleXMLElement_append($mgmprofile, $xml_append);
                        }
                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/dhcp/interface/entry[@name=\'$myname\']";
                            $xml_final = addslashes($mgmprofile->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','DHCP','dhcp','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/dhcp/interface";
                        $xml_final = addslashes($xml->interface->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('DHCP','dhcp','dhcp','$xml_final','$xpath','edit');");
                    }
                }


                # Monitor Profile
                $getMonitor = $projectdb->query("SELECT name,m_action,interva,threshold FROM monitor_profile WHERE source='$source' AND template='$template' AND name != '';");
                if ($getMonitor->num_rows >0){
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><profiles></profiles></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/profiles");
                    $xml = $xml1[0];
                    $xml->addChild("monitor-profile");

                    $MPXpath=$xml->{'monitor-profile'};
                    while ($getMonitorData=$getMonitor->fetch_assoc()){
                        $myname = $getMonitorData['name'];
                        $MPAction = $getMonitorData['m_action'];
                        $MPInterval = $getMonitorData['interva'];
                        $MPThreshold = $getMonitorData['threshold'];

                        if ($MPXpath->xpath("//entry[@name='$myname']") == null) {
                            $monitorProfile = $MPXpath->addChild('entry');
                            $monitorProfile->addAttribute('name', $getMonitorData['name']);
                            if (($MPInterval!=0) AND ($MPInterval!="")){
                                $monitorProfile->addChild("interval");
                                $monitorProfile->interval=$MPInterval;
                            }
                            if (($MPThreshold!=0) AND ($MPThreshold!="")){
                                $monitorProfile->addChild("threshold");
                                $monitorProfile->threshold=$MPThreshold;
                            }
                            if ($MPAction!=""){
                                $monitorProfile->addChild("action");
                                $monitorProfile->action=$MPAction;
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/profiles/monitor-profile/entry[@name=\'$myname\']";
                                $xml_final = addslashes($monitorProfile->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Monitor Profile','network_profiles','$xml_final','$xpath','edit');");
                            }
                        }

                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/profiles/monitor-profile";
                        $xml_final = addslashes($xml->{'monitor-profile'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Monitor Profile','network_profiles','network_profiles','$xml_final','$xpath','edit');");
                    }
                }


                # IKE CRYPTO

                $getIKECrypto = $projectdb->query("SELECT name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple FROM ike_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                if ($getIKECrypto->num_rows > 0){
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><ike><crypto-profiles></crypto-profiles></ike></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/ike/crypto-profiles");
                    $xml = $xml1[0];
                    $xml->addChild("ike-crypto-profiles");

                    $ike_crypto_xpath = $xml->{'ike-crypto-profiles'};
                    while ($dataIKEC = $getIKECrypto->fetch_assoc()){
                        $myname = $dataIKEC['name'];
                        $ike_encryption = $dataIKEC['encryption'];
                        $ike_hash = $dataIKEC['hash'];
                        $ike_dh_group = $dataIKEC['dh_group'];
                        $ike_seconds = $dataIKEC['seconds'];
                        $ike_minutes = $dataIKEC['minutes'];
                        $ike_hours = $dataIKEC['hours'];
                        $ike_days = $dataIKEC['days'];
                        $ike_authentication_multiple = $dataIKEC['authentication_multiple'];

                        if ($ike_crypto_xpath->xpath("//entry[@name='$myname']") == null) {

                            $ike_crypto = $ike_crypto_xpath->addChild('entry');
                            $ike_crypto->addAttribute('name', $dataIKEC['name']);

                            if ($ike_encryption != ""){
                                $ike_crypto->addChild("encryption");
                                $ike_encryption_array = explode(",", $ike_encryption);
                                foreach($ike_encryption_array as $member_ike){
                                    $ike_crypto->encryption->addChild("member", $member_ike);
                                }
                            }
                            if ($ike_hash != ""){
                                $ike_crypto->addChild("hash");
                                $ike_hash_array = explode(",", $ike_hash);
                                foreach($ike_hash_array as $member_ike){
                                    $ike_crypto->hash->addChild("member", $member_ike);
                                }
                            }
                            if ($ike_dh_group != ""){
                                $ike_crypto->addChild("dh-group");
                                $ike_dh_group_array = explode(",", $ike_dh_group);
                                foreach($ike_dh_group_array as $member_ike){
                                    $ike_crypto->{'dh-group'}->addChild("member", $member_ike);
                                }
                            }
                            if ($ike_seconds != 0){
                                $ike_crypto->addChild("lifetime");
                                $ike_crypto->{'lifetime'}->seconds = $ike_seconds;
                            }
                            if ($ike_minutes != 0){
                                $ike_crypto->addChild("lifetime");
                                $ike_crypto->{'lifetime'}->minutes = $ike_minutes;
                            }
                            if ($ike_hours != 0){
                                $ike_crypto->addChild("lifetime");
                                $ike_crypto->{'lifetime'}->hours = $ike_hours;
                            }
                            if ($ike_days != 0){
                                $ike_crypto->addChild("lifetime");
                                $ike_crypto->{'lifetime'}->days = $ike_days;
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name=\'$myname\']";
                                //$xml_final = addslashes($ike_crypto->asXML());
                                $xml_final = addslashes($xml->{'ike-crypto-profiles'}->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','IKE Crypto','network_profiles','$xml_final','$xpath','edit');");
                            }
                        }

                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/ike/crypto-profiles/ike-crypto-profiles";
                        $xml_final = addslashes($xml->{'ike-crypto-profiles'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('IKE Crypto','network_profiles','network_profiles','$xml_final','$xpath','edit');");
                    }
                }


                # IPSEC CRYPTO

                $getIPSECCrypto = $projectdb->query("SELECT name, encryption, hash, dh_group, protocol, seconds, minutes, hours, days, kb, mb, gb, tb FROM ipsec_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                if ($getIPSECCrypto->num_rows > 0){
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><ike><crypto-profiles></crypto-profiles></ike></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/ike/crypto-profiles");
                    $xml = $xml1[0];
                    $xml->addChild("ipsec-crypto-profiles");

                    $ipsec_crypto_xpath = $xml->{'ipsec-crypto-profiles'};

                    while ($dataIPSECC = $getIPSECCrypto->fetch_assoc()){
                        $myname = $dataIPSECC['name'];
                        $ipsec_encryption = $dataIPSECC['encryption'];
                        $ipsec_hash = $dataIPSECC['hash'];
                        $ipsec_dh_group = $dataIPSECC['dh_group'];
                        $ipsec_protocol = $dataIPSECC['protocol'];
                        $ipsec_seconds = $dataIPSECC['seconds'];
                        $ipsec_minutes = $dataIPSECC['minutes'];
                        $ipsec_hours = $dataIPSECC['hours'];
                        $ipsec_days = $dataIPSECC['days'];
                        $ipsec_kb = $dataIPSECC['kb'];
                        $ipsec_mb = $dataIPSECC['mb'];
                        $ipsec_gb = $dataIPSECC['gb'];
                        $ipsec_tb = $dataIPSECC['tb'];

                        if ($ipsec_crypto_xpath->xpath("//entry[@name='$myname']") == null) {

                            $ipsec_crypto = $ipsec_crypto_xpath->addChild('entry');
                            $ipsec_crypto->addAttribute('name', $dataIPSECC['name']);

                            if($ipsec_protocol == "ESP"){
                                $ipsec_crypto->addChild("esp");

                                if ($ipsec_encryption != ""){
                                    $ipsec_crypto->esp->addChild("encryption");
                                    $ipsec_encryption_array = explode(",", $ipsec_encryption);
                                    foreach($ipsec_encryption_array as $member_ike){
                                        $ipsec_crypto->esp->encryption->addChild("member", $member_ike);
                                    }
                                }
                                if ($ipsec_hash != ""){
                                    $ipsec_crypto->esp->addChild("authentication");
                                    $ipsec_hash_array = explode(",", $ipsec_hash);
                                    foreach($ipsec_hash_array as $member_ike){
                                        $ipsec_crypto->esp->authentication->addChild("member", $member_ike);
                                    }
                                }
                            }

                            if($ipsec_protocol == "AH"){
                                $ipsec_crypto->addChild("ah");

                                if ($ipsec_hash != ""){
                                    $ipsec_crypto->ah->addChild("authentication");
                                    $ipsec_hash_array = explode(",", $ipsec_hash);
                                    foreach($ipsec_hash_array as $member_ike){
                                        $ipsec_crypto->ah->authentication->addChild("member", $member_ike);
                                    }
                                }
                            }

                            if ($ipsec_dh_group != ""){
                                $ipsec_crypto->addChild("dh-group");
                                $ipsec_crypto->{'dh-group'} = $ipsec_dh_group;
                            }
                            if ($ipsec_seconds != 0){
                                $ipsec_crypto->addChild("lifetime");
                                $ipsec_crypto->{'lifetime'}->seconds = $ipsec_seconds;
                            }
                            if ($ipsec_minutes != 0){
                                $ipsec_crypto->addChild("lifetime");
                                $ipsec_crypto->{'lifetime'}->minutes = $ipsec_minutes;
                            }
                            if ($ipsec_hours != 0){
                                $ipsec_crypto->addChild("lifetime");
                                $ipsec_crypto->{'lifetime'}->hours = $ipsec_hours;
                            }
                            if ($ipsec_days != 0){
                                $ipsec_crypto->addChild("lifetime");
                                $ipsec_crypto->{'lifetime'}->days = $ipsec_days;
                            }

                            if ($ipsec_kb != 0){
                                $ipsec_crypto->addChild("lifesize");
                                $ipsec_crypto->{'lifesize'}->kb = $ipsec_kb;
                            }
                            if ($ipsec_mb != 0){
                                $ipsec_crypto->addChild("lifesize");
                                $ipsec_crypto->{'lifesize'}->mb = $ipsec_mb;
                            }
                            if ($ipsec_gb != 0){
                                $ipsec_crypto->addChild("lifesize");
                                $ipsec_crypto->{'lifesize'}->gb = $ipsec_gb;
                            }
                            if ($ipsec_tb != 0){
                                $ipsec_crypto->addChild("lifesize");
                                $ipsec_crypto->{'lifesize'}->tb = $ipsec_tb;
                            }

                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name=\'$myname\']";
                                //$xml_final = addslashes($ike_crypto->asXML());
                                $xml_final = addslashes($xml->{'ipsec-crypto-profiles'}->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','IPSEC Crypto','network_profiles','$xml_final','$xpath','edit');");
                            }
                        }

                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/ike/crypto-profiles/ipsec-crypto-profiles";
                        $xml_final = addslashes($xml->{'ipsec-crypto-profiles'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('IPSEC Crypto','network_profiles','network_profiles','$xml_final','$xpath','edit');");
                    }
                }

                # IKE GATEWAYS

                $getIKEGateways = $projectdb->query("SELECT name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, allow_id_payload_mismatch, local_certificate, certificate_profile, strict_validation_revocation, hash_and_url, base_url, nat_traversal, passive_mode, fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type  FROM ike_gateways_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                if ($getIKEGateways->num_rows > 0){
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><ike></ike></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/ike");
                    $xml = $xml1[0];
                    $xml->addChild("gateway");

                    $ike_gateways_xpath = $xml->{'gateway'};

                    while ($dataIKEGat = $getIKEGateways->fetch_assoc()){
                        $myname = $dataIKEGat['name'];
                        $ike_gat_version = $dataIKEGat['version'];
                        $ike_gat_dpd_ikev1 = $dataIKEGat['dpd_ikev1'];
                        $ike_gat_ike_interval_ikev1 = $dataIKEGat['ike_interval_ikev1'];
                        $ike_gat_retry_ikev1 = $dataIKEGat['retry_ikev1'];
                        $ike_gat_ike_crypto_profile_ikev1 = $dataIKEGat['ike_crypto_profile_ikev1'];
                        $ike_gat_exchange_mode_ikev1 = $dataIKEGat['exchange_mode_ikev1'];
                        $ike_gat_dpd_ikev2 = $dataIKEGat['dpd_ikev2'];
                        $ike_gat_ike_interval_ikev2 = $dataIKEGat['ike_interval_ikev2'];
                        $ike_gat_ike_crypto_profile_ikev2 = $dataIKEGat['ike_crypto_profile_ikev2'];
                        $ike_gat_require_cookie_ikev2 = $dataIKEGat['require_cookie_ikev2'];
                        $ike_gat_local_address_ip = $dataIKEGat['local_address_ip'];
                        $ike_gat_interface = $dataIKEGat['interface'];
                        $ike_gat_type_authentication = $dataIKEGat['type_authentication'];
                        $ike_gat_pre_shared_key = $dataIKEGat['pre_shared_key'];
                        $ike_gat_allow_id_payload_mismatch = $dataIKEGat['allow_id_payload_mismatch'];
                        $ike_gat_local_certificate = $dataIKEGat['local_certificate'];
                        $ike_gat_certificate_profile = $dataIKEGat['certificate_profile'];
                        $ike_gat_strict_validation_revocation = $dataIKEGat['strict_validation_revocation'];
                        $ike_gat_hash_and_url = $dataIKEGat['hash_and_url'];
                        $ike_gat_base_url = $dataIKEGat['base_url'];
                        $ike_gat_nat_traversal = $dataIKEGat['nat_traversal'];
                        $ike_gat_passive_mode = $dataIKEGat['passive_mode'];
                        $ike_gat_fragmentation = $dataIKEGat['fragmentation'];
                        $ike_gat_peer_ip_type = $dataIKEGat['peer_ip_type'];
                        $ike_gat_peer_ip_address = $dataIKEGat['peer_ip_address'];
                        $ike_gat_local_id = $dataIKEGat['local_id'];
                        $ike_gat_local_id_type = $dataIKEGat['local_id_type'];
                        $ike_gat_peer_id = $dataIKEGat['peer_id'];
                        $ike_gat_peer_id_type = $dataIKEGat['peer_id_type'];
                        $ike_gat_peer_id_matching = $dataIKEGat['peer_id_matching'];
                        $ike_gat_address_type = $dataIKEGat['address_type'];

                        if ($ike_gateways_xpath->xpath("//entry[@name='$myname']") == null) {

                            $ike_gateways = $ike_gateways_xpath->addChild('entry');
                            $ike_gateways->addAttribute('name', $dataIKEGat['name']);

                            if($ike_gat_dpd_ikev1 != ""){
                                $ike_gateways->addChild("protocol");
                                $ike_gateways->protocol->addChild("ikev1");
                                $ike_gateways->protocol->ikev1->addChild("dpd");
                                $ike_gateways->protocol->ikev1->dpd->enable = $ike_gat_dpd_ikev1;

                                if($ike_gat_dpd_ikev1 == "yes"){
                                    //$ike_gateways->protocol->ikev1->dpd->addChild("interval", $ike_gat_ike_interval_ikev1);
                                    $ike_gateways->protocol->ikev1->dpd->interval = $ike_gat_ike_interval_ikev1;
                                    $ike_gateways->protocol->ikev1->dpd->retry = $ike_gat_retry_ikev1;
                                }

                                if(($ike_gat_ike_crypto_profile_ikev1 != "") && ($ike_gat_ike_crypto_profile_ikev1 != "default")){
                                    $ike_gateways->protocol->ikev1->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev1;
                                }

                                if($ike_gat_exchange_mode_ikev1 != ""){
                                    $ike_gateways->protocol->ikev1->{'exchange-mode'} = $ike_gat_exchange_mode_ikev1;
                                }
                            }

                            // IKE V2 PARA LA VERSIÓN 7
                            if($version >= 7){
                                if($ike_gat_dpd_ikev2 != ""){

                                    $ike_gateways->protocol->ikev2->dpd->enable = $ike_gat_dpd_ikev2;
                                    $ike_gateways->protocol->ikev2->dpd->interval = $ike_gat_ike_interval_ikev2;

                                    if($ike_gat_ike_crypto_profile_ikev2 != ""){
                                        $ike_gateways->protocol->ikev2->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev2;
                                    }

                                    if($ike_gat_require_cookie_ikev2 != ""){
                                        $ike_gateways->protocol->ikev2->{'require-cookie'} = $ike_gat_require_cookie_ikev2;
                                    }

                                    if($ike_gat_version != ""){
                                        $ike_gateways->protocol->version = $ike_gat_version;
                                    }

                                }
                            }

                            if($ike_gat_interface != ""){
                                $ike_gateways->addChild("local-address");
                                $ike_gateways->{'local-address'}->interface = $ike_gat_interface;
                                if($ike_gat_local_address_ip != ""){
                                    $ike_gateways->{'local-address'}->ip = $ike_gat_local_address_ip;
                                }
                            }

                            $ike_gat_strict_validation_revocation = $dataIKEGat['strict_validation_revocation'];

                            if($ike_gat_type_authentication == "pre-shared-key"){
                                $ike_gateways->addChild("authentication");
                                $ike_gateways->authentication->{'pre-shared-key'}->key = $ike_gat_pre_shared_key;
                            }
                            elseif($ike_gat_type_authentication == "certificate"){

                                if($version < 7){

                                    $ike_gateways->addChild("authentication");

                                    if($ike_gat_allow_id_payload_mismatch == "yes"){
                                        $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                                    }
                                    $ike_gateways->authentication->certificate->{'local-certificate'} = $ike_gat_local_certificate;
                                    $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                                    if($ike_gat_strict_validation_revocation == "yes"){
                                        $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                                    }
                                }
                                else{
                                    // Version 7
                                    $ike_gateways->addChild("authentication");

                                    if($ike_gat_local_certificate != ""){
                                        $ike_gateways->authentication->certificate->{'local-certificate'}->name = $ike_gat_local_certificate;

                                        if($ike_gat_hash_and_url == "yes"){
                                            $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->enable = $ike_gat_hash_and_url;
                                            $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->{'base-url'} = $ike_gat_base_url;
                                        }
                                    }
                                    if($ike_gat_allow_id_payload_mismatch == "yes"){
                                        $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                                    }
                                    $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                                    if($ike_gat_strict_validation_revocation == "yes"){
                                        $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                                    }
                                }
                            }

                            if($ike_gat_nat_traversal != ""){
                                $ike_gateways->addChild("protocol-common");
                                $ike_gateways->{'protocol-common'}->{'nat-traversal'}->enable = $ike_gat_nat_traversal;
                                if($ike_gat_passive_mode == "yes"){
                                    $ike_gateways->{'protocol-common'}->{'passive-mode'} = $ike_gat_passive_mode;
                                }
                                if ($version > 5) {
                                    if($ike_gat_fragmentation == ""){
                                        $ike_gat_fragmentation = "no";
                                    }
                                    $ike_gateways->{'protocol-common'}->fragmentation->enable = $ike_gat_fragmentation;
                                }

                            }

                            if($ike_gat_peer_ip_type == "static"){
                                $ike_gateways->addChild("peer-address");
                                $ike_gateways->{'peer-address'}->ip = $ike_gat_peer_ip_address;
                            }else{
                                $ike_gateways->addChild("peer-address");
                                $ike_gateways->{'peer-address'}->addChild("dynamic");
                            }

                            if($ike_gat_local_id != ""){
                                $ike_gateways->addChild("local-id");
                                $ike_gateways->{'local-id'}->id = $ike_gat_local_id;
                                $ike_gateways->{'local-id'}->type = $ike_gat_local_id_type;
                            }

                            if($ike_gat_peer_id != ""){
                                $ike_gateways->addChild("peer-id");
                                $ike_gateways->{'peer-id'}->id = $ike_gat_peer_id;
                                $ike_gateways->{'peer-id'}->type = $ike_gat_peer_id_type;
                                if($ike_gat_peer_id_matching != ""){
                                    $ike_gateways->{'peer-id'}->matching = $ike_gat_peer_id_matching;
                                }
                            }

                            // Version 7
                            if($ike_gat_address_type == "ipv6"){
                                $ike_gateways->ipv6 = "yes";
                            }

                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/ike/gateway/entry[@name=\'$myname\']";
                                //$xml_final = addslashes($ike_crypto->asXML());
                                $xml_final = addslashes($xml->{'gateway'}->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','IKE Gateways','network_profiles','$xml_final','$xpath','edit');");
                            }
                        }

                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/ike/gateway";
                        $xml_final = addslashes($xml->{'gateway'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('IKE Gateways','network_profiles','network_profiles','$xml_final','$xpath','edit');");
                    }
                }

                # GLOBAL PROTECT IPSEC CRYPTO

                $getIKECrypto = $projectdb->query("SELECT name, encryption, hash FROM global_protect_app_ipsec_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                if ($getIKECrypto->num_rows > 0){
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><ike><crypto-profiles></crypto-profiles></ike></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/ike/crypto-profiles");
                    $xml = $xml1[0];
                    $xml->addChild("global-protect-app-crypto-profiles");

                    $ike_crypto_xpath = $xml->{'global-protect-app-crypto-profiles'};
                    while ($dataIKEC = $getIKECrypto->fetch_assoc()){
                        $myname = $dataIKEC['name'];
                        $ike_encryption = $dataIKEC['encryption'];
                        $ike_hash = $dataIKEC['hash'];

                        if ($ike_crypto_xpath->xpath("//entry[@name='$myname']") == null) {

                            $ike_crypto = $ike_crypto_xpath->addChild('entry');
                            $ike_crypto->addAttribute('name', $dataIKEC['name']);

                            if ($ike_encryption != ""){
                                $ike_crypto->addChild("encryption");
                                $ike_encryption_array = explode(",", $ike_encryption);
                                foreach($ike_encryption_array as $member_ike){
                                    $ike_crypto->encryption->addChild("member", $member_ike);
                                }
                            }
                            if ($ike_hash != ""){
                                $ike_crypto->addChild("authentication");
                                $ike_hash_array = explode(",", $ike_hash);
                                foreach($ike_hash_array as $member_ike){
                                    $ike_crypto->authentication->addChild("member", $member_ike);
                                }
                            }

                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/ike/crypto-profiles/global-protect-app-crypto-profiles/entry[@name=\'$myname\']";
                                //$xml_final = addslashes($ike_crypto->asXML());
                                $xml_final = addslashes($xml->{'global-protect-app-crypto-profiles'}->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','GlobalProtect IPSec Crypto','network_profiles','$xml_final','$xpath','edit');");
                            }
                        }

                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/ike/crypto-profiles/global-protect-app-crypto-profiles";
                        $xml_final = addslashes($xml->{'global-protect-app-crypto-profiles'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('GlobalProtect IPSec Crypto','network_profiles','network_profiles','$xml_final','$xpath','edit');");
                    }
                }

                # IPSEC TUNNEL

                $getIPSecTunnel = $projectdb->query("SELECT id, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, encryption, key_encry, local_address_ip, interface, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, local_certificate, publish_connected_routes, portal_address, publish_routes FROM ipsec_tunnel WHERE source = '$source' AND template = '$template' AND name != '';");
                if ($getIPSecTunnel->num_rows > 0){
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><tunnel></tunnel></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/tunnel");
                    $xml = $xml1[0];
                    $xml->addChild("ipsec");

                    $ike_ipsec_tunnel_xpath = $xml->{'ipsec'};

                    while ($dataIPSecTunnel = $getIPSecTunnel->fetch_assoc()){
                        $myname = $dataIPSecTunnel['name'];
                        $ipsec_tun_id = $dataIPSecTunnel['id'];
                        $ipsec_tun_anti_replay = $dataIPSecTunnel['anti_replay'];
                        $ipsec_tun_copy_tos = $dataIPSecTunnel['copy_tos'];
                        $ipsec_tun_tunnel_monitor = $dataIPSecTunnel['tunnel_monitor'];
                        $ipsec_tun_destination_ip = $dataIPSecTunnel['destination_ip'];
                        $ipsec_tun_tunnel_monitor_profile = $dataIPSecTunnel['tunnel_monitor_profile'];
                        $ipsec_tun_tunnel_interface = $dataIPSecTunnel['tunnel_interface'];
                        $ipsec_tun_address_type = $dataIPSecTunnel['address_type'];
                        $ipsec_tun_type_tunnel = $dataIPSecTunnel['type_tunnel'];
                        $ipsec_tun_ike_gateway = $dataIPSecTunnel['ike_gateway'];
                        $ipsec_tun_ipsec_crypto_profile = $dataIPSecTunnel['ipsec_crypto_profile'];
                        $ipsec_tun_protocol = $dataIPSecTunnel['protocol'];
                        $ipsec_tun_authentication = $dataIPSecTunnel['authentication'];
                        $ipsec_tun_key_auth = $dataIPSecTunnel['key_auth'];
                        $ipsec_tun_encryption = $dataIPSecTunnel['encryption'];
                        $ipsec_tun_key_encry = $dataIPSecTunnel['key_encry'];
                        $ipsec_tun_local_address_ip = $dataIPSecTunnel['local_address_ip'];
                        $ipsec_tun_interface = $dataIPSecTunnel['interface'];
                        $ipsec_tun_peer_ip_address = $dataIPSecTunnel['peer_ip_address'];
                        $ipsec_tun_local_spi = $dataIPSecTunnel['local_spi'];
                        $ipsec_tun_remote_spi = $dataIPSecTunnel['remote_spi'];
                        $ipsec_tun_external_ca = $dataIPSecTunnel['external_ca'];
                        $ipsec_tun_certificate_profile = $dataIPSecTunnel['certificate_profile'];
                        $ipsec_tun_local_certificate = $dataIPSecTunnel['local_certificate'];
                        $ipsec_tun_publish_connected_routes = $dataIPSecTunnel['publish_connected_routes'];
                        $ipsec_tun_portal_address = $dataIPSecTunnel['portal_address'];
                        $ipsec_tun_publish_routes = $dataIPSecTunnel['publish_routes'];

                        if ($ike_ipsec_tunnel_xpath->xpath("//entry[@name='$myname']") == null) {

                            $ipsec_tunnel = $ike_ipsec_tunnel_xpath->addChild('entry');
                            $ipsec_tunnel->addAttribute('name', $dataIPSecTunnel['name']);

                            # Auto Key
                            if($ipsec_tun_type_tunnel == "auto-key"){

                                $ipsec_tunnel->addChild("auto-key");

                                if($ipsec_tun_ike_gateway != ""){
                                    $ipsec_tunnel->{'auto-key'}->addChild("ike-gateway");
                                    $ipsec_tunnel->{'auto-key'}->{'ike-gateway'}->addChild('entry')->addAttribute('name', $ipsec_tun_ike_gateway);
                                }

                                // Mirar si hay Proxy ID type = v4
                                $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v4' AND template = '$template' AND source = '$source';");
                                if ($getProxyID->num_rows > 0){

                                    $ipsec_tunnel->{'auto-key'}->addChild("proxy-id");
                                    $ike_ipsec_tunnel_xpath_proxy_id = $ipsec_tunnel->{'auto-key'}->{'proxy-id'};

                                    while($dataPI = $getProxyID->fetch_assoc()){

                                        $name_proxy_id = $dataPI['name'];
                                        $protocol_proxy_id = $dataPI['protocol'];
                                        $local_port_proxy_id = $dataPI['local_port'];
                                        $remote_port_proxy_id = $dataPI['remote_port'];
                                        $number_proxy_id = $dataPI['number'];
                                        $local_proxy_id = $dataPI['local'];
                                        $remote_proxy_id = $dataPI['remote'];
                                        $type_proxy_id = $dataPI['type'];

                                        $ipsec_tunnel_proxy_id = $ike_ipsec_tunnel_xpath_proxy_id->addChild('entry');
                                        $ipsec_tunnel_proxy_id->addAttribute('name', $name_proxy_id);

                                        if ($protocol_proxy_id == "TCP"){
                                            $ipsec_tunnel_proxy_id->addChild("protocol");
                                            $ipsec_tunnel_proxy_id->protocol->addChild("tcp");
                                            //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                                            if($local_port_proxy_id == ""){
                                                $local_port_proxy_id = 0;
                                            }
                                            if($remote_port_proxy_id == ""){
                                                $remote_port_proxy_id = 0;
                                            }
                                            $ipsec_tunnel_proxy_id->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                                            $ipsec_tunnel_proxy_id->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                                        }
                                        elseif($protocol_proxy_id == "Number"){
                                            $ipsec_tunnel_proxy_id->addChild("protocol");
                                            $ipsec_tunnel_proxy_id->protocol->addChild("number");
                                            $ipsec_tunnel_proxy_id->protocol->number = $number_proxy_id;
                                        }
                                        elseif($protocol_proxy_id == "Any"){
                                            $ipsec_tunnel_proxy_id->addChild("protocol");
                                            $ipsec_tunnel_proxy_id->protocol->addChild("any");;
                                        }
                                        elseif($protocol_proxy_id == "UDP"){
                                            $ipsec_tunnel_proxy_id->addChild("protocol");
                                            $ipsec_tunnel_proxy_id->protocol->addChild("udp");
                                            if($local_port_proxy_id == ""){
                                                $local_port_proxy_id = 0;
                                            }
                                            if($remote_port_proxy_id == ""){
                                                $remote_port_proxy_id = 0;
                                            }
                                            $ipsec_tunnel_proxy_id->protocol->udp->{'local-port'} = $local_port_proxy_id;
                                            $ipsec_tunnel_proxy_id->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                                        }

                                        if($local_proxy_id != ""){
                                            $ipsec_tunnel_proxy_id->addChild("local");
                                            $ipsec_tunnel_proxy_id->local = $local_proxy_id;
                                        }
                                        if($remote_proxy_id != ""){
                                            $ipsec_tunnel_proxy_id->addChild("remote");
                                            $ipsec_tunnel_proxy_id->remote = $remote_proxy_id;
                                        }
                                    }
                                }

                                // Mirar si hay Proxy ID type = v6
                                $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v6' AND template = '$template' AND source = '$source';");
                                if ($getProxyID->num_rows > 0){

                                    $ipsec_tunnel->{'auto-key'}->addChild("proxy-id-v6");
                                    $ike_ipsec_tunnel_xpath_proxy_id_v6 = $ipsec_tunnel->{'auto-key'}->{'proxy-id-v6'};

                                    while($dataPI = $getProxyID->fetch_assoc()){

                                        $name_proxy_id = $dataPI['name'];
                                        $protocol_proxy_id = $dataPI['protocol'];
                                        $local_port_proxy_id = $dataPI['local_port'];
                                        $remote_port_proxy_id = $dataPI['remote_port'];
                                        $number_proxy_id = $dataPI['number'];
                                        $local_proxy_id = $dataPI['local'];
                                        $remote_proxy_id = $dataPI['remote'];
                                        $type_proxy_id = $dataPI['type'];

                                        $ipsec_tunnel_proxy_id_v6 = $ike_ipsec_tunnel_xpath_proxy_id_v6->addChild('entry');
                                        $ipsec_tunnel_proxy_id_v6->addAttribute('name', $name_proxy_id);

                                        if ($protocol_proxy_id == "TCP"){
                                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("tcp");
                                            //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                                            if($local_port_proxy_id == ""){
                                                $local_port_proxy_id = 0;
                                            }
                                            if($remote_port_proxy_id == ""){
                                                $remote_port_proxy_id = 0;
                                            }
                                            $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                                            $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                                        }
                                        elseif($protocol_proxy_id == "Number"){
                                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("number");
                                            $ipsec_tunnel_proxy_id_v6->protocol->number = $number_proxy_id;
                                        }
                                        elseif($protocol_proxy_id == "Any"){
                                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("any");;
                                        }
                                        elseif($protocol_proxy_id == "UDP"){
                                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("udp");
                                            if($local_port_proxy_id == ""){
                                                $local_port_proxy_id = 0;
                                            }
                                            if($remote_port_proxy_id == ""){
                                                $remote_port_proxy_id = 0;
                                            }
                                            $ipsec_tunnel_proxy_id_v6->protocol->udp->{'local-port'} = $local_port_proxy_id;
                                            $ipsec_tunnel_proxy_id_v6->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                                        }

                                        if($local_proxy_id != ""){
                                            $ipsec_tunnel_proxy_id_v6->addChild("local");
                                            $ipsec_tunnel_proxy_id_v6->local = $local_proxy_id;
                                        }
                                        if($remote_proxy_id != ""){
                                            $ipsec_tunnel_proxy_id_v6->addChild("remote");
                                            $ipsec_tunnel_proxy_id_v6->remote = $remote_proxy_id;
                                        }
                                    }
                                }

                                if($ipsec_tun_ipsec_crypto_profile != ""){
                                    $ipsec_tunnel->{'auto-key'}->addChild("ipsec-crypto-profile");
                                    $ipsec_tunnel->{'auto-key'}->{'ipsec-crypto-profile'} = $ipsec_tun_ipsec_crypto_profile;
                                }
                            } # Manual Key
                            elseif ($ipsec_tun_type_tunnel == "manual-key"){

                                $ipsec_tunnel->addChild("manual-key");

                                if($ipsec_tun_protocol == "ESP"){

                                    $ipsec_tunnel->{'manual-key'}->addChild("esp");

                                    if($ipsec_tun_authentication == "none"){
                                        $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                                        $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild("none");
                                    }else{
                                        //authentication->md5->key
                                        $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                                        $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild($ipsec_tun_authentication);
                                        $ipsec_tunnel->{'manual-key'}->esp->authentication->{$ipsec_tun_authentication}->key = $ipsec_tun_key_auth;
                                    }

                                    if($ipsec_tun_encryption != ""){
                                        $ipsec_tunnel->{'manual-key'}->esp->addChild("encryption");
                                        $ipsec_tunnel->{'manual-key'}->esp->encryption->algorithm = $ipsec_tun_encryption;

                                        if($ipsec_tun_key_encry != ""){
                                            $ipsec_tunnel->{'manual-key'}->esp->encryption->key = $ipsec_tun_key_encry;
                                        }
                                    }
                                }

                                if($ipsec_tun_protocol == "AH"){

                                    $ipsec_tunnel->{'manual-key'}->addChild("ah");

                                    if($ipsec_tun_authentication == "none"){
                                        $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                                        $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild("none");
                                    }else{
                                        //authentication->md5->key
                                        $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                                        $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild($ipsec_tun_authentication);
                                        $ipsec_tunnel->{'manual-key'}->ah->authentication->{$ipsec_tun_authentication}->key = $ipsec_tun_key_auth;
                                    }
                                }

                                if($ipsec_tun_interface != ""){
                                    $ipsec_tunnel->{'manual-key'}->addChild("local-address");
                                    if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                                        $ipsec_tunnel->{'manual-key'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                                    }
                                    $ipsec_tunnel->{'manual-key'}->{'local-address'}->interface = $ipsec_tun_interface;
                                }

                                if($ipsec_tun_peer_ip_address != ""){
                                    $ipsec_tunnel->{'manual-key'}->addChild("peer-address");
                                    $ipsec_tunnel->{'manual-key'}->{'peer-address'}->ip = $ipsec_tun_peer_ip_address;
                                }

                                if($ipsec_tun_local_spi != ""){
                                    $ipsec_tunnel->{'manual-key'}->{'local-spi'} = $ipsec_tun_local_spi;
                                }

                                if($ipsec_tun_remote_spi != ""){
                                    $ipsec_tunnel->{'manual-key'}->{'remote-spi'} = $ipsec_tun_remote_spi;
                                }

                            } # Global Protect Satellite
                            elseif ($ipsec_tun_type_tunnel == "global-protect-satellite"){

                                $ipsec_tunnel->addChild("global-protect-satellite");

                                if($ipsec_tun_publish_connected_routes == "yes"){
                                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-connected-routes");
                                    $ipsec_tunnel->{'global-protect-satellite'}->{'publish-connected-routes'}->enable = $ipsec_tun_publish_connected_routes;
                                }

                                if($ipsec_tun_interface != ""){
                                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("local-address");
                                    if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                                        $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                                    }
                                    $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->interface = $ipsec_tun_interface;
                                }

                                if($ipsec_tun_portal_address != ""){
                                    $ipsec_tunnel->{'global-protect-satellite'}->{'portal-address'} = $ipsec_tun_portal_address;
                                }

                                if($ipsec_tun_publish_routes != ""){
                                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-routes");
                                    $ipsec_tun_publish_routes_array = explode(",", $ipsec_tun_publish_routes);
                                    foreach($ipsec_tun_publish_routes_array as $member_publish){
                                        $ipsec_tunnel->{'global-protect-satellite'}->{'publish-routes'}->addChild("member", $member_publish);
                                    }
                                }

                                if($ipsec_tun_external_ca == "yes"){
                                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("external-ca");
                                    if($ipsec_tun_certificate_profile != ""){
                                        $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'certificate-profile'} = $ipsec_tun_certificate_profile;
                                    }
                                    if($ipsec_tun_local_certificate != ""){
                                        $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'local-certificate'} = $ipsec_tun_local_certificate;
                                    }
                                }

                            }

                            if($ipsec_tun_tunnel_monitor != ""){
                                $ipsec_tunnel->addChild("tunnel-monitor");
                                $ipsec_tunnel->{'tunnel-monitor'}->enable = $ipsec_tun_tunnel_monitor;

                                if($ipsec_tun_destination_ip != ""){
                                    $ipsec_tunnel->{'tunnel-monitor'}->{'destination-ip'} = $ipsec_tun_destination_ip;
                                }

                                if($ipsec_tun_tunnel_monitor_profile != ""){
                                    $ipsec_tunnel->{'tunnel-monitor'}->{'tunnel-monitor-profile'} = $ipsec_tun_tunnel_monitor_profile;
                                }
                            }

                            if($ipsec_tun_copy_tos == "yes"){
                                $ipsec_tunnel->{'copy-tos'} = $ipsec_tun_copy_tos;
                            }

                            // Version 7
                            if($ipsec_tun_address_type == "ipv6"){
                                $ipsec_tunnel->ipv6 = "yes";
                            }

                            if($ipsec_tun_tunnel_interface != ""){
                                $ipsec_tunnel->{'tunnel-interface'} = $ipsec_tun_tunnel_interface;
                            }

                            if($ipsec_tun_anti_replay == "yes"){
                                $ipsec_tunnel->{'anti-replay'} = $ipsec_tun_anti_replay;
                            }

                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/tunnel/ipsec/entry[@name=\'$myname\']";
                                //$xml_final = addslashes($ike_crypto->asXML());
                                $xml_final = addslashes($xml->{'ipsec'}->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','IPSec Tunnels','network_profiles','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/tunnel/ipsec";
                        $xml_final = addslashes($xml->{'ipsec'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('IPSec Tunnels','network_profiles','network_profiles','$xml_final','$xpath','edit');");
                    }
                }


                # management Profiles
                $getMP = $projectdb->query("SELECT name,permitted_ip,http,https,http_ocsp,ssh,snmp,userid_service,userid_syslog_listener_ssl,userid_syslog_listener_udp,ping,response_pages,telnet FROM interface_management_profile WHERE source='$source' AND template='$template' AND name != '' $sql_modified;");
                if ($getMP->num_rows > 0) {
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><profiles></profiles></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/profiles");
                    $xml = $xml1[0];
                    $xml->addChild("interface-management-profile");
                    while ($getMPData = $getMP->fetch_assoc()) {
                        $myname = $getMPData['name'];
                        $mgmprofile = $xml->{'interface-management-profile'}->addChild('entry');
                        $mgmprofile->addAttribute('name', $myname);

                        if ($getMPData['http'] != "") {
                            $mgmprofile->addChild("http", $getMPData['http']);
                        }
                        if ($getMPData['https'] != "") {
                            $mgmprofile->addChild("https", $getMPData['https']);
                        }
                        if ($getMPData['http_ocsp'] != "") {
                            $mgmprofile->addChild("http-ocsp", $getMPData['http_ocsp']);
                        }
                        if ($getMPData['ssh'] != "") {
                            $mgmprofile->addChild("ssh", $getMPData['ssh']);
                        }
                        if ($getMPData['snmp'] != "") {
                            $mgmprofile->addChild("snmp", $getMPData['snmp']);
                        }
                        if ($getMPData['userid_service'] != "") {
                            $mgmprofile->addChild("userid-service", $getMPData['userid_service']);
                        }
                        if ($getMPData['ping'] != "") {
                            $mgmprofile->addChild("ping", $getMPData['ping']);
                        }
                        if ($getMPData['telnet'] != "") {
                            $mgmprofile->addChild("telnet", $getMPData['telnet']);
                        }
                        if ($getMPData['response_pages'] != "") {
                            $mgmprofile->addChild("response-pages", $getMPData['response_pages']);
                        }
                        if ($version > 5) {
                            if ($getMPData['userid_syslog_listener_ssl'] != "") {
                                $mgmprofile->addChild("userid-syslog-listener-ssl", $getMPData['userid_syslog_listener_ssl']);
                            }
                            if ($getMPData['userid_syslog_listener_udp'] != "") {
                                $mgmprofile->addChild("userid-syslog-listener-udp", $getMPData['userid_syslog_listener_udp']);
                            }
                        }
                        if ($getMPData['permitted_ip'] != "") {
                            $interfaces_all = explode(",", $getMPData['permitted_ip']);
                            $mgmprofile->addChild("permitted-ip");
                            foreach ($interfaces_all as $key => $int_value) {
                                $newInt = $mgmprofile->{'permitted-ip'}->addChild("entry");
                                $newInt->addAttribute('name', $int_value);
                            }
                        }
                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/profiles/interface-management-profile/entry[@name=\'$myname\']";
                            $xml_final = addslashes($mgmprofile->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Interface Mgmt','network_profiles','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/profiles/interface-management-profile";
                        $xml_final = addslashes($xml->{'interface-management-profile'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Interface Mgmt','network_profiles','network_profiles','$xml_final','$xpath','edit');");
                    }
                }

                #Interfaces
                $getInterfaces = $projectdb->query("SELECT id FROM interfaces WHERE template='$template' AND source='$source' $sql_modified;");
                if ($getInterfaces->num_rows > 0) {
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><interface></interface></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/interface");
                    $xml = $xml1[0];


                    #Aggregate-Ethernet
                    $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND name=unitname GROUP BY name ORDER BY name");
                    if ($getIntEthernet->num_rows > 0) {
                        $xml->addChild("aggregate-ethernet");
                        while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                            $myname = $getIntEthernetData['name'];
                            $int2 = $xml->{'aggregate-ethernet'}->addChild('entry');
                            $int2->addAttribute('name', $myname);

                            if ($getIntEthernetData['comment'] != "") {
                                $int2->addChild("comment");
                                $int2->comment = $getIntEthernetData['comment'];
                            }

                            if ($getIntEthernetData['type'] == "virtual-wire") {
                                $int2->addChild("virtual-wire");
                                if ($getIntEthernetData['netflow_profile'] != "") {
                                    $int2->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                }
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                if ($getUnits->num_rows > 0) {
                                    $int2->{'virtual-wire'}->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $VWUnit = $int2->{'virtual-wire'}->units->addChild('entry');
                                        $VWUnit->addAttribute('name', $myname1);
                                        if ($getUnitsData['comment'] != "") {
                                            $VWUnit->addChild("comment");
                                            $VWUnit->comment = $getUnitsData['comment'];
                                        }
                                        if ($getUnitsData['netflow_profile'] != "") {
                                            $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                        }

                                        $VWUnit->addChild("tag", $getUnitsData['unittag']);

                                        if ($getUnitsData['ip_classifier'] != "") {
                                            $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                            $VWUnit->addChild("ip-classifier");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                            }
                                        }
                                    }
                                }
                            }
                            if ($getIntEthernetData['type'] == "layer2") {
                                $int2->addChild("layer2");
                                if ($getIntEthernetData['netflow_profile'] != "") {
                                    $int2->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                }
                                if ($version>=7){
                                    if ($getIntEthernetData['lldp'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                        SimpleXMLElement_append($int2->layer2, $xml_append);
                                    }
                                }
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                if ($getUnits->num_rows > 0) {
                                    $int2->{'layer2'}->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $VWUnit = $int2->{'layer2'}->units->addChild('entry');
                                        $VWUnit->addAttribute('name', $myname1);
                                        if ($getUnitsData['netflow_profile'] != "") {
                                            $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                        }
                                        if ($getUnitsData['comment'] != "") {
                                            $VWUnit->addChild("comment");
                                            $VWUnit->comment = $getUnitsData['comment'];
                                        }
                                        $VWUnit->addChild("tag", $getUnitsData['unittag']);
                                    }
                                }
                            }
                            elseif ($getIntEthernetData['type'] == "ha") {
                                $int2->addChild("ha");
                            }
                            elseif ($getIntEthernetData['type'] == "layer3") {
                                $int2->addChild("layer3");
                                if ($getIntEthernetData['netflow_profile'] != "") {
                                    $int2->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                }
                                if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                    $int2->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                                }
                                if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                    $int2->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                }

                                if ($getIntEthernetData['untagged_sub_interface'] != "") {
                                    $int2->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                                }
                                if ($getIntEthernetData['arp'] != "") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                    SimpleXMLElement_append($int2->layer3, $xml_append);
                                }
                                if ($version>=7){
                                    if ($getIntEthernetData['lldp'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                        SimpleXMLElement_append($int2->layer3, $xml_append);
                                    }
                                    if ($getIntEthernetData['ndpproxy'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                        SimpleXMLElement_append($int2->layer3, $xml_append);
                                    }
                                }

                                if ($getIntEthernetData['ipv4_type'] == "static") {
                                    if ($getIntEthernetData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                        SimpleXMLElement_append($int2->layer3, $xml_append);
                                    }
                                    if ($getIntEthernetData['unitipaddress'] != "") {
                                        $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                        $int2->layer3->addChild("ip");
                                        foreach ($interfaces_all as $key => $int_value) {
                                            $newInt = $int2->layer3->ip->addChild("entry");
                                            $newInt->addAttribute('name', $int_value);
                                        }
                                    }
                                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                        $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                    }
                                }
                                elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                    $int2->layer3->addChild("dhcp-client");
                                    if ($getIntEthernetData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                        SimpleXMLElement_append($int2->layer3, $xml_append);
                                    }
                                    if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                        $int2->layer3->{"dhcp-client"}->addChild("enable", "no");
                                    }
                                    if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                        $int2->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                    }
                                    if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                        $int2->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                                    }
                                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                        $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                    }
                                }
                                # UNITS
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                if ($getUnits->num_rows > 0) {
                                    $unit = $int2->layer3->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $UnitInt = $unit->addChild('entry');
                                        $UnitInt->addAttribute('name', $myname1);
                                        if ($getUnitsData['netflow_profile'] != "") {
                                            $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                        }
                                        if ($getUnitsData['unittag']!=0){
                                            $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                        }
                                        if ($getUnitsData['comment'] != "") {
                                            $UnitInt->addChild("comment");
                                            $UnitInt->comment = $getUnitsData['comment'];
                                        }
                                        if ($version>=7){
                                            if ($getUnitsData['ndpproxy'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['ndpproxy']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                        }
                                        if ($getUnitsData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                        }
                                        if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                            $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                        }
                                        if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                            $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                        }
                                        if ($getUnitsData['adjust_tcp_mss'] != "") {
                                            $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                        }
                                        if ($getUnitsData['arp'] != "") {
                                            $xml_append = simplexml_load_string($getUnitsData['arp']);
                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                        }
                                        if ($getUnitsData['ipv4_type'] == "static") {
                                            if ($getUnitsData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                $UnitInt->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $UnitInt->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                        } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                            $UnitInt->addChild("dhcp-client");

                                            if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                            }
                                            if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                            }
                                            if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                            }
                                        }
                                    }
                                }
                            }
                            elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                                $int2->addChild("decrypt-mirror");
                            }
                            if ($getIntEthernetData['lacp'] != "") {
                                $xml_append = simplexml_load_string($getIntEthernetData['lacp']);
                                SimpleXMLElement_append($int2->{$getIntEthernetData['type']}, $xml_append);
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/interface/aggregate-ethernet/entry[@name=\'$myname\']";
                                $xml_final = addslashes($int2->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','aggregate-ethernet','interfaces','$xml_final','$xpath','edit');");
                            }
                        }
                        if ($api_call == "atomic") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/interface/aggregate-ethernet";
                            $xml_final = addslashes($xml->{'aggregate-ethernet'}->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('aggregate-ethernet','aggregate-ethernet','interfaces','$xml_final','$xpath','edit');");
                        }
                    }
                    #Ethernet
                    $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unittag='0' AND unitname=name $sql_modified GROUP BY name ORDER BY name");
                    if ($getIntEthernet->num_rows > 0) {
                        $xml->addChild("ethernet");
                        while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                            $myname = $getIntEthernetData['name'];
                            $int = $xml->ethernet->addChild('entry');
                            $int->addAttribute('name', $myname);

                            if ($version>=7){
                                if ($getIntEthernetData['link_speed'] != "") {
                                    $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                                }
                                if ($getIntEthernetData['link_duplex'] != "") {
                                    $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                                }
                                if ($getIntEthernetData['link_state'] != "")  {
                                    $int->addChild("link-state", $getIntEthernetData['link_state']);
                                }
                            }
                            else{
                                if (($getIntEthernetData['link_speed'] != "") AND ( $getIntEthernetData['link_speed'] != "auto")) {
                                    $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                                }
                                if (($getIntEthernetData['link_duplex'] != "") AND ( $getIntEthernetData['link_duplex'] != "auto")) {
                                    $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                                }
                                if (($getIntEthernetData['link_state'] != "") AND ( $getIntEthernetData['link_state'] != "auto")) {
                                    $int->addChild("link-state", $getIntEthernetData['link_state']);
                                }
                            }

                            if ($getIntEthernetData['comment'] != "") {
                                $int->addChild("comment");
                                $int->comment = $getIntEthernetData['comment'];
                            }
                            if ($getIntEthernetData['type'] == "tap") {
                                $int->addChild("tap");
                                if ($getIntEthernetData['netflow_profile'] != "") {
                                    $int->tap->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                }
                            }
                            if ($getIntEthernetData['type'] == "virtual-wire") {
                                $int->addChild("virtual-wire");
                                if ($getIntEthernetData['netflow_profile'] != "") {
                                    $int->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                }
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname' $sql_modified;");
                                if ($getUnits->num_rows > 0) {
                                    $int->{'virtual-wire'}->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $VWUnit = $int->{'virtual-wire'}->units->addChild('entry');
                                        $VWUnit->addAttribute('name', $myname1);
                                        if ($getUnitsData['comment'] != "") {
                                            $VWUnit->addChild("comment");
                                            $VWUnit->comment = $getUnitsData['comment'];
                                        }
                                        if ($getUnitsData['netflow_profile'] != "") {
                                            $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                        }

                                        $VWUnit->addChild("tag", $getUnitsData['unittag']);

                                        if ($getUnitsData['ip_classifier'] != "") {
                                            $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                            $VWUnit->addChild("ip-classifier");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                            }
                                        }
                                    }
                                }
                            }
                            if ($getIntEthernetData['type'] == "layer2") {
                                $int->addChild("layer2");
                                if ($getIntEthernetData['netflow_profile'] != "") {
                                    $int->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                }
                                if ($version>=7){
                                    if ($getIntEthernetData['lldp'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                        SimpleXMLElement_append($int->layer2, $xml_append);
                                    }
                                }
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname' $sql_modified;");
                                if ($getUnits->num_rows > 0) {
                                    $int->{'layer2'}->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $VWUnit = $int->{'layer2'}->units->addChild('entry');
                                        $VWUnit->addAttribute('name', $myname1);
                                        if ($getUnitsData['netflow_profile'] != "") {
                                            $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                        }
                                        if ($getUnitsData['comment'] != "") {
                                            $VWUnit->addChild("comment");
                                            $VWUnit->comment = $getUnitsData['comment'];
                                        }
                                        $VWUnit->addChild("tag", $getUnitsData['unittag']);
                                    }
                                }
                            }
                            elseif ($getIntEthernetData['type'] == "ha") {
                                $int->addChild("ha");
                            }
                            elseif ($getIntEthernetData['type'] == "layer3") {
                                $int->addChild("layer3");
                                if ($getIntEthernetData['netflow_profile'] != "") {
                                    $int->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                }
                                if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                    $int->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                                }
                                if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                    $int->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                }

                                if ($getIntEthernetData['untagged_sub_interface'] != "") {
                                    $int->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                                }
                                if ($getIntEthernetData['arp'] != "") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                    SimpleXMLElement_append($int->layer3, $xml_append);
                                }
                                if ($version>=7){
                                    if ($getIntEthernetData['lldp'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                        SimpleXMLElement_append($int->layer3, $xml_append);
                                    }
                                    if ($getIntEthernetData['ndpproxy'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                        SimpleXMLElement_append($int->layer3, $xml_append);
                                    }
                                }
                                if ($getIntEthernetData['ipv4_type'] == "static") {
                                    if ($getIntEthernetData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                        SimpleXMLElement_append($int->layer3, $xml_append);
                                    }
                                    if ($getIntEthernetData['unitipaddress'] != "") {
                                        $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                        $int->layer3->addChild("ip");
                                        foreach ($interfaces_all as $key => $int_value) {
                                            $newInt = $int->layer3->ip->addChild("entry");
                                            $newInt->addAttribute('name', $int_value);
                                        }
                                    }
                                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                        $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                    }
                                }
                                elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                    $int->layer3->addChild("dhcp-client");
                                    if ($getIntEthernetData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                        SimpleXMLElement_append($int->layer3, $xml_append);
                                    }
                                    if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                        $int->layer3->{"dhcp-client"}->addChild("enable", "no");
                                    }
                                    if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                        $int->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                    }
                                    if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                        $int->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                                    }
                                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                        $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                    }
                                }
                                # UNITS
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname' $sql_modified;");
                                if ($getUnits->num_rows > 0) {
                                    $unit = $int->layer3->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $UnitInt = $unit->addChild('entry');
                                        $UnitInt->addAttribute('name', $myname1);
                                        if ($getUnitsData['netflow_profile'] != "") {
                                            $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                        }
                                        if ($getUnitsData['unittag']!=0){
                                            $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                        }
                                        if ($getUnitsData['comment'] != "") {
                                            $UnitInt->addChild("comment");
                                            $UnitInt->comment = $getUnitsData['comment'];
                                        }
                                        if ($version>=7){
                                            if ($getUnitsData['ndpproxy'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['ndpproxy']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                        }
                                        if ($getUnitsData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                        }
                                        if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                            $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                        }
                                        if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                            $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                        }
                                        if ($getUnitsData['adjust_tcp_mss'] != "") {
                                            $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                        }
                                        if ($getUnitsData['arp'] != "") {
                                            $xml_append = simplexml_load_string($getUnitsData['arp']);
                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                        }
                                        if ($getUnitsData['ipv4_type'] == "static") {
                                            if ($getUnitsData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                $UnitInt->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $UnitInt->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                        } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                            $UnitInt->addChild("dhcp-client");

                                            if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                            }
                                            if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                            }
                                            if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                            }
                                        }
                                    }
                                }
                            }
                            elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                                $int->addChild("decrypt-mirror");
                            }
                            if ($getIntEthernetData['type'] == "log-card") {
                                $xml_append = simplexml_load_string($getIntEthernetData['log_card']);
                                SimpleXMLElement_append($int, $xml_append);
                            }
                            if ($getIntEthernetData['type'] == "aggregate-group"){
                                $int->addChild("aggregate-group",$getIntEthernetData['aggregate_group']);
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/interface/ethernet/entry[@name=\'$myname\']";
                                $xml_final = addslashes($int->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','ethernet','interfaces','$xml_final','$xpath','edit');");
                            }
                        }
                        if ($api_call == "atomic") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/interface/ethernet";
                            $xml_final = addslashes($xml->ethernet->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('ethernet','ethernet','interfaces','$xml_final','$xpath','edit');");
                        }
                    }
                    # Vlan
                    $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND name='vlan' $sql_modified GROUP BY name ORDER BY name");
                    if ($getIntEthernet->num_rows > 0) {
                        $vlanint = $xml->addChild("vlan");
                        while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                            if ($getIntEthernetData['ipv6'] != "") {
                                $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                SimpleXMLElement_append($vlanint, $xml_append);
                            }
                            if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                $vlanint->addChild("mtu", $getIntEthernetData['mtu']);
                            }
                            if ($getIntEthernetData['comment'] != "") {
                                $vlanint->addChild("comment");
                                $vlanint->comment = $getIntEthernetData['comment'];
                            }
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $vlanint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                            }
                            if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                $vlanint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                            }
                            if ($getIntEthernetData['arp'] != "") {
                                $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                SimpleXMLElement_append($vlanint, $xml_append);
                            }
                            if ($version>=7){
                                if ($getIntEthernetData['ndpproxy'] != "") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                    SimpleXMLElement_append($vlanint, $xml_append);
                                }
                            }
                            if ($getIntEthernetData['ipv4_type'] == "static") {
                                if ($getIntEthernetData['unitipaddress'] != "") {
                                    $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                    $vlanint->addChild("ip");
                                    foreach ($interfaces_all as $key => $int_value) {
                                        $newInt = $vlanint->ip->addChild("entry");
                                        $newInt->addAttribute('name', $int_value);
                                    }
                                }
                            } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                $vlanint->addChild("dhcp-client");
                                if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                    $vlanint->{"dhcp-client"}->addChild("enable", "no");
                                }
                                if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                    $vlanint->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                }
                                if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                    $vlanint->{"dhcp-client"}->addChild("create-default-route", "no");
                                }
                            }
                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND unitname!='vlan' $sql_modified;");
                            if ($getUnits->num_rows > 0) {
                                $vlanint->addChild("units");
                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                    $myname1 = $getUnitsData['unitname'];
                                    $UnitInt = $vlanint->units->addChild('entry');
                                    $UnitInt->addAttribute('name', $myname1);
                                    if ($getUnitsData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                    }
                                    if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                        $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                    }
                                    if ($getUnitsData['adjust_tcp_mss'] != "") {
                                        $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                    }
                                    if ($getUnitsData['comment'] != "") {
                                        $UnitInt->addChild("comment");
                                        $UnitInt->comment = $getUnitsData['comment'];
                                    }
                                    if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                        $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                    }
                                    if ($getUnitsData['arp'] != "") {
                                        $xml_append = simplexml_load_string($getUnitsData['arp']);
                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                    }
                                    if ($getUnitsData['ipv4_type'] == "static") {
                                        if ($getUnitsData['unitipaddress'] != "") {
                                            $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                            $UnitInt->addChild("ip");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $newInt = $UnitInt->ip->addChild("entry");
                                                $newInt->addAttribute('name', $int_value);
                                            }
                                        }
                                    } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                        $UnitInt->addChild("dhcp-client");
                                        if ($getUnitsData['dhcp_client_enable'] == "no") {
                                            $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                        }
                                        if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                            $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                        }
                                        if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                            $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                        }
                                    }
                                }
                            }
                        }
                        if (($api_call == "atomic") Or ( $api_call == "single")) {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/interface";
                            $xml_final = addslashes($xml->vlan->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('vlan','vlan','interfaces','$xml_final','$xpath','set');");
                        }
                    }
                    # Loopback
                    $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND name='loopback' $sql_modified GROUP BY name ORDER BY name");
                    if ($getIntEthernet->num_rows > 0) {
                        $loopackint = $xml->addChild("loopback");
                        while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                            if ($getIntEthernetData['ipv6'] != "") {
                                $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                SimpleXMLElement_append($loopackint, $xml_append);
                            }
                            if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                $loopackint->addChild("mtu", $getIntEthernetData['mtu']);
                            }
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $loopackint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                            }
                            if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                $loopackint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                            }
                            if ($getIntEthernetData['comment'] != "") {
                                $loopackint->addChild("comment");
                                $loopackint->comment = $getIntEthernetData['comment'];
                            }
                            if ($getIntEthernetData['ipv4_type'] == "static") {
                                if ($getIntEthernetData['unitipaddress'] != "") {
                                    $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                    $loopackint->addChild("ip");
                                    foreach ($interfaces_all as $key => $int_value) {
                                        $newInt = $loopackint->ip->addChild("entry");
                                        $newInt->addAttribute('name', $int_value);
                                    }
                                }
                            }
                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND unitname!='loopback' $sql_modified;");
                            if ($getUnits->num_rows > 0) {
                                $unit = $loopackint->addChild("units");
                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                    $myname1 = $getUnitsData['unitname'];
                                    $UnitInt = $unit->addChild('entry');
                                    $UnitInt->addAttribute('name', $myname1);
                                    if ($getUnitsData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                    }
                                    if ($getUnitsData['comment'] != "") {
                                        $UnitInt->addChild("comment");
                                        $UnitInt->comment = $getUnitsData['comment'];
                                    }
                                    if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                        $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                    }
                                    if ($getUnitsData['adjust_tcp_mss'] != "") {
                                        $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                    }
                                    if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                        $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                    }
                                    if ($getUnitsData['ipv4_type'] == "static") {
                                        if ($getUnitsData['unitipaddress'] != "") {
                                            $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                            $UnitInt->addChild("ip");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $newInt = $UnitInt->ip->addChild("entry");
                                                $newInt->addAttribute('name', $int_value);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (($api_call == "atomic") Or ( $api_call == "single")) {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/interface";
                            $xml_final = addslashes($xml->loopback->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('loopback','loopback','interfaces','$xml_final','$xpath','set');");
                        }
                    }
                    # Tunnel
                    $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND name='tunnel' $sql_modified GROUP BY name ORDER BY name");
                    if ($getIntEthernet->num_rows > 0) {
                        $tunnelint = $xml->addChild("tunnel");
                        while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                            if ($getIntEthernetData['ipv6'] != "") {
                                $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                SimpleXMLElement_append($tunnelint, $xml_append);
                            }
                            if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                $tunnelint->addChild("mtu", $getIntEthernetData['mtu']);
                            }
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $tunnelint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                            }
                            if ($getIntEthernetData['comment'] != "") {
                                $tunnelint->addChild("comment");
                                $tunnelint->comment = $getIntEthernetData['comment'];
                            }
                            if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                $tunnelint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                            }
                            if ($getIntEthernetData['ipv4_type'] == "static") {
                                if ($getIntEthernetData['unitipaddress'] != "") {
                                    $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                    $tunnelint->addChild("ip");
                                    foreach ($interfaces_all as $key => $int_value) {
                                        $newInt = $tunnelint->ip->addChild("entry");
                                        $newInt->addAttribute('name', $int_value);
                                    }
                                }
                            }
                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND unitname!='tunnel' $sql_modified;");
                            if ($getUnits->num_rows > 0) {
                                $unit = $tunnelint->addChild("units");
                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                    $myname1 = $getUnitsData['unitname'];
                                    $UnitInt = $unit->addChild('entry');
                                    $UnitInt->addAttribute('name', $myname1);
                                    if ($getUnitsData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                    }
                                    if ($getUnitsData['comment'] != "") {
                                        $UnitInt->addChild("comment");
                                        $UnitInt->comment = $getUnitsData['comment'];
                                    }
                                    if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                        $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                    }
                                    if ($getUnitsData['adjust_tcp_mss'] != "") {
                                        $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                    }
                                    if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                        $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                    }
                                    if ($getUnitsData['ipv4_type'] == "static") {
                                        if ($getUnitsData['unitipaddress'] != "") {
                                            $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                            $UnitInt->addChild("ip");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $newInt = $UnitInt->ip->addChild("entry");
                                                $newInt->addAttribute('name', $int_value);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (($api_call == "atomic") Or ( $api_call == "single")) {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/interface";
                            $xml_final = addslashes($xml->tunnel->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('tunnel','tunnel','interfaces','$xml_final','$xpath','set');");
                        }
                    }
                }

                #Virtual Wire
                $getVW = $projectdb->query("SELECT id,name,multicast_firewalling,tag_allowed,link_state_pass_through,interface1,interface2 FROM virtual_wires WHERE source='$source' AND template='$template';");
                if ($getVW->num_rows > 0) {
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><virtual-wire></virtual-wire></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/virtual-wire");
                    $theVW = $xml1[0];

                    while ($getVRData = $getVW->fetch_assoc()) {
                        $myname = $getVRData['name'];
                        $multicast_firewalling = $getVRData['multicast_firewalling'];
                        $tag_allowed = $getVRData['tag_allowed'];
                        $link_state_pass_through = $getVRData['link_state_pass_through'];
                        $interface1 = $getVRData['interface1'];
                        $interface2 = $getVRData['interface2'];

                        $vwire = $theVW->addChild('entry');
                        $vwire->addAttribute('name', $myname);
                        if ($link_state_pass_through != "") {
                            $vwire->addChild("link-state-pass-through");
                            $vwire->{'link-state-pass-through'}->addChild("enable", $link_state_pass_through);
                        }
                        if ($multicast_firewalling != "") {
                            $vwire->addChild("multicast-firewalling");
                            $vwire->{'multicast-firewalling'}->addChild("enable", $multicast_firewalling);
                        }
                        if ($tag_allowed != "") {
                            $vwire->addchild("tag-allowed", $tag_allowed);
                        }
                        if ($interface1 != "") {
                            $vwire->addChild("interface1", $interface1);
                        }
                        if ($interface2 != "") {
                            $vwire->addChild("interface2", $interface2);
                        }
                    }
                    if (($api_call == "atomic") Or ( $api_call == "single")) {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/virtual-wire";
                        $xml_final = addslashes($theVW->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('vwire','vwire','virtual_wires','$xml_final','$xpath','edit');");
                    }
                }

                #VLANS
                $getVW = $projectdb->query("SELECT id, name, interface, mac, virtual_interface, mac_interfaces, l3_forwarding FROM vlans WHERE source='$source' AND template='$template' AND name != '';");
                if ($getVW->num_rows > 0) {
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><vlan></vlan></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/vlan");
                    $theVW = $xml1[0];
                    while ($getVRData = $getVW->fetch_assoc()) {
                        $myname = $getVRData['name'];
                        $interface = $getVRData['interface'];
                        $mac = $getVRData['mac'];
                        $mac_interfaces = $getVRData['mac_interfaces'];
                        $virtual_interface = $getVRData['virtual_interface'];
                        $l3_forwarding = $getVRData['l3_forwarding'];

                        $vwire = $theVW->addChild('entry');
                        $vwire->addAttribute('name', $myname);
                        if ($interface != "") {
                            $vwire->addChild("interface");
                            foreach (explode(",", $interface) as $key => $value) {
                                $vwire->interface->addChild("member", $value);
                            }
                        }

                        if ($mac != "") {
                            //$xml_append = simplexml_load_string($mac);
                            //SimpleXMLElement_append($vwire, $xml_append);
                            $index_array = 0;
                            $interfaces_mac_array = explode(",", $mac_interfaces);

                            $vlan_pad = $vwire->addChild("mac");

                            foreach (explode(",", $mac) as $key => $value) {
                                $vlan_mac = $vlan_pad->addChild('entry');
                                $vlan_mac->addAttribute('name', $value);

                                $vlan_mac->interface = $interfaces_mac_array[$index_array];
                                $index_array ++;
                            }
                        }

                        if($version > 5){
                            if ($virtual_interface != "") {
                                $vwire->addChild("virtual-interface");
                                $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                            }
                        }
                        else{
                            $vwire->addChild("virtual-interface");
                            $vwire->{'virtual-interface'}->addChild("l3-forwarding", $l3_forwarding);
                            if ($virtual_interface != "") {
                                $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                            }
                        }
                    }

                    /*if (($api_call == "atomic") Or ( $api_call == "single")) {
                    $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network";
                    $xml_final = addslashes($theVW->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('vlan','vlan','vlan','$xml_final','$xpath','set');");
                }*/
                    // EDIT
                    if (($api_call == "atomic") Or ( $api_call == "single")) {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/vlan";
                        $xml_final = addslashes($theVW->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('vlan','vlan','vlan','$xml_final','$xpath','edit');");
                    }
                }

                #Virtual Router
                $getVR = $projectdb->query("SELECT id,name,map_name,interfaces,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,protocol,multicast,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext,ecmp FROM virtual_routers WHERE source='$source' AND template='$template' ;");
                if ($getVR->num_rows > 0) {
                    $xml0 = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><network><virtual-router></virtual-router></network></entry></devices></config>");
                    $xml1 = $xml0->xpath("/config/devices/entry/network/virtual-router");
                    $xml = $xml1[0];
                    while ($getVRData = $getVR->fetch_assoc()) {
                        $vr_id = $getVRData['id'];
                        $myname = $getVRData['name'];
                        $map_name = $getVRData['map_name'];
                        $interfaces = $getVRData['interfaces'];
                        $admin_dist_static = $getVRData['admin_dist_static'];
                        $admin_dist_ospf_int = $getVRData['admin_dist_ospf_int'];
                        $admin_dist_ospf_ext = $getVRData['admin_dist_ospf_ext'];
                        $admin_dist_ibgp = $getVRData['admin_dist_ibgp'];
                        $admin_dist_ebgp = $getVRData['admin_dist_ebgp'];
                        $admin_dist_rip = $getVRData['admin_dist_rip'];
                        $protocol = $getVRData['protocol'];
                        $multicast = $getVRData['multicast'];
                        $admin_dist_static_ipv6 = $getVRData['admin_dist_static_ipv6'];
                        $admin_dist_ospfv3_int = $getVRData['admin_dist_ospfv3_int'];
                        $admin_dist_ospfv3_ext = $getVRData['admin_dist_ospfv3_ext'];
                        $ecmp=$getVRData['ecmp'];

                        $vr = $xml->addChild('entry');
                        $vr->addAttribute('name', $myname);

                        $vr->addChild("interface");
                        $interface = $vr->interface;
                        if ($interfaces != "") {
                            foreach (explode(",", $interfaces) as $key => $value) {
                                $interface->addChild("member", $value);
                            }
                        }

                        if ($protocol != "") {
                            $xml_append = simplexml_load_string($protocol);
                            SimpleXMLElement_append($vr, $xml_append);
                        }
                        if ($version>=7){
                            if ($ecmp != "") {
                                $xml_append = simplexml_load_string($ecmp);
                                SimpleXMLElement_append($vr, $xml_append);
                            }
                        }
                        if ($multicast != "") {
                            $vr->addChild("multicast");
                            $multicastxml = $vr->multicast;
                            $xml_append = simplexml_load_string($multicast);
                            SimpleXMLElement_append($multicastxml, $xml_append);
                        }

                        #Metrics
                        $vr->addChild("admin-dists");
                        if (( $admin_dist_static == "") OR ( $admin_dist_static == "0")) {

                        } else {
                            $vr->{'admin-dists'}->addChild("static", $admin_dist_static);
                        }

                        if (( $admin_dist_ospf_int == "") OR ( $admin_dist_ospf_int == "0")) {

                        } else {
                            $vr->{'admin-dists'}->addChild("ospf-int", $admin_dist_ospf_int);
                        }

                        if (( $admin_dist_ospf_ext == "") OR ( $admin_dist_ospf_ext == "0")) {

                        } else {
                            $vr->{'admin-dists'}->addChild("ospf-ext", $admin_dist_ospf_ext);
                        }

                        if (( $admin_dist_ibgp == "") OR ( $admin_dist_ibgp == "0")) {

                        } else {
                            $vr->{'admin-dists'}->addChild("ibgp", $admin_dist_ibgp);
                        }

                        if (( $admin_dist_ebgp == "") OR ( $admin_dist_ebgp == "0")) {

                        } else {
                            $vr->{'admin-dists'}->addChild("ebgp", $admin_dist_ebgp);
                        }

                        if (( $admin_dist_rip == "") OR ( $admin_dist_rip == "0")) {

                        } else {
                            $vr->{'admin-dists'}->addChild("rip", $admin_dist_rip);
                        }

                        if ($version >= 6) {
                            if (( $admin_dist_static_ipv6 == "") OR ( $admin_dist_static_ipv6 == "0")) {

                            } else {
                                $vr->{'admin-dists'}->addChild("static-ipv6", $admin_dist_static_ipv6);
                            }

                            if (( $admin_dist_ospfv3_int == "") OR ( $admin_dist_ospfv3_int == "0")) {

                            } else {
                                $vr->{'admin-dists'}->addChild("ospfv3-int", $admin_dist_ospfv3_int);
                            }

                            if (( $admin_dist_ospfv3_ext == "") OR ( $admin_dist_ospfv3_ext == "0")) {

                            } else {
                                $vr->{'admin-dists'}->addChild("ospfv3-ext", $admin_dist_ospfv3_ext);
                            }
                        }

                        # Static Routing
                        $exist = $projectdb->query("SELECT id FROM routes_static WHERE template='$template' AND source='$source' AND vr_id='$vr_id' $sql_modified;");
                        if ($exist->num_rows > 0) {
                            $vr->addChild("routing-table");
                            # IPV4
                            $getStatic = $projectdb->query("SELECT name,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,zone FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v4' AND source='$source' AND template='$template' $sql_modified;");
                            if ($getStatic->num_rows > 0) {
                                $vr->{'routing-table'}->addChild("ip");
                                $vr->{'routing-table'}->ip->addChild("static-route");
                                $routes = $vr->{'routing-table'}->ip->{'static-route'};
                                while ($getStaticData = $getStatic->fetch_assoc()) {
                                    $name = $getStaticData['name'];
                                    $destination = $getStaticData['destination'];
                                    $tointerface = $getStaticData['tointerface'];
                                    $nexthop = $getStaticData['nexthop'];
                                    $nexthop_value = $getStaticData['nexthop_value'];
                                    $metric = $getStaticData['metric'];
                                    $admin_dist = $getStaticData['admin_dist'];
                                    $option_no_install = $getStaticData['option_no_install'];
                                    $zone = $getStaticData['zone'];

                                    $route = $routes->addChild("entry");
                                    $route->addAttribute('name', $name);

                                    if ($destination != "") {
                                        $route->addChild("destination", $destination);
                                    }

                                    if ($option_no_install == 1) {
                                        $route->addChild("option");
                                        $route->option->addChild("no-install");
                                    }

                                    if (($metric != "") AND ( $metric != "0") AND ( $metric != null)) {
                                        $route->addChild("metric", $metric);
                                    }

                                    if (($admin_dist != "") AND ( $admin_dist != "0") AND ( $admin_dist != null)) {
                                        $route->addChild("admin-dist", $admin_dist);
                                    }

                                    if ($tointerface != "") {
                                        $route->addChild("interface", $tointerface);
                                    }

                                    if ($nexthop != "None") {
                                        $route->addChild("nexthop");
                                        if ($nexthop_value != "") {
                                            $route->nexthop->addChild($nexthop, $nexthop_value);
                                        } else {
                                            $route->nexthop->addChild($nexthop);
                                        }
                                    }
                                }
                            }

                            #IPV6
                            $getStatic = $projectdb->query("SELECT name,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,zone FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v6' AND source='$source' AND template='$template' $sql_modified;");
                            if ($getStatic->num_rows > 0) {
                                $vr->{'routing-table'}->addChild("ipv6");
                                $vr->{'routing-table'}->ipv6->addChild("static-route");
                                $routes = $vr->{'routing-table'}->ipv6->{'static-route'};
                                while ($getStaticData = $getStatic->fetch_assoc()) {
                                    $name = $getStaticData['name'];
                                    $destination = $getStaticData['destination'];
                                    $tointerface = $getStaticData['tointerface'];
                                    $nexthop = $getStaticData['nexthop'];
                                    $nexthop_value = $getStaticData['nexthop_value'];
                                    $metric = $getStaticData['metric'];
                                    $admin_dist = $getStaticData['admin_dist'];
                                    $option_no_install = $getStaticData['option_no_install'];
                                    $zone = $getStaticData['zone'];

                                    $route = $routes->addChild("entry");
                                    $route->addAttribute('name', $name);

                                    if ($destination != "") {
                                        $route->addChild("destination", $destination);
                                    }

                                    if ($option_no_install == 1) {
                                        $route->addChild("option");
                                        $route->option->addChild("no-install");
                                    }

                                    if (($metric != "") AND ( $metric != "0") AND ( $metric != null)) {
                                        $route->addChild("metric", $metric);
                                    }

                                    if (($admin_dist != "") AND ( $admin_dist != "0") AND ( $admin_dist != null)) {
                                        $route->addChild("admin-dist", $admin_dist);
                                    }

                                    if ($tointerface != "") {
                                        $route->addChild("interface", $tointerface);
                                    }

                                    if ($nexthop != "None") {
                                        $route->addChild("nexthop");
                                        if ($nexthop_value != "") {
                                            $route->nexthop->addChild($nexthop, $nexthop_value);
                                        } else {
                                            $route->nexthop->addChild($nexthop);
                                        }
                                    }
                                }
                            }
                        }

                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/virtual-router/entry[@name=\'$myname\']";
                            $xml_final = addslashes($vr->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','virtual_router','virtual_router','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/network/virtual-router";
                        $xml_final = addslashes($xml->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('virtual_router','virtual_router','$xml_final','$xpath','edit');");
                    }
                }

            }
        }
        else {
            # Is Panorama
            # Templates
            $getTemplate = $projectdb->query("SELECT id,name FROM templates_mapping WHERE source='$source';");
            if ($getTemplate->num_rows > 0) {
                $xml = new SimpleXMLElement("<config><devices><entry name=\"localhost.localdomain\"><template></template></entry></devices></config>");

                $existTemplateroot = $xml->xpath("//devices/entry[@name='localhost.localdomain']/template");
                if (empty($existTemplateroot)) {
                    $rootTemplate1 = $xml->xpath("//devices/entry[@name='localhost.localdomain']");
                    $rootTemplate = $rootTemplate1[0]->addChild('template');
                } else {
                    $SA = $xml->xpath("//devices/entry[@name='localhost.localdomain']/template");
                    unset($SA[0][0]);
                    $rootTemplate = $xml->devices->entry[0]->addChild('template');
                }
                while ($getTemplateData = $getTemplate->fetch_assoc()) {
                    $template = $getTemplateData['id'];
                    $template_name = $getTemplateData['name'];
                    $getTemplateInfo = $projectdb->query("SELECT description,multi_vsys,operational_mode,vpn_disable_mode,devices FROM templates WHERE templates_mapping_id='$template';");
                    if ($getTemplateInfo->num_rows == 1) {
                        $getTemplateInfoData = $getTemplateInfo->fetch_assoc();
                        #$template_name = $getTemplateInfoData['name'];
                        $template_description = $getTemplateInfoData['description'];
                        $template_multi_vsys = $getTemplateInfoData['multi_vsys'];
                        $template_operational_mode = strtolower($getTemplateInfoData['operational_mode']);
                        $template_vpn_disable_mode = $getTemplateInfoData['vpn_disable_mode'];
                        $template_devices = $getTemplateInfoData['devices'];

                        $myTemplate = $rootTemplate->addChild("entry");
                        $myTemplate->addAttribute('name', $template_name);
                        $myTemplate->addChild("settings");
                        if ($template_vpn_disable_mode != "") {
                            $myTemplate->settings->addChild("vpn-disable-mode", $template_vpn_disable_mode);
                        }
                        if ($template_operational_mode != "") {
                            $myTemplate->settings->addchild("operational-mode", $template_operational_mode);
                        }
                        if ($template_multi_vsys == "yes") {
                            $myTemplate->settings->addchild("multi-vsys", "yes");
                        }
                        if ($template_devices != "") {
                            $xml_append = simplexml_load_string($template_devices);
                            SimpleXMLElement_append($myTemplate, $xml_append);
                        }

                        $myTemplate->addChild("config");

                        # Template - Shared
                        $myTemplateShared = $myTemplate->config->addChild("shared");

                        # RESPONSE-PAGES
                        //$getShared = $projectdb->query("SELECT name,type,html FROM shared_response_pages WHERE source='$source' AND template='$template' ORDER BY id;");
                        $getShared = $projectdb->query("SELECT name,type,html FROM response_pages WHERE source='$source' AND template='$template' AND vsys = 'shared' ORDER BY id;");
                        if ($getShared->num_rows > 0) {
                            $myTemplateShared->addChild('response-page');
                            while ($data2 = $getShared->fetch_assoc()) {
                                $xmlfield = $data2['html'];
                                $xmlname = $data2['type'];
                                $reportname = $data2['name'];
                                if ($reportname != "") {
                                    if (!isset($myTemplateShared->{'response-page'}->{$xmlname})) {
                                        $myTemplateShared->{'response-page'}->addChild($xmlname);
                                        $newrp = $myTemplateShared->{'response-page'}->{$xmlname}->addChild("entry");
                                        $newrp->addAttribute('name', $reportname);
                                        $newrp->addChild("page");
                                        $newrp->page = $xmlfield;
                                    } else {
                                        if ($myTemplateShared->{'response-page'}->{$xmlname}->xpath("entry[@name='$reportname']") !== null) {
                                            $SA = $myTemplateShared->{'response-page'}->{$xmlname}->xpath("entry[@name='$reportname']");
                                            unset($SA[0][0]);
                                        }
                                        $newrp = $myTemplateShared->{'response-page'}->{$xmlname}->addChild("entry");
                                        $newrp->addAttribute('name', $reportname);
                                        $newrp->addChild("page");
                                        $newrp->page = $xmlfield;
                                    }
                                } else {
                                    $SA = $myTemplateShared->xpath("response-page/$xmlname");
                                    unset($SA[0][0]);
                                    #$xml_append = simplexml_load_string($xmlfield);
                                    $xml_append = simplexml_load_string("<$xmlname>$xmlfield</$xmlname>");
                                    SimpleXMLElement_append($myTemplateShared->{'response-page'}, $xml_append);
                                }
                            }
                        }

                        # Template - Devices
                        $myTemplate->config->addChild("devices");
                        $myTemplateDevice = $myTemplate->config->devices->addChild("entry");
                        $myTemplateDevice->addAttribute('name', 'localhost.localdomain');

                        # Template - Network
                        $myTemplateDeviceNetwork = $myTemplateDevice->addChild("network");

                        #DHCP
                        $getDHCP = $projectdb->query("SELECT name,dhcp_type,xml FROM dhcp WHERE source='$source' AND template='$template';");
                        if ($getDHCP->num_rows > 0) {
                            $myTemplateDeviceNetwork->addChild("dhcp");
                            $myTemplateDeviceNetwork->dhcp->addChild("interface");

                            while ($getDHCPData = $getDHCP->fetch_assoc()) {
                                $xmlname = $getDHCPData['name'];
                                $xmlfield = $getDHCPData['xml'];
                                $xml_append = simplexml_load_string($xmlfield);
//                                echo $xml_append->asXML();
                                if ($myTemplateDeviceNetwork->dhcp->interface->xpath("//entry[@name='$xmlname']") != null) {
                                    add_log('warning', 'Exporting Schedules [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                                }
                                else {
                                    SimpleXMLElement_append($myTemplateDeviceNetwork->dhcp->interface, $xml_append);
                                }
                            }
                        }

                        # DNS-PROXY
                        $getDHCP = $projectdb->query("SELECT name,xml FROM dns_proxy WHERE source='$source' AND template='$template';");
                        if ($getDHCP->num_rows > 0) {
                            $myTemplateDeviceNetwork->addChild("dns-proxy");

                            while ($getDHCPData = $getDHCP->fetch_assoc()) {
                                $xmlname = $getDHCPData['name'];
                                $xmlfield = $getDHCPData['xml'];
                                $xml_append = simplexml_load_string($xmlfield);
                                if ($myTemplateDeviceNetwork->{'dns-proxy'}->xpath("//entry[@name='$xmlname']") != null) {
                                    add_log('warning', 'Exporting Schedules [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                                } else {
                                    SimpleXMLElement_append($myTemplateDeviceNetwork->{'dns-proxy'}, $xml_append);
                                }
                            }
                        }

                        # Template - Device - Network - Profiles
                        $myTemplateDeviceNetworkProfiles = $myTemplateDeviceNetwork->addChild("profiles");

                        # management Profiles
                        $getMP = $projectdb->query("SELECT name,permitted_ip,http,https,http_ocsp,ssh,snmp,userid_service,userid_syslog_listener_ssl,userid_syslog_listener_udp,ping,response_pages,telnet FROM interface_management_profile WHERE source='$source' AND template='$template' AND name != '';");
                        if ($getMP->num_rows > 0) {
                            $myTemplateDeviceNetworkProfiles->addChild('interface-management-profile');

                            while ($getMPData = $getMP->fetch_assoc()) {
                                $myname = $getMPData['name'];
                                $mgmprofile = $myTemplateDeviceNetworkProfiles->{'interface-management-profile'}->addChild('entry');
                                $mgmprofile->addAttribute('name', $myname);

                                if ($getMPData['http'] != "") {
                                    $mgmprofile->addChild("http", $getMPData['http']);
                                }
                                if ($getMPData['https'] != "") {
                                    $mgmprofile->addChild("https", $getMPData['https']);
                                }
                                if ($getMPData['http_ocsp'] != "") {
                                    $mgmprofile->addChild("http-ocsp", $getMPData['http_ocsp']);
                                }
                                if ($getMPData['ssh'] != "") {
                                    $mgmprofile->addChild("ssh", $getMPData['ssh']);
                                }
                                if ($getMPData['snmp'] != "") {
                                    $mgmprofile->addChild("snmp", $getMPData['snmp']);
                                }
                                if ($getMPData['userid_service'] != "") {
                                    $mgmprofile->addChild("userid-service", $getMPData['userid_service']);
                                }
                                if ($getMPData['ping'] != "") {
                                    $mgmprofile->addChild("ping", $getMPData['ping']);
                                }
                                if ($getMPData['telnet'] != "") {
                                    $mgmprofile->addChild("telnet", $getMPData['telnet']);
                                }
                                if ($getMPData['response_pages'] != "") {
                                    $mgmprofile->addChild("response-pages", $getMPData['response_pages']);
                                }
                                if ($version > 5) {
                                    if ($getMPData['userid_syslog_listener_ssl'] != "") {
                                        $mgmprofile->addChild("userid-syslog-listener-ssl", $getMPData['userid_syslog_listener_ssl']);
                                    }
                                    if ($getMPData['userid_syslog_listener_udp'] != "") {
                                        $mgmprofile->addChild("userid-syslog-listener-udp", $getMPData['userid_syslog_listener_udp']);
                                    }
                                }
                                if ($getMPData['permitted_ip'] != "") {
                                    $interfaces_all = explode(",", $getMPData['permitted_ip']);
                                    $mgmprofile->addChild("permitted-ip");
                                    foreach ($interfaces_all as $key => $int_value) {
                                        $newInt = $mgmprofile->{'permitted-ip'}->addChild("entry");
                                        $newInt->addAttribute('name', $int_value);
                                    }
                                }
                            }
                        }

                        # Monitor Profile
                        $getMonitor = $projectdb->query("SELECT name,m_action,interva,threshold FROM monitor_profile WHERE source='$source' AND template='$template' AND name != '';");
                        if ($getMonitor->num_rows >0){

                            $myTemplateDeviceNetworkProfiles->addChild("monitor-profile");

                            $MPXpath=$myTemplateDeviceNetworkProfiles->{'monitor-profile'};
                            while ($getMonitorData=$getMonitor->fetch_assoc()){
                                $myname = $getMonitorData['name'];
                                $MPAction=$getMonitorData['m_action'];
                                $MPInterval=$getMonitorData['interva'];
                                $MPThreshold=$getMonitorData['threshold'];

                                if ($MPXpath->xpath("//entry[@name='$myname']") == null) {
                                    $monitorProfile = $MPXpath->addChild('entry');
                                    $monitorProfile->addAttribute('name', $getMonitorData['name']);
                                    if (($MPInterval!=0) AND ($MPInterval!="")){
                                        $monitorProfile->addChild("interval");
                                        $monitorProfile->interval=$MPInterval;
                                    }
                                    if (($MPThreshold!=0) AND ($MPThreshold!="")){
                                        $monitorProfile->addChild("threshold");
                                        $monitorProfile->threshold=$MPThreshold;
                                    }
                                    if ($MPAction!=""){
                                        $monitorProfile->addChild("action");
                                        $monitorProfile->action=$MPAction;
                                    }
                                }
                            }
                        }

                        # DeviceConfig

                        $getBanner=$projectdb->query("SELECT xml FROM deviceconfig WHERE source='$source' AND template='$template';");
                        if ($getBanner->num_rows==1){

                            $getBannerData=$getBanner->fetch_assoc();
                            if ($getBannerData['xml']!=""){
                                $myBannerRaw=simplexml_load_string($getBannerData['xml']);
                                $myBanner=$myBannerRaw->deviceconfig->asXML();
                                SimpleXMLElement_append($myTemplateDevice, $myBannerRaw);


                            }
                        }


                        # Template - Device - Network - IKE
                        $myTemplateDeviceNetworkIKE = $myTemplateDeviceNetwork->addChild("ike");

                        $create_branch_ike_crypto_profile = 0;

                        # IKE CRYPTO
                        $getIKECrypto = $projectdb->query("SELECT name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple FROM ike_crypto_profiles WHERE source='$source' AND template='$template' AND name != '';");
                        if ($getIKECrypto->num_rows >0){

                            if($create_branch_ike_crypto_profile == 0){
                                $myTemplateDeviceNetworkIKE_CRYPTO = $myTemplateDeviceNetworkIKE->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }

                            $myTemplateDeviceNetworkIKE_CRYPTO->addChild("ike-crypto-profiles");

                            $ike_crypto_path = $myTemplateDeviceNetworkIKE_CRYPTO->{'ike-crypto-profiles'};

                            while ($dataIKEC = $getIKECrypto->fetch_assoc()){
                                $myname = $dataIKEC['name'];
                                $ike_encryption = $dataIKEC['encryption'];
                                $ike_hash = $dataIKEC['hash'];
                                $ike_dh_group = $dataIKEC['dh_group'];
                                $ike_seconds = $dataIKEC['seconds'];
                                $ike_minutes = $dataIKEC['minutes'];
                                $ike_hours = $dataIKEC['hours'];
                                $ike_days = $dataIKEC['days'];
                                $ike_authentication_multiple = $dataIKEC['authentication_multiple'];

                                if ($ike_crypto_path->xpath("//entry[@name='$myname']") == null) {

                                    $ike_crypto = $ike_crypto_path->addChild('entry');
                                    $ike_crypto->addAttribute('name', $dataIKEC['name']);

                                    if ($ike_encryption != ""){
                                        $ike_crypto->addChild("encryption");
                                        $ike_encryption_array = explode(",", $ike_encryption);
                                        foreach($ike_encryption_array as $member_ike){
                                            $ike_crypto->encryption->addChild("member", $member_ike);
                                        }
                                    }
                                    if ($ike_hash != ""){
                                        $ike_crypto->addChild("hash");
                                        $ike_hash_array = explode(",", $ike_hash);
                                        foreach($ike_hash_array as $member_ike){
                                            $ike_crypto->hash->addChild("member", $member_ike);
                                        }
                                    }
                                    if ($ike_dh_group != ""){
                                        $ike_crypto->addChild("dh-group");
                                        $ike_dh_group_array = explode(",", $ike_dh_group);
                                        foreach($ike_dh_group_array as $member_ike){
                                            $ike_crypto->{'dh-group'}->addChild("member", $member_ike);
                                        }
                                    }
                                    if ($ike_seconds != 0){
                                        $ike_crypto->addChild("lifetime");
                                        $ike_crypto->{'lifetime'}->seconds = $ike_seconds;

                                    }
                                    if ($ike_minutes != 0){
                                        $ike_crypto->addChild("lifetime");
                                        $ike_crypto->{'lifetime'}->minutes = $ike_minutes;
                                    }
                                    if ($ike_hours != 0){
                                        $ike_crypto->addChild("lifetime");
                                        $ike_crypto->{'lifetime'}->hours = $ike_hours;

                                    }
                                    if ($ike_days != 0){
                                        $ike_crypto->addChild("lifetime");
                                        $ike_crypto->{'lifetime'}->days = $ike_days;
                                    }

                                }
                            }
                        }

                        # IPSEC CRYPTO
                        $getIPSECCrypto = $projectdb->query("SELECT name, encryption, hash, dh_group, protocol, seconds, minutes, hours, days, kb, mb, gb, tb FROM ipsec_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                        if ($getIPSECCrypto->num_rows >0){

                            if($create_branch_ike_crypto_profile == 0){
                                $myTemplateDeviceNetworkIKE_CRYPTO = $myTemplateDeviceNetworkIKE->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }
                            $myTemplateDeviceNetworkIKE_CRYPTO->addChild("ipsec-crypto-profiles");

                            $ipsec_crypto_xpath = $myTemplateDeviceNetworkIKE_CRYPTO->{'ipsec-crypto-profiles'};

                            while ($dataIPSECC = $getIPSECCrypto->fetch_assoc()){
                                $myname = $dataIPSECC['name'];
                                $ipsec_encryption = $dataIPSECC['encryption'];
                                $ipsec_hash = $dataIPSECC['hash'];
                                $ipsec_dh_group = $dataIPSECC['dh_group'];
                                $ipsec_protocol = $dataIPSECC['protocol'];
                                $ipsec_seconds = $dataIPSECC['seconds'];
                                $ipsec_minutes = $dataIPSECC['minutes'];
                                $ipsec_hours = $dataIPSECC['hours'];
                                $ipsec_days = $dataIPSECC['days'];
                                $ipsec_kb = $dataIPSECC['kb'];
                                $ipsec_mb = $dataIPSECC['mb'];
                                $ipsec_gb = $dataIPSECC['gb'];
                                $ipsec_tb = $dataIPSECC['tb'];

                                if ($ipsec_crypto_xpath->xpath("//entry[@name='$myname']") == null) {

                                    $ipsec_crypto = $ipsec_crypto_xpath->addChild('entry');
                                    $ipsec_crypto->addAttribute('name', $dataIPSECC['name']);

                                    if($ipsec_protocol == "ESP"){
                                        $ipsec_crypto->addChild("esp");

                                        if ($ipsec_encryption != ""){
                                            $ipsec_crypto->esp->addChild("encryption");
                                            $ipsec_encryption_array = explode(",", $ipsec_encryption);
                                            foreach($ipsec_encryption_array as $member_ike){
                                                $ipsec_crypto->esp->encryption->addChild("member", $member_ike);
                                            }
                                        }
                                        if ($ipsec_hash != ""){
                                            $ipsec_crypto->esp->addChild("authentication");
                                            $ipsec_hash_array = explode(",", $ipsec_hash);
                                            foreach($ipsec_hash_array as $member_ike){
                                                $ipsec_crypto->esp->authentication->addChild("member", $member_ike);
                                            }
                                        }
                                    }

                                    if($ipsec_protocol == "AH"){
                                        $ipsec_crypto->addChild("ah");

                                        if ($ipsec_hash != ""){
                                            $ipsec_crypto->ah->addChild("authentication");
                                            $ipsec_hash_array = explode(",", $ipsec_hash);
                                            foreach($ipsec_hash_array as $member_ike){
                                                $ipsec_crypto->ah->authentication->addChild("member", $member_ike);
                                            }
                                        }
                                    }

                                    if ($ipsec_dh_group != ""){
                                        $ipsec_crypto->addChild("dh-group");
                                        $ipsec_crypto->{'dh-group'} = $ipsec_dh_group;
                                    }
                                    if ($ipsec_seconds != 0){
                                        $ipsec_crypto->addChild("lifetime");
                                        $ipsec_crypto->{'lifetime'}->seconds = $ipsec_seconds;
                                    }
                                    if ($ipsec_minutes != 0){
                                        $ipsec_crypto->addChild("lifetime");
                                        $ipsec_crypto->{'lifetime'}->minutes = $ipsec_minutes;
                                    }
                                    if ($ipsec_hours != 0){
                                        $ipsec_crypto->addChild("lifetime");
                                        $ipsec_crypto->{'lifetime'}->hours = $ipsec_hours;
                                    }
                                    if ($ipsec_days != 0){
                                        $ipsec_crypto->addChild("lifetime");
                                        $ipsec_crypto->{'lifetime'}->days = $ipsec_days;
                                    }

                                    if ($ipsec_kb != 0){
                                        $ipsec_crypto->addChild("lifesize");
                                        $ipsec_crypto->{'lifesize'}->kb = $ipsec_kb;
                                    }
                                    if ($ipsec_mb != 0){
                                        $ipsec_crypto->addChild("lifesize");
                                        $ipsec_crypto->{'lifesize'}->mb = $ipsec_mb;
                                    }
                                    if ($ipsec_gb != 0){
                                        $ipsec_crypto->addChild("lifesize");
                                        $ipsec_crypto->{'lifesize'}->gb = $ipsec_gb;
                                    }
                                    if ($ipsec_tb != 0){
                                        $ipsec_crypto->addChild("lifesize");
                                        $ipsec_crypto->{'lifesize'}->tb = $ipsec_tb;
                                    }

                                }
                            }
                        }

                        # IKE GATEWAYS
                        $getIKEGateways = $projectdb->query("SELECT name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, allow_id_payload_mismatch, local_certificate, certificate_profile, strict_validation_revocation, hash_and_url, base_url, nat_traversal, passive_mode, fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type  FROM ike_gateways_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                        if ($getIKEGateways->num_rows >0){

                            $ike_gateways_xpath = $myTemplateDeviceNetworkIKE->addChild("gateway");

                            while ($dataIKEGat = $getIKEGateways->fetch_assoc()){
                                $myname = $dataIKEGat['name'];
                                $ike_gat_version = $dataIKEGat['version'];
                                $ike_gat_dpd_ikev1 = $dataIKEGat['dpd_ikev1'];
                                $ike_gat_ike_interval_ikev1 = $dataIKEGat['ike_interval_ikev1'];
                                $ike_gat_retry_ikev1 = $dataIKEGat['retry_ikev1'];
                                $ike_gat_ike_crypto_profile_ikev1 = $dataIKEGat['ike_crypto_profile_ikev1'];
                                $ike_gat_exchange_mode_ikev1 = $dataIKEGat['exchange_mode_ikev1'];
                                $ike_gat_dpd_ikev2 = $dataIKEGat['dpd_ikev2'];
                                $ike_gat_ike_interval_ikev2 = $dataIKEGat['ike_interval_ikev2'];
                                $ike_gat_ike_crypto_profile_ikev2 = $dataIKEGat['ike_crypto_profile_ikev2'];
                                $ike_gat_require_cookie_ikev2 = $dataIKEGat['require_cookie_ikev2'];
                                $ike_gat_local_address_ip = $dataIKEGat['local_address_ip'];
                                $ike_gat_interface = $dataIKEGat['interface'];
                                $ike_gat_type_authentication = $dataIKEGat['type_authentication'];
                                $ike_gat_pre_shared_key = $dataIKEGat['pre_shared_key'];
                                $ike_gat_allow_id_payload_mismatch = $dataIKEGat['allow_id_payload_mismatch'];
                                $ike_gat_local_certificate = $dataIKEGat['local_certificate'];
                                $ike_gat_certificate_profile = $dataIKEGat['certificate_profile'];
                                $ike_gat_strict_validation_revocation = $dataIKEGat['strict_validation_revocation'];
                                $ike_gat_hash_and_url = $dataIKEGat['hash_and_url'];
                                $ike_gat_base_url = $dataIKEGat['base_url'];
                                $ike_gat_nat_traversal = $dataIKEGat['nat_traversal'];
                                $ike_gat_passive_mode = $dataIKEGat['passive_mode'];
                                $ike_gat_fragmentation = $dataIKEGat['fragmentation'];
                                $ike_gat_peer_ip_type = $dataIKEGat['peer_ip_type'];
                                $ike_gat_peer_ip_address = $dataIKEGat['peer_ip_address'];
                                $ike_gat_local_id = $dataIKEGat['local_id'];
                                $ike_gat_local_id_type = $dataIKEGat['local_id_type'];
                                $ike_gat_peer_id = $dataIKEGat['peer_id'];
                                $ike_gat_peer_id_type = $dataIKEGat['peer_id_type'];
                                $ike_gat_peer_id_matching = $dataIKEGat['peer_id_matching'];
                                $ike_gat_address_type = $dataIKEGat['address_type'];

                                if ($ike_gateways_xpath->xpath("//entry[@name='$myname']") == null) {

                                    $ike_gateways = $ike_gateways_xpath->addChild('entry');
                                    $ike_gateways->addAttribute('name', $dataIKEGat['name']);

                                    if($ike_gat_dpd_ikev1 != ""){
                                        $ike_gateways->addChild("protocol");
                                        $ike_gateways->protocol->addChild("ikev1");
                                        $ike_gateways->protocol->ikev1->addChild("dpd");
                                        $ike_gateways->protocol->ikev1->dpd->enable = $ike_gat_dpd_ikev1;

                                        if($ike_gat_dpd_ikev1 == "yes"){
                                            $ike_gateways->protocol->ikev1->dpd->interval = $ike_gat_ike_interval_ikev1;
                                            $ike_gateways->protocol->ikev1->dpd->retry = $ike_gat_retry_ikev1;
                                        }

                                        if(($ike_gat_ike_crypto_profile_ikev1 != "") && ($ike_gat_ike_crypto_profile_ikev1 != "default")){
                                            $ike_gateways->protocol->ikev1->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev1;
                                        }

                                        if($ike_gat_exchange_mode_ikev1 != ""){
                                            $ike_gateways->protocol->ikev1->{'exchange-mode'} = $ike_gat_exchange_mode_ikev1;
                                        }
                                    }

                                    // IKE V2 PARA LA VERSIÓN 7
                                    if($version >= 7){
                                        if($ike_gat_dpd_ikev2 != ""){

                                            $ike_gateways->protocol->ikev2->dpd->enable = $ike_gat_dpd_ikev2;
                                            $ike_gateways->protocol->ikev2->dpd->interval = $ike_gat_ike_interval_ikev2;

                                            if($ike_gat_ike_crypto_profile_ikev2 != ""){
                                                $ike_gateways->protocol->ikev2->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev2;
                                            }

                                            if($ike_gat_require_cookie_ikev2 != ""){
                                                $ike_gateways->protocol->ikev2->{'require-cookie'} = $ike_gat_require_cookie_ikev2;
                                            }

                                            if($ike_gat_version != ""){
                                                $ike_gateways->protocol->version = $ike_gat_version;
                                            }

                                        }
                                    }

                                    if($ike_gat_interface != ""){
                                        $ike_gateways->addChild("local-address");
                                        $ike_gateways->{'local-address'}->interface = $ike_gat_interface;
                                        if($ike_gat_local_address_ip != ""){
                                            $ike_gateways->{'local-address'}->ip = $ike_gat_local_address_ip;
                                        }
                                    }

                                    $ike_gat_strict_validation_revocation = $dataIKEGat['strict_validation_revocation'];

                                    if($ike_gat_type_authentication == "pre-shared-key"){
                                        $ike_gateways->addChild("authentication");
                                        $ike_gateways->authentication->{'pre-shared-key'}->key = $ike_gat_pre_shared_key;
                                    }
                                    elseif($ike_gat_type_authentication == "certificate"){

                                        if($version < 7){

                                            $ike_gateways->addChild("authentication");

                                            if($ike_gat_allow_id_payload_mismatch == "yes"){
                                                $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                                            }
                                            $ike_gateways->authentication->certificate->{'local-certificate'} = $ike_gat_local_certificate;
                                            $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                                            if($ike_gat_strict_validation_revocation == "yes"){
                                                $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                                            }
                                        }
                                        else{
                                            // Version 7
                                            $ike_gateways->addChild("authentication");

                                            if($ike_gat_local_certificate != ""){
                                                $ike_gateways->authentication->certificate->{'local-certificate'}->name = $ike_gat_local_certificate;

                                                if($ike_gat_hash_and_url == "yes"){
                                                    $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->enable = $ike_gat_hash_and_url;
                                                    $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->{'base-url'} = $ike_gat_base_url;
                                                }
                                            }
                                            if($ike_gat_allow_id_payload_mismatch == "yes"){
                                                $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                                            }
                                            $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                                            if($ike_gat_strict_validation_revocation == "yes"){
                                                $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                                            }
                                        }
                                    }

                                    // FALTA HASH AND URL / BASE URL PARA LA VERSIÓN 7

                                    if($ike_gat_nat_traversal != ""){
                                        $ike_gateways->addChild("protocol-common");
                                        $ike_gateways->{'protocol-common'}->{'nat-traversal'}->enable = $ike_gat_nat_traversal;
                                        if($ike_gat_passive_mode == "yes"){
                                            $ike_gateways->{'protocol-common'}->{'passive-mode'} = $ike_gat_passive_mode;
                                        }
                                        if ($version > 5) {
                                            if($ike_gat_fragmentation == ""){
                                                $ike_gat_fragmentation = "no";
                                            }
                                            $ike_gateways->{'protocol-common'}->fragmentation->enable = $ike_gat_fragmentation;
                                        }

                                    }

                                    if($ike_gat_peer_ip_type == "static"){
                                        $ike_gateways->addChild("peer-address");
                                        $ike_gateways->{'peer-address'}->ip = $ike_gat_peer_ip_address;
                                    }else{
                                        $ike_gateways->addChild("peer-address");
                                        $ike_gateways->{'peer-address'}->addChild("dynamic");
                                    }

                                    if($ike_gat_local_id != ""){
                                        $ike_gateways->addChild("local-id");
                                        $ike_gateways->{'local-id'}->id = $ike_gat_local_id;
                                        $ike_gateways->{'local-id'}->type = $ike_gat_local_id_type;
                                    }

                                    if($ike_gat_peer_id != ""){
                                        $ike_gateways->addChild("peer-id");
                                        $ike_gateways->{'peer-id'}->id = $ike_gat_peer_id;
                                        $ike_gateways->{'peer-id'}->type = $ike_gat_peer_id_type;
                                        if($ike_gat_peer_id_matching != ""){
                                            $ike_gateways->{'peer-id'}->matching = $ike_gat_peer_id_matching;
                                        }
                                    }

                                    // Version 7
                                    if($ike_gat_address_type == "ipv6"){
                                        $ike_gateways->ipv6 = "yes";
                                    }

                                }
                            }
                        }

                        # GLOBAL PROTECT IPSEC CRYPTO
                        $getIKECrypto = $projectdb->query("SELECT name, encryption, hash FROM global_protect_app_ipsec_crypto_profiles WHERE source='$source' AND template='$template' AND name != '';");
                        if ($getIKECrypto->num_rows >0){

                            if($create_branch_ike_crypto_profile == 0){
                                $myTemplateDeviceNetworkIKE_CRYPTO = $myTemplateDeviceNetworkIKE->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }

                            $myTemplateDeviceNetworkIKE_CRYPTO->addChild("global-protect-app-crypto-profiles");

                            $ike_crypto_path = $myTemplateDeviceNetworkIKE_CRYPTO->{'global-protect-app-crypto-profiles'};

                            while ($dataIKEC = $getIKECrypto->fetch_assoc()){
                                $myname = $dataIKEC['name'];
                                $ike_encryption = $dataIKEC['encryption'];
                                $ike_hash = $dataIKEC['hash'];

                                if ($ike_crypto_path->xpath("//entry[@name='$myname']") == null) {

                                    $ike_crypto = $ike_crypto_path->addChild('entry');
                                    $ike_crypto->addAttribute('name', $dataIKEC['name']);

                                    if ($ike_encryption != ""){
                                        $ike_crypto->addChild("encryption");
                                        $ike_encryption_array = explode(",", $ike_encryption);
                                        foreach($ike_encryption_array as $member_ike){
                                            $ike_crypto->encryption->addChild("member", $member_ike);
                                        }
                                    }
                                    if ($ike_hash != ""){
                                        $ike_crypto->addChild("authentication");
                                        $ike_hash_array = explode(",", $ike_hash);
                                        foreach($ike_hash_array as $member_ike){
                                            $ike_crypto->authentication->addChild("member", $member_ike);
                                        }
                                    }
                                }
                            }
                        }

                        # Template - Device - Network - TUNNEL
                        $myTemplateDeviceNetworkTunnel = $myTemplateDeviceNetwork->addChild("tunnel");

                        # IPSEC TUNNEL
                        $getIPSecTunnel = $projectdb->query("SELECT id, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, encryption, key_encry, local_address_ip, interface, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, local_certificate, publish_connected_routes, portal_address, publish_routes FROM ipsec_tunnel WHERE source = '$source' AND template = '$template' AND name != '';");
                        if ($getIPSecTunnel->num_rows > 0){

                            $ike_ipsec_tunnel_xpath = $myTemplateDeviceNetworkTunnel->addChild("ipsec");

                            while ($dataIPSecTunnel = $getIPSecTunnel->fetch_assoc()){
                                $myname = $dataIPSecTunnel['name'];
                                $ipsec_tun_id = $dataIPSecTunnel['id'];
                                $ipsec_tun_anti_replay = $dataIPSecTunnel['anti_replay'];
                                $ipsec_tun_copy_tos = $dataIPSecTunnel['copy_tos'];
                                $ipsec_tun_tunnel_monitor = $dataIPSecTunnel['tunnel_monitor'];
                                $ipsec_tun_destination_ip = $dataIPSecTunnel['destination_ip'];
                                $ipsec_tun_tunnel_monitor_profile = $dataIPSecTunnel['tunnel_monitor_profile'];
                                $ipsec_tun_tunnel_interface = $dataIPSecTunnel['tunnel_interface'];
                                $ipsec_tun_address_type = $dataIPSecTunnel['address_type'];
                                $ipsec_tun_type_tunnel = $dataIPSecTunnel['type_tunnel'];
                                $ipsec_tun_ike_gateway = $dataIPSecTunnel['ike_gateway'];
                                $ipsec_tun_ipsec_crypto_profile = $dataIPSecTunnel['ipsec_crypto_profile'];
                                $ipsec_tun_protocol = $dataIPSecTunnel['protocol'];
                                $ipsec_tun_authentication = $dataIPSecTunnel['authentication'];
                                $ipsec_tun_key_auth = $dataIPSecTunnel['key_auth'];
                                $ipsec_tun_encryption = $dataIPSecTunnel['encryption'];
                                $ipsec_tun_key_encry = $dataIPSecTunnel['key_encry'];
                                $ipsec_tun_local_address_ip = $dataIPSecTunnel['local_address_ip'];
                                $ipsec_tun_interface = $dataIPSecTunnel['interface'];
                                $ipsec_tun_peer_ip_address = $dataIPSecTunnel['peer_ip_address'];
                                $ipsec_tun_local_spi = $dataIPSecTunnel['local_spi'];
                                $ipsec_tun_remote_spi = $dataIPSecTunnel['remote_spi'];
                                $ipsec_tun_external_ca = $dataIPSecTunnel['external_ca'];
                                $ipsec_tun_certificate_profile = $dataIPSecTunnel['certificate_profile'];
                                $ipsec_tun_local_certificate = $dataIPSecTunnel['local_certificate'];
                                $ipsec_tun_publish_connected_routes = $dataIPSecTunnel['publish_connected_routes'];
                                $ipsec_tun_portal_address = $dataIPSecTunnel['portal_address'];
                                $ipsec_tun_publish_routes = $dataIPSecTunnel['publish_routes'];

                                if ($ike_ipsec_tunnel_xpath->xpath("//entry[@name='$myname']") == null) {

                                    $ipsec_tunnel = $ike_ipsec_tunnel_xpath->addChild('entry');
                                    $ipsec_tunnel->addAttribute('name', $dataIPSecTunnel['name']);

                                    # Auto Key
                                    if($ipsec_tun_type_tunnel == "auto-key"){

                                        $ipsec_tunnel->addChild("auto-key");

                                        if($ipsec_tun_ike_gateway != ""){
                                            $ipsec_tunnel->{'auto-key'}->addChild("ike-gateway");
                                            $ipsec_tunnel->{'auto-key'}->{'ike-gateway'}->addChild('entry')->addAttribute('name', $ipsec_tun_ike_gateway);
                                        }

                                        // Mirar si hay Proxy ID type = v4
                                        $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v4' AND template = '$template' AND source = '$source';");
                                        if ($getProxyID->num_rows > 0){

                                            $ipsec_tunnel->{'auto-key'}->addChild("proxy-id");
                                            $ike_ipsec_tunnel_xpath_proxy_id = $ipsec_tunnel->{'auto-key'}->{'proxy-id'};

                                            while($dataPI = $getProxyID->fetch_assoc()){

                                                $name_proxy_id = $dataPI['name'];
                                                $protocol_proxy_id = $dataPI['protocol'];
                                                $local_port_proxy_id = $dataPI['local_port'];
                                                $remote_port_proxy_id = $dataPI['remote_port'];
                                                $number_proxy_id = $dataPI['number'];
                                                $local_proxy_id = $dataPI['local'];
                                                $remote_proxy_id = $dataPI['remote'];
                                                $type_proxy_id = $dataPI['type'];

                                                $ipsec_tunnel_proxy_id = $ike_ipsec_tunnel_xpath_proxy_id->addChild('entry');
                                                $ipsec_tunnel_proxy_id->addAttribute('name', $name_proxy_id);

                                                if ($protocol_proxy_id == "TCP"){
                                                    $ipsec_tunnel_proxy_id->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id->protocol->addChild("tcp");
                                                    //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                                                    if($local_port_proxy_id == ""){
                                                        $local_port_proxy_id = 0;
                                                    }
                                                    if($remote_port_proxy_id == ""){
                                                        $remote_port_proxy_id = 0;
                                                    }
                                                    $ipsec_tunnel_proxy_id->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                                                    $ipsec_tunnel_proxy_id->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                                                }
                                                elseif($protocol_proxy_id == "Number"){
                                                    $ipsec_tunnel_proxy_id->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id->protocol->addChild("number");
                                                    $ipsec_tunnel_proxy_id->protocol->number = $number_proxy_id;
                                                }
                                                elseif($protocol_proxy_id == "Any"){
                                                    $ipsec_tunnel_proxy_id->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id->protocol->addChild("any");;
                                                }
                                                elseif($protocol_proxy_id == "UDP"){
                                                    $ipsec_tunnel_proxy_id->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id->protocol->addChild("udp");
                                                    if($local_port_proxy_id == ""){
                                                        $local_port_proxy_id = 0;
                                                    }
                                                    if($remote_port_proxy_id == ""){
                                                        $remote_port_proxy_id = 0;
                                                    }
                                                    $ipsec_tunnel_proxy_id->protocol->udp->{'local-port'} = $local_port_proxy_id;
                                                    $ipsec_tunnel_proxy_id->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                                                }

                                                if($local_proxy_id != ""){
                                                    $ipsec_tunnel_proxy_id->addChild("local");
                                                    $ipsec_tunnel_proxy_id->local = $local_proxy_id;
                                                }
                                                if($remote_proxy_id != ""){
                                                    $ipsec_tunnel_proxy_id->addChild("remote");
                                                    $ipsec_tunnel_proxy_id->remote = $remote_proxy_id;
                                                }
                                            }
                                        }

                                        // Mirar si hay Proxy ID type = v6
                                        $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v6' AND template = '$template' AND source = '$source';");
                                        if ($getProxyID->num_rows > 0){

                                            $ipsec_tunnel->{'auto-key'}->addChild("proxy-id-v6");
                                            $ike_ipsec_tunnel_xpath_proxy_id_v6 = $ipsec_tunnel->{'auto-key'}->{'proxy-id-v6'};

                                            while($dataPI = $getProxyID->fetch_assoc()){

                                                $name_proxy_id = $dataPI['name'];
                                                $protocol_proxy_id = $dataPI['protocol'];
                                                $local_port_proxy_id = $dataPI['local_port'];
                                                $remote_port_proxy_id = $dataPI['remote_port'];
                                                $number_proxy_id = $dataPI['number'];
                                                $local_proxy_id = $dataPI['local'];
                                                $remote_proxy_id = $dataPI['remote'];
                                                $type_proxy_id = $dataPI['type'];

                                                $ipsec_tunnel_proxy_id_v6 = $ike_ipsec_tunnel_xpath_proxy_id_v6->addChild('entry');
                                                $ipsec_tunnel_proxy_id_v6->addAttribute('name', $name_proxy_id);

                                                if ($protocol_proxy_id == "TCP"){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->addChild("tcp");
                                                    //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                                                    if($local_port_proxy_id == ""){
                                                        $local_port_proxy_id = 0;
                                                    }
                                                    if($remote_port_proxy_id == ""){
                                                        $remote_port_proxy_id = 0;
                                                    }
                                                    $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                                                    $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                                                }
                                                elseif($protocol_proxy_id == "Number"){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->addChild("number");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->number = $number_proxy_id;
                                                }
                                                elseif($protocol_proxy_id == "Any"){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->addChild("any");;
                                                }
                                                elseif($protocol_proxy_id == "UDP"){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->addChild("udp");
                                                    if($local_port_proxy_id == ""){
                                                        $local_port_proxy_id = 0;
                                                    }
                                                    if($remote_port_proxy_id == ""){
                                                        $remote_port_proxy_id = 0;
                                                    }
                                                    $ipsec_tunnel_proxy_id_v6->protocol->udp->{'local-port'} = $local_port_proxy_id;
                                                    $ipsec_tunnel_proxy_id_v6->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                                                }

                                                if($local_proxy_id != ""){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("local");
                                                    $ipsec_tunnel_proxy_id_v6->local = $local_proxy_id;
                                                }
                                                if($remote_proxy_id != ""){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("remote");
                                                    $ipsec_tunnel_proxy_id_v6->remote = $remote_proxy_id;
                                                }
                                            }
                                        }

                                        if($ipsec_tun_ipsec_crypto_profile != ""){
                                            $ipsec_tunnel->{'auto-key'}->addChild("ipsec-crypto-profile");
                                            $ipsec_tunnel->{'auto-key'}->{'ipsec-crypto-profile'} = $ipsec_tun_ipsec_crypto_profile;
                                        }
                                    } # Manual Key
                                    elseif ($ipsec_tun_type_tunnel == "manual-key"){

                                        $ipsec_tunnel->addChild("manual-key");

                                        if($ipsec_tun_protocol == "ESP"){

                                            $ipsec_tunnel->{'manual-key'}->addChild("esp");

                                            if($ipsec_tun_authentication == "none"){
                                                $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                                                $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild("none");
                                            }else{
                                                //authentication->md5->key
                                                $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                                                $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild($ipsec_tun_authentication);
                                                $ipsec_tunnel->{'manual-key'}->esp->authentication->{$ipsec_tun_authentication}->key = $ipsec_tun_key_auth;
                                            }

                                            if($ipsec_tun_encryption != ""){
                                                $ipsec_tunnel->{'manual-key'}->esp->addChild("encryption");
                                                $ipsec_tunnel->{'manual-key'}->esp->encryption->algorithm = $ipsec_tun_encryption;

                                                if($ipsec_tun_key_encry != ""){
                                                    $ipsec_tunnel->{'manual-key'}->esp->encryption->key = $ipsec_tun_key_encry;
                                                }
                                            }
                                        }

                                        if($ipsec_tun_protocol == "AH"){

                                            $ipsec_tunnel->{'manual-key'}->addChild("ah");

                                            if($ipsec_tun_authentication == "none"){
                                                $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                                                $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild("none");
                                            }else{
                                                //authentication->md5->key
                                                $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                                                $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild($ipsec_tun_authentication);
                                                $ipsec_tunnel->{'manual-key'}->ah->authentication->{$ipsec_tun_authentication}->key = $ipsec_tun_key_auth;
                                            }
                                        }

                                        if($ipsec_tun_interface != ""){
                                            $ipsec_tunnel->{'manual-key'}->addChild("local-address");
                                            if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                                                $ipsec_tunnel->{'manual-key'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                                            }
                                            $ipsec_tunnel->{'manual-key'}->{'local-address'}->interface = $ipsec_tun_interface;
                                        }

                                        if($ipsec_tun_peer_ip_address != ""){
                                            $ipsec_tunnel->{'manual-key'}->addChild("peer-address");
                                            $ipsec_tunnel->{'manual-key'}->{'peer-address'}->ip = $ipsec_tun_peer_ip_address;
                                        }

                                        if($ipsec_tun_local_spi != ""){
                                            $ipsec_tunnel->{'manual-key'}->{'local-spi'} = $ipsec_tun_local_spi;
                                        }

                                        if($ipsec_tun_remote_spi != ""){
                                            $ipsec_tunnel->{'manual-key'}->{'remote-spi'} = $ipsec_tun_remote_spi;
                                        }

                                    } # Global Protect Satellite
                                    elseif ($ipsec_tun_type_tunnel == "global-protect-satellite"){

                                        $ipsec_tunnel->addChild("global-protect-satellite");

                                        if($ipsec_tun_publish_connected_routes == "yes"){
                                            $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-connected-routes");
                                            $ipsec_tunnel->{'global-protect-satellite'}->{'publish-connected-routes'}->enable = $ipsec_tun_publish_connected_routes;
                                        }

                                        if($ipsec_tun_interface != ""){
                                            $ipsec_tunnel->{'global-protect-satellite'}->addChild("local-address");
                                            if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                                                $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                                            }
                                            $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->interface = $ipsec_tun_interface;
                                        }

                                        if($ipsec_tun_portal_address != ""){
                                            $ipsec_tunnel->{'global-protect-satellite'}->{'portal-address'} = $ipsec_tun_portal_address;
                                        }

                                        if($ipsec_tun_publish_routes != ""){
                                            $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-routes");
                                            $ipsec_tun_publish_routes_array = explode(",", $ipsec_tun_publish_routes);
                                            foreach($ipsec_tun_publish_routes_array as $member_publish){
                                                $ipsec_tunnel->{'global-protect-satellite'}->{'publish-routes'}->addChild("member", $member_publish);
                                            }
                                        }

                                        if($ipsec_tun_external_ca == "yes"){
                                            $ipsec_tunnel->{'global-protect-satellite'}->addChild("external-ca");
                                            if($ipsec_tun_certificate_profile != ""){
                                                $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'certificate-profile'} = $ipsec_tun_certificate_profile;
                                            }
                                            if($ipsec_tun_local_certificate != ""){
                                                $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'local-certificate'} = $ipsec_tun_local_certificate;
                                            }
                                        }

                                    }

                                    if($ipsec_tun_tunnel_monitor != ""){
                                        $ipsec_tunnel->addChild("tunnel-monitor");
                                        $ipsec_tunnel->{'tunnel-monitor'}->enable = $ipsec_tun_tunnel_monitor;

                                        if($ipsec_tun_destination_ip != ""){
                                            $ipsec_tunnel->{'tunnel-monitor'}->{'destination-ip'} = $ipsec_tun_destination_ip;
                                        }

                                        if($ipsec_tun_tunnel_monitor_profile != ""){
                                            $ipsec_tunnel->{'tunnel-monitor'}->{'tunnel-monitor-profile'} = $ipsec_tun_tunnel_monitor_profile;
                                        }
                                    }

                                    if($ipsec_tun_copy_tos == "yes"){
                                        $ipsec_tunnel->{'copy-tos'} = $ipsec_tun_copy_tos;
                                    }

                                    // Version 7
                                    if($ipsec_tun_address_type == "ipv6"){
                                        $ipsec_tunnel->ipv6 = "yes";
                                    }

                                    if($ipsec_tun_tunnel_interface != ""){
                                        $ipsec_tunnel->{'tunnel-interface'} = $ipsec_tun_tunnel_interface;
                                    }

                                    if($ipsec_tun_anti_replay == "yes"){
                                        $ipsec_tunnel->{'anti_replay'} = $ipsec_tun_anti_replay;
                                    }
                                }
                            }
                        }

                        # Template - Device - Network - Interfaces
                        $myTemplateDeviceNetwork->addChild("interface");
                        $theINT = $myTemplateDeviceNetwork->interface;

                        #Interfaces
                        $getInterfaces = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' LIMIT 1;");
                        if ($getInterfaces->num_rows > 0) {
                            #Aggregate-Ethernet
                            $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND unitname=name GROUP BY name ORDER BY name");
                            if ($getIntEthernet->num_rows > 0) {
                                $theINT->addChild("aggregate-ethernet");
                                while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                    $myname = $getIntEthernetData['name'];
                                    $int2 = $theINT->{'aggregate-ethernet'}->addChild('entry');
                                    $int2->addAttribute('name', $myname);

                                    if ($getIntEthernetData['comment'] != "") {
                                        $int2->addChild("comment");
                                        $int2->comment = $getIntEthernetData['comment'];
                                    }

                                    if ($getIntEthernetData['type'] == "virtual-wire") {
                                        $int2->addChild("virtual-wire");
                                        if ($getIntEthernetData['netflow_profile'] != "") {
                                            $int2->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                        }
                                        $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                        if ($getUnits->num_rows > 0) {
                                            $int2->{'virtual-wire'}->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $VWUnit = $int2->{'virtual-wire'}->units->addChild('entry');
                                                $VWUnit->addAttribute('name', $myname1);
                                                if ($getUnitsData['comment'] != "") {
                                                    $VWUnit->addChild("comment");
                                                    $VWUnit->comment = $getUnitsData['comment'];
                                                }
                                                if ($getUnitsData['netflow_profile'] != "") {
                                                    $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                }

                                                $VWUnit->addChild("tag", $getUnitsData['unittag']);

                                                if ($getUnitsData['ip_classifier'] != "") {
                                                    $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                                    $VWUnit->addChild("ip-classifier");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if ($getIntEthernetData['type'] == "layer2") {
                                        $int2->addChild("layer2");
                                        if ($getIntEthernetData['netflow_profile'] != "") {
                                            $int2->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                        }
                                        if ($version>=7){
                                            if ($getIntEthernetData['lldp'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                                SimpleXMLElement_append($int2->layer2, $xml_append);
                                            }
                                        }
                                        $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                        if ($getUnits->num_rows > 0) {
                                            $int2->{'layer2'}->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $VWUnit = $int2->{'layer2'}->units->addChild('entry');
                                                $VWUnit->addAttribute('name', $myname1);
                                                if ($getUnitsData['netflow_profile'] != "") {
                                                    $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                }
                                                if ($getUnitsData['comment'] != "") {
                                                    $VWUnit->addChild("comment");
                                                    $VWUnit->comment = $getUnitsData['comment'];
                                                }
                                                $VWUnit->addChild("tag", $getUnitsData['unittag']);
                                            }
                                        }
                                    }
                                    elseif ($getIntEthernetData['type'] == "ha") {
                                        $int2->addChild("ha");
                                    }
                                    elseif ($getIntEthernetData['type'] == "layer3") {
                                        $int2->addChild("layer3");
                                        if ($getIntEthernetData['netflow_profile'] != "") {
                                            $int2->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                        }
                                        if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                            $int2->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                                        }
                                        if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                            $int2->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                        }

                                        if ($getIntEthernetData['untagged_sub_interface'] != "") {
                                            $int2->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                                        }
                                        if ($getIntEthernetData['arp'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                            SimpleXMLElement_append($int2->layer3, $xml_append);
                                        }
                                        if ($version>=7){
                                            if ($getIntEthernetData['lldp'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                                SimpleXMLElement_append($int2->layer3, $xml_append);
                                            }
                                            if ($getIntEthernetData['ndpproxy'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                                SimpleXMLElement_append($int2->layer3, $xml_append);
                                            }
                                        }
                                        if ($getIntEthernetData['ipv4_type'] == "static") {
                                            if ($getIntEthernetData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                                SimpleXMLElement_append($int2->layer3, $xml_append);
                                            }
                                            if ($getIntEthernetData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                                $int2->layer3->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $int2->layer3->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                                $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                            }
                                        } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                            $int2->layer3->addChild("dhcp-client");
                                            if ($getIntEthernetData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                                SimpleXMLElement_append($int2->layer3, $xml_append);
                                            }
                                            if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                                $int2->layer3->{"dhcp-client"}->addChild("enable", "no");
                                            }
                                            if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                                $int2->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                            }
                                            if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                                $int2->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                                            }
                                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                                $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                            }
                                        }
                                        # UNITS
                                        $queryUnits = "SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';";
//                                        echo $queryUnits;
                                        $getUnits = $projectdb->query($queryUnits);
                                        if ($getUnits->num_rows > 0) {
                                            $unit = $int2->layer3->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $UnitInt = $unit->addChild('entry');
                                                $UnitInt->addAttribute('name', $myname1);
                                                if ($getUnitsData['netflow_profile'] != "") {
                                                    $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                }
                                                if ($getUnitsData['unittag']!=0){
                                                    $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                                }
                                                if ($getUnitsData['comment'] != "") {
                                                    $UnitInt->addChild("comment");
                                                    $UnitInt->comment = $getUnitsData['comment'];
                                                }
                                                if ($version>=7){
                                                    if ($getUnitsData['ndpproxy'] != "") {
                                                        $xml_append = simplexml_load_string($getUnitsData['ndpproxy']);
                                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                                    }
                                                }
                                                if ($getUnitsData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                                if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                    $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                                }
                                                if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                    $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                                }
                                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                    $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                                }
                                                if ($getUnitsData['arp'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['arp']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                                if ($getUnitsData['ipv4_type'] == "static") {
                                                    if ($getUnitsData['unitipaddress'] != "") {
                                                        $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                        $UnitInt->addChild("ip");
                                                        foreach ($interfaces_all as $key => $int_value) {
                                                            $newInt = $UnitInt->ip->addChild("entry");
                                                            $newInt->addAttribute('name', $int_value);
                                                        }
                                                    }
                                                } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                                    $UnitInt->addChild("dhcp-client");

                                                    if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                        $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                                    }
                                                    if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                        $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                                    }
                                                    if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                        $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                                        $int2->addChild("decrypt-mirror");
                                    }
                                    if ($getIntEthernetData['lacp'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['lacp']);
                                        SimpleXMLElement_append($int2->{$getIntEthernetData['type']}, $xml_append);
                                    }
                                }
                            }
                            #Ethernet
                            $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unittag='0' AND unitname=name GROUP BY name ORDER BY name");
                            if ($getIntEthernet->num_rows > 0) {
                                $theINT->addChild("ethernet");
                                while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                    $myname = $getIntEthernetData['name'];
                                    $int = $theINT->ethernet->addChild('entry');
                                    $int->addAttribute('name', $myname);

                                    if ($version>=7){
                                        if ($getIntEthernetData['link_speed'] != "")  {
                                            $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                                        }
                                        if ($getIntEthernetData['link_duplex'] != "")  {
                                            $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                                        }
                                        if ($getIntEthernetData['link_state'] != "")  {
                                            $int->addChild("link-state", $getIntEthernetData['link_state']);
                                        }
                                    }
                                    else{
                                        if (($getIntEthernetData['link_speed'] != "") AND ( $getIntEthernetData['link_speed'] != "auto")) {
                                            $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                                        }
                                        if (($getIntEthernetData['link_duplex'] != "") AND ( $getIntEthernetData['link_duplex'] != "auto")) {
                                            $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                                        }
                                        if (($getIntEthernetData['link_state'] != "") AND ( $getIntEthernetData['link_state'] != "auto")) {
                                            $int->addChild("link-state", $getIntEthernetData['link_state']);
                                        }
                                    }


                                    if ($getIntEthernetData['comment'] != "") {
                                        $int->addChild("comment");
                                        $int->comment = $getIntEthernetData['comment'];
                                    }
                                    if ($getIntEthernetData['type'] == "tap") {
                                        $int->addChild("tap");
                                        if ($getIntEthernetData['netflow_profile'] != "") {
                                            $int->tap->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                        }
                                    }
                                    if ($getIntEthernetData['type'] == "virtual-wire") {
                                        $int->addChild("virtual-wire");
                                        if ($getIntEthernetData['netflow_profile'] != "") {
                                            $int->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                        }
                                        $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                                        if ($getUnits->num_rows > 0) {
                                            $int->{'virtual-wire'}->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $VWUnit = $int->{'virtual-wire'}->units->addChild('entry');
                                                $VWUnit->addAttribute('name', $myname1);
                                                if ($getUnitsData['comment'] != "") {
                                                    $VWUnit->addChild("comment");
                                                    $VWUnit->comment = $getUnitsData['comment'];
                                                }
                                                if ($getUnitsData['netflow_profile'] != "") {
                                                    $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                }

                                                $VWUnit->addChild("tag", $getUnitsData['unittag']);

                                                if ($getUnitsData['ip_classifier'] != "") {
                                                    $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                                    $VWUnit->addChild("ip-classifier");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if ($getIntEthernetData['type'] == "layer2") {
                                        $int->addChild("layer2");
                                        if ($getIntEthernetData['netflow_profile'] != "") {
                                            $int->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                        }
                                        if ($version>=7){
                                            if ($getIntEthernetData['lldp'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                                SimpleXMLElement_append($int->layer2, $xml_append);
                                            }
                                        }
                                        $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                                        if ($getUnits->num_rows > 0) {
                                            $int->{'layer2'}->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $VWUnit = $int->{'layer2'}->units->addChild('entry');
                                                $VWUnit->addAttribute('name', $myname1);
                                                if ($getUnitsData['netflow_profile'] != "") {
                                                    $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                }
                                                if ($getUnitsData['comment'] != "") {
                                                    $VWUnit->addChild("comment");
                                                    $VWUnit->comment = $getUnitsData['comment'];
                                                }
                                                $VWUnit->addChild("tag", $getUnitsData['unittag']);
                                            }
                                        }
                                    }
                                    elseif ($getIntEthernetData['type'] == "ha") {
                                        $int->addChild("ha");
                                    }
                                    elseif ($getIntEthernetData['type'] == "layer3") {
                                        $int->addChild("layer3");
                                        if ($getIntEthernetData['netflow_profile'] != "") {
                                            $int->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                        }
                                        if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                            $int->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                                        }
                                        if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                            $int->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                        }

                                        if ($getIntEthernetData['untagged_sub_interface'] != "") {
                                            $int->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                                        }
                                        if ($getIntEthernetData['arp'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                            SimpleXMLElement_append($int->layer3, $xml_append);
                                        }
                                        if ($version>=7){
                                            if ($getIntEthernetData['lldp'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                                SimpleXMLElement_append($int->layer3, $xml_append);
                                            }
                                            if ($getIntEthernetData['ndpproxy'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                                SimpleXMLElement_append($int->layer3, $xml_append);
                                            }
                                        }
                                        if ($getIntEthernetData['ipv4_type'] == "static") {
                                            if ($getIntEthernetData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                                SimpleXMLElement_append($int->layer3, $xml_append);
                                            }
                                            if ($getIntEthernetData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                                $int->layer3->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $int->layer3->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                                $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                            }
                                        } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                            $int->layer3->addChild("dhcp-client");
                                            if ($getIntEthernetData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                                SimpleXMLElement_append($int->layer3, $xml_append);
                                            }
                                            if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                                $int->layer3->{"dhcp-client"}->addChild("enable", "no");
                                            }
                                            if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                                $int->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                            }
                                            if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                                $int->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                                            }
                                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                                $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                            }
                                        }
                                        # UNITS
                                        $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' unitname!='$myname' AND name='$myname';");
                                        if ($getUnits->num_rows > 0) {
                                            $unit = $int->layer3->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $UnitInt = $unit->addChild('entry');
                                                $UnitInt->addAttribute('name', $myname1);
                                                if ($getUnitsData['netflow_profile'] != "") {
                                                    $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                }
                                                if ($getUnitsData['unittag']!=0){
                                                    $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                                }
                                                if ($getUnitsData['comment'] != "") {
                                                    $UnitInt->addChild("comment");
                                                    $UnitInt->comment = $getUnitsData['comment'];
                                                }
                                                if ($getUnitsData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                                if ($version>=7){
                                                    if ($getUnitsData['ndpproxy'] != "") {
                                                        $xml_append = simplexml_load_string($getUnitsData['ndpproxy']);
                                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                                    }
                                                }
                                                if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                    $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                                }
                                                if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                    $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                                }
                                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                    $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                                }
                                                if ($getUnitsData['arp'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['arp']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                                if ($getUnitsData['ipv4_type'] == "static") {
                                                    if ($getUnitsData['unitipaddress'] != "") {
                                                        $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                        $UnitInt->addChild("ip");
                                                        foreach ($interfaces_all as $key => $int_value) {
                                                            $newInt = $UnitInt->ip->addChild("entry");
                                                            $newInt->addAttribute('name', $int_value);
                                                        }
                                                    }
                                                } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                                    $UnitInt->addChild("dhcp-client");

                                                    if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                        $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                                    }
                                                    if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                        $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                                    }
                                                    if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                        $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                                        $int->addChild("decrypt-mirror");
                                    }
                                    if ($getIntEthernetData['type'] == "aggregate-group"){
                                        $int->addChild("aggregate-group",$getIntEthernetData['aggregate_group']);
                                    }
                                    if ($getIntEthernetData['type'] == "log-card") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['log_card']);
                                        SimpleXMLElement_append($int, $xml_append);
                                    }
                                }
                            }
                            # Vlan
                            $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND name='vlan' GROUP BY name ORDER BY name");
                            if ($getIntEthernet->num_rows > 0) {
                                $vlanint = $theINT->addChild("vlan");
                                while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                    if ($getIntEthernetData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                        SimpleXMLElement_append($vlanint, $xml_append);
                                    }
                                    if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                        $vlanint->addChild("mtu", $getIntEthernetData['mtu']);
                                    }
                                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                        $vlanint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                    }
                                    if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                        $vlanint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                    }
                                    if ($getIntEthernetData['arp'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                        SimpleXMLElement_append($vlanint, $xml_append);
                                    }
                                    if ($version>=7){
                                        if ($getIntEthernetData['ndpproxy'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                            SimpleXMLElement_append($vlanint, $xml_append);
                                        }
                                    }
                                    if ($getIntEthernetData['comment'] != "") {
                                        $vlanint->addChild("comment");
                                        $vlanint->comment = $getIntEthernetData['comment'];
                                    }
                                    if ($getIntEthernetData['ipv4_type'] == "static") {
                                        if ($getIntEthernetData['unitipaddress'] != "") {
                                            $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                            $vlanint->addChild("ip");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $newInt = $vlanint->ip->addChild("entry");
                                                $newInt->addAttribute('name', $int_value);
                                            }
                                        }
                                    } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                        $vlanint->addChild("dhcp-client");
                                        if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                            $vlanint->{"dhcp-client"}->addChild("enable", "no");
                                        }
                                        if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                            $vlanint->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                        }
                                        if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                            $vlanint->{"dhcp-client"}->addChild("create-default-route", "no");
                                        }
                                    }
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND unitname!='vlan';");
                                    if ($getUnits->num_rows > 0) {
                                        $vlanint->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $UnitInt = $vlanint->units->addChild('entry');
                                            $UnitInt->addAttribute('name', $myname1);
                                            if ($getUnitsData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                            if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                            }
                                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                            }
                                            if ($getUnitsData['comment'] != "") {
                                                $UnitInt->addChild("comment");
                                                $UnitInt->comment = $getUnitsData['comment'];
                                            }
                                            if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                            }
                                            if ($getUnitsData['arp'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['arp']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                            if ($getUnitsData['ipv4_type'] == "static") {
                                                if ($getUnitsData['unitipaddress'] != "") {
                                                    $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                    $UnitInt->addChild("ip");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $newInt = $UnitInt->ip->addChild("entry");
                                                        $newInt->addAttribute('name', $int_value);
                                                    }
                                                }
                                            } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                                $UnitInt->addChild("dhcp-client");
                                                if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                    $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                                }
                                                if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                    $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                                }
                                                if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                    $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            # Loopback
                            $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND name='loopback' GROUP BY name ORDER BY name");
                            if ($getIntEthernet->num_rows > 0) {
                                $loopackint = $theINT->addChild("loopback");
                                while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                    if ($getIntEthernetData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                        SimpleXMLElement_append($loopackint, $xml_append);
                                    }
                                    if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                        $loopackint->addChild("mtu", $getIntEthernetData['mtu']);
                                    }
                                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                        $loopackint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                    }
                                    if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                        $loopackint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                    }
                                    if ($getIntEthernetData['comment'] != "") {
                                        $loopackint->addChild("comment");
                                        $loopackint->comment = $getIntEthernetData['comment'];
                                    }
                                    if ($getIntEthernetData['ipv4_type'] == "static") {
                                        if ($getIntEthernetData['unitipaddress'] != "") {
                                            $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                            $loopackint->addChild("ip");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $newInt = $loopackint->ip->addChild("entry");
                                                $newInt->addAttribute('name', $int_value);
                                            }
                                        }
                                    }
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND unitname!='loopback';");
                                    if ($getUnits->num_rows > 0) {
                                        $unit = $loopackint->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $UnitInt = $unit->addChild('entry');
                                            $UnitInt->addAttribute('name', $myname1);
                                            if ($getUnitsData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                            if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                            }
                                            if ($getUnitsData['comment'] != "") {
                                                $UnitInt->addChild("comment");
                                                $UnitInt->comment = $getUnitsData['comment'];
                                            }
                                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                            }
                                            if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                            }
                                            if ($getUnitsData['ipv4_type'] == "static") {
                                                if ($getUnitsData['unitipaddress'] != "") {
                                                    $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                    $UnitInt->addChild("ip");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $newInt = $UnitInt->ip->addChild("entry");
                                                        $newInt->addAttribute('name', $int_value);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            # Tunnel
                            $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND name='tunnel' GROUP BY name ORDER BY name");
                            if ($getIntEthernet->num_rows > 0) {
                                $tunnelint = $theINT->addChild("tunnel");
                                while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                    if ($getIntEthernetData['ipv6'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                        SimpleXMLElement_append($tunnelint, $xml_append);
                                    }
                                    if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                        $tunnelint->addChild("mtu", $getIntEthernetData['mtu']);
                                    }
                                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                        $tunnelint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                    }
                                    if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                        $tunnelint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                    }
                                    if ($getIntEthernetData['comment'] != "") {
                                        $tunnelint->addChild("comment");
                                        $tunnelint->comment = $getIntEthernetData['comment'];
                                    }
                                    if ($getIntEthernetData['ipv4_type'] == "static") {
                                        if ($getIntEthernetData['unitipaddress'] != "") {
                                            $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                            $tunnelint->addChild("ip");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $newInt = $tunnelint->ip->addChild("entry");
                                                $newInt->addAttribute('name', $int_value);
                                            }
                                        }
                                    }
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND unitname!='tunnel';");
                                    if ($getUnits->num_rows > 0) {
                                        $unit = $tunnelint->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $UnitInt = $unit->addChild('entry');
                                            $UnitInt->addAttribute('name', $myname1);
                                            if ($getUnitsData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                            if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                            }
                                            if ($getUnitsData['comment'] != "") {
                                                $UnitInt->addChild("comment");
                                                $UnitInt->comment = $getUnitsData['comment'];
                                            }
                                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                            }
                                            if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                            }
                                            if ($getUnitsData['ipv4_type'] == "static") {
                                                if ($getUnitsData['unitipaddress'] != "") {
                                                    $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                    $UnitInt->addChild("ip");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $newInt = $UnitInt->ip->addChild("entry");
                                                        $newInt->addAttribute('name', $int_value);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        #Virtual Wire
                        $getVW = $projectdb->query("SELECT id,name,multicast_firewalling,tag_allowed,link_state_pass_through,interface1,interface2 FROM virtual_wires WHERE source='$source' AND template='$template';");
                        if ($getVW->num_rows > 0) {
                            $xml0 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network/virtual-wire");
                            $myTemplateDeviceNetwork->addChild("virtual-wire");
                            $theVW = $myTemplateDeviceNetwork->{'virtual-wire'};
                            while ($getVRData = $getVW->fetch_assoc()) {
                                $myname = $getVRData['name'];
                                $multicast_firewalling = $getVRData['multicast_firewalling'];
                                $tag_allowed = $getVRData['tag_allowed'];
                                $link_state_pass_through = $getVRData['link_state_pass_through'];
                                $interface1 = $getVRData['interface1'];
                                $interface2 = $getVRData['interface2'];

                                $vwire = $theVW->addChild('entry');
                                $vwire->addAttribute('name', $myname);
                                if ($link_state_pass_through != "") {
                                    $vwire->addChild("link-state-pass-through");
                                    $vwire->{'link-state-pass-through'}->addChild("enable", $link_state_pass_through);
                                }
                                if ($multicast_firewalling != "") {
                                    $vwire->addChild("multicast-firewalling");
                                    $vwire->{'multicast-firewalling'}->addChild("enable", $multicast_firewalling);
                                }
                                if ($tag_allowed != "") {
                                    $vwire->addchild("tag-allowed", $tag_allowed);
                                }
                                if ($interface1 != "") {
                                    $vwire->addChild("interface1", $interface1);
                                }
                                if ($interface2 != "") {
                                    $vwire->addChild("interface2", $interface2);
                                }
                            }
                        }

                        #VLANS
                        $getVW = $projectdb->query("SELECT id, name, interface, mac, virtual_interface, mac_interfaces, l3_forwarding FROM vlans WHERE source='$source' AND template='$template' AND name != '';");
                        if ($getVW->num_rows > 0) {
                            $myTemplateDeviceNetwork->addChild('vlan');
                            $theVW = $myTemplateDeviceNetwork->vlan;
                            while ($getVRData = $getVW->fetch_assoc()) {
                                $myname = $getVRData['name'];
                                $interface = $getVRData['interface'];
                                $mac = $getVRData['mac'];
                                $mac_interfaces = $getVRData['mac_interfaces'];
                                $virtual_interface = $getVRData['virtual_interface'];
                                $l3_forwarding = $getVRData['l3_forwarding'];

                                $vwire = $theVW->addChild('entry');
                                $vwire->addAttribute('name', $myname);
                                if ($interface != "") {
                                    $vwire->addChild("interface");
                                    foreach (explode(",", $interface) as $key => $value) {
                                        $vwire->interface->addChild("member", $value);
                                    }
                                }

                                if ($mac != "") {
                                    //$xml_append = simplexml_load_string($mac);
                                    //SimpleXMLElement_append($vwire, $xml_append);
                                    $index_array = 0;
                                    $interfaces_mac_array = explode(",", $mac_interfaces);

                                    $vlan_pad = $vwire->addChild("mac");

                                    foreach (explode(",", $mac) as $key => $value) {
                                        $vlan_mac = $vlan_pad->addChild('entry');
                                        $vlan_mac->addAttribute('name', $value);

                                        $vlan_mac->interface = $interfaces_mac_array[$index_array];
                                        $index_array ++;
                                    }
                                }

                                if($version > 5){
                                    if ($virtual_interface != "") {
                                        $vwire->addChild("virtual-interface");
                                        $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                                    }
                                }
                                else{
                                    $vwire->addChild("virtual-interface");
                                    $vwire->{'virtual-interface'}->addChild("l3-forwarding", $l3_forwarding);
                                    if ($virtual_interface != "") {
                                        $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                                    }
                                }

                            }
                        }

                        #Virtual Router
                        $getVR = $projectdb->query("SELECT id,name,map_name,interfaces,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,protocol,multicast,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext,ecmp FROM virtual_routers WHERE source='$source' AND template='$template';");
                        if ($getVR->num_rows > 0) {
                            $myTemplateDeviceNetwork->addChild('virtual-router');
                            $theVR = $myTemplateDeviceNetwork->{'virtual-router'};

                            while ($getVRData = $getVR->fetch_assoc()) {
                                $vr_id = $getVRData['id'];
                                $myname = $getVRData['name'];
                                $map_name = $getVRData['map_name'];
                                $interfaces = $getVRData['interfaces'];
                                $admin_dist_static = $getVRData['admin_dist_static'];
                                $admin_dist_ospf_int = $getVRData['admin_dist_ospf_int'];
                                $admin_dist_ospf_ext = $getVRData['admin_dist_ospf_ext'];
                                $admin_dist_ibgp = $getVRData['admin_dist_ibgp'];
                                $admin_dist_ebgp = $getVRData['admin_dist_ebgp'];
                                $admin_dist_rip = $getVRData['admin_dist_rip'];
                                $protocol = $getVRData['protocol'];
                                $multicast = $getVRData['multicast'];
                                $admin_dist_static_ipv6 = $getVRData['admin_dist_static_ipv6'];
                                $admin_dist_ospfv3_int = $getVRData['admin_dist_ospfv3_int'];
                                $admin_dist_ospfv3_ext = $getVRData['admin_dist_ospfv3_ext'];
                                $ecmp=$getVRData['ecmp'];

                                $vr = $theVR->addChild('entry');
                                $vr->addAttribute('name', $myname);

                                $vr->addChild("interface");
                                $interface = $vr->interface;
                                if ($interfaces != "") {
                                    foreach (explode(",", $interfaces) as $key => $value) {
                                        $interface->addChild("member", $value);
                                    }
                                }

                                if ($protocol != "") {
                                    $xml_append = simplexml_load_string($protocol);
                                    SimpleXMLElement_append($vr, $xml_append);
                                    //$myvrprotocol=$vr->addChild("protocol");
                                    //$xml_append = simplexml_load_string($protocol);
                                    //SimpleXMLElement_append($myvrprotocol, $xml_append);
                                }

                                if ($version>=7){
                                    if ($ecmp != "") {
                                        $xml_append = simplexml_load_string($ecmp);
                                        SimpleXMLElement_append($vr, $xml_append);
                                    }
                                }
                                if ($multicast != "") {
                                    $vr->addChild("multicast");
                                    $multicastxml = $vr->multicast;
                                    $xml_append = simplexml_load_string($multicast);
                                    SimpleXMLElement_append($multicastxml, $xml_append);
                                }

                                #Metrics
                                $vr->addChild("admin-dists");
                                if (( $admin_dist_static == "") OR ( $admin_dist_static == "0")) {

                                } else {
                                    $vr->{'admin-dists'}->addChild("static", $admin_dist_static);
                                }

                                if (( $admin_dist_ospf_int == "") OR ( $admin_dist_ospf_int == "0")) {

                                } else {
                                    $vr->{'admin-dists'}->addChild("ospf-int", $admin_dist_ospf_int);
                                }

                                if (( $admin_dist_ospf_ext == "") OR ( $admin_dist_ospf_ext == "0")) {

                                } else {
                                    $vr->{'admin-dists'}->addChild("ospf-ext", $admin_dist_ospf_ext);
                                }

                                if ( ( $admin_dist_ibgp == "") OR ( $admin_dist_ibgp == "0")) {

                                } else {
                                    $vr->{'admin-dists'}->addChild("ibgp", $admin_dist_ibgp);
                                }

                                if (( $admin_dist_ebgp == "") OR ( $admin_dist_ebgp == "0")) {

                                } else {
                                    $vr->{'admin-dists'}->addChild("ebgp", $admin_dist_ebgp);
                                }

                                if (( $admin_dist_rip == "") OR ( $admin_dist_rip == "0")) {

                                } else {
                                    $vr->{'admin-dists'}->addChild("rip", $admin_dist_rip);
                                }

                                if ($version >= 6) {
                                    if (( $admin_dist_static_ipv6 == "") OR ( $admin_dist_static_ipv6 == "0")) {

                                    } else {
                                        $vr->{'admin-dists'}->addChild("static-ipv6", $admin_dist_static_ipv6);
                                    }

                                    if (( $admin_dist_ospfv3_int == "") OR ( $admin_dist_ospfv3_int == "0")) {

                                    } else {
                                        $vr->{'admin-dists'}->addChild("ospfv3-int", $admin_dist_ospfv3_int);
                                    }

                                    if (( $admin_dist_ospfv3_ext == "") OR ( $admin_dist_ospfv3_ext == "0")) {

                                    } else {
                                        $vr->{'admin-dists'}->addChild("ospfv3-ext", $admin_dist_ospfv3_ext);
                                    }
                                }

                                # Static Routing
                                $exist = $projectdb->query("SELECT id FROM routes_static WHERE template='$template' AND source='$source' AND vr_id='$vr_id';");
                                if ($exist->num_rows > 0) {
                                    $vr->addChild("routing-table");
                                    # IPV4
                                    $getStatic = $projectdb->query("SELECT name,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,zone FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v4' AND source='$source' AND template='$template';");
                                    if ($getStatic->num_rows > 0) {
                                        $vr->{'routing-table'}->addChild("ip");
                                        $vr->{'routing-table'}->ip->addChild("static-route");
                                        $routes = $vr->{'routing-table'}->ip->{'static-route'};
                                        while ($getStaticData = $getStatic->fetch_assoc()) {
                                            $name = $getStaticData['name'];
                                            $destination = $getStaticData['destination'];
                                            $tointerface = $getStaticData['tointerface'];
                                            $nexthop = $getStaticData['nexthop'];
                                            $nexthop_value = $getStaticData['nexthop_value'];
                                            $metric = $getStaticData['metric'];
                                            $admin_dist = $getStaticData['admin_dist'];
                                            $option_no_install = $getStaticData['option_no_install'];
                                            $zone = $getStaticData['zone'];

                                            $route = $routes->addChild("entry");
                                            $route->addAttribute('name', $name);

                                            if ($destination != "") {
                                                $route->addChild("destination", $destination);
                                            }

                                            if ($option_no_install == 1) {
                                                $route->addChild("option");
                                                $route->option->addChild("no-install");
                                            }

                                            if (($metric != "") AND ( $metric != "0")) {
                                                $route->addChild("metric", $metric);
                                            }

                                            if (($admin_dist != "") AND ( $admin_dist != "0")) {
                                                $route->addChild("admin-dist", $admin_dist);
                                            }

                                            if ($tointerface != "") {
                                                $route->addChild("interface", $tointerface);
                                            }

                                            if ($nexthop != "None") {
                                                $route->addChild("nexthop");
                                                if ($nexthop_value != "") {
                                                    $route->nexthop->addChild($nexthop, $nexthop_value);
                                                } else {
                                                    $route->nexthop->addChild($nexthop);
                                                }
                                            }
                                        }
                                    }

                                    #IPV6
                                    $getStatic = $projectdb->query("SELECT name,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,zone FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v6' AND source='$source' AND template='$template';");
                                    if ($getStatic->num_rows > 0) {
                                        $vr->{'routing-table'}->addChild("ipv6");
                                        $vr->{'routing-table'}->ipv6->addChild("static-route");
                                        $routes = $vr->{'routing-table'}->ipv6->{'static-route'};
                                        while ($getStaticData = $getStatic->fetch_assoc()) {
                                            $name = $getStaticData['name'];
                                            $destination = $getStaticData['destination'];
                                            $tointerface = $getStaticData['tointerface'];
                                            $nexthop = $getStaticData['nexthop'];
                                            $nexthop_value = $getStaticData['nexthop_value'];
                                            $metric = $getStaticData['metric'];
                                            $admin_dist = $getStaticData['admin_dist'];
                                            $option_no_install = $getStaticData['option_no_install'];
                                            $zone = $getStaticData['zone'];

                                            $route = $routes->addChild("entry");
                                            $route->addAttribute('name', $name);

                                            if ($destination != "") {
                                                $route->addChild("destination", $destination);
                                            }

                                            if ($option_no_install == 1) {
                                                $route->addChild("option");
                                                $route->option->addChild("no-install");
                                            }

                                            if ($metric != "") {
                                                $route->addChild("metric", $metric);
                                            }

                                            if ($admin_dist != "") {
                                                $route->addChild("admin-dist", $admin_dist);
                                            }

                                            if ($tointerface != "") {
                                                $route->addChild("interface", $tointerface);
                                            }

                                            if ($nexthop != "None") {
                                                $route->addChild("nexthop");
                                                if ($nexthop_value != "") {
                                                    $route->nexthop->addChild($nexthop, $nexthop_value);
                                                } else {
                                                    $route->nexthop->addChild($nexthop);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        # Template - Devices - Vsys
                        $myTemplateDevice->addChild('vsys');

                        # VSYS
                        $getDG = $projectdb->query("SELECT * FROM virtual_systems WHERE source='$source' AND template='$template';");
                        if ($getDG->num_rows > 0) {
                            #$platform="vsys";
                            while ($DG = $getDG->fetch_assoc()) {
                                $DGName = $DG['name'];

                                $thedevicegroup = $myTemplateDevice->vsys->addChild('entry');
                                $thedevicegroup->addAttribute('name', $DGName);

                                if ($DG['display_name'] != "") {
                                    // $thedevicegroup->addChild("display-name", $DG['display_name']);
                                }

                                $thedevicegroup->addChild('import');
                                $thedevicegroup->import->addChild('network');

                                #Interface
                                if ($DG['interfaces'] != "") {
                                    $thedevicegroup->import->network->addChild('interface');
                                    $interfaces = explode(",", $DG['interfaces']);
                                    foreach ($interfaces as $key => $value) {
                                        if ($value != "") {
                                            $thedevicegroup->import->network->interface->addChild('member', $value);
                                        }
                                    }
                                }
                                if ($DG['virtual_router'] != "") {
                                    $thedevicegroup->import->network->addChild('virtual-router');
                                    $interfaces = explode(",", $DG['virtual_router']);
                                    foreach ($interfaces as $key => $value) {
                                        if ($value != "") {
                                            $thedevicegroup->import->network->{'virtual-router'}->addChild('member', $value);
                                        }
                                    }
                                }
                                if ($DG['virtual_wire'] != "") {
                                    $thedevicegroup->import->network->addChild('virtual-wire');
                                    $interfaces = explode(",", $DG['virtual_wire']);
                                    foreach ($interfaces as $key => $value) {
                                        if ($value != "") {
                                            $thedevicegroup->import->network->{'virtual-wire'}->addChild('member', $value);
                                        }
                                    }
                                }
                                if ($DG['vlan'] != "") {
                                    $thedevicegroup->import->network->addChild('vlan');
                                    $interfaces = explode(",", $DG['vlan']);
                                    foreach ($interfaces as $key => $value) {
                                        if ($value != "") {
                                            $thedevicegroup->import->network->{'vlan'}->addChild('member', $value);
                                        }
                                    }
                                }
                                if ($DG['visible_vsys'] != "") {
                                    $thedevicegroup->import->network->addChild('visible-vsys');
                                    $interfaces = explode(",", $DG['visible_vsys']);
                                    foreach ($interfaces as $key => $value) {
                                        if ($value != "") {
                                            $thedevicegroup->import->network->{'visible-vsys'}->addChild('member', $value);
                                        }
                                    }
                                }

                                $thedevicegroup->import->addChild('resource');
                                $DGresource = $thedevicegroup->import->resource;
                                $max_application_override_rules = $DG['max_application_override_rules'];
                                if ($max_application_override_rules != "0") {
                                    $DGresource->addChild('max-application-override-rules', $max_application_override_rules);
                                }
                                $max_concurrent_ssl_vpn_tunnels = $DG['max_concurrent_ssl_vpn_tunnels'];
                                if ($max_concurrent_ssl_vpn_tunnels != "0") {
                                    $DGresource->addChild('max-concurrent-ssl-vpn-tunnels', $max_concurrent_ssl_vpn_tunnels);
                                }
                                $max_cp_rules = $DG['max_cp_rules'];
                                if ($max_cp_rules != "0") {
                                    $DGresource->addChild('max-cp-rules', $max_cp_rules);
                                }
                                $max_dos_rules = $DG['max_dos_rules'];
                                if ($max_dos_rules != "0") {
                                    $DGresource->addChild('max-dos-rules', $max_dos_rules);
                                }
                                $max_nat_rules = $DG['max_nat_rules'];
                                if ($max_nat_rules != "0") {
                                    $DGresource->addChild('max-nat-rules', $max_nat_rules);
                                }
                                $max_pbf_rules = $DG['max_pbf_rules'];
                                if ($max_pbf_rules != "0") {
                                    $DGresource->addChild('max-pbf-rules', $max_pbf_rules);
                                }
                                $max_qos_rules = $DG['max_qos_rules'];
                                if ($max_qos_rules != "0") {
                                    $DGresource->addChild('max-qos-rules', $max_qos_rules);
                                }
                                $max_security_rules = $DG['max_security_rules'];
                                if ($max_security_rules != "0") {
                                    $DGresource->addChild('max-security-rules', $max_security_rules);
                                }
                                $max_sessions = $DG['max_sessions'];
                                if ($max_sessions != "0") {
                                    $DGresource->addChild('max-sessions', $max_sessions);
                                }
                                $max_site_to_site_vpn_tunnels = $DG['max_site_to_site_vpn_tunnels'];
                                if ($max_site_to_site_vpn_tunnels != "0") {
                                    $DGresource->addChild('max-site-to-site-vpn-tunnels', $max_site_to_site_vpn_tunnels);
                                }
                                $max_ssl_decryption_rules = $DG['max_ssl_decryption_rules'];
                                if ($max_ssl_decryption_rules != "0") {
                                    $DGresource->addChild('max-ssl-decryption-rules', $max_ssl_decryption_rules);
                                }
                                $dns_proxy = $DG['dns_proxy'];
                                if (($dns_proxy != "") AND ( $dns_proxy != "None")) {
                                    $thedevicegroup->import->addChild('dns-proxy');
                                    $thedevicegroup->import->{'dns-proxy'}->addChild($dns_proxy);
                                }
                                $allow_forward_decrypted_content = $DG['allow_forward_decrypted_content'];
                                if ($allow_forward_decrypted_content == "") {
                                    $allow_forward_decrypted_content = "no";
                                }

                                if (($max_application_override_rules==0) AND ($max_concurrent_ssl_vpn_tunnels==0) AND ($max_cp_rules==0) AND ($max_dos_rules==0)
                                    AND ($max_nat_rules==0) AND ($max_pbf_rules==0) AND ($max_qos_rules==0) AND ($max_security_rules==0) AND ($max_ssl_decryption_rules==0)
                                    AND ($dns_proxy==0) AND ($max_sessions==0) AND ($max_site_to_site_vpn_tunnels==0)) {
                                    if ($thedevicegroup->xpath("import/resource")){
                                        $SA = $thedevicegroup->xpath("import/resource");
                                        unset($SA[0][0]);
                                    }
                                }

                                if (isset($thedevicegroup->setting->{'ssl-decrypt'})) {

                                    $SA = $thedevicegroup->xpath("/setting/ssl-decrypt");
                                    unset($SA[0][0]);
                                    #$thedevicegroup->addChild('setting');
                                    #$thedevicegroup->setting->addChild('ssl-decrypt');
                                    #$thedevicegroup->setting->{'ssl-decrypt'}->addChild('allow-forward-decrypted-content',$allow_forward_decrypted_content);
                                }

                                # Add content Under the VSYS and TEMPLATE
                                # ZONES
                                $getShared = $projectdb->query("SELECT id,name,type,interfaces,zone_protection_profile,log_setting_id,include_list,exclude_list,enable_user_identification,log_setting_table_name FROM zones WHERE source='$source' AND vsys='$DGName' AND template='$template' ORDER BY id;");
                                if ($getShared->num_rows > 0) {
                                    $thedevicegroup->addChild('zone');
                                    while ($data = $getShared->fetch_assoc()) {
                                        $myname = $data['name'];
                                        $type = $data['type'];
                                        $interfaces = $data['interfaces'];
                                        $zone_protection_profile = $data['zone_protection_profile'];
                                        $log_setting_id = $data['log_setting_id'];
                                        $log_setting_table_name = $data['log_setting_table_name'];
                                        $include_list = $data['include_list'];
                                        $exclude_list = $data['exclude_list'];
                                        $enable_user_identification = $data['enable_user_identification'];

                                        $zone = $thedevicegroup->zone->addChild('entry');
                                        $zone->addAttribute('name', $myname);
                                        $zone->addChild('network');

                                        $zone->network->addChild($type);
                                        if ($interfaces != "") {
                                            $allinterfaces = explode(",", $interfaces);
                                            foreach ($allinterfaces as $key => $vvvalue) {
                                                $zone->network->{$type}->addChild('member', $vvvalue);
                                            }
                                        }

                                        if (($zone_protection_profile != "") AND ( $zone_protection_profile != "None")) {
                                            $zone->network->addChild('zone-protection-profile', $zone_protection_profile);
                                        }
                                        if (($log_setting_id != "") AND ( $log_setting_table_name != "")) {
                                            $getLP = $projectdb->query("SELECT name FROM $log_setting_table_name WHERE id='$log_setting_id';");
                                            if ($getLP->num_rows == 1) {
                                                $LPData = $getLP->fetch_assoc();
                                                $zone->network->addChild('log-setting', $LPData['name']);
                                            }
                                        }
                                        if (($include_list != "") OR ( $exclude_list != "")) {
                                            $zone->addChild('user-acl');
                                        }
                                        if ($include_list != "") {
                                            $allinclude = explode(",", $include_list);
                                            $zone->{'user-acl'}->addChild('include-list');
                                            foreach ($allinclude as $key => $vvvalue) {
                                                $zone->{'user-acl'}->{'include-list'}->addChild('member', $vvvalue);
                                            }
                                        }
                                        if ($exclude_list != "") {
                                            $allinclude = explode(",", $exclude_list);
                                            $zone->{'user-acl'}->addChild('exclude-list');
                                            foreach ($allinclude as $key => $vvvalue) {
                                                $zone->{'user-acl'}->{'exclude-list'}->addChild('member', $vvvalue);
                                            }
                                        }
                                        if ($enable_user_identification == "yes") {
                                            $zone->addChild('enable-user-identification', $enable_user_identification);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if ($api_call == "single") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/template";

                        $xml_final = addslashes($myTemplate->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('templates','$template_name','$xml_final','$xpath','set');");
                    }
                }

                if ($api_call == "atomic") {
                    $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/template";
                    $xml_final = addslashes($xml->devices->entry->template->asXML());
                    $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('templates','templates','$xml_final','$xpath','edit');");
                }
            }
        }

        update_progress($project, '0.10', 'Generating Shared Objects');

        #ADD SHARED OBJECTS
        $xml = new SimpleXMLElement('<config></config>');
        # SHARED ADDRESS
        $xml->addChild('shared');
        //$getShared = $projectdb->query("SELECT name,type,ipaddress,cidr,description,fqdn,v4,v6,tag FROM shared_address WHERE source='$source'  AND dummy=0 $sql_modified;");
        $getShared = $projectdb->query("SELECT name,type,ipaddress,cidr,description,fqdn,v4,v6,tag FROM address WHERE source='$source' AND vsys = 'shared'  AND dummy=0 $sql_modified;");
        if ($getShared->num_rows > 0) {
            #SHARED ADDRESS
            $xml->shared->addChild('address');
            while ($Data = $getShared->fetch_assoc()) {
                $myname = $Data['name'];
                $address = $xml->shared->address->addChild('entry');
                $address->addAttribute('name', $Data['name']);
                if ($Data['type'] == "ip-netmask") {
                    $address->addChild('ip-netmask', $Data['ipaddress'] . '/' . $Data['cidr']);
                }
                elseif ($Data['type'] == "ip-range") {
                    $address->addChild('ip-range', $Data['ipaddress']);
                }
                elseif ($Data['type'] == "fqdn") {
                    $address->addChild('fqdn', $Data['ipaddress']);
                }
                elseif ($Data['type'] == "dynamic") {
                    if ($version == 5) {
                        $address->addChild('dynamic', $Data['ipaddress']);
                    } elseif ($version >= 6) {
                        add_log('error', 'Exporting Shared Address', 'Dynamic Address Not supported in Panos 6.x [' . $myname . ']', $source, 'Object was Not Migrated');
                    }
                }
                if ($Data['description'] != "") {
                    $address->addChild('description');
                    $address->description = $Data['description'];
                }
                if (($Data['tag'] != "") AND ( $version >= 6)) {
                    $tags = $address->addChild('tag');
                    $mytags = explode(",", $Data['tag']);
                    foreach ($mytags as $key => $value) {
                        $tags->addChild('member', $value);
                    }
                }
                if ($api_call == "single") {
                    $xpath = "/config/shared/address/entry[@name=\'$myname\']";
                    $xml_final = addslashes($address->asXML());
                    //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','address','shared_address','$xml_final','$xpath','edit');");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','address','address','$xml_final','$xpath','edit');");
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/address";
                $xml_final = addslashes($xml->shared->address->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('address','shared_address','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('address','address','$xml_final','$xpath','edit');");
            }
        }

        # SHARED SCHEDULES
        //$getShared = $projectdb->query("SELECT name,xml FROM shared_schedules WHERE source='$source' AND dummy = 0 $sql_modified  ORDER BY id;");
        $getShared = $projectdb->query("SELECT name,xml FROM schedules WHERE source='$source' AND vsys = 'shared' AND dummy = 0 $sql_modified  ORDER BY id;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('schedule');
            $theProfiles2 = $xml->xpath("/config/shared/schedule");
            $theProfiles = $theProfiles2[0];
            while ($data2 = $getShared->fetch_assoc()) {
                $xmlfield = $data2['xml'];
                $xmlname = $data2['name'];
                if ($version >= 7) {
                    if (strpos($xmlfield,"<schedule-type>")==false){
                        if (strpos($xmlfield,"<recurring>")!== false){
                            $xmlfield = str_replace("<recurring>", "<schedule-type><recurring>", $xmlfield);
                        }
                        if (strpos($xmlfield,"</recurring>")!== false){
                            $xmlfield = str_replace("</recurring>", "</recurring></schedule-type>", $xmlfield);
                        }
                        if (strpos($xmlfield,"<non-recurring>")!== false){
                            $xmlfield = str_replace("<non-recurring>", "<schedule-type><non-recurring>", $xmlfield);
                        }
                        if (strpos($xmlfield,"</non-recurring>")!== false){
                            $xmlfield = str_replace("</non-recurring>", "</non-recurring></schedule-type>", $xmlfield);
                        }
                    }

                }
                $xml_append = simplexml_load_string($xmlfield);
                SimpleXMLElement_append($theProfiles, $xml_append);
                if ($api_call == "single") {
                    $xpath = "/config/shared/schedule/entry[@name=\'$xmlname\']";
                    $xml_final = addslashes($xmlfield);
                    //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','schedules','shared_schedules','$xml_final','$xpath','edit');");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','schedules','schedules','$xml_final','$xpath','edit');");
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/schedule";
                $xml_final = addslashes($xml->shared->schedule->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('schedules','shared_schedules','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('schedules','schedules','$xml_final','$xpath','edit');");
            }
        }

        # SHARED LOG SETTINGS
        if ($ispanorama==1){
            //$getShared = $projectdb->query("SELECT type FROM shared_log_settings WHERE source='$source' AND type='profiles' AND dummy = 0 $sql_modified  GROUP BY type ORDER BY id;");
            $getShared = $projectdb->query("SELECT type FROM log_settings WHERE source='$source' AND vsys = 'shared' AND type='profiles' AND dummy = 0 $sql_modified  GROUP BY type ORDER BY id;");
            if ($getShared->num_rows > 0) {
                $xml->shared->addChild('log-settings');
                $theProfiles = $xml->shared->{'log-settings'};
                while ($Data = $getShared->fetch_assoc()) {
                    $type = $Data['type'];
                    $thetype = $theProfiles->{$type};
                    if (empty($thetype)) {
                        $thetype = $theProfiles->addChild($type);
                    }
                    //$getbyType = $projectdb->query("SELECT xml,name FROM shared_log_settings WHERE source='$source' AND type='$type' AND dummy = 0 $sql_modified ORDER BY id;");
                    $getbyType = $projectdb->query("SELECT xml,name FROM log_settings WHERE source='$source' AND vsys = 'shared' AND type='$type' AND dummy = 0 $sql_modified ORDER BY id;");
                    if ($getbyType->num_rows > 0) {
                        while ($data2 = $getbyType->fetch_assoc()) {
                            $xmlfield = $data2['xml'];
                            $xmlname = $data2['name'];
                            $xml_append = simplexml_load_string($xmlfield);
                            SimpleXMLElement_append($xml->shared->{'log-settings'}->{$type}, $xml_append);
                            if ($api_call == "single") {
                                $xpath = "/config/shared/log-settings/$type/entry[@name=\'$xmlname\']";
                                $xml_final = addslashes($xmlfield);
                                //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','log_settings','shared_log_settings','$xml_final','$xpath','edit');");
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','log_settings','log_settings','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                }
                if ($api_call == "atomic") {
                    $xpath = "/config/shared/log-settings";
                    $xml_final = addslashes($xml->shared->{'log-settings'}->asXML());
                    //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('log_settings','shared_log_settings','$xml_final','$xpath','edit');");
                    $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('log_settings','log_settings','$xml_final','$xpath','edit');");
                }
            }
        }
        else{
            //$getShared = $projectdb->query("SELECT type FROM shared_log_settings WHERE source='$source' AND dummy = 0 $sql_modified  GROUP BY type ORDER BY id;");
            $getShared = $projectdb->query("SELECT type FROM log_settings WHERE source='$source' AND vsys = 'shared' AND dummy = 0 $sql_modified  GROUP BY type ORDER BY id;");
            if ($getShared->num_rows > 0) {
                $xml->shared->addChild('log-settings');
                $theProfiles = $xml->shared->{'log-settings'};
                while ($Data = $getShared->fetch_assoc()) {
                    $type = $Data['type'];
                    $thetype = $theProfiles->{$type};
                    if (empty($thetype)) {
                        $thetype = $theProfiles->addChild($type);
                    }
                    //$getbyType = $projectdb->query("SELECT xml,name FROM shared_log_settings WHERE source='$source' AND type='$type' AND dummy = 0 $sql_modified ORDER BY id;");
                    $getbyType = $projectdb->query("SELECT xml,name FROM log_settings WHERE source='$source' AND vsys = 'shared' AND type='$type' AND dummy = 0 $sql_modified ORDER BY id;");
                    if ($getbyType->num_rows > 0) {
                        while ($data2 = $getbyType->fetch_assoc()) {
                            $xmlfield = $data2['xml'];
                            $xmlname = $data2['name'];

                            if($version >= 7){
                                if($type == "snmptrap"){
                                    // En versión 7, el campo member tiene que ser una IP sino da error
                                    // Check if is IP
                                    $xmlfield2 = $xmlfield;
                                    $search_member = explode ("<manager>", $xmlfield2);
                                    $search_member2 = explode ("</manager>", $search_member[1]);
                                    $member = $search_member2[0];
                                    $is_ip = validateIpAddress($member, "v4");
                                    // Return 1: ip correct
                                    // si da error, añadir mensaje de error en el output mapping
                                }
                            }

                            $xml_append = simplexml_load_string($xmlfield);
                            SimpleXMLElement_append($xml->shared->{'log-settings'}->{$type}, $xml_append);
                            if ($api_call == "single") {
                                $xpath = "/config/shared/log-settings/$type/entry[@name=\'$xmlname\']";
                                $xml_final = addslashes($xmlfield);
                                //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','log_settings','shared_log_settings','$xml_final','$xpath','edit');");
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','log_settings','log_settings','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                }
                if ($api_call == "atomic") {
                    $xpath = "/config/shared/log-settings";
                    $xml_final = addslashes($xml->shared->{'log-settings'}->asXML());
                    //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('log_settings','shared_log_settings','$xml_final','$xpath','edit');");
                    $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('log_settings','log_settings','$xml_final','$xpath','edit');");
                }
            }
        }

        # SHARED PROFILES
        //$getShared = $projectdb->query("SELECT type FROM shared_profiles WHERE source='$source' AND (name!='strict') AND (name!='default') $sql_modified GROUP BY type ORDER BY id;");
        $getShared = $projectdb->query("SELECT type FROM profiles WHERE source='$source' AND vsys = 'shared' AND (name!='strict') AND (name!='default') $sql_modified GROUP BY type ORDER BY id;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('profiles');
            $theProfiles = $xml->shared->profiles;
            while ($Data = $getShared->fetch_assoc()) {
                $type = $Data['type'];
                $thetype = $theProfiles->{$type};
                if (empty($thetype)) {
                    $thetype = $theProfiles->addChild($type);
                }
                //$getbyType = $projectdb->query("SELECT xml,name FROM shared_profiles WHERE source='$source' AND (name!='strict') AND (name!='default') AND type='$type' $sql_modified ORDER BY id;");
                $getbyType = $projectdb->query("SELECT xml,name FROM profiles WHERE source='$source' AND vsys = 'shared' AND (name!='strict') AND (name!='default') AND type='$type' $sql_modified ORDER BY id;");
                if ($getbyType->num_rows > 0) {
                    while ($data2 = $getbyType->fetch_assoc()) {
                        $xmlfield = $data2['xml'];
                        $xmlname = $data2['name'];
                        if ($version > 5) {
                            if ((strpos($xmlfield, "<packet-capture>yes</packet-capture>") !== false) AND ( $type != "virus")) {
                                $xmlfield = str_replace("<packet-capture>yes</packet-capture>", "<packet-capture>single-packet</packet-capture>", $xmlfield);
                            }
                            if ((strpos($xmlfield, "<packet-capture>no</packet-capture>") !== false) AND ( $type != "virus")) {
                                $xmlfield = str_replace("<packet-capture>no</packet-capture>", "<packet-capture>disable</packet-capture>", $xmlfield);
                            }
                        }
                        if ($version >= 7) {
                            if ((strpos($xmlfield,"<action>block</action>")!== false) AND ($type == "virus")){
                                $xmlfield = str_replace("<action>block</action>", "<action>drop</action>", $xmlfield);
                            }
                            if ((strpos($xmlfield,"<wildfire-action>block</wildfire-action>")!== false) AND ($type == "virus")){
                                $xmlfield = str_replace("<wildfire-action>block</wildfire-action>", "<wildfire-action>drop</wildfire-action>", $xmlfield);
                            }
                            //if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "spyware")){
                            //    $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                            //}
                            if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "vulnerability")){
                                $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                            }
                            /* SE TENDRÁ QUE HACER INSERT EN LA TABLA DE OUTPUT MAPPING EN EL CAMPO ERROR MESSAGE Y QUE SALGA EN EL + --> PENSAR COMO HACERLO */
                            if ((strpos($xmlfield,"<action>forward</action>")!== false) AND ($type == "file-blocking")){
                                $xmlfield = str_replace("<action>forward</action>", "", $xmlfield);
                            }
                            if ((strpos($xmlfield,"<action>continue-and-forward</action>")!== false) AND ($type == "file-blocking")){
                                $xmlfield = str_replace("<action>continue-and-forward</action>", "", $xmlfield);
                            }

                        }
                        $xml_append = simplexml_load_string($xmlfield);
                        SimpleXMLElement_append($xml->shared->profiles->{$type}, $xml_append);
                        if ($api_call == "single") {
                            $xpath = "/config/shared/profiles/$type/entry[@name=\'$xmlname\']";
                            $xml_final = addslashes($xmlfield);
                            //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','profiles','shared_profiles','$xml_final','$xpath','edit');");
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','profiles','profiles','$xml_final','$xpath','edit');");
                        }
                    }
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/profiles";
                $xml_final = addslashes($xml->shared->profiles->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('profiles','shared_profiles','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('profiles','profiles','$xml_final','$xpath','edit');");
            }
        }

        # SHARED PROFILES GROUPS
        //$getShared = $projectdb->query("SELECT name,xml FROM shared_profiles_groups WHERE source='$source' AND dummy = 0 $sql_modified ORDER BY id;");
        $getShared = $projectdb->query("SELECT name,xml FROM profiles_groups WHERE source='$source' AND vsys = 'shared' AND dummy = 0 $sql_modified ORDER BY id;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('profile-group');
            $theProfiles2 = $xml->xpath("/config/shared/profile-group");
            $theProfiles = $theProfiles2[0];
            while ($data2 = $getShared->fetch_assoc()) {
                $xmlfield = $data2['xml'];
                $xmlname = $data2['name'];
                $xml_append = simplexml_load_string($xmlfield);
                SimpleXMLElement_append($theProfiles, $xml_append);
                if ($api_call == "single") {
                    $xpath = "/config/shared/profile-group/entry[@name=\'$xmlname\']";
                    $xml_final = addslashes($xmlfield);
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','profiles_group','shared_profiles_groups','$xml_final','$xpath','edit');");
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/profile-group";
                $xml_final = addslashes($xml->shared->{'profile-group'}->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('profiles_group','shared_profiles_group','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('profiles_group','profiles_group','$xml_final','$xpath','edit');");
            }
        }

        # SHARED ADDRESS GROUPS
        //$getShared = $projectdb->query("SELECT name,id,tag,filter,type,description FROM shared_address_groups_id WHERE source='$source' $sql_modified;");
        $getShared = $projectdb->query("SELECT name,id,tag,filter,type,description FROM address_groups_id WHERE source='$source' AND vsys = 'shared' $sql_modified;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('address-group');
            while ($Data = $getShared->fetch_assoc()) {
                $groupName = $Data['name'];
                $lid = $Data['id'];
                $myname = $Data['name'];
                if ($xml->xpath("/config/shared/address-group/entry[@name='$myname']") == null) {
                    //$getMembers = $projectdb->query("SELECT table_name,member_lid FROM shared_address_groups WHERE source='$source' and lid='$lid'");
                    $getMembers = $projectdb->query("SELECT table_name,member_lid FROM address_groups WHERE source='$source' AND lid='$lid'");
                    if ($getMembers->num_rows > 0) {
                        $service = $xml->shared->{'address-group'}->addChild('entry');
                        $service->addAttribute('name', $Data['name']);
                        if (($version >= 6) AND ( $Data['type'] == "static")) {
                            $service2 = $service->addChild('static');
                        } elseif ($version < 6) {
                            $service2 = $service;
                        }
                        while ($Datas = $getMembers->fetch_assoc()) {
                            $table_name = $Datas['table_name'];
                            $member_lid = $Datas['member_lid'];
                            $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                            if ($getName->num_rows==1){
                                $Datas2 = $getName->fetch_assoc();
                                $member = $service2->addChild('member', $Datas2['name']);
                            }
                        }
                    } else {
                        $service = $xml->shared->{'address-group'}->addChild('entry');
                        $service->addAttribute('name', $Data['name']);
                        if (($version >= 6) AND ( $Data['type'] == "dynamic")) {
                            $service2 = $service->addChild('dynamic');
                            $filter = str_replace("<br>", "\n", $Data['filter']);
                            $service2 = $service->dynamic->addChild('filter', $filter);
                        }
                    }
                    if ($Data['description'] != "") {
                        $service->addChild('description');
                        $service->description = $Data['description'];
                    }
                    if ($Data['tag'] != "") {
                        $tags = explode(",", $Data['tag']);
                        $shtag = $service->addChild('tag');
                        foreach ($tags as $kkey => $vvalue) {
                            $shtag->addChild('member', $vvalue);
                        }
                    }
                    if ($api_call == "single") {
                        $xpath = "/config/shared/address-group/entry[@name=\'$myname\']";
                        $xml_final = addslashes($service->asXML());
                        //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','address_groups','shared_address_groups','$xml_final','$xpath','edit');");
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','address_groups','address_groups','$xml_final','$xpath','edit');");
                    }
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/address-group";
                $xml_final = addslashes($xml->shared->{'address-group'}->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('address_groups','shared_address_groups','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('address_groups','address_groups','$xml_final','$xpath','edit');");
            }
        }

        # SHARED TAGS
        //$getShared = $projectdb->query("SELECT name,color,comments FROM shared_tag WHERE source='$source' AND dummy = 0 $sql_modified;");
        $getShared = $projectdb->query("SELECT name,color,comments FROM tag WHERE source='$source' AND vsys = 'shared' AND dummy = 0 $sql_modified;");
        if (($version >= 6) AND ( $getShared->num_rows > 0)) {
            $xml->shared->addChild('tag');
            $theProfiles = $xml->shared->tag;
            while ($tag = $getShared->fetch_assoc()) {
                $tagName = $tag['name'];
                $newtag = $theProfiles->addChild('entry');
                $newtag->addAttribute('name', $tagName);
                if (($tag['color'] != "") AND ( $tag['color'] != "None")) {
                    $newtag->addChild('color', $tag['color']);
                }
                if ($tag['comments'] != "") {
                    $newtag->addChild('comments', $tag['comments']);
                }
                if ($api_call == "single") {
                    $xpath = "/config/shared/tag/entry[@name=\'$tagName\']";
                    $xml_final = addslashes($newtag->asXML());
                    //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$tagName','tag','shared_tag','$xml_final','$xpath','edit');");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$tagName','tag','tag','$xml_final','$xpath','edit');");
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/tag";
                $xml_final = addslashes($xml->shared->tag->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('tag','shared_tag','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('tag','tag','$xml_final','$xpath','edit');");
            }
        }

        # SHARED SERVICES
        //$getShared = $projectdb->query("SELECT name,dport,sport,protocol,tag,description FROM shared_services WHERE source='$source'  AND (protocol = 'tcp' or protocol = 'udp') AND (name <> 'application-default' AND name <> 'service-http' AND name <> 'service-https') AND dummy=0 $sql_modified;");
        $getShared = $projectdb->query("SELECT name,dport,sport,protocol,tag,description FROM services WHERE source='$source' AND vsys = 'shared'  AND (protocol = 'tcp' or protocol = 'udp') AND (name <> 'application-default' AND name <> 'service-http' AND name <> 'service-https') AND dummy=0 $sql_modified;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('service');
            while ($Data = $getShared->fetch_assoc()) {
                $myname = $Data['name'];
                if ($xml->xpath("/config/shared/service/entry[@name='$myname']") == null) {
                    $service = $xml->shared->service->addChild('entry');
                    $service->addAttribute('name', $Data['name']);
                    $protocol = $service->addChild('protocol');
                    $port = $protocol->addChild($Data['protocol']);
                    $port->addChild('port', $Data['dport']);
                    if (($Data['sport'] != NULL) or ( $Data['sport'] != "")) {
                        $port->addChild('source-port', $Data['sport']);
                    }
                    if ($Data['description'] != "") {
                        $protocol = $service->addChild('description');
                        $service->description = $Data['description'];
                    }
                    if (($version >= 6) AND ( $Data['tag'] != "")) {
                        $tags = $service->addChild('tag');
                        $mytags = explode(",", $Data['tag']);
                        foreach ($mytags as $key => $value) {
                            $tags->addChild('member', $value);
                        }
                    }
                    if ($api_call == "single") {
                        $xpath = "/config/shared/service/entry[@name=\'$myname\']";
                        $xml_final = addslashes($service->asXML());
                        //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','services','shared_services','$xml_final','$xpath','edit');");
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','services','services','$xml_final','$xpath','edit');");
                    }
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/service";
                $xml_final = addslashes($xml->shared->service->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('services','shared_services','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('services','services','$xml_final','$xpath','edit');");
            }
        }

        # SHARED SERVICES GROUPS
        //$getShared = $projectdb->query("SELECT name,id,tag FROM shared_services_groups_id WHERE source='$source' $sql_modified;");
        $getShared = $projectdb->query("SELECT name,id,tag FROM services_groups_id WHERE source='$source' AND vsys = 'shared' $sql_modified;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('service-group');
            while ($Data = $getShared->fetch_assoc()) {
                $groupName = $Data['name'];
                $lid = $Data['id'];
                $myname = $Data['name'];
                if ($xml->xpath("/config/shared/service-group/entry[@name='$myname']") == null) {
                    //$getMembers = $projectdb->query("SELECT table_name,member_lid FROM shared_services_groups WHERE source='$source' and lid='$lid'");
                    $getMembers = $projectdb->query("SELECT table_name,member_lid FROM services_groups WHERE source='$source' AND lid='$lid';");
                    if ($getMembers->num_rows > 0) {
                        $service = $xml->shared->{'service-group'}->addChild('entry');
                        $service->addAttribute('name', $Data['name']);
                        if ($version >= 6) {
                            $service2 = $service->addChild('members');
                        } elseif ($version < 6) {
                            $service2 = $service;
                        }
                        while ($Datas = $getMembers->fetch_assoc()) {
                            $table_name = $Datas['table_name'];
                            $member_lid = $Datas['member_lid'];
                            $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                            if ($getName->num_rows==1){
                                $Datas2 = $getName->fetch_assoc();
                                $member = $service2->addChild('member', $Datas2['name']);
                            }
                        }
                        if (($version >= 6) AND ( $Data['tag'] != "")) {
                            $tags = $service->addChild('tag');
                            $mytags = explode(",", $Data['tag']);
                            foreach ($mytags as $key => $value) {
                                $tags->addChild('member', $value);
                            }
                        }
                        if ($api_call == "single") {
                            $xpath = "/config/shared/service-group/entry[@name=\'$myname\']";
                            $xml_final = addslashes($service->asXML());
                            //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','services_groups','shared_services_groups','$xml_final','$xpath','edit');");
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','services_groups','services_groups','$xml_final','$xpath','edit');");
                        }
                    }
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/service-group";
                $xml_final = addslashes($xml->shared->{'service-group'}->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('services_groups','shared_services_groups','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('services_groups','services_groups','$xml_final','$xpath','edit');");
            }
        }

        # SHARED EXTERNAL-LISTS
        //$getShared = $projectdb->query("SELECT name,xml FROM shared_external_list WHERE source='$source' $sql_modified GROUP BY name ORDER BY id;");
        $getShared = $projectdb->query("SELECT name,xml FROM external_list WHERE source='$source' AND vsys = 'shared' $sql_modified GROUP BY name ORDER BY id;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('external-list');
            $theProfiles2 = $xml->xpath("/config/shared/external-list");
            $theProfiles = $theProfiles2[0];
            while ($data2 = $getShared->fetch_assoc()) {
                $xmlfield = $data2['xml'];
                $xmlname = $data2['name'];
                $xml_append = simplexml_load_string($xmlfield);
                SimpleXMLElement_append($theProfiles, $xml_append);
                if ($api_call == "single") {
                    $xpath = "/config/shared/external-list/entry[@name=\'$xmlname\']";
                    $xml_final = addslashes($xmlfield);
                    //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','external_list','shared_external_list','$xml_final','$xpath','edit');");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','external_list','external_list','$xml_final','$xpath','edit');");
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/external-list";
                $xml_final = addslashes($xml->shared->{'external-list'}->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('external_list','shared_external_list','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('external_list','external_list','$xml_final','$xpath','edit');");
            }
        }

        # SHARED REGIONS
        //$getShared = $projectdb->query("SELECT name,xml,address,latitude,longitude FROM shared_regions WHERE source='$source' $sql_modified ORDER BY id;");
        $getShared = $projectdb->query("SELECT name,xml,address,latitude,longitude FROM regions WHERE source='$source' AND vsys = 'shared' $sql_modified ORDER BY id;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('region');
            $theProfiles2 = $xml->xpath("/config/shared/region");
            $theProfiles = $theProfiles2[0];
            while ($data2 = $getShared->fetch_assoc()) {
                $xmlfield = $data2['xml'];
                $xmlname = $data2['name'];
                $latitude=$data2['latitude'];
                $longitude=$data2['longitude'];
                $regionMembers=$data2['address'];

                $newRegion=$theProfiles->addChild("entry");
                $newRegion->addAttribute('name', $xmlname);
                if ($regionMembers!=""){
                    $newRegion->addChild("address");
                    $regionMembersArray=explode(",",$regionMembers);
                    foreach ($regionMembersArray as $regionMembersValue){
                        $newRegion->address->addChild("member",$regionMembersValue);
                    }
                }
                if (($longitude!="") AND ($latitude!="")){
                    $newRegion->addChild("geo-location");
                    $newRegion->{'geo-location'}->addChild("latitude",$latitude);
                    $newRegion->{'geo-location'}->addChild("longitude",$longitude);
                }

                if ($api_call == "single") {
                    $xpath = "/config/shared/region/entry[@name=\'$xmlname\']";
                    $newRegionXML=$newRegion->asXML();
                    //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','regions','shared_regions','$newRegionXML','$xpath','edit');");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','regions','regions','$newRegionXML','$xpath','edit');");
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/region";
                $xml_final = addslashes($xml->shared->region->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('regions','shared_regions','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('regions','regions','$xml_final','$xpath','edit');");
            }
        }

        # SHARED APPLICATIONS
        //$getShared = $projectdb->query("SELECT id,name,description,spyware_ident,category,subcategory,parent_app,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,tcp_half_closed_timeout,tcp_time_wait_timeout FROM shared_applications WHERE source='$source' AND dummy=0 $sql_modified ORDER BY id;");
        $getShared = $projectdb->query("SELECT id,name,description,spyware_ident,category,subcategory,parent_app,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,tcp_half_closed_timeout,tcp_time_wait_timeout FROM applications WHERE source='$source' AND vsys = 'shared' AND dummy=0 $sql_modified ORDER BY id;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('application');
            while ($data2 = $getShared->fetch_object()) {
                $appid = $data2->id;
                $myname = $data2->name;
                if ($xml->xpath("/config/shared/application/entry[@name='$myname']") == null) {
                    $application = $xml->shared->application->addChild('entry');
                    $application->addAttribute('name', $myname);
                    if ($data2->description != "") {
                        $application->addChild('description');
                        $application->description = $data2->description;
                    }
                    if ($data2->category != "") {
                        $application->addChild('category', $data2->category);
                    }
                    if ($data2->subcategory != "") {
                        $application->addChild('subcategory', $data2->subcategory);
                    }
                    if ($data2->risk != "") {
                        $application->addChild('risk', $data2->risk);
                    }
                    if ($data2->technology != "") {
                        $application->addChild('technology', $data2->technology);
                    }
                    if ($data2->evasive_behavior != "") {
                        $application->addChild('evasive-behavior', $data2->evasive_behavior);
                    }
                    if ($data2->consume_big_bandwidth != "") {
                        $application->addChild('consume-big-bandwidth', $data2->consume_big_bandwidth);
                    }
                    if ($data2->used_by_malware != "") {
                        $application->addChild('used-by-malware', $data2->used_by_malware);
                    }
                    if ($data2->able_to_transfer_file != "") {
                        $application->addChild('able-to-transfer-file', $data2->able_to_transfer_file);
                    }
                    if ($data2->has_known_vulnerability != "") {
                        $application->addChild('has-known-vulnerability', $data2->has_known_vulnerability);
                    }
                    if ($data2->tunnel_other_application != "") {
                        $application->addChild('tunnel-other-application', $data2->tunnel_other_application);
                    }
                    if ($data2->tunnel_applications != "") {
                        $application->addChild('tunnel-applications', $data2->tunnel_applications);
                    }
                    if ($data2->prone_to_misuse != "") {
                        $application->addChild('prone-to-misuse', $data2->prone_to_misuse);
                    }
                    if ($data2->pervasive_use != "") {
                        $application->addChild('pervasive-use', $data2->pervasive_use);
                    }
                    if ($data2->file_type_ident != "") {
                        $application->addChild('file-type-ident', $data2->file_type_ident);
                    }
                    if ($data2->virus_ident != "") {
                        $application->addChild('virus-ident', $data2->virus_ident);
                    }
                    if ($data2->data_ident != "") {
                        $application->addChild('data-ident', $data2->data_ident);
                    }
                    if ($version < 6) {
                        if ($data2->spyware_ident != "")  {
                            $application->addChild('spyware-ident', $data2->spyware_ident);
                        }
                    }

                    if (($data2->parent_app != "None") AND ( $data2->parent_app != "")){
                        $application->addChild('parent-app', $data2->parent_app);
                    }
                    if ($data2->timeout > 0) {
                        $application->addChild('timeout', $data2->timeout);
                    }
                    if ($data2->tcp_timeout > 0) {
                        $application->addChild('tcp-timeout', $data2->tcp_timeout);
                    }
                    if ($data2->udp_timeout > 0) {
                        $application->addChild('udp-timeout', $data2->udp_timeout);
                    }
                    if($version >= 6){
                        if ($data2->tcp_half_closed_timeout > 0) {
                            $application->addChild('tcp-half-closed-timeout', $data2->tcp_half_closed_timeout);
                        }
                        if ($data2->tcp_time_wait_timeout > 0) {
                            $application->addChild('tcp-time-wait-timeout', $data2->tcp_time_wait_timeout);
                        }
                    }
                    if ($data2->default_type == "port") {
                        $default = $application->addChild('default');
                        $port = $default->addChild('port');
                        $ports = explode(",", $data2->value);
                        foreach ($ports as $kkey => $vvalue) {
                            $port->addChild('member', $vvalue);
                        }
                    } elseif ($data2->default_type == "ident-by-ip-protocol") {
                        $default = $application->addChild('default');
                        $port = $default->addChild('ident-by-ip-protocol', $data2->value);
                    } elseif ($data2->default_type == "ident-by-icmp-type") {
                        if($version < 7){
                            $default = $application->addChild('default');
                            $port = $default->addChild('ident-by-icmp-type', $data2->type);
                        }else{
                            $default = $application->addChild('default');
                            $port = $default->addChild('ident-by-icmp-type');
                            $port->addChild('type', $data2->type);
                            $port->addChild('code', $data2->code);
                        }
                    } elseif ($data2->default_type == "ident-by-icmp6-type") {
                        $default = $application->addChild('default');
                        $port = $default->addChild('ident-by-icmp6-type');
                        $port->addChild('code', $data2->code);
                        $port->addChild('type', $data2->type);
                    } elseif ($data2->default_type == "None") {

                    }

                    //$getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE source='$source' AND member_lid='$appid' AND table_name='shared_applications';");
                    $getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE source='$source' AND member_lid='$appid' AND table_name='applications';");
                    if ($getSignature->num_rows > 0) {
                        $application->addChild('signature');
                        $sig = $application->signature;
                        while ($data3 = $getSignature->fetch_assoc()) {
                            $xml_append = simplexml_load_string($data3['signature']);
                            SimpleXMLElement_append($sig, $xml_append);
                        }
                    }
                    if ($api_call == "single") {
                        $xpath = "/config/shared/application/entry[@name=\'$myname\']";
                        $xml_final = addslashes($application->asXML());
                        //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications','shared_applications','$xml_final','$xpath','edit');");
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications','applications','$xml_final','$xpath','edit');");
                    }
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/application";
                $xml_final = addslashes($xml->shared->application->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications','shared_applications','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications','applications','$xml_final','$xpath','edit');");
            }
        }

        #SHARED APPLICATIONS FILTERS
        //$getShared = $projectdb->query("SELECT id,name,category,subcategory,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,prone_to_misuse,pervasive_use FROM shared_applications_filters WHERE source='$source' $sql_modified ORDER BY id;");
        $getShared = $projectdb->query("SELECT id,name,category,subcategory,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,prone_to_misuse,pervasive_use FROM applications_filters WHERE source='$source' AND vsys = 'shared' $sql_modified ORDER BY id;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('application-filter');
            while ($data2 = $getShared->fetch_object()) {
                $appid = $data2->id;
                $myname = $data2->name;
                if ($xml->xpath("/config/shared/application-filter/entry[@name='$myname']") == null) {
                    $application_filters = $xml->shared->{'application-filter'}->addChild('entry');
                    $application_filters->addAttribute('name', $myname);

                    if($data2->category != ""){
                        $category = $application_filters->addChild('category');
                        $category_s = explode(",", $data2->category);
                        foreach ($category_s as $kkey => $vvalue) {
                            $category->addChild('member', $vvalue);
                        }
                    }
                    if($data2->subcategory != ""){
                        $subcategory = $application_filters->addChild('subcategory');
                        $subcategory_s = explode(",", $data2->subcategory);
                        foreach ($subcategory_s as $kkey => $vvalue) {
                            $subcategory->addChild('member', $vvalue);
                        }
                    }
                    if($data2->risk != ""){
                        $risk = $application_filters->addChild('risk');
                        $risk_s = explode(",", $data2->risk);
                        foreach ($risk_s as $kkey => $vvalue) {
                            $risk->addChild('member', $vvalue);
                        }
                    }
                    if($data2->technology != ""){
                        $technology = $application_filters->addChild('technology');
                        $technology_s = explode(",", $data2->technology);
                        foreach ($technology_s as $kkey => $vvalue) {
                            $technology->addChild('member', $vvalue);
                        }
                    }

                    if ($data2->evasive_behavior != "") {
                        $application_filters->addChild('evasive', $data2->evasive_behavior);
                    }
                    if ($data2->consume_big_bandwidth != "") {
                        $application_filters->addChild('excessive-bandwidth-use', $data2->consume_big_bandwidth);
                    }
                    if ($data2->used_by_malware != "") {
                        $application_filters->addChild('used-by-malware', $data2->used_by_malware);
                    }
                    if ($data2->able_to_transfer_file != "") {
                        $application_filters->addChild('transfers-files', $data2->able_to_transfer_file);
                    }
                    if ($data2->has_known_vulnerability != "") {
                        $application_filters->addChild('has-known-vulnerabilities', $data2->has_known_vulnerability);
                    }
                    if ($data2->tunnel_other_application != "") {
                        $application_filters->addChild('tunnels-other-apps', $data2->tunnel_other_application);
                    }
                    if ($data2->prone_to_misuse != "") {
                        $application_filters->addChild('prone-to-misuse', $data2->prone_to_misuse);
                    }
                    if ($data2->pervasive_use != "") {
                        $application_filters->addChild('pervasive', $data2->pervasive_use);
                    }

                    if ($api_call == "single") {
                        //$xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/application-filter";
                        $xpath = "/config/shared/application-filter/entry[@name=\'$myname\']";
                        $xml_final = addslashes($application_filters->asXML());
                        //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications_filters','shared_applications_filters','$xml_final','$xpath','edit');");
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications_filters','applications_filters','$xml_final','$xpath','edit');");
                    }
                }
            }
            if ($api_call == "atomic") {
                //$xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/application-filter";
                $xpath = "/config/shared/application-filter";
                $xml_final = addslashes($xml->shared->{'application-filter'}->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications_filters','shared_applications_filters','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications_filters','applications_filters','$xml_final','$xpath','edit');");
            }
        }

        # SHARED APPLICATIONS GROUPS
        //$getShared = $projectdb->query("SELECT name,id FROM shared_applications_groups_id WHERE source='$source' $sql_modified;");
        $getShared = $projectdb->query("SELECT name,id FROM applications_groups_id WHERE source='$source' AND vsys = 'shared' $sql_modified;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('application-group');
            while ($Data = $getShared->fetch_assoc()) {
                $groupName = $Data['name'];
                $lid = $Data['id'];
                $myname = $Data['name'];
                if ($xml->xpath("/config/shared/application-group/entry[@name='$myname']") == null) {
                    //$getMembers = $projectdb->query("SELECT table_name,member_lid FROM shared_applications_groups WHERE source='$source' and lid='$lid';");
                    $getMembers = $projectdb->query("SELECT table_name,member_lid FROM applications_groups WHERE source='$source' AND lid='$lid';");
                    if ($getMembers->num_rows > 0) {
                        $service = $xml->shared->{'application-group'}->addChild('entry');
                        $service->addAttribute('name', $Data['name']);
                        if ($version >= 7) {
                            $service2 = $service->addChild('members');
                        }else{
                            $service2 = $service;
                        }
                        while ($Datas = $getMembers->fetch_assoc()) {
                            $table_name = $Datas['table_name'];
                            $member_lid = $Datas['member_lid'];
                            $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid';");
                            if ($getName->num_rows==1){
                                $Datas2 = $getName->fetch_assoc();
                                $member = $service2->addChild('member', $Datas2['name']);
                            }
                        }
                    } else {
                        $service = $xml->shared->{'application-group'}->addChild('entry');
                        $service->addAttribute('name', $Data['name']);
                    }

                    if ($api_call == "single") {
                        $xpath = "/config/shared/application-group/entry[@name=\'$myname\']";
                        $xml_final = addslashes($service->asXML());
                        //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications_groups','shared_applications_groups','$xml_final','$xpath','edit');");
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications_groups','applications_groups','$xml_final','$xpath','edit');");
                    }
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/application-group";
                $xml_final = addslashes($xml->shared->{'application-group'}->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications_groups','shared_applications_groups','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications_groups','applications_groups','$xml_final','$xpath','edit');");
            }
        }


        # SHARED RESPONSE PAGES
        //$getShared = $projectdb->query("SELECT name,type,html FROM shared_response_pages WHERE source='$source' $sql_modified ORDER BY id;");
        $getShared = $projectdb->query("SELECT name,type,html FROM response_pages WHERE source='$source' AND vsys = 'shared' $sql_modified ORDER BY id;");
        if ($getShared->num_rows > 0) {
            $xml->shared->addChild('response-page');
            while ($data2 = $getShared->fetch_assoc()) {
                $xmlfield = $data2['html'];
                $xmlname = $data2['type'];
                $reportname = $data2['name'];
                if ($reportname != "") {
                    if (!isset($xml->shared->{'response-page'}->{$xmlname})) {
                        $xml->shared->{'response-page'}->addChild($xmlname);
                        $newrp = $xml->shared->{'response-page'}->{$xmlname}->addChild("entry");
                        $newrp->addAttribute('name', $reportname);
                        $newrp->addChild("page");
                        $newrp->page = $xmlfield;
                    } else {
                        if ($xml->shared->{'response-page'}->{$xmlname}->xpath("entry[@name='$reportname']") !== null) {
                            $SA = $xml->shared->{'response-page'}->{$xmlname}->xpath("entry[@name='$reportname']");
                            unset($SA[0][0]);
                        }
                        $newrp = $xml->shared->{'response-page'}->{$xmlname}->addChild("entry");
                        $newrp->addAttribute('name', $reportname);
                        $newrp->addChild("page");
                        $newrp->page = $xmlfield;
                    }
                } else {
                    $SA = $xml->shared->xpath("response-page/$xmlname");
                    unset($SA[0][0]);
                    #$xml_append = simplexml_load_string($xmlfield);
                    $xml_append = simplexml_load_string("<$xmlname>$xmlfield</$xmlname>");
                    SimpleXMLElement_append($xml->shared->{'response-page'}, $xml_append);
                }
                if ($api_call == "single") {
                    $xpath = "/config/shared/response-page/$xmlname";
                    $xml_final = addslashes($xml->shared->{'response-page'}->{$xmlname}->asXML());
                    //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','response-pages','shared_response_pages','$xml_final','$xpath','edit');");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','response-pages','response_pages','$xml_final','$xpath','edit');");
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/response-page";
                $xml_final = addslashes($xml->shared->{'response-page'}->asXML());
                //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('response-pages','shared_response_pages','$xml_final','$xpath','edit');");
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('response-pages','response_pages','$xml_final','$xpath','edit');");
            }
        }

        # SHARED REPORTS
        //$getShared = $projectdb->query("SELECT id,name,type,period,topn,topm,caption,starttime,endtime,query,frequency FROM reports WHERE source='$source' ORDER BY id;");
        $getShared = $projectdb->query("SELECT id,name,type,period,topn,topm,caption,starttime,endtime,query,frequency FROM reports WHERE source='$source' ORDER BY id;");
        if ($getShared->num_rows > 0) {
            if (!isset($xml->shared->reports)) {
                $xml->shared->addChild('reports');
            }
            $theProfiles2 = $xml->shared->xpath("reports");
            $theProfiles = $theProfiles2[0];
            while ($data2 = $getShared->fetch_assoc()) {
                $reportname = $data2['name'];
                $reporttype = $data2['type'];
                $reportperiod = $data2['period'];
                $reporttopn = $data2['topn'];
                $reporttopm = $data2['topm'];
                $reportcaption = $data2['caption'];
                $reportstarttime = $data2['starttime'];
                $reportendtime = $data2['endtime'];
                $reportquery = $data2['query'];
                $reportfrequency = $data2['frequency'];

                if ($reportname != "") {
                    if ($theProfiles->xpath("//entry[@name='$reportname']") == null) {
                        $report = $theProfiles->addChild('entry');
                        $report->addAttribute('name', $reportname);
                        if ($reporttype != "") {
                            $xml_append = simplexml_load_string($reporttype);
                            SimpleXMLElement_append($report, $xml_append);
                        }
                        if ($reportcaption != "") {
                            $report->addChild("caption");
                            $report->caption = $reportcaption;
                        }
                        if ($reportperiod != "") {
                            $report->addChild("period");
                            $report->period = $reportperiod;
                        } else {
                            $report->addChild("start-time");
                            $report->{'start-time'} = $reportstarttime;
                            $report->addChild("end-time");
                            $report->{'end-time'} = $reportendtime;
                        }
                        if ($reporttopn != "") {
                            $report->addChild("topn");
                            $report->topn = $reporttopn;
                        }
                        if ($reporttopm != "") {
                            $report->addChild("topm");
                            $report->topm = $reporttopm;
                        }
                        if ($reportquery != "") {
                            $report->addChild("query");
                            $report->query = $reportquery;
                        }
                        if ($reportfrequency != "") {
                            $report->addChild("frequency");
                            $report->frequency = $reportfrequency;
                        }
                    }
                    if ($api_call == "single") {
                        $xpath = "/config/shared/reports/entry[@name=\'$reportname\']";
                        $xml_final = addslashes($report->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$reportname','reports','reports','$xml_final','$xpath','edit');");
                    }
                }
            }
            if ($api_call == "atomic") {
                $xpath = "/config/shared/reports";
                $xml_final = addslashes($xml->shared->reports->asXML());
                $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('reports','reports','$xml_final','$xpath','edit');");
            }
        }
        else {
            #DELETE SHARED EXTERNAL-LISTS
            $SA = $xml->xpath("/config/shared/reports");
            unset($SA[0][0]);
        }

        update_progress($project, '0.25', 'Shared Objects Loaded');

        if ($ispanorama == 1) {
            #Shared Policies
            $policies = array("pre-rulebase", "post-rulebase");
            $vsys = "shared";
            foreach ($policies as $pkey => $pvalue) {
                if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
                    $preorpost = 0;
                } elseif ($pvalue == "post-rulebase") {
                    $preorpost = 1;
                }

                # SECURITY
                $getPolicies = $projectdb->query("SELECT icmp_unreachable,rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                if ($getPolicies->num_rows > 0) {
                    $xml = new SimpleXMLElement("<config></config>");
                    $xml->addChild($pvalue);
                    $xml->{$pvalue}->addChild("security");
                    $xml->{$pvalue}->security->addChild('rules');
                    $policy_order = array();
                    while ($data2 = $getPolicies->fetch_object()) {
                        $myname = $data2->name;
                        $policy_order[] = $data2->name;
                        $lid = $data2->id;
                        if ($xml->xpath("/$pvalue/security/rules/entry[@name='$myname']") == null) {
                            $rule = $xml->{$pvalue}->security->rules->addChild('entry');
                            $rule->addAttribute('name', $myname);
                            if ($version > 6.0) {
                                if ($data2->rule_type != "universal") {
                                    $rule->addChild("rule-type", $data2->rule_type);
                                }
                            }
                            if ($data2->dsri == 0) {
                                $dsri = "no";
                            } else {
                                $dsri = "yes";
                            }
                            if ($dsri!="no"){
                                $rule->addChild('option');
                                $rule->option->addChild('disable-server-response-inspection', $dsri);
                            }
                            if ($version>=7){
                                if ($data2->icmp_unreachable!=""){
                                    $rule->addChild('icmp-unreachable',$data2->icmp_unreachable);
                                }
                            }
                            $getFrom = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$lid' ;");
                            if ($getFrom->num_rows > 0) {
                                $rule->addChild('from');
                                while ($k = $getFrom->fetch_object()) {
                                    $rule->from->addChild('member', $k->name);
                                }
                            } else {
                                $rule->addChild('from');
                                $rule->from->addChild('member', 'any');
                            }
                            $getTo = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid='$lid' ;");
                            if ($getTo->num_rows > 0) {
                                $rule->addChild('to');
                                while ($k = $getTo->fetch_object()) {
                                    $rule->to->addChild('member', $k->name);
                                }
                            } else {
                                $rule->addChild('to');
                                $rule->to->addChild('member', 'any');
                            }
                            $getSource = $projectdb->query("SELECT member_lid,table_name FROM security_rules_src WHERE rule_lid='$lid' ;");
                            if ($getSource->num_rows > 0) {
                                $rule->addChild('source');
                                while ($k = $getSource->fetch_object()) {

                                    if ($k->table_name == "default_regions") {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    } else {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                    }
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->source->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild('source');
                                $rule->source->addChild('member', 'any');
                            }
                            $getDestination = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$lid';");
                            if ($getDestination->num_rows > 0) {
                                $rule->addChild('destination');
                                while ($k = $getDestination->fetch_object()) {
                                    //if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                    if (($k->table_name == "regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") ) {
//                                        $thename = "name";
//                                    } else {
//                                        $thename = "name";
//                                    }
                                    if ($k->table_name == "default_regions") {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    } else {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                    }
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
//                                            $rule->destination->addChild('member', $kk->{$thename});
                                            $rule->destination->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild('destination');
                                $rule->destination->addChild('member', 'any');
                            }
                            $getUser = $projectdb->query("SELECT name FROM security_rules_usr WHERE rule_lid='$lid';");
                            if ($getUser->num_rows > 0) {
                                $rule->addChild('source-user');
                                while ($k = $getUser->fetch_object()) {
                                    $rule->{'source-user'}->addChild('member',htmlentities($k->name));
                                }
                            } else {
                                $rule->addChild('source-user');
                                $rule->{'source-user'}->addChild('member', 'any');
                            }
                            $getAPP = $projectdb->query("SELECT member_lid,table_name FROM security_rules_app WHERE rule_lid='$lid';");
                            if ($getAPP->num_rows > 0) {
                                $rule->addChild('application');
                                while ($k = $getAPP->fetch_object()) {
                                    $thesql = "SELECT name FROM " . $k->table_name . " WHERE id='" . $k->member_lid . "';";
                                    $getMember = $projectdb->query($thesql);
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->{'application'}->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild('application');
                                $rule->{'application'}->addChild('member', 'any');
                            }
                            $getSRV = $projectdb->query("SELECT member_lid,table_name FROM security_rules_srv WHERE rule_lid='$lid';");
                            if ($getSRV->num_rows > 0) {
                                $rule->addChild('service');
                                while ($k = $getSRV->fetch_object()) {
                                    $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE source='$source' AND id='$k->member_lid';");
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->{'service'}->addChild('member', $kk->name);
                                        }
                                    } else {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'service'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild('service');
                                $rule->{'service'}->addChild('member', 'any');
                            }
                            $getHIP = $projectdb->query("SELECT member_lid,table_name,name FROM security_rules_hip WHERE rule_lid='$lid';");
                            $hipProfiles_field = ($version >= 10)?'source-hip':'hip-profiles';
                            if ($getHIP->num_rows > 0) {
                                $rule->addChild($hipProfiles_field);
                                while ($k = $getHIP->fetch_object()) {
                                    if (($k->member_lid == 0) AND ( $k->table_name == "default")) {
                                        $rule->{$hipProfiles_field}->addChild('member', $k->name);
                                    } else {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND type='hip-profiles';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{$hipProfiles_field}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild($hipProfiles_field);
                                $rule->{$hipProfiles_field}->addChild('member', 'any');
                            }
                            $getCategory = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid='$lid' ;");
                            if ($getCategory->num_rows > 0) {
                                $rule->addChild('category');
                                while ($k = $getCategory->fetch_object()) {
                                    $rule->category->addChild('member', $k->name);
                                }
                            } else {
                                $rule->addChild('category');
                                $rule->category->addChild('member', 'any');
                            }
                            $rule->addChild('action', $data2->action);
                            if ($data2->log_start == 1) {
                                $rule->addChild('log-start', 'yes');
                            }
                            if ($data2->log_end == 1) {
                                $rule->addChild('log-end', 'yes');
                            }
                            else{
                                $rule->addChild('log-end', 'no');
                            }
                            if ($data2->disabled == 1) {
                                $rule->addChild('disabled', 'yes');
                            } else {
                                //$rule->addChild('disabled', 'no');
                            }
                            if ($data2->negate_source == 1) {
                                $rule->addChild('negate-source', 'yes');
                            } else {
                                //$rule->addChild('negate-source', 'no');
                            }
                            if ($data2->negate_destination == 1) {
                                $rule->addChild('negate-destination', 'yes');
                            } else {
                                //$rule->addChild('negate-destination', 'no');
                            }
                            if ($data2->description != "") {
                                $rule->addChild('description');
                                $rule->description = $data2->description;
                            }
                            if ($data2->schedule != "") {
                                $rule->addChild('schedule', $data2->schedule);
                            }
                            if ($data2->log_forwarding != "") {
                                $rule->addChild('log-setting', $data2->log_forwarding);
                            }
                            if ($data2->qos != "None") {
                                if($version >=7){
                                    $rule->addChild('qos');
                                    $rule->qos->addChild('marking');
                                    $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                                }elseif($data2->qos == "ip-dscp" || $data2->qos == "ip-precedence"){
                                    $rule->addChild('qos');
                                    $rule->qos->addChild('marking');
                                    $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                                }
                            }
                            if ($data2->profile_type != "None") {
                                $rule->addChild('profile-setting');
                                if ($data2->profile_type == "group") {
                                    $profile = $rule->{'profile-setting'}->addChild('group');
                                    $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                                    if ($getProfiles->num_rows > 0) {
                                        while ($k = $getProfiles->fetch_object()) {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $profile->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    $profile = $rule->{'profile-setting'}->addChild('profiles');
                                    $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                                    if ($getProfiles->num_rows > 0) {
                                        while ($k = $getProfiles->fetch_object()) {
                                            $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $thetype = $kk->{'type'};
                                                    $theprofiles = $profile->addChild($thetype);
                                                    $theprofiles->addChild('member', $kk->name);
                                                }
                                            } else {
                                                $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE source=0 AND id='$k->member_lid';");
                                                if ($getMember->num_rows > 0) {
                                                    while ($kk = $getMember->fetch_object()) {
                                                        $thetype = $kk->{'type'};
                                                        $theprofiles = $profile->addChild($thetype);
                                                        $theprofiles->addChild('member', $kk->name);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE rule_lid='$lid';");
                            if ($getTAG->num_rows > 0) {
                                $rule->addChild('tag');
                                while ($k = $getTAG->fetch_object()) {
                                    $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->{'tag'}->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            }
                            if ($data2->target != "") {
                                libxml_use_internal_errors(true);
                                $xml_append = simplexml_load_string($data2->target);
                                if ($xml_append) {
                                    SimpleXMLElement_append($rule, $xml_append);
                                }
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/shared/$pvalue/security/rules/entry[@name=\'$myname\']";
                                $xml_final = addslashes($rule->asXML());
                                // shared_security_rules?!?!?!?!?!
                                //$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','shared_security_rules','security_rules','$xml_final','$xpath','edit');");
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','security_rules','security_rules','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/shared/$pvalue/security/rules";
                        $xml_final = "";
                        //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action,name) VALUES ('shared_security_rules','security_rules','$xml_final','$xpath','delete','Delete Rules');");
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action,name) VALUES ('security_rules','security_rules','$xml_final','$xpath','delete','Delete Rules');");
                        $xpath = "/config/shared/$pvalue/security";
                        $xml_final = addslashes($xml->{$pvalue}->security->asXML());
                        //$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('shared_security_rules','security_rules','$xml_final','$xpath','edit');");
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('security_rules','security_rules','$xml_final','$xpath','edit');");
                    }
                    if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                        $first = $policy_order[0];
                        $last = $policy_order[count($policy_order) - 1];
                        # Set first Rule
                        $xpath = addslashes("/config/shared/$pvalue/security/rules/entry[@name='$first']");
                        $where = "top";
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','shared_security_rules','order','','$xpath','move','$where','');");
                        if ($first==$last){}
                        else{
                            $xpath = addslashes("/config/shared/$pvalue/security/rules/entry[@name='$last']");
                            $where = "bottom";
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$last to Bottom','shared_security_rules','order','','$xpath','move','$where','');");
                        }
                        # Set last Rule
                        unset($policy_order[count($policy_order) - 1]);
                        unset($policy_order[0]);
                        foreach ($policy_order as $key => $value) {
                            $xpath = addslashes("/config/shared/$pvalue/security/rules/entry[@name='$value']");
                            $where = "after";
                            $dst = addslashes("$first");
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','shared_security_rules','order','','$xpath','move','$where','$dst');");
                            $first = $value;
                        }
                        unset($policy_order);
                    }
                }

                # NAT
                $getPolicies = $projectdb->query("SELECT id,position,name,description,target,disabled,vsys,lid,tp_sat_bidirectional,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,preorpost,tag,active_active_device_binding,nat_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback,tp_fallback_type FROM nat_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                if ($getPolicies->num_rows > 0) {
                    $xml = new SimpleXMLElement("<config></config>");
                    $xml->addChild($pvalue);
                    $xml->{$pvalue}->addChild("nat");
                    $xml->{$pvalue}->nat->addChild('rules');

                    while ($data2 = $getPolicies->fetch_object()) {
                        $myname = $data2->name;
                        $lid = $data2->id;
                        if ($xml->xpath("/$pvalue/nat/rules/entry[@name='$myname']") == null) {
                            $rule = $xml->{$pvalue}->nat->rules->addChild('entry');
                            $rule->addAttribute('name', $myname);
                            if ($data2->tp_sat_type == "dynamic-ip") {
                                $rule->addChild('source-translation');
                                $stnat = $rule->{'source-translation'}->addChild('dynamic-ip');
                                if ($data2->tp_fallback_type == "translated-address") {
                                    $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address_fallback WHERE rule_lid='$lid';");
                                    if ($getAddr->num_rows > 0) {
                                        $stnat->addChild('fallback');
                                        $stnat->fallback->addChild('translated-address');
                                        while ($getAddrData = $getAddr->fetch_object()) {
                                            $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                            if ($getAddrName->num_rows == 1) {
                                                $getAddrNameData = $getAddrName->fetch_object();
                                                $stnat->fallback->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                            }
                                        }
                                    }
                                } elseif ($data2->tp_fallback_type == "interface-address") {
                                    $stnat->addChild('fallback');
                                    $stnat->fallback->addChild('interface-address');
                                    if ($data2->tp_sat_interface_fallback != "") {
                                        $stnat->fallback->{'interface-address'}->addChild('interface', $data2->tp_sat_interface_fallback);
                                    }
                                    if ($data2->tp_sat_ipaddress_fallback != "") {
                                        $stnat->fallback->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress_fallback);
                                    }
                                }
                                $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid' ;");
                                if ($getAddr->num_rows > 0) {
                                    $stnat->addChild('translated-address');
                                    while ($getAddrData = $getAddr->fetch_object()) {
                                        $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                        if ($getAddrName->num_rows == 1) {
                                            $getAddrNameData = $getAddrName->fetch_object();
                                            $stnat->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                        }
                                    }
                                }
                            } elseif ($data2->tp_sat_type == "dynamic-ip-and-port") {
                                $rule->addChild('source-translation');
                                $stnat = $rule->{'source-translation'}->addChild('dynamic-ip-and-port');
                                if ($data2->tp_sat_address_type == "interface-address") {
                                    $stnat->addChild('interface-address');
                                    $stnat->{'interface-address'}->addChild('interface', $data2->tp_sat_interface);
                                    if (($data2->tp_sat_ipaddress != "") AND ($data2->tp_sat_ipaddress != "None")) {
                                        $stnat->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress);
                                    }
                                } else {
                                    $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid' ;");
                                    if ($getAddr->num_rows > 0) {
                                        $stnat->addChild('translated-address');
                                        while ($getAddrData = $getAddr->fetch_object()) {
                                            $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                            if ($getAddrName->num_rows == 1) {
                                                $getAddrNameData = $getAddrName->fetch_object();
                                                $stnat->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                            }
                                        }
                                    }
                                }
                            } elseif ($data2->tp_sat_type == "static-ip") {
                                $rule->addChild('source-translation');
                                $stnat = $rule->{'source-translation'}->addChild('static-ip');
                                if ($data2->tp_sat_bidirectional == 1) {
                                    $stnat->addChild('bi-directional', 'yes');
                                } else {
                                    $stnat->addChild('bi-directional', 'no');
                                }
                                $getAddr = $projectdb->query("SELECT table_name,member_lid FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                                if ($getAddr->num_rows == 1) {
                                    $getAddrData = $getAddr->fetch_object();
                                    $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                    if ($getAddrName->num_rows == 1) {
                                        $getAddrNameData = $getAddrName->fetch_assoc();
                                        $stnat->addChild('translated-address', $getAddrNameData['name']);
                                    }
                                }
                            }
                            if ($data2->is_dat == 1) {
                                $dtnat = $rule->addChild('destination-translation');
                                if (($data2->tp_dat_address_lid == 0) AND ( $data2->tp_dat_address_table == "")) {

                                } else {
                                    $getAddr = $projectdb->query("SELECT name FROM $data2->tp_dat_address_table WHERE id='$data2->tp_dat_address_lid';");
                                    if ($getAddr->num_rows == 1) {
                                        $getAddrData = $getAddr->fetch_object();
                                        $dtnat->addChild('translated-address', $getAddrData->name);
                                    }
                                }
                                if ($data2->tp_dat_port != 0) {
                                    $dtnat->addChild('translated-port', $data2->tp_dat_port);
                                }
                            }
                            if ($data2->op_zone_to != "") {
                                $rule->addChild('to');
                                $rule->to->addChild('member', $data2->op_zone_to);
                            } else {
                                $rule->addChild('to');
                                $rule->to->addChild('member', 'any');
                            }
                            $getFrom = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$lid';");
                            if ($getFrom->num_rows > 0) {
                                $rule->addChild('from');
                                while ($k = $getFrom->fetch_object()) {
                                    $rule->from->addChild('member', $k->name);
                                }
                            } else {
                                $rule->addChild('from');
                                $rule->from->addChild('member', 'any');
                            }
                            $getSource = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$lid' ;");
                            if ($getSource->num_rows > 0) {
                                $rule->addChild('source');
                                while ($k = $getSource->fetch_object()) {

                                    if ($k->table_name == "default_regions") {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    } else {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                    }
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->source->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild('source');
                                $rule->source->addChild('member', 'any');
                            }
                            $getDestination = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$lid';");
                            if ($getDestination->num_rows > 0) {
                                $rule->addChild('destination');
                                while ($k = $getDestination->fetch_object()) {
                                    //if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                    if (($k->table_name == "regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") ) {
//                                        $thename = "name";
//                                    } else {
//                                        $thename = "name";
//                                    }
                                    if ($k->table_name == "default_regions") {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    } else {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                    }
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->destination->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild('destination');
                                $rule->destination->addChild('member', 'any');
                            }
                            if (($data2->op_service_table != "") AND ( $data2->op_service_lid != "")) {
                                $getsrv = $projectdb->query("SELECT name FROM $data2->op_service_table WHERE id='$data2->op_service_lid';");
                                $getsrvdata = $getsrv->fetch_assoc();
                                $rule->addChild('service', $getsrvdata['name']);
                            } else {
                                $rule->addChild('service', 'any');
                            }
                            if ($data2->op_to_interface != "") {
                                $rule->addChild('to-interface', $data2->op_to_interface);
                            }
                            if ($data2->disabled == 1) {
                                $rule->addChild('disabled', 'yes');
                            } else {
                                //$rule->addChild('disabled', 'no');
                            }
                            if ($data2->nat_type != "") {
                                $rule->addChild('nat-type', $data2->nat_type);
                            } else {
                                $rule->addChild('nat-type', 'ipv4');
                            }
                            $getTAG = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_tag WHERE rule_lid='$lid';");
                            if ($getTAG->num_rows > 0) {
                                $rule->addChild('tag');
                                while ($k = $getTAG->fetch_object()) {
                                    $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->{'tag'}->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            }
                            if ($data2->target != "") {
                                libxml_use_internal_errors(true);
                                $xml_append = simplexml_load_string($data2->target);
                                if ($xml_append) {
                                    SimpleXMLElement_append($rule, $xml_append);
                                }
                            }
                            if ($data2->description != "") {
                                $rule->addChild('description');
                                $rule->description = $data2->description;
                            }
                            if ($data2->active_active_device_binding != "") {
                                $rule->addChild('active-active-device-binding', $data2->active_active_device_binding);
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/shared/$pvalue/nat/rules/entry[@name=\'$myname\']";
                                $xml_final = addslashes($rule->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','nat_rules','nat_rules','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/shared/$pvalue/nat";
                        $xml_final = addslashes($xml->{$pvalue}->nat->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('nat_rules','nat_rules','$xml_final','$xpath','edit');");
                    }
                }

                # APPLICATION OVERRIDE
                $getPolicies = $projectdb->query("SELECT position,name,negate_source,negate_destination,description,disabled,id,target,protocol,app_id,app_table,port FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                if ($getPolicies->num_rows > 0) {
                    $xml = new SimpleXMLElement("<config></config>");
                    $xml->addChild($pvalue);
                    $xml->{$pvalue}->addChild("application-override");
                    $xml->{$pvalue}->{'application-override'}->addChild('rules');

                    while ($data2 = $getPolicies->fetch_object()) {
                        $myname = $data2->name;
                        $lid = $data2->id;
                        if ($xml->xpath("/$pvalue/application-override/rules/entry[@name='$myname']") == null) {
                            $rule = $xml->{$pvalue}->{'application-override'}->rules->addChild('entry');
                            $rule->addAttribute('name', $myname);
                            $getFrom = $projectdb->query("SELECT name FROM appoverride_rules_from WHERE rule_lid='$lid' ;");
                            if ($getFrom->num_rows > 0) {
                                $rule->addChild('from');
                                while ($k = $getFrom->fetch_object()) {
                                    $rule->from->addChild('member', $k->name);
                                }
                            } else {
                                $rule->addChild('from');
                                $rule->from->addChild('member', 'any');
                            }
                            $getTo = $projectdb->query("SELECT name FROM appoverride_rules_to WHERE rule_lid='$lid' ;");
                            if ($getTo->num_rows > 0) {
                                $rule->addChild('to');
                                while ($k = $getTo->fetch_object()) {
                                    $rule->to->addChild('member', $k->name);
                                }
                            } else {
                                $rule->addChild('to');
                                $rule->to->addChild('member', 'any');
                            }
                            $getSource = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_src WHERE rule_lid='$lid';");
                            if ($getSource->num_rows > 0) {
                                $rule->addChild('source');
                                while ($k = $getSource->fetch_object()) {
                                    if ($k->table_name == "default_regions") {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    } else {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                    }
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->source->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild('source');
                                $rule->source->addChild('member', 'any');
                            }
                            $getDestination = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_dst WHERE rule_lid='$lid' ;");
                            if ($getDestination->num_rows > 0) {
                                $rule->addChild('destination');
                                while ($k = $getDestination->fetch_object()) {
                                    if ($k->table_name == "default_regions") {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    } else {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                    }
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->destination->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            } else {
                                $rule->addChild('destination');
                                $rule->destination->addChild('member', 'any');
                            }

                            $getAPP = $projectdb->query("SELECT name FROM $data2->app_table WHERE id='$data2->app_id';");
                            if ($getAPP->num_rows == 1) {
                                $k = $getAPP->fetch_object();
                                $rule->addChild('application', $k->name);
                            }

                            if ($data2->disabled == 1) {
                                $rule->addChild('disabled', 'yes');
                            } else {
                                //$rule->addChild('disabled', 'no');
                            }
                            if ($data2->negate_source == 1) {
                                $rule->addChild('negate-source', 'yes');
                            } else {
                                //$rule->addChild('negate-source', 'no');
                            }
                            if ($data2->negate_destination == 1) {
                                $rule->addChild('negate-destination', 'yes');
                            } else {
                                //$rule->addChild('negate-destination', 'no');
                            }
                            if ($data2->description != "") {
                                $rule->addChild('description');
                                $rule->description = $data2->description;
                            }
                            $rule->addChild('protocol', $data2->protocol);
                            $rule->addChild('port', $data2->port);
                            $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE rule_lid='$lid';");
                            if ($getTAG->num_rows > 0) {
                                $rule->addChild('tag');
                                while ($k = $getTAG->fetch_object()) {
                                    $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $rule->{'tag'}->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            }
                            if ($data2->target != "") {
                                libxml_use_internal_errors(true);
                                $xml_append = simplexml_load_string($data2->target);
                                if ($xml_append) {
                                    SimpleXMLElement_append($rule, $xml_append);
                                }
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/shared/$pvalue/application-override/rules/entry[@name=\'$myname\']";
                                $xml_final = addslashes($rule->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','appoverride_rules','appoverride_rules','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/shared/$pvalue/application-override";
                        $xml_final = addslashes($xml->{$pvalue}->{'application-override'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('appoverride_rules','appoverride_rules','$xml_final','$xpath','edit');");
                    }
                }

                # OTHER RULES
                $getPolicies = $projectdb->query("SELECT id,type,xml FROM other_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY id ASC;");
                if ($getPolicies->num_rows > 0) {
                    $xml = new SimpleXMLElement("<config></config>");
                    $xml->addChild($pvalue);


                    while ($data2 = $getPolicies->fetch_assoc()) {
                        $lid = $data2->id;

                        $thetype = $data2['type'];
                        $xmlfield = $data2['xml'];
                        $xml_append = simplexml_load_string($xmlfield);
                        $xml->{$pvalue}->addChild($thetype);
                        $theProfiles = $xml->{$pvalue}->{$thetype};
                        SimpleXMLElement_append($theProfiles, $xml_append);

                        if (($api_call == "single") OR ( $api_call == "atomic")) {
                            $xpath = "/config/shared/$platform/entry[@name=\'$vsys\']/$pvalue/$thetype";
                            $xml_final = addslashes($theProfiles->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$thetype','$thetype','$thetype','$xml_final','$xpath','edit');");
                        }
                    }
                }

                unset($xml);
            }

            #Panorama
            $getDG = $projectdb->query("SELECT devices,master_device,description,device_mapping_id FROM devicegroups WHERE source='$source';");
            if ($getDG->num_rows > 0) {
                $xml = new SimpleXMLElement('<config><devices><entry name="localhost.localdomain"><device-group></device-group></entry></devices></config>');
                $allDG = array();
                $platform = "device-group";
                $policies = array("pre-rulebase", "post-rulebase");
                while ($DG = $getDG->fetch_assoc()) {
                    $device_mapping_id = $DG['device_mapping_id'];
                    $getDGname = $projectdb->query("SELECT vsys FROM device_mapping WHERE id='$device_mapping_id';");
                    if ($getDGname->num_rows == 1) {
                        $getDGnameData = $getDGname->fetch_assoc();
                        $DGName = $getDGnameData['vsys'];
                    }
                    $allDG[] = $DGName; # To be used after this process to do a loop
                    $thedevicegroup1 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/device-group/entry[@name='$DGName']");
                    if (empty($thedevicegroup1)) {
                        $thedevicegroupPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/device-group");
                        $thedevicegroup = $thedevicegroupPath[0]->addChild('entry');
                        $thedevicegroup->addAttribute('name', $DGName);
                        if ($DG['devices'] != "") {
                            $xml_append = simplexml_load_string($DG['devices']);
                            SimpleXMLElement_append($thedevicegroup, $xml_append);
                        } else {
                            $thedevicegroup->addChild('devices');
                        }

                        if (($DG['master_device'] == "") OR ( $DG['master_device'] == "None") OR ( $DG['master_device'] == null)) {

                        } else {
                            $xml_append = simplexml_load_string($DG['master_device']);
                            SimpleXMLElement_append($thedevicegroup, $xml_append);
                        }
                        if ($DG['description'] != "") {
                            $thedevicegroup->addChild('description');
                            $thedevicegroup->description = $DG['description'];
                        }
                    } else {
                        $thedevicegroup = $thedevicegroup1[0];
                        if ($DG['description'] != "") {
                            if (!isset($thedevicegroup->description)) {
                                $thedevicegroup->addChild('description');
                                $thedevicegroup->description = $DG['description'];
                            } else {
                                $thedevicegroup->description = $DG['description'];
                            }
                        }
                    }
                    if (($api_call == "atomic") OR ( $api_call == "single")) {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/device-group";
                        $xml_final = addslashes($thedevicegroup->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$DGName','devicegroup','devicegroup','$xml_final','$xpath','set');");
                    }
                    # HEREEEEeEEEEEEEEE
                }
            }

        }
        else {

            #Firewall
            //$getDG = $projectdb->query("SELECT * FROM virtual_systems WHERE source='$source' $sql_modified;");
            $getDG = $projectdb->query("SELECT * FROM virtual_systems WHERE source='$source';");
            if ($getDG->num_rows > 0) {
                #Check if VSYS root Exists
                $xml = new SimpleXMLElement('<config><devices><entry name="localhost.localdomain"><vsys></vsys></entry></devices></config>');
                $allDG = array();
                $platform = "vsys";
                $policies = array("rulebase");
                while ($DG = $getDG->fetch_assoc()) {
                    $DGName = $DG['name'];
                    $allDG[] = $DGName; # To be used after this process to do a loop
                    $thedevicegroup1 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$DGName']");
                    if (empty($thedevicegroup1)) {
                        $thedevicegroupPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/vsys");
                        $thedevicegroup = $thedevicegroupPath[0]->addChild('entry');
                        $thedevicegroup->addAttribute('name', $DGName);

                        if ($DG['display_name'] != "") {
                            $thedevicegroup->addChild("display-name", $DG['display_name']);
                        }
                    } else {
                        $thedevicegroup = $thedevicegroup1[0];
                    }
                    $thedevicegroup->addChild('import');
                    $thedevicegroup->import->addChild('network');
                    $DGnetwork = $thedevicegroup->import->network;
                    $interfaces = $DG['interfaces'];
                    if ($interfaces != "") {
                        $interfaces = explode(",", $DG['interfaces']);
                        $DGnetwork->addChild('interface');
                        foreach ($interfaces as $key => $newvalue) {
                            $DGnetwork->interface->addChild('member', $newvalue);
                        }
                    }
                    $virtual_router = $DG['virtual_router'];
                    if ($virtual_router != "") {
                        $virtual_router = explode(",", $DG['virtual_router']);
                        $DGnetwork->addChild('virtual-router');
                        foreach ($virtual_router as $key => $newvalue) {
                            $DGnetwork->{'virtual-router'}->addChild('member', $newvalue);
                        }
                    }
                    $virtual_wire = $DG['virtual_wire'];
                    if ($virtual_wire != "") {
                        $virtual_wire = explode(",", $DG['virtual_wire']);
                        $DGnetwork->addChild('virtual-wire');
                        foreach ($virtual_wire as $key => $newvalue) {
                            $DGnetwork->{'virtual-wire'}->addChild('member', $newvalue);
                        }
                    }
                    $vlan = $DG['vlan'];
                    if ($vlan != "") {
                        $vlan = explode(",", $DG['vlan']);
                        $DGnetwork->addChild('vlan');
                        foreach ($vlan as $key => $newvalue) {
                            $DGnetwork->{'vlan'}->addChild('member', $newvalue);
                        }
                    }
                    $visible_vsys = $DG['visible_vsys'];
                    if ($visible_vsys != "") {
                        $visible_vsys = explode(",", $DG['visible_vsys']);
                        $DGnetwork->addChild('visible-vsys');
                        foreach ($visible_vsys as $key => $newvalue) {
                            $DGnetwork->{'visible-vsys'}->addChild('member', $newvalue);
                        }
                    }
                    $thedevicegroup->import->addChild('resource');
                    $DGresource = $thedevicegroup->import->resource;
                    $max_application_override_rules = $DG['max_application_override_rules'];
                    if ($max_application_override_rules != "0") {
                        $DGresource->addChild('max-application-override-rules', $max_application_override_rules);
                    }
                    $max_concurrent_ssl_vpn_tunnels = $DG['max_concurrent_ssl_vpn_tunnels'];
                    if ($max_concurrent_ssl_vpn_tunnels != "0") {
                        $DGresource->addChild('max-concurrent-ssl-vpn-tunnels', $max_concurrent_ssl_vpn_tunnels);
                    }
                    $max_cp_rules = $DG['max_cp_rules'];
                    if ($max_cp_rules != "0") {
                        $DGresource->addChild('max-cp-rules', $max_cp_rules);
                    }
                    $max_dos_rules = $DG['max_dos_rules'];
                    if ($max_dos_rules != "0") {
                        $DGresource->addChild('max-dos-rules', $max_dos_rules);
                    }
                    $max_nat_rules = $DG['max_nat_rules'];
                    if ($max_nat_rules != "0") {
                        $DGresource->addChild('max-nat-rules', $max_nat_rules);
                    }
                    $max_pbf_rules = $DG['max_pbf_rules'];
                    if ($max_pbf_rules != "0") {
                        $DGresource->addChild('max-pbf-rules', $max_pbf_rules);
                    }
                    $max_qos_rules = $DG['max_qos_rules'];
                    if ($max_qos_rules != "0") {
                        $DGresource->addChild('max-qos-rules', $max_qos_rules);
                    }
                    $max_security_rules = $DG['max_security_rules'];
                    if ($max_security_rules != "0") {
                        $DGresource->addChild('max-security-rules', $max_security_rules);
                    }
                    $max_sessions = $DG['max_sessions'];
                    if ($max_sessions != "0") {
                        $DGresource->addChild('max-sessions', $max_sessions);
                    }
                    $max_site_to_site_vpn_tunnels = $DG['max_site_to_site_vpn_tunnels'];
                    if ($max_site_to_site_vpn_tunnels != "0") {
                        $DGresource->addChild('max-site-to-site-vpn-tunnels', $max_site_to_site_vpn_tunnels);
                    }
                    $max_ssl_decryption_rules = $DG['max_ssl_decryption_rules'];
                    if ($max_ssl_decryption_rules != "0") {
                        $DGresource->addChild('max-ssl-decryption-rules', $max_ssl_decryption_rules);
                    }
                    $dns_proxy = $DG['dns_proxy'];
                    if (($dns_proxy != "") AND ( $dns_proxy != "None")) {
                        $thedevicegroup->import->addChild('dns-proxy');
                        $thedevicegroup->import->{'dns-proxy'}->addChild($dns_proxy);
                    }
                    $allow_forward_decrypted_content = $DG['allow_forward_decrypted_content'];
                    if ($allow_forward_decrypted_content == "") {
                        $allow_forward_decrypted_content = "no";
                    }
                    if (($max_application_override_rules==0) AND ($max_concurrent_ssl_vpn_tunnels==0) AND ($max_cp_rules==0) AND ($max_dos_rules==0)
                        AND ($max_nat_rules==0) AND ($max_pbf_rules==0) AND ($max_qos_rules==0) AND ($max_security_rules==0) AND ($max_ssl_decryption_rules==0)
                        AND ($dns_proxy==0) AND ($max_sessions==0) AND ($max_site_to_site_vpn_tunnels==0)) {
                        if ($thedevicegroup->xpath("import/resource")){
                            $SA = $thedevicegroup->xpath("import/resource");
                            unset($SA[0][0]);
                        }
                    }
                    $thedevicegroup->addChild('setting');
                    $thedevicegroup->setting->addChild('ssl-decrypt');
                    $thedevicegroup->setting->{'ssl-decrypt'}->addChild('allow-forward-decrypted-content', $allow_forward_decrypted_content);



                    if (($api_call == "atomic") OR ( $api_call == "single")) {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/vsys";
                        $xml_final = addslashes($thedevicegroup->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$DGName','vsys','vsys','$xml_final','$xpath','set');");
                    }
                }
            }
        }

        # ADD Objects into the DeviceGRoup or VSYS
        if (count($allDG) > 0) {
            foreach ($allDG as $kkey => $vvalue) {
                $vsys = $vvalue;
                update_progress($project, '0.40', 'Loading Objects into VSYS/DEVICE-GROUP ' . $vsys);
                $xml = new SimpleXMLElement("<config></config>");

                # ADDRESS
                $getShared = $projectdb->query("SELECT name,type,ipaddress,cidr,description,fqdn,v4,v6,tag FROM address WHERE source='$source' AND vsys='$vsys'  AND dummy=0 $sql_modified;");
                if ($getShared->num_rows > 0) {
                    # ADDRESS
                    $xml->addChild('address');
                    while ($Data = $getShared->fetch_assoc()) {
                        $myname = $Data['name'];
                        $address = $xml->address->addChild('entry');
                        $address->addAttribute('name', $Data['name']);
                        if ($Data['type'] == "ip-netmask") {
                            $address->addChild('ip-netmask', $Data['ipaddress'] . '/' . $Data['cidr']);
                        } elseif ($Data['type'] == "ip-range") {
                            $address->addChild('ip-range', $Data['ipaddress']);
                        } elseif ($Data['type'] == "fqdn") {
                            $address->addChild('fqdn', $Data['ipaddress']);
                        } elseif ($Data['type'] == "dynamic") {
                            if ($version == 5) {
                                $address->addChild('dynamic', $Data['ipaddress']);
                            } elseif ($version >= 6) {
                                add_log('error', 'Exporting Shared Address', 'Dynamic Address Not supported in Panos 6.x [' . $myname . ']', $source, 'Object was Not Migrated');
                            }
                        }
                        if ($Data['description'] != "") {
                            $address->addChild('description');
                            $address->description = $Data['description'];
                        }
                        if (($Data['tag'] != "") AND ( $version >= 6)) {
                            $tags = $address->addChild('tag');
                            $mytags = explode(",", $Data['tag']);
                            foreach ($mytags as $key => $value) {
                                $tags->addChild('member', $value);
                            }
                        }
                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/address/entry[@name=\'$myname\']";
                            $xml_final = addslashes($address->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','address','address','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/address";
                        $xml_final = addslashes($xml->address->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('address','address','$xml_final','$xpath','edit');");
                    }
                }

                # SCHEDULES
                $getShared = $projectdb->query("SELECT name,xml FROM schedules WHERE source='$source' AND vsys='$vsys' AND dummy = 0 $sql_modified  ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('schedule');
                    $theProfiles2 = $xml->xpath("/config/schedule");
                    $theProfiles = $theProfiles2[0];
                    while ($data2 = $getShared->fetch_assoc()) {
                        $xmlfield = $data2['xml'];
                        $xmlname = $data2['name'];
                        if ($version >= 7) {
                            if (strpos($xmlfield,"<schedule-type>")==false){
                                if (strpos($xmlfield,"<recurring>")!== false){
                                    $xmlfield = str_replace("<recurring>", "<schedule-type><recurring>", $xmlfield);
                                }
                                if (strpos($xmlfield,"</recurring>")!== false){
                                    $xmlfield = str_replace("</recurring>", "</recurring></schedule-type>", $xmlfield);
                                }
                                if (strpos($xmlfield,"<non-recurring>")!== false){
                                    $xmlfield = str_replace("<non-recurring>", "<schedule-type><non-recurring>", $xmlfield);
                                }
                                if (strpos($xmlfield,"</non-recurring>")!== false){
                                    $xmlfield = str_replace("</non-recurring>", "</non-recurring></schedule-type>", $xmlfield);
                                }
                            }

                        }
                        $xml_append = simplexml_load_string($xmlfield);
                        SimpleXMLElement_append($theProfiles, $xml_append);
                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/schedule/entry[@name=\'$xmlname\']";
                            $xml_final = addslashes($xmlfield);
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','schedules','schedules','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/schedule";
                        $xml_final = addslashes($xml->schedule->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('schedules','schedules','$xml_final','$xpath','edit');");
                    }
                }

                # LOG SETTINGS
                $queryShared = "SELECT type FROM log_settings WHERE source='$source' AND (type!='system') AND (type!='config')  AND vsys='$vsys' AND dummy = 0 $sql_modified  GROUP BY type ORDER BY id;";
                $getShared = $projectdb->query($queryShared);
                if ($getShared->num_rows > 0) {
                    $xml->addChild('log-settings');
                    $theProfiles = $xml->{'log-settings'};
                    while ($Data = $getShared->fetch_assoc()) {
                        $type = $Data['type'];
                        $thetype = $theProfiles->{$type};
                        if (empty($thetype)) {
                            $thetype = $theProfiles->addChild($type);
                        }
                        $getbyType = $projectdb->query("SELECT xml,name FROM log_settings WHERE source='$source' AND type='$type' AND vsys='$vsys' AND dummy = 0 $sql_modified ORDER BY id;");
                        if ($getbyType->num_rows > 0) {
                            while ($data2 = $getbyType->fetch_assoc()) {
                                $xmlfield = $data2['xml'];
                                $xmlname = $data2['name'];

                                if($version >= 7){
                                    if($type == "snmptrap"){
                                        // En versión 7, el campo member tiene que ser una IP sino da error
                                        // Check if is IP
                                        $xmlfield2 = $xmlfield;
                                        $search_member = explode ("<manager>", $xmlfield2);
                                        $search_member2 = explode ("</manager>", $search_member[1]);
                                        $member = $search_member2[0];
                                        $is_ip = validateIpAddress($member, "v4");
                                        // Return 1: ip correct
                                        // si da error, añadir mensaje de error en el output mapping
                                    }
                                }

                                $xml_append = simplexml_load_string($xmlfield);
                                SimpleXMLElement_append($xml->{'log-settings'}->{$type}, $xml_append);
                                if ($api_call == "single") {
                                    $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/log-settings/$type/entry[@name=\'$xmlname\']";
                                    $xml_final = addslashes($xmlfield);
                                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','log_settings','log_settings','$xml_final','$xpath','edit');");
                                }
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/log-settings";
                        $xml_final = addslashes($xml->{'log-settings'}->profiles->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('log_settings','log_settings','$xml_final','$xpath','set');");
                    }
                }

                # PROFILES
                $getShared = $projectdb->query("SELECT type FROM profiles WHERE source='$source' AND (name!='strict') AND (name!='default') AND vsys='$vsys' AND dummy = 0 $sql_modified GROUP BY type ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('profiles');
                    $theProfiles = $xml->profiles;
                    while ($Data = $getShared->fetch_assoc()) {
                        $type = $Data['type'];
                        $thetype = $theProfiles->{$type};
                        if (empty($thetype)) {
                            $thetype = $theProfiles->addChild($type);
                        }
                        $getbyType = $projectdb->query("SELECT xml,name FROM profiles WHERE source='$source' AND (name!='strict') AND (name!='default') AND type='$type' AND vsys='$vsys' AND dummy = 0 $sql_modified ORDER BY id;");
                        if ($getbyType->num_rows > 0) {
                            while ($data2 = $getbyType->fetch_assoc()) {
                                $xmlfield = $data2['xml'];
                                $xmlname = $data2['name'];
                                if ($version > 5) {
                                    if ((strpos($xmlfield,"<packet-capture>yes</packet-capture>")!== false) AND ($type!="virus")){
                                        $xmlfield = str_replace("<packet-capture>yes</packet-capture>", "<packet-capture>single-packet</packet-capture>", $xmlfield);
                                    }
                                    if ((strpos($xmlfield,"<packet-capture>no</packet-capture>")!== false) AND ($type!="virus")){
                                        $xmlfield = str_replace("<packet-capture>no</packet-capture>", "<packet-capture>disable</packet-capture>", $xmlfield);
                                    }
                                }
                                if ($version >= 7) {
                                    if ((strpos($xmlfield,"<action>block</action>")!== false) AND ($type == "virus")){
                                        $xmlfield = str_replace("<action>block</action>", "<action>drop</action>", $xmlfield);
                                    }
                                    if ((strpos($xmlfield,"<wildfire-action>block</wildfire-action>")!== false) AND ($type == "virus")){
                                        $xmlfield = str_replace("<wildfire-action>block</wildfire-action>", "<wildfire-action>drop</wildfire-action>", $xmlfield);
                                    }
                                    //if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "spyware")){
                                    //    $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                                    //}
                                    if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "vulnerability")){
                                        $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                                    }
                                    /* SE TENDRÁ QUE HACER INSERT EN LA TABLA DE OUTPUT MAPPING EN EL CAMPO ERROR MESSAGE Y QUE SALGA EN EL + --> PENSAR COMO HACERLO */
                                    if ((strpos($xmlfield,"<action>forward</action>")!== false) AND ($type == "file-blocking")){
                                        $xmlfield = str_replace("<action>forward</action>", "", $xmlfield);
                                    }
                                    if ((strpos($xmlfield,"<action>continue-and-forward</action>")!== false) AND ($type == "file-blocking")){
                                        $xmlfield = str_replace("<action>continue-and-forward</action>", "", $xmlfield);
                                    }

                                }

                                $xml_append = simplexml_load_string($xmlfield);
                                SimpleXMLElement_append($xml->profiles->{$type}, $xml_append);
                                if ($api_call == "single") {
                                    $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/profiles/$type/entry[@name=\'$xmlname\']";
                                    $xml_final = addslashes($xmlfield);
                                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','profiles','profiles','$xml_final','$xpath','edit');");
                                }
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/profiles";
                        $xml_final = addslashes($xml->profiles->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('profiles','profiles','$xml_final','$xpath','edit');");
                    }
                }

                # PROFILES GROUPS
                $getShared = $projectdb->query("SELECT name,xml FROM profiles_groups WHERE source='$source' AND vsys='$vsys' AND dummy = 0 $sql_modified ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('profile-group');
                    $theProfiles2 = $xml->xpath("/config/profile-group");
                    $theProfiles = $theProfiles2[0];
                    while ($data2 = $getShared->fetch_assoc()) {
                        $xmlfield = $data2['xml'];
                        $xmlname = $data2['name'];
                        $xml_append = simplexml_load_string($xmlfield);
                        SimpleXMLElement_append($theProfiles, $xml_append);

                        // En version 6 hay la opción de poner alertAll pero en la 7 no, como proceder?
                        if ($version >= 7) {
                            if ((strpos($xmlfield,"<file-blocking><member>alertAll</member></file-blocking>")!== false) AND ($type == "file-blocking")){
                                $xmlfield = str_replace("<file-blocking><member>alertAll</member></file-blocking>", "<file-blocking><member>All-Files</member></file-blocking>", $xmlfield);
                            }
                        }

                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/profile-group/entry[@name=\'$xmlname\']";
                            $xml_final = addslashes($xmlfield);
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','profiles_group','profiles_groups','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/profile-group";
                        $xml_final = addslashes($xml->{'profile-group'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('profiles_group','profiles_group','$xml_final','$xpath','edit');");
                    }
                }

                # ADDRESS GROUPS
                $getShared = $projectdb->query("SELECT name,id,tag,filter,type,description FROM address_groups_id WHERE source='$source' AND vsys='$vsys' $sql_modified;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('address-group');
                    while ($Data = $getShared->fetch_assoc()) {
                        $groupName = $Data['name'];
                        $lid = $Data['id'];
                        $myname = $Data['name'];
                        if ($xml->xpath("/config/address-group/entry[@name='$myname']") == null) {
                            $getMembers = $projectdb->query("SELECT table_name,member_lid FROM address_groups WHERE source='$source' and lid='$lid'");
                            if ($getMembers->num_rows > 0) {
                                $service = $xml->{'address-group'}->addChild('entry');
                                $service->addAttribute('name', $Data['name']);
                                if (($version >= 6) AND ( $Data['type'] == "static")) {
                                    $service2 = $service->addChild('static');
                                } elseif ($version < 6) {
                                    $service2 = $service;
                                }
                                while ($Datas = $getMembers->fetch_assoc()) {
                                    $table_name = $Datas['table_name'];
                                    $member_lid = $Datas['member_lid'];
                                    $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                                    if ($getName->num_rows==1){
                                        $Datas2 = $getName->fetch_assoc();
                                        $member = $service2->addChild('member', $Datas2['name']);
                                    }
                                }
                            } else {
                                $service = $xml->{'address-group'}->addChild('entry');
                                $service->addAttribute('name', $Data['name']);
                                if (($version >= 6) AND ( $Data['type'] == "dynamic")) {
                                    $service2 = $service->addChild('dynamic');
                                    $filter = str_replace("<br>", "\n", $Data['filter']);
                                    $service2 = $service->dynamic->addChild('filter', $filter);
                                }
                            }
                            if ($Data['description'] != "") {
                                $service->addChild('description');
                                $service->description = $Data['description'];
                            }
                            if ($Data['tag'] != "") {
                                $tags = explode(",", $Data['tag']);
                                $shtag = $service->addChild('tag');
                                foreach ($tags as $kkey => $vvalue) {
                                    $shtag->addChild('member', $vvalue);
                                }
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/address-group/entry[@name=\'$myname\']";
                                $xml_final = addslashes($service->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','address_groups','address_groups','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/address-group";
                        $xml_final = addslashes($xml->{'address-group'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('address_groups','address_groups','$xml_final','$xpath','edit');");
                    }
                }

                # TAGS
                $getShared = $projectdb->query("SELECT name,color,comments FROM tag WHERE source='$source' AND vsys='$vsys' AND dummy = 0 $sql_modified;");
                if (($version >= 6) AND ( $getShared->num_rows > 0)) {
                    $xml->addChild('tag');
                    $theProfiles = $xml->tag;
                    while ($tag = $getShared->fetch_assoc()) {
                        $tagName = $tag['name'];
                        $newtag = $theProfiles->addChild('entry');
                        $newtag->addAttribute('name', $tagName);
                        if (($tag['color'] != "") AND ( $tag['color'] != "None")) {
                            $newtag->addChild('color', $tag['color']);
                        }
                        if ($tag['comments'] != "") {
                            $newtag->addChild('comments', $tag['comments']);
                        }
                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/tag/entry[@name=\'$tagName\']";
                            $xml_final = addslashes($newtag->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$tagName','tag','tag','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/tag";
                        $xml_final = addslashes($xml->tag->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('tag','tag','$xml_final','$xpath','edit');");
                    }
                }

                # SERVICES
                $getShared = $projectdb->query("SELECT name,dport,sport,protocol,tag,description FROM services WHERE source='$source' AND vsys='$vsys' AND (protocol = 'tcp' or protocol = 'udp') AND (name <> 'application-default' AND name <> 'service-http' AND name <> 'service-https') AND dummy=0 $sql_modified;");
                $sql = "SELECT name,dport,sport,protocol,tag,description FROM services WHERE source='$source' AND vsys='$vsys' AND (protocol = 'tcp' or protocol = 'udp') AND (name <> 'application-default' AND name <> 'service-http' AND name <> 'service-https') AND dummy=0 $sql_modified;";

                if ($getShared->num_rows > 0) {
                    $xml->addChild('service');
                    while ($Data = $getShared->fetch_assoc()) {
                        $myname = $Data['name'];
                        if ($xml->xpath("/config/service/entry[@name='$myname']") == null) {
                            $service = $xml->service->addChild('entry');
                            $service->addAttribute('name', $Data['name']);
                            $protocol = $service->addChild('protocol');
                            $port = $protocol->addChild($Data['protocol']);
                            $port->addChild('port', $Data['dport']);
                            if (($Data['sport'] != NULL) or ( $Data['sport'] != "")) {
                                $port->addChild('source-port', $Data['sport']);
                            }
                            if ($Data['description'] != "") {
                                $protocol = $service->addChild('description');
                                $service->description = $Data['description'];
                            }
                            if (($version >= 6) AND ( $Data['tag'] != "")) {
                                $tags = $service->addChild('tag');
                                $mytags = explode(",", $Data['tag']);
                                foreach ($mytags as $key => $value) {
                                    $tags->addChild('member', $value);
                                }
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/service/entry[@name=\'$myname\']";
                                $xml_final = addslashes($service->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','services','services','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/service";
                        $xml_final = addslashes($xml->service->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('services','services','$xml_final','$xpath','edit');");
                    }
                }

                # SERVICES GROUPS
                $getShared = $projectdb->query("SELECT name,id,tag FROM services_groups_id WHERE source='$source' AND vsys='$vsys' $sql_modified;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('service-group');
                    while ($Data = $getShared->fetch_assoc()) {
                        $groupName = $Data['name'];
                        $lid = $Data['id'];
                        $myname = $Data['name'];
                        if ($xml->xpath("/config/service-group/entry[@name='$myname']") == null) {
                            $getMembers = $projectdb->query("SELECT table_name,member_lid FROM services_groups WHERE source='$source' and lid='$lid'");
                            if ($getMembers->num_rows > 0) {
                                $service = $xml->{'service-group'}->addChild('entry');
                                $service->addAttribute('name', $Data['name']);
                                if ($version >= 6) {
                                    $service2 = $service->addChild('members');
                                } elseif ($version < 6) {
                                    $service2 = $service;
                                }
                                while ($Datas = $getMembers->fetch_assoc()) {
                                    $table_name = $Datas['table_name'];
                                    $member_lid = $Datas['member_lid'];
                                    $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                                    if ($getName->num_rows==1){
                                        $Datas2 = $getName->fetch_assoc();
                                        $member = $service2->addChild('member', $Datas2['name']);
                                    }
                                }
                                if (($version >= 6) AND ( $Data['tag'] != "")) {
                                    $tags = $service->addChild('tag');
                                    $mytags = explode(",", $Data['tag']);
                                    foreach ($mytags as $key => $value) {
                                        $tags->addChild('member', $value);
                                    }
                                }
                                if ($api_call == "single") {
                                    $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/service-group/entry[@name=\'$myname\']";
                                    $xml_final = addslashes($service->asXML());
                                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','services_groups','services_groups','$xml_final','$xpath','edit');");
                                }
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/service-group";
                        $xml_final = addslashes($xml->{'service-group'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('services_groups','services_groups','$xml_final','$xpath','edit');");
                    }
                }

                # EXTERNAL-LISTS
                $getShared = $projectdb->query("SELECT name,xml FROM external_list WHERE source='$source' AND vsys='$vsys' GROUP BY name ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('external-list');
                    $theProfiles2 = $xml->xpath("/config/external-list");
                    $theProfiles = $theProfiles2[0];
                    while ($data2 = $getShared->fetch_assoc()) {
                        $xmlfield = $data2['xml'];
                        $xmlname = $data2['name'];
                        $xml_append = simplexml_load_string($xmlfield);
                        SimpleXMLElement_append($theProfiles, $xml_append);
                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/external-list/entry[@name=\'$xmlname\']";
                            $xml_final = addslashes($xmlfield);
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','external_list','external_list','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/external-list";
                        $xml_final = addslashes($xml->{'external-list'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('external_list','external_list','$xml_final','$xpath','edit');");
                    }
                }

                # REGIONS
                $getShared = $projectdb->query("SELECT name,xml,address,latitude,longitude FROM regions WHERE source='$source' AND vsys='$vsys' $sql_modified ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('region');
                    $theProfiles2 = $xml->xpath("/config/region");
                    $theProfiles = $theProfiles2[0];
                    while ($data2 = $getShared->fetch_assoc()) {
                        $xmlfield = $data2['xml'];
                        $xmlname = $data2['name'];
                        $latitude=$data2['latitude'];
                        $longitude=$data2['longitude'];
                        $regionMembers=$data2['address'];

                        $newRegion=$theProfiles->addChild("entry");
                        $newRegion->addAttribute('name', $xmlname);
                        if ($regionMembers!=""){
                            $newRegion->addChild("address");
                            $regionMembersArray=explode(",",$regionMembers);
                            foreach ($regionMembersArray as $regionMembersValue){
                                $newRegion->address->addChild("member",$regionMembersValue);
                            }
                        }
                        if (($longitude!="") AND ($latitude!="")){
                            $newRegion->addChild("geo-location");
                            $newRegion->{'geo-location'}->addChild("latitude",$latitude);
                            $newRegion->{'geo-location'}->addChild("longitude",$longitude);
                        }
                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/region/entry[@name=\'$xmlname\']";
                            $newRegionXML=$newRegion->asXML();
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','regions','regions','$newRegionXML','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/region";
                        $xml_final = addslashes($xml->region->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('regions','regions','$xml_final','$xpath','edit');");
                    }
                }

                # APPLICATIONS
                $getShared = $projectdb->query("SELECT id,name,description,spyware_ident,category,subcategory,parent_app,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,tcp_half_closed_timeout,tcp_time_wait_timeout FROM applications WHERE source='$source' AND vsys='$vsys' AND dummy=0 $sql_modified ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('application');
                    while ($data2 = $getShared->fetch_object()) {
                        $appid = $data2->id;
                        $myname = $data2->name;
                        if ($xml->xpath("/config/application/entry[@name='$myname']") == null) {
                            $application = $xml->application->addChild('entry');
                            $application->addAttribute('name', $myname);
                            if ($data2->description != "") {
                                $application->addChild('description');
                                $application->description = $data2->description;
                            }
                            if ($data2->category != "") {
                                $application->addChild('category', $data2->category);
                            }
                            if ($data2->subcategory != "") {
                                $application->addChild('subcategory', $data2->subcategory);
                            }
                            if ($data2->risk != "") {
                                $application->addChild('risk', $data2->risk);
                            }
                            if ($data2->technology != "") {
                                $application->addChild('technology', $data2->technology);
                            }
                            if ($data2->evasive_behavior != "") {
                                $application->addChild('evasive-behavior', $data2->evasive_behavior);
                            }
                            if ($data2->consume_big_bandwidth != "") {
                                $application->addChild('consume-big-bandwidth', $data2->consume_big_bandwidth);
                            }
                            if ($data2->used_by_malware != "") {
                                $application->addChild('used-by-malware', $data2->used_by_malware);
                            }
                            if ($data2->able_to_transfer_file != "") {
                                $application->addChild('able-to-transfer-file', $data2->able_to_transfer_file);
                            }
                            if ($data2->has_known_vulnerability != "") {
                                $application->addChild('has-known-vulnerability', $data2->has_known_vulnerability);
                            }
                            if ($data2->tunnel_other_application != "") {
                                $application->addChild('tunnel-other-application', $data2->tunnel_other_application);
                            }
                            if ($data2->tunnel_applications != "") {
                                $application->addChild('tunnel-applications', $data2->tunnel_applications);
                            }
                            if ($data2->prone_to_misuse != "") {
                                $application->addChild('prone-to-misuse', $data2->prone_to_misuse);
                            }
                            if ($data2->pervasive_use != "") {
                                $application->addChild('pervasive-use', $data2->pervasive_use);
                            }
                            if ($data2->file_type_ident != "") {
                                $application->addChild('file-type-ident', $data2->file_type_ident);
                            }
                            if ($data2->virus_ident != "") {
                                $application->addChild('virus-ident', $data2->virus_ident);
                            }
                            if ($data2->data_ident != "") {
                                $application->addChild('data-ident', $data2->data_ident);
                            }
                            if ($version < 6) {
                                if ($data2->spyware_ident != "") {
                                    $application->addChild('spyware-ident', $data2->spyware_ident);
                                }
                            }
                            if (($data2->parent_app != "None") AND ( $data2->parent_app != "")) {
                                $application->addChild('parent-app', $data2->parent_app);
                            }
                            if ($data2->timeout > 0) {
                                $application->addChild('timeout', $data2->timeout);
                            }
                            if ($data2->tcp_timeout > 0) {
                                $application->addChild('tcp-timeout', $data2->tcp_timeout);
                            }
                            if ($data2->udp_timeout > 0) {
                                $application->addChild('udp-timeout', $data2->udp_timeout);
                            }
                            if($version >= 6){
                                if ($data2->tcp_half_closed_timeout > 0) {
                                    $application->addChild('tcp-half-closed-timeout', $data2->tcp_half_closed_timeout);
                                }
                                if ($data2->tcp_time_wait_timeout > 0) {
                                    $application->addChild('tcp-time-wait-timeout', $data2->tcp_time_wait_timeout);
                                }
                            }
                            if ($data2->default_type == "port") {
                                $default = $application->addChild('default');
                                $port = $default->addChild('port');
                                $ports = explode(",", $data2->value);
                                foreach ($ports as $kkey => $vvalue) {
                                    $port->addChild('member', $vvalue);
                                }
                            } elseif ($data2->default_type == "ident-by-ip-protocol") {
                                $default = $application->addChild('default');
                                $port = $default->addChild('ident-by-ip-protocol', $data2->value);
                            } elseif ($data2->default_type == "ident-by-icmp-type") {
                                if($version < 7){
                                    $default = $application->addChild('default');
                                    $port = $default->addChild('ident-by-icmp-type', $data2->type);
                                }else{
                                    $default = $application->addChild('default');
                                    $port = $default->addChild('ident-by-icmp-type');
                                    $port->addChild('type', $data2->type);
                                    $port->addChild('code', $data2->code);
                                }
                            } elseif ($data2->default_type == "ident-by-icmp6-type") {
                                $default = $application->addChild('default');
                                $port = $default->addChild('ident-by-icmp6-type');
                                $port->addChild('code', $data2->code);
                                $port->addChild('type', $data2->type);
                            } elseif ($data2->default_type == "None") {

                            }

                            $getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE source='$source' AND member_lid='$appid' AND table_name='applications';");
                            if ($getSignature->num_rows > 0) {
                                $application->addChild('signature');
                                $sig = $application->signature;
                                while ($data3 = $getSignature->fetch_assoc()) {
                                    $xml_append = simplexml_load_string($data3['signature']);
                                    SimpleXMLElement_append($sig, $xml_append);
                                }
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/application/entry[@name=\'$myname\']";
                                $xml_final = addslashes($application->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications','applications','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/application";
                        $xml_final = addslashes($xml->application->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications','applications','$xml_final','$xpath','edit');");
                    }
                }

                # APPLICATIONS FILTERS
                $getShared = $projectdb->query("SELECT id,name,category,subcategory,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,prone_to_misuse,pervasive_use,disable_override FROM applications_filters WHERE source='$source' AND vsys='$vsys' $sql_modified ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('application-filter');
                    while ($data2 = $getShared->fetch_object()) {
                        $appid = $data2->id;
                        $myname = $data2->name;
                        if ($xml->xpath("/config/application-filter/entry[@name='$myname']") == null) {
                            $application_filters = $xml->{'application-filter'}->addChild('entry');
                            $application_filters->addAttribute('name', $myname);
                            if (($data2->disable_override!="") AND ($version>=7)){
                                $disable_override=$application_filters->addChild('disable-override',$data2->disable_override);
                            }
                            if($data2->category != ""){
                                $category = $application_filters->addChild('category');
                                $category_s = explode(",", $data2->category);
                                foreach ($category_s as $kkey => $vvalue) {
                                    $category->addChild('member', $vvalue);
                                }
                            }
                            if($data2->subcategory != ""){
                                $subcategory = $application_filters->addChild('subcategory');
                                $subcategory_s = explode(",", $data2->subcategory);
                                foreach ($subcategory_s as $kkey => $vvalue) {
                                    $subcategory->addChild('member', $vvalue);
                                }
                            }
                            if($data2->risk != ""){
                                $risk = $application_filters->addChild('risk');
                                $risk_s = explode(",", $data2->risk);
                                foreach ($risk_s as $kkey => $vvalue) {
                                    $risk->addChild('member', $vvalue);
                                }
                            }
                            if($data2->technology != ""){
                                $technology = $application_filters->addChild('technology');
                                $technology_s = explode(",", $data2->technology);
                                foreach ($technology_s as $kkey => $vvalue) {
                                    $technology->addChild('member', $vvalue);
                                }
                            }

                            if ($data2->evasive_behavior != "") {
                                $application_filters->addChild('evasive', $data2->evasive_behavior);
                            }
                            if ($data2->consume_big_bandwidth != "") {
                                $application_filters->addChild('excessive-bandwidth-use', $data2->consume_big_bandwidth);
                            }
                            if ($data2->used_by_malware != "") {
                                $application_filters->addChild('used-by-malware', $data2->used_by_malware);
                            }
                            if ($data2->able_to_transfer_file != "") {
                                $application_filters->addChild('transfers-files', $data2->able_to_transfer_file);
                            }
                            if ($data2->has_known_vulnerability != "") {
                                $application_filters->addChild('has-known-vulnerabilities', $data2->has_known_vulnerability);
                            }
                            if ($data2->tunnel_other_application != "") {
                                $application_filters->addChild('tunnels-other-apps', $data2->tunnel_other_application);
                            }
                            if ($data2->prone_to_misuse != "") {
                                $application_filters->addChild('prone-to-misuse', $data2->prone_to_misuse);
                            }
                            if ($data2->pervasive_use != "") {
                                $application_filters->addChild('pervasive', $data2->pervasive_use);
                            }

                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/application-filter/entry[@name=\'$myname\']";
                                $xml_final = addslashes($application_filters->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications_filters','applications_filters','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/application-filter";
                        $xml_final = addslashes($xml->{'application-filter'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications_filters','applications_filters','$xml_final','$xpath','edit');");
                    }
                }

                # APPLICATIONS GROUPS
                $getShared = $projectdb->query("SELECT name, id FROM applications_groups_id WHERE source='$source' AND vsys='$vsys' $sql_modified;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('application-group');
                    while ($Data = $getShared->fetch_assoc()) {
                        $groupName = $Data['name'];
                        $lid = $Data['id'];
                        $myname = $Data['name'];
                        if ($xml->xpath("/config/application-group/entry[@name='$myname']") == null) {
                            $getMembers = $projectdb->query("SELECT table_name,member_lid FROM applications_groups WHERE source='$source' and lid='$lid'");
                            if ($getMembers->num_rows > 0) {
                                $service = $xml->{'application-group'}->addChild('entry');
                                $service->addAttribute('name', $Data['name']);
                                if ($version >= 7) {
                                    $service2 = $service->addChild('members');
                                }
                                else{
                                    $service2 = $service;
                                }
                                while ($Datas = $getMembers->fetch_assoc()) {
                                    $table_name = $Datas['table_name'];
                                    $member_lid = $Datas['member_lid'];
                                    $getName = $projectdb->query("SELECT name FROM $table_name WHERE id = '$member_lid'");
                                    if ($getName->num_rows==1){
                                        $Datas2 = $getName->fetch_assoc();
                                        $member = $service2->addChild('member', $Datas2['name']);
                                    }
                                }
                            } else {
                                $service = $xml->{'application-group'}->addChild('entry');
                                $service->addAttribute('name', $Data['name']);
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/application-group/entry[@name=\'$myname\']";
                                $xml_final = addslashes($service->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','applications_groups','applications_groups','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/application-group";
                        $xml_final = addslashes($xml->{'application-group'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('applications_groups','applications_groups','$xml_final','$xpath','edit');");
                    }
                }


                # RESPONSE PAGES
                $getShared = $projectdb->query("SELECT name,type,html FROM response_pages WHERE source='$source' AND vsys='$vsys' $sql_modified ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    $xml->addChild('response-page');
                    while ($data2 = $getShared->fetch_assoc()) {
                        $xmlfield = $data2['html'];
                        $xmlname = $data2['type'];
                        $reportname = $data2['name'];
                        if ($reportname != "") {
                            if (!isset($xml->{'response-page'}->{$xmlname})) {
                                $xml->{'response-page'}->addChild($xmlname);
                                $newrp = $xml->{'response-page'}->{$xmlname}->addChild("entry");
                                $newrp->addAttribute('name', $reportname);
                                $newrp->addChild("page");
                                $newrp->page = $xmlfield;
                            } else {
                                if ($xml->{'response-page'}->{$xmlname}->xpath("entry[@name='$reportname']") !== null) {
                                    $SA = $xml->{'response-page'}->{$xmlname}->xpath("entry[@name='$reportname']");
                                    unset($SA[0][0]);
                                }
                                $newrp = $xml->{'response-page'}->{$xmlname}->addChild("entry");
                                $newrp->addAttribute('name', $reportname);
                                $newrp->addChild("page");
                                $newrp->page = $xmlfield;
                            }
                        } else {
                            $SA = $xml->xpath("response-page/$xmlname");
                            unset($SA[0][0]);
                            #$xml_append = simplexml_load_string($xmlfield);
                            $xml_append = simplexml_load_string("<$xmlname>$xmlfield</$xmlname>");
                            SimpleXMLElement_append($xml->{'response-page'}, $xml_append);
                        }
                        if ($api_call == "single") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/response-page/$xmlname";
                            $xml_final = addslashes($xml->{'response-page'}->{$xmlname}->asXML());
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','response-pages','response_pages','$xml_final','$xpath','edit');");
                        }
                    }
                    if ($api_call == "atomic") {
                        $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/response-page";
                        $xml_final = addslashes($xml->{'response-page'}->asXML());
                        $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('response-pages','response_pages','$xml_final','$xpath','edit');");
                    }
                }

                if ($ispanorama == 0) {
                    #ZONES
                    $getShared = $projectdb->query("SELECT id,name,type,interfaces,zone_protection_profile,log_setting_id,include_list,exclude_list,enable_user_identification,log_setting_table_name FROM zones WHERE source='$source' AND vsys='$vsys' $sql_modified ORDER BY id;");
                    if ($getShared->num_rows > 0) {
                        $xml->addChild('zone');
                        while ($data = $getShared->fetch_assoc()) {
                            $myname = $data['name'];
                            $type = $data['type'];
                            $interfaces = $data['interfaces'];
                            $zone_protection_profile = $data['zone_protection_profile'];
                            $log_setting_id = $data['log_setting_id'];
                            $log_setting_table_name = $data['log_setting_table_name'];
                            $include_list = $data['include_list'];
                            $exclude_list = $data['exclude_list'];
                            $enable_user_identification = $data['enable_user_identification'];

                            $zone = $xml->zone->addChild('entry');
                            $zone->addAttribute('name', $myname);
                            $zone->addChild('network');

                            $zone->network->addChild($type);
                            if ($interfaces != "") {
                                $allinterfaces = explode(",", $interfaces);
                                foreach ($allinterfaces as $key => $vvvalue) {
                                    $zone->network->{$type}->addChild('member', $vvvalue);
                                }
                            }

                            if (($zone_protection_profile != "") AND ( $zone_protection_profile != "None")) {
                                $zone->network->addChild('zone-protection-profile', $zone_protection_profile);
                            }
                            if (($log_setting_id != "") AND ( $log_setting_table_name != "")) {
                                $getLP = $projectdb->query("SELECT name FROM $log_setting_table_name WHERE id='$log_setting_id';");
                                if ($getLP->num_rows == 1) {
                                    $LPData = $getLP->fetch_assoc();
                                    $zone->network->addChild('log-setting', $LPData['name']);
                                }
                            }
                            if (($include_list != "") OR ( $exclude_list != "")) {
                                $zone->addChild('user-acl');
                            }
                            if ($include_list != "") {
                                $allinclude = explode(",", $include_list);
                                $zone->{'user-acl'}->addChild('include-list');
                                foreach ($allinclude as $key => $vvvalue) {
                                    $zone->{'user-acl'}->{'include-list'}->addChild('member', $vvvalue);
                                }
                            }
                            if ($exclude_list != "") {
                                $allinclude = explode(",", $exclude_list);
                                $zone->{'user-acl'}->addChild('exclude-list');
                                foreach ($allinclude as $key => $vvvalue) {
                                    $zone->{'user-acl'}->{'exclude-list'}->addChild('member', $vvvalue);
                                }
                            }
                            if ($enable_user_identification == "yes") {
                                $zone->addChild('enable-user-identification', $enable_user_identification);
                            }
                            if ($api_call == "single") {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/zone/entry[@name=\'$myname\']";
                                $xml_final = addslashes($zone->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','zones','zones','$xml_final','$xpath','edit');");
                            }
                        }
                        if ($api_call == "atomic") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/zone";
                            $xml_final = addslashes($xml->zone->asXML());
                            $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('zones','zones','$xml_final','$xpath','edit');");
                        }
                    }
                }

                #POLICIES
                update_progress($project, '0.40', 'Loading Policies into VSYS/DEVICE-GROUP ' . $vsys);
                foreach ($policies as $pkey => $pvalue) {
                    if ($pvalue == "pre-rulebase") {
                        $preorpost = 0;
                        $getPolicies = $projectdb->query(
                            "SELECT icmp_unreachable,rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag 
                         FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                        $getNatPolicies = $projectdb->query(
                            "SELECT id,position,name,description,target,disabled,vsys,lid,tp_sat_bidirectional,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,preorpost,tag,active_active_device_binding,nat_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback,tp_fallback_type 
                         FROM nat_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                        $getAppOverPolicies = $projectdb->query(
                            "SELECT position,name,negate_source,negate_destination,description,disabled,id,target,protocol,app_id,app_table,port 
                         FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                        $getOtherRulesPolicies = $projectdb->query(
                            "SELECT id,type,xml 
                         FROM other_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY id ASC;");
                    }
                    elseif ($pvalue == "post-rulebase") {
                        $preorpost = 1;
                        $getPolicies = $projectdb->query(
                            "SELECT icmp_unreachable,rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag 
                         FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                        $getNatPolicies = $projectdb->query(
                            "SELECT id,position,name,description,target,disabled,vsys,lid,tp_sat_bidirectional,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,preorpost,tag,active_active_device_binding,nat_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback,tp_fallback_type 
                         FROM nat_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                        $getAppOverPolicies = $projectdb->query(
                            "SELECT position,name,negate_source,negate_destination,description,disabled,id,target,protocol,app_id,app_table,port 
                         FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                        $getOtherRulesPolicies = $projectdb->query(
                            "SELECT id,type,xml 
                         FROM other_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY id ASC;");
                    }
                    elseif ($pvalue == "rulebase") {
                        $getPolicies = $projectdb->query(
                            "SELECT icmp_unreachable,rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag 
                         FROM security_rules WHERE source='$source' AND vsys='$vsys' $sql_modified ORDER BY position ASC;");
                        $getNatPolicies = $projectdb->query(
                            "SELECT id,position,name,description,target,disabled,vsys,lid,tp_sat_bidirectional,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,preorpost,tag,active_active_device_binding,nat_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback,tp_fallback_type 
                         FROM nat_rules WHERE source='$source' AND vsys='$vsys' $sql_modified ORDER BY position ASC;");
                        $getAppOverPolicies = $projectdb->query(
                            "SELECT position,name,negate_source,negate_destination,description,disabled,id,target,protocol,app_id,app_table,port 
                         FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' $sql_modified ORDER BY position ASC;");
                        $getOtherRulesPolicies = $projectdb->query(
                            "SELECT id,type,xml 
                         FROM other_rules WHERE source='$source' AND vsys='$vsys' ORDER BY id ASC;");
                    }

                    # SECURITY
                    #$getPolicies = $projectdb->query("SELECT rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' $sql_modified ORDER BY position ASC;");
                    if ($getPolicies->num_rows > 0) {
                        $xml = new SimpleXMLElement("<config></config>");
                        $xml->addChild($pvalue);
                        $xml->{$pvalue}->addChild("security");
                        $xml->{$pvalue}->security->addChild('rules');
                        $policy_order = array();
                        while ($data2 = $getPolicies->fetch_object()) {
                            $myname = $data2->name;
                            $policy_order[] = $data2->name;
                            $lid = $data2->id;
                            if ($xml->xpath("/$pvalue/security/rules/entry[@name='$myname']") == null) {
                                $rule = $xml->{$pvalue}->security->rules->addChild('entry');
                                $rule->addAttribute('name', $myname);
                                if ($version > 6.0) {
                                    if ($data2->rule_type != "universal") {
                                        $rule->addChild("rule-type", $data2->rule_type);
                                    }
                                }
                                if ($data2->dsri == 0) {
                                    $dsri = "no";
                                } else {
                                    $dsri = "yes";
                                }
                                if ($dsri!="no"){
                                    $rule->addChild('option');
                                    $rule->option->addChild('disable-server-response-inspection', $dsri);
                                }
                                if ($version>=7){
                                    if ($data2->icmp_unreachable!=""){
                                        $rule->addChild('icmp-unreachable',$data2->icmp_unreachable);
                                    }
                                }
                                $getFrom = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$lid' ;");
                                if ($getFrom->num_rows > 0) {
                                    $rule->addChild('from');
                                    while ($k = $getFrom->fetch_object()) {
                                        $rule->from->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('from');
                                    $rule->from->addChild('member', 'any');
                                }
                                $getTo = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid='$lid';");
                                if ($getTo->num_rows > 0) {
                                    $rule->addChild('to');
                                    while ($k = $getTo->fetch_object()) {
                                        $rule->to->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('to');
                                    $rule->to->addChild('member', 'any');
                                }
                                $getSource = $projectdb->query("SELECT member_lid,table_name FROM security_rules_src WHERE rule_lid='$lid';");
                                if ($getSource->num_rows > 0) {
                                    $rule->addChild('source');
                                    while ($k = $getSource->fetch_object()) {
                                        //if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") ) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name";
//                                        }
                                        if ($k->table_name == "default_regions") {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                        }
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
//                                                $rule->source->addChild('member', $kk->{$thename});
                                                $rule->source->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('source');
                                    $rule->source->addChild('member', 'any');
                                }
                                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$lid' ;");
                                if ($getDestination->num_rows > 0) {
                                    $rule->addChild('destination');
                                    while ($k = $getDestination->fetch_object()) {
                                        //if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                        if (($k->table_name == "regions")  OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") ) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name";
//                                        }
                                        if ($k->table_name == "default_regions") {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                        }
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
//                                                $rule->destination->addChild('member', $kk->{$thename});
                                                $rule->destination->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('destination');
                                    $rule->destination->addChild('member', 'any');
                                }
                                $getUser = $projectdb->query("SELECT name FROM security_rules_usr WHERE rule_lid='$lid';");
                                if ($getUser->num_rows > 0) {
                                    $rule->addChild('source-user');
                                    while ($k = $getUser->fetch_object()) {
                                        $rule->{'source-user'}->addChild('member',htmlentities($k->name));
                                    }
                                } else {
                                    $rule->addChild('source-user');
                                    $rule->{'source-user'}->addChild('member', 'any');
                                }
                                $getAPP = $projectdb->query("SELECT member_lid,table_name FROM security_rules_app WHERE rule_lid='$lid';");
                                if ($getAPP->num_rows > 0) {
                                    $rule->addChild('application');
                                    while ($k = $getAPP->fetch_object()) {
                                        $thesql = "SELECT name FROM " . $k->table_name . " WHERE id='" . $k->member_lid . "';";
                                        $getMember = $projectdb->query($thesql);
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'application'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('application');
                                    $rule->{'application'}->addChild('member', 'any');
                                }
                                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM security_rules_srv WHERE rule_lid='$lid';");
                                if ($getSRV->num_rows > 0) {
                                    $rule->addChild('service');
                                    while ($k = $getSRV->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'service'}->addChild('member', $kk->name);
                                            }
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->{'service'}->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('service');
                                    $rule->{'service'}->addChild('member', 'any');
                                }
                                $getHIP = $projectdb->query("SELECT member_lid,table_name,name FROM security_rules_hip WHERE rule_lid='$lid';");
                                $hipProfiles_field = ($version >= 10)?'source-hip':'hip-profiles';
                                if ($getHIP->num_rows > 0) {
                                    $rule->addChild($hipProfiles_field);
                                    while ($k = $getHIP->fetch_object()) {
                                        if (($k->member_lid == 0) AND ( $k->table_name == "default")) {
                                            $rule->{$hipProfiles_field}->addChild('member', $k->name);
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND type='hip-profiles';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->{$hipProfiles_field}->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild($hipProfiles_field);
                                    $rule->{$hipProfiles_field}->addChild('member', 'any');
                                }
                                $getCategory = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid='$lid' ;");
                                if ($getCategory->num_rows > 0) {
                                    $rule->addChild('category');
                                    while ($k = $getCategory->fetch_object()) {
                                        $rule->category->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('category');
                                    $rule->category->addChild('member', 'any');
                                }
                                $rule->addChild('action', $data2->action);
                                if ($data2->log_start == 1) {
                                    $rule->addChild('log-start', 'yes');
                                }
                                if ($data2->log_end == 1) {
                                    $rule->addChild('log-end', 'yes');
                                }
                                else{
                                    $rule->addChild('log-end', 'no');
                                }
                                if ($data2->disabled == 1) {
                                    $rule->addChild('disabled', 'yes');
                                } else {
                                    //$rule->addChild('disabled', 'no');
                                }
                                if ($data2->negate_source == 1) {
                                    $rule->addChild('negate-source', 'yes');
                                } else {
                                    //$rule->addChild('negate-source', 'no');
                                }
                                if ($data2->negate_destination == 1) {
                                    $rule->addChild('negate-destination', 'yes');
                                } else {
                                    //$rule->addChild('negate-destination', 'no');
                                }
                                if ($data2->description != "") {
                                    $rule->addChild('description');
                                    $rule->description = $data2->description;
                                }
                                if ($data2->schedule != "") {
                                    $rule->addChild('schedule', $data2->schedule);
                                }
                                if ($data2->log_forwarding != "") {
                                    $rule->addChild('log-setting', $data2->log_forwarding);
                                }
                                if ($data2->qos != "None") {
                                    if($version >=7){
                                        $rule->addChild('qos');
                                        $rule->qos->addChild('marking');
                                        $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                                    }elseif($data2->qos == "ip-dscp" || $data2->qos == "ip-precedence"){
                                        $rule->addChild('qos');
                                        $rule->qos->addChild('marking');
                                        $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                                    }
                                }
                                if ($data2->profile_type != "None") {
                                    $rule->addChild('profile-setting');
                                    if ($data2->profile_type == "group") {
                                        $profile = $rule->{'profile-setting'}->addChild('group');
                                        $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                                        if ($getProfiles->num_rows > 0) {
                                            while ($k = $getProfiles->fetch_object()) {
                                                $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                                if ($getMember->num_rows > 0) {
                                                    while ($kk = $getMember->fetch_object()) {
                                                        $profile->addChild('member', $kk->name);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        $profile = $rule->{'profile-setting'}->addChild('profiles');
                                        $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                                        if ($getProfiles->num_rows > 0) {
                                            while ($k = $getProfiles->fetch_object()) {
                                                $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE source='$source' AND id='$k->member_lid';");
                                                if ($getMember->num_rows > 0) {
                                                    while ($kk = $getMember->fetch_object()) {
                                                        $thetype = $kk->{'type'};
                                                        $theprofiles = $profile->addChild($thetype);
                                                        $theprofiles->addChild('member', $kk->name);
                                                    }
                                                } else {
                                                    $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE source=0 AND id='$k->member_lid';");
                                                    if ($getMember->num_rows > 0) {
                                                        while ($kk = $getMember->fetch_object()) {
                                                            $thetype = $kk->{'type'};
                                                            $theprofiles = $profile->addChild($thetype);
                                                            $theprofiles->addChild('member', $kk->name);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE rule_lid='$lid';");
                                if ($getTAG->num_rows > 0) {
                                    $rule->addChild('tag');
                                    while ($k = $getTAG->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE source='$source' AND id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'tag'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                }
                                if ($data2->target != "") {
                                    libxml_use_internal_errors(true);

                                    $xml_append = simplexml_load_string($data2->target);
                                    if ($xml_append) {
                                        SimpleXMLElement_append($rule, $xml_append);
                                    }
                                }
                                if ($api_call == "single") {
                                    $xpath = addslashes("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$pvalue/security/rules/entry[@name='$myname']");
                                    $xml_final = addslashes($rule->asXML());
                                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','security_rules','security_rules','$xml_final','$xpath','edit');");
                                }
                            }
                        }
                        if ($api_call == "atomic") {
                            #$xpath=addslashes("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$pvalue/security/rules");
                            #$xml_final="";
                            #$projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action,name) VALUES ('security_rules','security_rules','$xml_final','$xpath','delete','Delete Rules');");

                            $xpath = addslashes("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$pvalue/security");
                            $xml_final = addslashes($xml->{$pvalue}->security->asXML());
                            $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('security_rules','security_rules','$xml_final','$xpath','edit');");
                        }
                        if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                            $first = $policy_order[0];
                            $last = $policy_order[count($policy_order) - 1];
                            # Set first Rule
                            $xpath = addslashes("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$pvalue/security/rules/entry[@name='$first']");
                            $where = "top";
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','security_rules','order','','$xpath','move','$where','');");
                            # Set last Rule
                            #$xpath=addslashes("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$pvalue/security/rules/entry[@name='$last']");
                            #$where="bottom";
                            #$projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$last to bottom','security_rules','order','','$xpath','move','$where','');");
                            unset($policy_order[0]);
                            foreach ($policy_order as $key => $value) {
                                $xpath = addslashes("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$pvalue/security/rules/entry[@name='$value']");
                                $where = "after";
                                $dst = addslashes("$first");
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','security_rules','order','','$xpath','move','$where','$dst');");
                                $first = $value;
                            }
                            unset($policy_order);
                        }
                    }

                    # NAT
                    if ($getNatPolicies->num_rows > 0) {
                        $xml = new SimpleXMLElement("<config></config>");
                        $xml->addChild($pvalue);
                        $xml->{$pvalue}->addChild("nat");
                        $xml->{$pvalue}->nat->addChild('rules');

                        while ($data2 = $getNatPolicies->fetch_object()) {
                            $myname = $data2->name;
                            $lid = $data2->id;
                            if ($xml->xpath("/$pvalue/nat/rules/entry[@name='$myname']") == null) {
                                $rule = $xml->{$pvalue}->nat->rules->addChild('entry');
                                $rule->addAttribute('name', $myname);
                                if ($data2->tp_sat_type == "dynamic-ip") {
                                    $rule->addChild('source-translation');
                                    $stnat = $rule->{'source-translation'}->addChild('dynamic-ip');
                                    if ($data2->tp_fallback_type == "translated-address") {
                                        $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address_fallback WHERE rule_lid='$lid' ;");
                                        if ($getAddr->num_rows > 0) {
                                            $stnat->addChild('fallback');
                                            $stnat->fallback->addChild('translated-address');
                                            while ($getAddrData = $getAddr->fetch_object()) {
                                                $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                                if ($getAddrName->num_rows == 1) {
                                                    $getAddrNameData = $getAddrName->fetch_object();
                                                    $stnat->fallback->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                                }
                                            }
                                        }
                                    } elseif ($data2->tp_fallback_type == "interface-address") {
                                        $stnat->addChild('fallback');
                                        $stnat->fallback->addChild('interface-address');
                                        if ($data2->tp_sat_interface_fallback != "") {
                                            $stnat->fallback->{'interface-address'}->addChild('interface', $data2->tp_sat_interface_fallback);
                                        }
                                        if ($data2->tp_sat_ipaddress_fallback != "") {
                                            $stnat->fallback->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress_fallback);
                                        }
                                    }
                                    $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid' ;");
                                    if ($getAddr->num_rows > 0) {
                                        $stnat->addChild('translated-address');
                                        while ($getAddrData = $getAddr->fetch_object()) {
                                            $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                            if ($getAddrName->num_rows == 1) {
                                                $getAddrNameData = $getAddrName->fetch_object();
                                                $stnat->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                            }
                                        }
                                    }
                                } elseif ($data2->tp_sat_type == "dynamic-ip-and-port") {
                                    $rule->addChild('source-translation');
                                    $stnat = $rule->{'source-translation'}->addChild('dynamic-ip-and-port');
                                    if ($data2->tp_sat_address_type == "interface-address") {
                                        $stnat->addChild('interface-address');
                                        $stnat->{'interface-address'}->addChild('interface', $data2->tp_sat_interface);
                                        if (($data2->tp_sat_ipaddress != "") AND ($data2->tp_sat_ipaddress != "None")){
                                            $stnat->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress);
                                        }
                                    } else {
                                        $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                                        if ($getAddr->num_rows > 0) {
                                            $stnat->addChild('translated-address');
                                            while ($getAddrData = $getAddr->fetch_object()) {
                                                $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                                if ($getAddrName->num_rows == 1) {
                                                    $getAddrNameData = $getAddrName->fetch_object();
                                                    $stnat->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                                }
                                            }
                                        }
                                    }
                                } elseif ($data2->tp_sat_type == "static-ip") {
                                    $rule->addChild('source-translation');
                                    $stnat = $rule->{'source-translation'}->addChild('static-ip');
                                    if ($data2->tp_sat_bidirectional == 1) {
                                        $stnat->addChild('bi-directional', 'yes');
                                    } else {
                                        $stnat->addChild('bi-directional', 'no');
                                    }
                                    $getAddr = $projectdb->query("SELECT table_name,member_lid FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                                    if ($getAddr->num_rows == 1) {
                                        $getAddrData = $getAddr->fetch_object();
                                        $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                        if ($getAddrName->num_rows == 1) {
                                            $getAddrNameData = $getAddrName->fetch_assoc();
                                            $stnat->addChild('translated-address', $getAddrNameData['name']);
                                        }
                                    }
                                }
                                if ($data2->is_dat == 1) {
                                    $dtnat = $rule->addChild('destination-translation');
                                    if (($data2->tp_dat_address_lid == 0) AND ( $data2->tp_dat_address_table == "")) {

                                    } else {
                                        $getAddr = $projectdb->query("SELECT name FROM $data2->tp_dat_address_table WHERE id='$data2->tp_dat_address_lid';");
                                        if ($getAddr->num_rows == 1) {
                                            $getAddrData = $getAddr->fetch_object();
                                            $dtnat->addChild('translated-address', $getAddrData->name);
                                        }
                                    }
                                    if ($data2->tp_dat_port != 0) {
                                        $dtnat->addChild('translated-port', $data2->tp_dat_port);
                                    }
                                }
                                if ($data2->op_zone_to != "") {
                                    $rule->addChild('to');
                                    $rule->to->addChild('member', $data2->op_zone_to);
                                } else {
                                    $rule->addChild('to');
                                    $rule->to->addChild('member', 'any');
                                }
                                $getFrom = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$lid' ;");
                                if ($getFrom->num_rows > 0) {
                                    $rule->addChild('from');
                                    while ($k = $getFrom->fetch_object()) {
                                        $rule->from->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('from');
                                    $rule->from->addChild('member', 'any');
                                }
                                $getSource = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$lid' ;");
                                if ($getSource->num_rows > 0) {
                                    $rule->addChild('source');
                                    while ($k = $getSource->fetch_object()) {
                                        //if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") ) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name";
//                                        }
                                        if ($k->table_name == "default_regions") {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                        }
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
//                                                $rule->source->addChild('member', $kk->{$thename});
                                                $rule->source->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('source');
                                    $rule->source->addChild('member', 'any');
                                }
                                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$lid';");
                                if ($getDestination->num_rows > 0) {
                                    $rule->addChild('destination');
                                    while ($k = $getDestination->fetch_object()) {
                                        //if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") ) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name";
//                                        }
                                        if ($k->table_name == "default_regions") {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                        }
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
//                                                $rule->destination->addChild('member', $kk->{$thename});
                                                $rule->destination->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('destination');
                                    $rule->destination->addChild('member', 'any');
                                }
                                if (($data2->op_service_table != "") AND ( $data2->op_service_lid != "")) {
                                    $getsrv = $projectdb->query("SELECT name FROM $data2->op_service_table WHERE id='$data2->op_service_lid';");
                                    $getsrvdata = $getsrv->fetch_assoc();
                                    $rule->addChild('service', $getsrvdata['name']);
                                } else {
                                    $rule->addChild('service', 'any');
                                }
                                if ($data2->op_to_interface != "") {
                                    $rule->addChild('to-interface', $data2->op_to_interface);
                                }
                                if ($data2->disabled == 1) {
                                    $rule->addChild('disabled', 'yes');
                                } else {
                                    //$rule->addChild('disabled', 'no');
                                }
                                if ($data2->nat_type != "") {
                                    $rule->addChild('nat-type', $data2->nat_type);
                                } else {
                                    $rule->addChild('nat-type', 'ipv4');
                                }
                                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_tag WHERE rule_lid='$lid';");
                                if ($getTAG->num_rows > 0) {
                                    $rule->addChild('tag');
                                    while ($k = $getTAG->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'tag'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                }
                                if ($data2->target != "") {
                                    libxml_use_internal_errors(true);
                                    $xml_append = simplexml_load_string($data2->target);
                                    if ($xml_append) {
                                        SimpleXMLElement_append($rule, $xml_append);
                                    }
                                }
                                if ($data2->description != "") {
                                    $rule->addChild('description');
                                    $rule->description = $data2->description;
                                }
                                if ($data2->active_active_device_binding != "") {
                                    $rule->addChild('active-active-device-binding', $data2->active_active_device_binding);
                                }
                                if ($api_call == "single") {
                                    $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/$pvalue/nat/rules/entry[@name=\'$myname\']";
                                    $xml_final = addslashes($rule->asXML());
                                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','nat_rules','nat_rules','$xml_final','$xpath','edit');");
                                }
                            }
                        }
                        if ($api_call == "atomic") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/$pvalue/nat";
                            $xml_final = addslashes($xml->{$pvalue}->nat->asXML());
                            $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('nat_rules','nat_rules','$xml_final','$xpath','edit');");
                        }
                    }

                    # APPLICATION OVERRIDE
                    if ($getAppOverPolicies->num_rows > 0) {
                        $xml = new SimpleXMLElement("<config></config>");
                        $xml->addChild($pvalue);
                        $xml->{$pvalue}->addChild("application-override");
                        $xml->{$pvalue}->{'application-override'}->addChild('rules');

                        while ($data2 = $getAppOverPolicies->fetch_object()) {
                            $myname = $data2->name;
                            $lid = $data2->id;
                            if ($xml->xpath("/$pvalue/application-override/rules/entry[@name='$myname']") == null) {
                                $rule = $xml->{$pvalue}->{'application-override'}->rules->addChild('entry');
                                $rule->addAttribute('name', $myname);
                                $getFrom = $projectdb->query("SELECT name FROM appoverride_rules_from WHERE rule_lid='$lid' ;");
                                if ($getFrom->num_rows > 0) {
                                    $rule->addChild('from');
                                    while ($k = $getFrom->fetch_object()) {
                                        $rule->from->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('from');
                                    $rule->from->addChild('member', 'any');
                                }
                                $getTo = $projectdb->query("SELECT name FROM appoverride_rules_to WHERE rule_lid='$lid' ;");
                                if ($getTo->num_rows > 0) {
                                    $rule->addChild('to');
                                    while ($k = $getTo->fetch_object()) {
                                        $rule->to->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('to');
                                    $rule->to->addChild('member', 'any');
                                }
                                $getSource = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_src WHERE rule_lid='$lid' ;");
                                if ($getSource->num_rows > 0) {
                                    $rule->addChild('source');
                                    while ($k = $getSource->fetch_object()) {
                                        //if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                        if (($k->table_name == "regions")  OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") ) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name";
//                                        }
                                        if ($k->table_name == "default_regions") {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                        }
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
//                                                $rule->source->addChild('member', $kk->{$thename});
                                                $rule->source->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('source');
                                    $rule->source->addChild('member', 'any');
                                }
                                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_dst WHERE rule_lid='$lid';");
                                if ($getDestination->num_rows > 0) {
                                    $rule->addChild('destination');
                                    while ($k = $getDestination->fetch_object()) {
                                        //if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") ) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name";
//                                        }
                                        if ($k->table_name == "default_regions") {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND source='$source';");
                                        }
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
//                                                $rule->destination->addChild('member', $kk->{$thename});
                                                $rule->destination->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('destination');
                                    $rule->destination->addChild('member', 'any');
                                }

                                $getAPP = $projectdb->query("SELECT name FROM $data2->app_table WHERE id='$data2->app_id';");
                                if ($getAPP->num_rows == 1) {
                                    $k = $getAPP->fetch_object();
                                    $rule->addChild('application', $k->name);
                                }

                                if ($data2->disabled == 1) {
                                    $rule->addChild('disabled', 'yes');
                                } else {
                                    // $rule->addChild('disabled', 'no');
                                }
                                if ($data2->negate_source == 1) {
                                    $rule->addChild('negate-source', 'yes');
                                } else {
                                    //$rule->addChild('negate-source', 'no');
                                }
                                if ($data2->negate_destination == 1) {
                                    $rule->addChild('negate-destination', 'yes');
                                } else {
                                    //$rule->addChild('negate-destination', 'no');
                                }
                                if ($data2->description != "") {
                                    $rule->addChild('description');
                                    $rule->description = $data2->description;
                                }
                                $rule->addChild('protocol', $data2->protocol);
                                $rule->addChild('port', $data2->port);
                                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE rule_lid='$lid';");
                                if ($getTAG->num_rows > 0) {
                                    $rule->addChild('tag');
                                    while ($k = $getTAG->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE source='$source' AND id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'tag'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                }
                                if ($data2->target != "") {
                                    libxml_use_internal_errors(true);
                                    $xml_append = simplexml_load_string($data2->target);
                                    if ($xml_append) {
                                        SimpleXMLElement_append($rule, $xml_append);
                                    }
                                }
                                if ($api_call == "single") {
                                    $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/$pvalue/application-override/rules/entry[@name=\'$myname\']";
                                    $xml_final = addslashes($rule->asXML());
                                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','appoverride_rules','appoverride_rules','$xml_final','$xpath','edit');");
                                }
                            }
                        }
                        if ($api_call == "atomic") {
                            $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/$pvalue/application-override";
                            $xml_final = addslashes($xml->{$pvalue}->{'application-override'}->asXML());
                            $projectdb->query("INSERT INTO output_mapping (object,table_name,xml_final,xpath,action) VALUES ('appoverride_rules','appoverride_rules','$xml_final','$xpath','edit');");
                        }
                    }

                    # OTHER RULES
                    if ($getOtherRulesPolicies->num_rows > 0) {
                        $xml = new SimpleXMLElement("<config></config>");
                        $xml->addChild($pvalue);


                        while ($data2 = $getOtherRulesPolicies->fetch_assoc()) {
                            $lid = $data2['id'];

                            $thetype = $data2['type'];
                            $xmlfield = $data2['xml'];
                            $xml_append = simplexml_load_string($xmlfield);
                            $xml->{$pvalue}->addChild($thetype);
                            $theProfiles = $xml->{$pvalue}->{$thetype};
                            SimpleXMLElement_append($theProfiles, $xml_append);

                            if (($api_call == "single") OR ( $api_call == "atomic")) {
                                $xpath = "/config/devices/entry[@name=\'localhost.localdomain\']/$platform/entry[@name=\'$vsys\']/$pvalue/$thetype";
                                $xml_final = addslashes($theProfiles->asXML());
                                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$thetype','$thetype','$thetype','$xml_final','$xpath','edit');");
                            }
                        }
                    }
                }
            }
        }

        update_progress($project, '1.00', 'Done.');
    }
    else{
        add_progress($project, '-1.0', 'There is NO Base Config');
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    return $message;
}


function send_api_calls(STRING $projectName, ARRAY $data){
    global $app;

//    ini_set('max_execution_time', 10000);
//    ini_set("memory_limit", "1000M");

    $isProxy=false;

//    global $pandb;
    $projectdb = selectDatabase($projectName);
    $ids = (isset($data['ids'])) ? $data['ids']: '';

    //Get selected devices
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;
    $api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));
    $project = $app->project->where('name', '=', $projectName)->get()->first();
    $userSettings = $app->userSettings->where('user_id','=',$userID)->where('project_id','=',$project->id)->first();
    $devices = explode(',',$userSettings->selectedDevices);

    $message = array();
    $message['code'] = true;

    $parentJobID = $jobID = registerParentJob($user, $project->id, 'Bundle of Send API Calls');

    foreach($devices as $device) {
        if ($deviceEntity = $app->device->where('id', '=', $device)->get()->first()) {
            $data_individual = [
                'serial'     => $deviceEntity->serial,
                'devicename' => $deviceEntity->devicename,
                'params' => $ids,
                'project' => $projectName,
                'key'   => $api_key
            ];

            $jobID = registerJob($data_individual, $user, 'Send API calls', $parentJobID);

            $taskID = registerTask($data_individual, $user, $jobID, "SendAPICall", "Send API Calls to PANOS device");
            send_APICallMessage($data_individual, $user, $taskID, "SendAPICall");

        }
    }
    update_progress($project->name, '1.00', 'Done.');
    $message['msg'] = $parentJobID;
    return $message;
}

function get_api_calls(STRING $projectName, STRING $objfilter, STRING $objsearch, STRING $namesearch='', STRING $vsys='', $start=0, $limit=0){
//    global $app;
    $projectdb = selectDatabase($projectName);
    if ($limit==""){$limit =0;}
    if(!accessControl("any", ['project.admin','projectRole.'.$projectName.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to check API calls';
        return $message;
    }

    $message = array();
    $addFilter = "";
    if ($objfilter != "All") {
        $addFilter = " WHERE table_name='$objfilter' ";
    }
    if ($objsearch != "") {
        if ($addFilter == "") {
            $addFilter = " WHERE (name LIKE '%$objsearch%' OR xpath LIKE '%$objsearch%') ";
        } else {
            $addFilter = $addFilter . " AND (name LIKE '%$objsearch%' OR xpath LIKE '%$objsearch%')";
        }
    }

    $vsysSearch = explode(",", $vsys);
    $vsyses = [];
    foreach($vsysSearch as $item){
        if($item != '' && $item !='all')
            $vsyses[] = ' xpath LIKE ("%/device-group/entry[@name=\''.strtoupper(trim($item)).'\'%")';
    }
    if(count($vsyses)>0){
        if($addFilter == ''){
            $addFilter = " WHERE (".implode(" OR ",$vsyses).")";
        }
        else{
            $addFilter = $addFilter . "AND (".implode(" OR ", $vsyses).")";
        }
    }

    $namesearchs = explode(",", $namesearch);
    $names = [];
    foreach ($namesearchs as $item){
        $names[] = '"'.strtoupper(trim($item)).'"';
    }
    if($namesearch != "" ){
        if ($addFilter == "") {
            $addFilter = " WHERE name IN (".implode(",",$names).") ";
        } else {
            $addFilter = $addFilter . " AND UPPER(name) IN (".implode(",",$names).")";
        }
    }

    $queryCalls = "SELECT * FROM output_mapping $addFilter;";
    $getCalls = $projectdb->query($queryCalls);
    $total = $getCalls->num_rows;
    $message['total']=$total;
    $queryCalls = "SELECT * FROM output_mapping $addFilter LIMIT $start, $limit ;";
    $getCalls = $projectdb->query($queryCalls);
    $count = $getCalls->num_rows;
    $myData = array();
    if ($count > 0) {
        while ($data = $getCalls->fetch_object()) {
            $myData[] = $data;
        }
    }
    if ($count == 0) {
        $myData = [];
        $message['total']=0;
    }

    $message['code'] = true;
    $message['msg'] = $myData;

    return $message;
}


function registerTask(ARRAY $data, $user, INT $jobID, STRING $processCode, STRING $processName){
    global $app;

    if(!isset($data['params'])){
        $data['params'] = '';
    }
    $data['userId'] = $user->id;

    $params = [
        'job_id'        => $jobID,
        'taskType'      => 'Send API Call',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    //Count number of API calls that will be sent
    $idsString = $data['params'];
    $project = $data['project'];
    global $projectdb;
    $projectdb = selectDatabase($project);
    if($idsString == ''){
        $query = "SELECT count(*) as total FROM output_mapping";
        $result = $projectdb->query($query);
        $dataQuery = $result->fetch_assoc();
        $number_calls = $dataQuery['total'];
    }
    else{
        $ids = explode(',', $idsString);
        $number_calls = count($ids);
    }
    $job = $app->job->where('id', $jobID)->first();
    $jobParams = [
        'tasks' => $job->tasks + $number_calls,
    ];
    $job->update($jobParams);

    if($job->parentJob != ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks + $number_calls,
        ];
        $parentJob->update($parentJobParams);
    }

    return $task->id;
}

function send_APICallMessage(ARRAY $data, $user, INT $taskID, STRING $process){
    $configtype = (isset($data['configtype'])) ? $data['configtype'] : 'running';
    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'params'        => [
            'serial'        => $data['serial'],
            'devicename'    => $data['devicename'],
            'configtype'    => $configtype,
            'taskId'        => $taskID,
            'project'   => $data['project'],
            'userId'    => $user->id,
            'key'       => $data['key'],
            'params'    => $data['params'],
        ]
    ];

    sendMessage($message);

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Done';
    return $message;
}

function sendMessage($message){
    $messageSender = new MessageSender($message);
    $messageSender->send();
}

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $device = $app->device->where('devicename',$data['devicename'])->first();
    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'devices',
        'parentId'      => $device->id,
        'description'   => $description .' to '.$data['devicename'],
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerParentJob($user, $projectID, STRING $description){
    global $app;

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'project',
        'parentId'      => $projectID,
        'description'   => $description,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}



?>