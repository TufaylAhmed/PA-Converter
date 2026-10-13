<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/sanitize.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action = (isset($_GET['action']) ? $_GET['action'] : '');
        $filter = (isset($_GET['filter']) ? $_GET['filter'] : '');
        $project = (isset($_GET['project']) ? $_GET['project'] : '');
        $source = (isset($_GET['source']) ? $_GET['source'] : '');
        $vsys = (isset($_GET['vsys']) ? $_GET['vsys'] : '');
        $type = (isset($_GET['type']) ? $_GET['type'] : '');
        $start = (integer) (isset($_GET['start']) ? $_GET['start'] : '');
        $limit = (integer) (isset($_GET['limit']) ? $_GET['limit'] : '');
        break;
    case 'POST':
        $action = (string) (isset($_POST['action']) ? $_POST['action'] : '');
        $filter = (isset($_POST['filter']) ? $_POST['filter'] : '');
        $project = (isset($_POST['project']) ? $_POST['project'] : '');
        $source = (isset($_POST['source']) ? $_POST['source'] : '');
        $vsys = (isset($_POST['vsys']) ? $_POST['vsys'] : '');
        $type = (isset($_POST['type']) ? $_POST['type'] : '');
        $start = (integer) (isset($_POST['start']) ? $_POST['start'] : '');
        $limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : '');
        break;
    case 'DELETE':
        $action = "remove";
        $request_body   = file_get_contents('php://input');
        $data           = json_decode($request_body, true);
        parse_str(file_get_contents("php://input"),$post_vars);
        break;

    default:
}

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

global $app;
# Access Control
if ($project==""){
    if  (!accessControl("any", ['expedition.admin'])){
        echo '{"total":"0","snippets":[]}';
        return;
    }
}
else{
    if (!checkProjectRights($project,'view')) {
        echo '{"total":"0","snippets":[]}';
        return;
    }
}

$action = $pandb->real_escape_string($action);
$filter = $pandb->real_escape_string($filter);
$project = $pandb->real_escape_string($project);
$source = $pandb->real_escape_string($source);
$vsys = $pandb->real_escape_string($vsys);
$type = $pandb->real_escape_string($type);
$start = $pandb->real_escape_string($start);
$limit = $pandb->real_escape_string($limit);


if ((!isset($action)) OR ($action=="")){$action="list";}

if ($action == "list") {
    $getSnippets = $pandb->query("SELECT id,name,type,description,panos,data FROM snippets ;");
    $count = $getSnippets->num_rows;
    $getSnippets = $pandb->query("SELECT id,name,type,description,panos,data FROM snippets ORDER BY type ASC ;");
    if ($getSnippets->num_rows > 0) {
        while ($row = $getSnippets->fetch_assoc()) {
            $databases[] = $row;
        }
        $total = count($databases);
        echo '{"total":"' . $total . '","snippets":' . json_encode($databases) . '}';
    } else {
        echo '{"total":"0","snippets":[]}';
    }
} 
elseif ($action == "list_types") {
    $getSnippets = $pandb->query("SELECT id,name,description FROM snippets_type GROUP BY name;");
    if ($getSnippets->num_rows > 0) {
        while ($row = $getSnippets->fetch_assoc()) {
            $databases[] = $row;
        }
        $total = count($databases);
        echo '{"total":"' . $total . '","result":' . json_encode($databases) . '}';
    } else {
        echo '{"total":"0","result":[]}';
    }
} 
elseif ($action == "add") {
    $pandb->query("INSERT INTO snippets (name,data) values ('new','replace   by Panos XML <entry name=\"example\"></entry> and click on Save');");
    echo json_encode(array("success" => true));
} 
elseif ($action == "remove"){
    $type= $pandb->real_escape_string($data["type"]);
    $id=$pandb->real_escape_string($data["id"]);
    if ($type == "all") {
        $pandb->query("TRUNCATE TABLE snippets;");
        echo json_encode(array("success" => true));
    }
    else{
        $pandb->query("DELETE FROM snippets WHERE id='$id';");
        echo json_encode(array("success" => true));
    }
} 
elseif ($action == "import") {
    if ($type == "snippets") {
        $ids = $pandb->real_escape_string((isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        require_once INC_ROOT.'/libs/projectdb.php';
        $projectdb = selectDatabase($project);

        $data1 = explode(",", $ids);
        foreach ($data1 as $key => $value) {
            $getSnippet = $pandb->query("SELECT name, type, data, panos FROM snippets WHERE id='$value';");
            if ($getSnippet->num_rows == 1) {
                $getSnippetData = $getSnippet->fetch_assoc();
                $data = $getSnippetData['data'];
                $name = $getSnippetData['name'];
                $type = $getSnippetData['type'];
                $version = $getSnippetData['panos'];
                
                if ( ($data != "") AND ($type != "response_page") AND ($type != "applications_groups") AND ($type != "address") AND ($type != "services") AND ($type != "wildfire_profile")){
                    $profilesArray1 = simplexml_load_string($data);
                    if ($profilesArray1!=FALSE){
                        $nameXML = $profilesArray1->attributes()->name;
                        if ($nameXML!=""){
                            $name=$nameXML;
                        }
                    }

                }
                
                if ($type == "log_profile") {
                    $table = "log_settings";
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND vsys='$vsys' AND source='$source';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table (source,name,xml,type,vsys) VALUES ('$source','$name','$data','profiles','$vsys');");
                    }
                } 
                elseif ($type == "appid") {

                    $sql = array();
                    $profilesArray = simplexml_load_string($data);
                    if ($profilesArray!=FALSE){
                        $GroupName = $profilesArray->attributes()->name;
                        $subcategory = $profilesArray->subcategory;
                        $category = $profilesArray->category;
                        $technology = $profilesArray->technology;
                        $risk = $profilesArray->risk;
                        $evasive_behavior = $profilesArray->{'evasive-behavior'};
                        $consume_big_bandwidth = $profilesArray->{'consume-big-bandwidth'};
                        $used_by_malware = $profilesArray->{'used-by-malware'};
                        $able_to_transfer_file = $profilesArray->{'able-to-transfer-file'};
                        $has_known_vulnerability = $profilesArray->{'has-known-vulnerability'};
                        $tunnel_other_application = $profilesArray->{'tunnel-other-application'};
                        $tunnel_applications = $profilesArray->{'tunnel-applications'};
                        $prone_to_misuse = $profilesArray->{'prone-to-misuse'};
                        $pervasive_use = $profilesArray->{'pervasive-use'};
                        $file_type_ident = $profilesArray->{'file-type-ident'};
                        $virus_ident = $profilesArray->{'virus-ident'};
                        $spyware_ident = $profilesArray->{'spyware-ident'};
                        $data_ident = $profilesArray->{'data-ident'};
                        $parent_app = $profilesArray->{'parent-app'};
                        $timeout = $profilesArray->timeout;
                        $timeout_tcp = $profilesArray->{'tcp-timeout'};
                        $timeout_udp = $profilesArray->{'udp-timeout'};
                        $tcp_half_closed_timeout = $profilesArray->{'tcp-half-closed-timeout'};
                        $tcp_time_wait_timeout = $profilesArray->{'tcp-time-wait-timeout'};
                        $icmp_code = "";
                        $default_value = "";

                        if (isset($profilesArray->default->port)) {
                            $default_type = "port";
                            $default_value_array = array();
                            foreach ($profilesArray->default->port->member as $vvvalue) {
                                $default_value_array[] = $vvvalue;
                            }
                            //$default_value = implode(",", $default_value_array);
                        } elseif (isset($profilesArray->default->{'ident-by-ip-protocol'})) {
                            $default_type = "ident-by-ip-protocol";
                            $default_value = $profilesArray->default->{'ident-by-ip-protocol'};
                        } elseif (isset($profilesArray->default->{'ident-by-icmp-type'})) {
                            $default_type = "ident-by-icmp-type";
                            $default_value = $profilesArray->default->{'ident-by-icmp-type'};
                            $icmp_type = $profilesArray->default->{'ident-by-icmp-type'};

                            if(isset($profilesArray->default->{'ident-by-icmp-type'}->type)){
                                $icmp_type = $profilesArray->default->{'ident-by-icmp-type'}->type;
                                $icmp_code = $profilesArray->default->{'ident-by-icmp-type'}->code;
                            }

                        } elseif (isset($profilesArray->default->{'ident-by-icmp6-type'})) {
                            $default_type = "ident-by-icmp6-type";
                            $icmp_type = $profilesArray->default->{'ident-by-icmp6-type'}->type;
                            $icmp_code = $profilesArray->default->{'ident-by-icmp6-type'}->code;
                            $default_value = "";
                        } elseif (!isset($profilesArray->default)) {
                            $default_type = "None";
                            $default_value = "";
                        }

                        $table = "applications";

                        $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$GroupName' AND vsys='$vsys' AND source='$source';");
                        if ($getDup->num_rows == 0) {
                            $projectdb->query("INSERT INTO $table (default_type,value,type,code,parent_app,source,name,vsys,devicegroup,subcategory,category,technology,risk,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,spyware_ident,data_ident,timeout,tcp_timeout,udp_timeout,tcp_half_closed_timeout, tcp_time_wait_timeout) "
                                . "VALUES ('$default_type','$default_value','$icmp_type','$icmp_code','$parent_app','$source','$GroupName','$vsys','','$subcategory','$category','$technology','$risk','$evasive_behavior','$consume_big_bandwidth','$used_by_malware','$able_to_transfer_file','$has_known_vulnerability','$tunnel_other_application','$tunnel_applications','$prone_to_misuse','$pervasive_use','$file_type_ident','$virus_ident','$spyware_ident','$data_ident','$timeout','$timeout_tcp','$timeout_udp','$tcp_half_closed_timeout', '$tcp_time_wait_timeout');");

                            $appid = $projectdb->insert_id;

                            if (isset($profilesArray->signature)) {
                                foreach ($profilesArray->signature->entry as $signature) {
                                    $signatureXML = $signature->asXML();
                                    $projectdb->query("INSERT INTO applications_signatures (member_lid,table_name,signature,vsys,devicegroup,source) VALUES ('$appid','applications','$signatureXML','$new_vsys','$devicegroup','$config_filename');");
                                }
                            }

                            if($default_type == "port"){
                                if (count($default_value_array) > 0) {
                                    foreach ($default_value_array as $port) {
                                        $projectdb->query("INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$appid','applications','$port','$new_vsys','$devicegroup','$config_filename');");
                                        //echo "INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$appid','applications','$port','$vsys','$devicegroup','$source');\n";
                                    }
                                }
                            }
                        }
                    }

                }
                elseif ($type == "applications_groups") {

                    $sql = array();
                    $profilesArray = simplexml_load_string($data);
                    if ($profilesArray!=FALSE){
                        foreach($profilesArray->entry as $data_xml){

                            $group_name = $data_xml->attributes()->name;

                            $members_all = array();

                            if($version >= 7){
                                foreach ($data_xml as $field => $value) {
                                    if ($field == "members") {
                                        foreach ($value as $kkey => $memberss) {
                                            $members_all[] = $memberss;
                                        }
                                    }
                                }
                            }
                            else{
                                foreach ($data_xml->member as $memberss) {
                                    $members_all[] = $memberss;
                                }
                            }

                            $table = "applications_groups_id";
                            $table_members = "applications_groups";

                            $getDup = $projectdb->query("SELECT id FROM $table WHERE BINARY name='$group_name' AND vsys='$vsys' AND source='$source';");
                            if ($getDup->num_rows == 0) {
                                $projectdb->query("INSERT INTO $table (source, name, vsys, devicegroup) VALUES ('$source', '$group_name', '$vsys', '');");
                                $group_app_lid = $projectdb->insert_id;

                                foreach ($members_all as $member) {

                                    $getMembers = get_member_and_lid($member, $source, $vsys, "application");
                                    $member_lid = $getMembers['member_lid'];
                                    $table_name = $getMembers['table_name'];

                                    if(($member_lid != "") && ($table_name != "")){
                                        $projectdb->query("INSERT INTO $table_members (source, vsys, devicegroup, member_lid, table_name, lid) VALUES ('$source','$vsys','', '$member_lid', '$table_name', '$group_app_lid');");
                                    }
                                    else{
                                        // Member not found
                                        add_log2('error', 'Reading Members Applications Groups', 'Application member not found: [' . $member . '] at Group [' . $group_name . ']', $source, 'Add the right Member on that Group', 'applications_groups', $group_app_lid, 'applications_groups_id');
                                    }

                                    /*$getDefaultApp = $projectdb->query("SELECT id FROM default_applications WHERE name = '$member';");
                                    //echo "SELECT id FROM default_applications WHERE name = '$member';\n";
                                    if ($getDefaultApp->num_rows == 1) {
                                        $dataDA = $getDefaultApp->fetch_assoc();
                                        $app_id = $dataDA['id'];
                                        $app_table = "default_applications";

                                        $projectdb->query("INSERT INTO $table_members (source, vsys, devicegroup, member_lid, table_name, lid) VALUES ('$source','$vsys','', '$app_id', '$app_table', '$group_app_lid');");
                                    }
                                    else{
                                        // Member no es un default applications
                                        add_log2('error', 'Reading Members Applications Groups', 'Application member not found in Default Application [' . $member . '] at Group [' . $group_name . ']', $source, 'Add the right Member on that Group', 'applications_groups', $group_app_lid, 'applications_groups_id');
                                    }*/
                                }
                            }
                        }
                    }

                }
                elseif ($type == "address"){
                    
                    $sql = array();
                    $profilesArray = simplexml_load_string($data);
                    $table = "address";
                    if ($profilesArray!=FALSE){
                        foreach($profilesArray->entry as $data_xml){

                            $description = "";
                            $ip = "";
                            $type = "";
                            $tag_out = "";
                            $tag = array();
                            $address_name = $data_xml->attributes()->name;

                            foreach ($data_xml as $field => $value) {
                                if (($field == "ip-netmask") OR ( $field == "fqdn") OR ( $field == "ip-range") OR ( $field == "dynamic")) {
                                    if (($field == "ip-netmask") AND ( strpos($value, '/') === FALSE)) {
                                        $ip = $value;
                                        $cidr = "32";
                                        $type = $field;
                                    } elseif ($field == "ip-range") {
                                        $ip = $value;
                                        $cidr = "";
                                        $type = $field;
                                    } else {
                                        $ip_mask = $value;
                                        if (preg_match("/\//", $ip_mask)) {
                                            list($ip, $cidr) = explode("/", $ip_mask);
                                        } else {
                                            $ip = $ip_mask;
                                            $cidr = 32;
                                        }
                                        $type = $field;
                                    }
                                } elseif ($field == "description") {
                                    $description = addslashes($value);
                                } elseif ($field == "tag") {
                                    foreach ($value as $kkey => $vvalue) {
                                        $tag[] = $vvalue;
                                    }
                                    if (count($tag) > 0) {
                                        sort($tag, SORT_STRING);
                                        $tag_out = implode(',', $tag);
                                        $tag = array();
                                    }
                                }
                            }
                            $getDup = $projectdb->query("SELECT id FROM $table WHERE source='$source' AND BINARY name='$address_name' AND vsys='$vsys'");
                            if ($getDup->num_rows == 0) {
                                $sql[] = "('$address_name','$address_name','$type','$ip','$cidr','$description','','$vsys','$source','$tag_out')";
                            }
                        }

                        $sql1 = "INSERT INTO $table (name_ext,name,type,ipaddress,cidr,description,devicegroup,vsys,source,tag) VALUES ";
                        if (count($sql) > 0) {
                            $output = implode(",", $sql);
                            $sql0 = $sql1 . $output;
                            $projectdb->query($sql0);
                        }
                    }

                }
                elseif ($type == "services"){
                    
                    $sql = array();
                    $profilesArray = simplexml_load_string($data);

                    $table = "services";
                    if ($profilesArray!=FALSE){
                        foreach($profilesArray->entry as $data_xml){

                            $description = "";
                            $dport = "";
                            $protocol = "";
                            $tag = array();
                            $sport = "";
                            $tag_out="";
                            $service_name = $data_xml->attributes()->name;

                            foreach ($data_xml as $field => $value) {
                                if ($field == "protocol") {
                                    foreach ($value as $proto => $dataplus) {
                                        $protocol = $proto;
                                        foreach ($dataplus as $whereport => $port) {
                                            if ($whereport == "port") {
                                                $dport = $port;
                                            } elseif ($whereport == "source-port") {
                                                $sport = $port;
                                            }
                                        }
                                    }
                                } elseif ($field == "description") {
                                    $description = addslashes($value);
                                } elseif ($field == "tag") {
                                    foreach ($value as $kkey => $vvalue) {
                                        $tag[] = $vvalue;
                                    }
                                    if (count($tag) > 0) {
                                        sort($tag, SORT_STRING);
                                        $tag_out = implode(',', $tag);
                                        $tag = array();
                                    }
                                }
                            }
                            $getDup = $projectdb->query("SELECT id FROM $table WHERE source='$source' AND BINARY name='$service_name' AND vsys='$vsys'");
                            if ($getDup->num_rows == 0) {
                                $sql[] = "('$service_name','$service_name','$protocol','$dport','$description','','$source','$vsys','$sport','$tag_out')";
                            }

                        }

                        $sql1 = "INSERT INTO $table (name_ext,name,protocol,dport,description,devicegroup,source,vsys,sport,tag) VALUES ";
                        if (count($sql) > 0) {
                            $output = implode(",", $sql);
                            $sql0 = $sql1 . $output;
                            $projectdb->query($sql0);
                        }
                    }

                }
                elseif ($type == "wildfire_profile"){
                    
                    if($version >= 7){
                        $sql = array();
                        $profilesArray = simplexml_load_string($data);
                        $table = "profiles";
                        if ($profilesArray!=FALSE){
                            foreach($profilesArray->entry as $data_xml){

                                $xml_wildfire = "";

                                $wildfire_name = $data_xml->attributes()->name;
                                $wildfire_content = addslashes($data_xml->asXML());

                                $getDup = $projectdb->query("SELECT id FROM $table WHERE source='$source' AND BINARY name='$wildfire_name' AND type='wildfire-analysis' AND vsys='$vsys'");
                                if ($getDup->num_rows == 0) {
                                    $sql[] = "('$source','$wildfire_name','$wildfire_content','wildfire-analysis','$vsys','')";
                                }

                            }
                            $sql1 = "INSERT INTO $table (source,name,xml,type,vsys,devicegroup) VALUES ";
                            if (count($sql) > 0) {
                                $output = implode(",", $sql);
                                $sql0 = $sql1 . $output;
                                $projectdb->query($sql0);
                            }
                        }

                    }
                }
                elseif ($type == "av_profile") {
                    $table = "profiles";
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND vsys='$vsys' AND source='$source' AND type='virus';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table (source,name,xml,type,vsys) VALUES ('$source','$name','$data','virus','$vsys');");
                    }
                } 
                elseif ($type == "file_profile") {
                    $table = "profiles";
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND vsys='$vsys' AND source='$source' AND type='file-blocking';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table (source,name,xml,type,vsys) VALUES ('$source','$name','$data','file-blocking','$vsys');");
                    }
                } 
                elseif ($type == "ips_profile") {
                    $table = "profiles";
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND vsys='$vsys' AND source='$source' AND type='vulnerability';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table (source,name,xml,type,vsys) VALUES ('$source','$name','$data','vulnerability','$vsys');");
                    }
                } 
                elseif ($type == "url_profile") {
                    $table = "profiles";
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND vsys='$vsys' AND source='$source' AND type='url-filtering';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table (source,name,xml,type,vsys) VALUES ('$source','$name','$data','url-filtering','$vsys');");
                    }
                } 
                elseif ($type == "spy_profile") {
                    $table = "profiles";
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND vsys='$vsys' AND source='$source' AND type='spyware';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table (source,name,xml,type,vsys) VALUES ('$source','$name','$data','spyware','$vsys');");
                    }
                }
                elseif ($type == "management_profile") {
                    $table = "interface_management_profile";
                    $getTemplate = $projectdb->query("SELECT panorama_template FROM config_views WHERE source='$source';");
                    $getTemplateData = $getTemplate->fetch_assoc();
                    $template = $getTemplateData['panorama_template'];
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND template='$template' AND source='$source';");
                    if ($getDup->num_rows == 0) {
                        $xml = simplexml_load_string($data);
                        if ($xml!=FALSE) {
                            $vrName = $xml->attributes()->name;
                            if (isset($xml->http)) {
                                $http = $xml->http;
                            }
                            if (isset($xml->https)) {
                                $https = $xml->https;
                            }
                            if (isset($xml->{'http-ocsp'})) {
                                $http_ocsp = $xml->{'http-ocsp'};
                            }
                            if (isset($xml->ssh)) {
                                $ssh = $xml->ssh;
                            }
                            if (isset($xml->snmp)) {
                                $snmp = $xml->snmp;
                            }
                            if (isset($xml->{'userid-service'})) {
                                $userid_service = $xml->{'userid-service'};
                            }
                            if (isset($xml->ping)) {
                                $ping = $xml->ping;
                            }
                            if (isset($xml->telnet)) {
                                $telnet = $xml->telnet;
                            }
                            if (isset($xml->{'response-pages'})) {
                                $response_pages = $xml->{'response-pages'};
                            }


                            if (isset($xml->{'userid-syslog-listener-ssl'})) {
                                $userid_syslog_listener_ssl = $xml->{'userid-syslog-listener-ssl'};
                            }
                            if (isset($xml->{'userid-syslog-listener-udp'})) {
                                $userid_syslog_listener_udp = $xml->{'userid-syslog-listener-udp'};
                            }
                            if (isset($xml->{'permitted-ip'})) {
                                $interfaces = array();
                                foreach ($xml->{'permitted-ip'}->entry as $mmkey => $mmvalue) {
                                    $interfaces[] = $mmvalue->attributes()->name;
                                    ;
                                }
                                $interface = implode(",", $interfaces);
                                unset($interfaces);
                            } else {
                                $interface = "";
                            }

                            $projectdb->query("INSERT INTO interface_management_profile (vsys,source,template,name,permitted_ip,http,https,http_ocsp,ssh,snmp,userid_service,userid_syslog_listener_ssl,userid_syslog_listener_udp,ping,response_pages,telnet) VALUES ('$vsys','$source','$template','$vrName','$interface','$http','$https','$http_ocsp','$ssh','$snmp','$userid_service','$userid_syslog_listener_ssl','$userid_syslog_listener_udp','$ping','$response_pages','$telnet');");
                        }
                    }
                }
                elseif ($type == "response_page"){
                    $getTemplate = $projectdb->query("SELECT panorama_template FROM config_views WHERE source='$source';");
                    $getTemplateData = $getTemplate->fetch_assoc();
                    $template = $getTemplateData['panorama_template'];
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND template='$template' AND source='$source';");
//                    if ($vsys == "shared") {
//                        $table = "shared_response_pages";
//                    } else {
//                        $table = "response_pages";
//                    }
                    $table = "response_pages";
                    $getDup=$projectdb->query("SELECT id FROM $table WHERE source='$source' AND template='$template' AND vsys='$vsys' AND name='$name';");
                    if ($getDup->num_rows==0){
                        $projectdb->query("INSERT INTO $table (source,vsys,type,html,template,name) VALUES ('$source','$vsys','$name','$data','$template','');");
                    }
                        
                }
                elseif ($type == "custom_report"){

                    $sql = array();
                    $profilesArray = simplexml_load_string($data);
                    if ($profilesArray!=FALSE){
                        $theProfileName = $profilesArray->attributes()->name;
                        $report_type = "";
                        $report_period = "";
                        $report_topn = "";
                        $report_topm = "";
                        $report_caption = "";
                        $report_starttime = "";
                        $report_endtime = "";
                        $report_query = "";
                        $report_frequency = "";
                        if (isset($profilesArray->type)) {
                            $report_type = $profilesArray->type->asXML();
                        }
                        if (isset($profilesArray->period)) {
                            $report_period = $profilesArray->period;
                        }
                        if (isset($profilesArray->topn)) {
                            $report_topn = $profilesArray->topn;
                        }
                        if (isset($profilesArray->topm)) {
                            $report_topm = $profilesArray->topm;
                        }
                        if (isset($profilesArray->caption)) {
                            $report_caption = $profilesArray->caption;
                        }
                        if (isset($profilesArray->{'start-time'})) {
                            $report_starttime = $profilesArray->{'start-time'};
                        }
                        if (isset($profilesArray->{'end-time'})) {
                            $report_endtime = $profilesArray->{'end-time'};
                        }
                        if (isset($profilesArray->{'query'})) {
                            $report_query = addslashes($profilesArray->{'query'});
                        }
                        if (isset($profilesArray->{'frequency'})) {
                            $report_frequency = addslashes($profilesArray->{'frequency'});
                        }
                        $getDup = $projectdb->query("SELECT id FROM reports WHERE name='$theProfileName' AND source='$source';");
                        if ($getDup->num_rows == 0) {
                            $projectdb->query("INSERT INTO reports (source,name,type,period,topn,topm,caption,starttime,endtime,query,frequency,vsys) VALUES ('$source','$theProfileName','$report_type','$report_period','$report_topn','$report_topm','$report_caption','$report_starttime','$report_endtime','$report_query','$report_frequency','shared')");
                        }
                    }

                }
                elseif ($type=="profile_group"){
//                    if ($vsys == "shared") {
//                        $table = "shared_profiles_groups";
//                    } else {
//                        $table = "profiles_groups";
//                    }
                    $table = "profiles_groups";
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND vsys='$vsys' AND source='$source';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table (source,name,xml,type,vsys) VALUES ('$source','$name','$data','','$vsys');");

                    }
                }
                
                elseif ($type == "profile_group") {
//                    if ($vsys == "shared") {
//                        $table = "shared_profiles_groups";
//                    } else {
//                        $table = "profiles_groups";
//                    }
                    $table = "profiles_groups";
                    $getDup = $projectdb->query("SELECT id FROM $table WHERE name='$name' AND vsys='$vsys' AND source='$source';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table (source,name,xml,type,vsys) VALUES ('$source','$name','$data','','$vsys');");
                    }
                } 
            }
        }
        echo json_encode(array("success" => true));
    }
} 
elseif ($action == "save") {
    $id = $pandb->real_escape_string((isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
    $data_input = (isset($_POST['data']) ? $_POST['data'] : $_GET['data']);
    $data_input = htmlspecialchars_decode($data_input, ENT_XML1);
    $data_input = htmlspecialchars_decode($data_input, ENT_QUOTES);
    $data_input = preg_replace('/\\\n\s*/', '', $data_input);
    $data_input = preg_replace('/\n\s*/', '', $data_input);
    $data_input = preg_replace('/\\\\+/', '', $data_input);
    $data_input = preg_replace('/>n\s*</', '><', $data_input);
    $data_input = simplexml_load_string($data_input);
    $data = preg_replace('/^<\?xml.*\?>\n/', '', $data_input->asXML());

    // Optional: Format the XML string with indentation
    $dom = new DOMDocument('1.0');
    $dom->preserveWhiteSpace = false;
    $dom->formatOutput = true;
    $dom->loadXML($data);
    $data = preg_replace('/^<\?xml.*\?>\n/', '', $dom->saveXML());

    $name = $pandb->real_escape_string((isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
    $type = $pandb->real_escape_string((isset($_POST['type']) ? $_POST['type'] : $_GET['type']));
    $description = $pandb->real_escape_string((isset($_POST['description']) ? $_POST['description'] : $_GET['description']));
    $panos = $pandb->real_escape_string((isset($_POST['panos']) ? $_POST['panos'] : $_GET['panos']));

    $description = htmlspecialchars($description, ENT_QUOTES);

    $data = sanitize_sql_string($data);
    $description = sanitize_sql_string($description);
    $panos = sanitize_sql_string($panos);

    if($type == "applications_groups"){
        $pos = strpos($data, "<application-group>");
        if ($pos === false) {
            // Add tags <application-group></application-group>
            $data = "<application-group>" .$data. "</application-group>";
        }
    }
    elseif($type == "address"){
        $pos = strpos($data, "<address>");
        if ($pos === false) {
            $data = "<address>" .$data. "</address>";
        }
    }
    elseif($type == "services"){
        $pos = strpos($data, "<service>");
        if ($pos === false) {
            // Add tags <application-group></application-group>
            $data = "<service>" .$data. "</service>";
        }
    }
    elseif($type == "wildfire_profile"){
        $pos = strpos($data, "<wildfire-analysis>");
        if ($pos === false) {
            // Add tags <application-group></application-group>
            $data = "<wildfire-analysis>" .$data. "</wildfire-analysis>";
        }
    }
    
    $pandb->query("UPDATE snippets SET data='$data',name='$name', description='$description', type='$type', panos='$panos' WHERE id='$id';");
    
    echo json_encode(array("success" => true));
}
?>