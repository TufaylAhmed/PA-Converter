<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
# Generic Functions
function xml_add_vsys($projectdb,$source,$vsys,$template,$new_value,$version){

    $getDup=$projectdb->query("SELECT id FROM virtual_systems WHERE template='$template' AND name='$vsys' AND source='$source';");
   if ($getDup->num_rows==1){

   }
   else{
       $displayName = $new_value->{'display-name'};

       $VsysInterface = "";
       $VsysVR = "";
       $VsysVWire = "";
       $VsysVlan = "";
       if (isset($new_value->import->network->interface)) {
           $vsysInt = array();
           foreach ($new_value->import->network->interface->member as $kkkey => $int) {
               $vsysInt[] = $int;
               // MT-1063 Here when Panorama: Get the vsys associated with this interface
               $projectdb->query("UPDATE interfaces SET vsys = '$vsys' WHERE unitname = '$int' AND template='$template' AND source='$source'; ");

           }
           $VsysInterface = implode(",", $vsysInt);
       }
       if (isset($new_value->import->network->{'virtual-router'})) {
           $vsysInt = array();
           foreach ($new_value->import->network->{'virtual-router'}->member as $kkkey => $int) {
               $vsysInt[] = $int;
           }
           $VsysVR = implode(",", $vsysInt);
       }
       if (isset($new_value->import->network->{'virtual-wire'})) {
           $vsysInt = array();
           foreach ($new_value->import->network->{'virtual-wire'}->member as $kkkey => $int) {
               $vsysInt[] = $int;
           }
           $VsysVWire = implode(",", $vsysInt);
       }
       if (isset($new_value->import->network->vlan)) {
           $vsysInt = array();
           foreach ($new_value->import->network->vlan->member as $kkkey => $int) {
               $vsysInt[] = $int;
           }
           $VsysVlan = implode(",", $vsysInt);
       }

       if (isset($new_value->import->resource)) {
           $max_application_override_rules = $new_value->import->resource->{'max-application-override-rules'};
           $max_concurrent_ssl_vpn_tunnels = $new_value->import->resource->{'max-concurrent-ssl-vpn-tunnels'};
           if ($version>=8){$max_cp_rules = $new_value->import->resource->{'max-auth-rules'};}
           else{$max_cp_rules = $new_value->import->resource->{'max-cp-rules'};}
           $max_dos_rules = $new_value->import->resource->{'max-dos-rules'};
           $max_nat_rules = $new_value->import->resource->{'max-nat-rules'};
           $max_pbf_rules = $new_value->import->resource->{'max-pbf-rules'};
           $max_qos_rules = $new_value->import->resource->{'max-qos-rules'};
           $max_security_rules = $new_value->import->resource->{'max-security-rules'};
           $max_sessions = $new_value->import->resource->{'max-sessions'};
           $max_site_to_site_vpn_tunnels = $new_value->import->resource->{'max-site-to-site-vpn-tunnels'};
           $max_ssl_decryption_rules = $new_value->import->resource->{'max-ssl-decryption-rules'};
       }
       else {
           $max_application_override_rules = "";
           $max_concurrent_ssl_vpn_tunnels = "";
           $max_cp_rules = "";
           $max_dos_rules = "";
           $max_nat_rules = "";
           $max_pbf_rules = "";
           $max_qos_rules = "";
           $max_security_rules = "";
           $max_sessions = "";
           $max_site_to_site_vpn_tunnels = "";
           $max_ssl_decryption_rules = "";
       }

       if (isset($new_value->import->{'visible-vsys'})) {
           $vsysInt = array();
           foreach ($new_value->import->{'visible-vsys'}->member as $kkkey => $int) {
               $vsysInt[] = $int;
           }
           $visible_vsys = implode(",", $vsysInt);
       }
       else {
           $visible_vsys = "";
       }

       $dns_proxy = $new_value->import->{'dns-proxy'};
       if (isset($new_value->setting->{'ssl-decrypt'}->{'allow-forward-decrypted-content'})) {
           $allow_forward_decrypted_content = $new_value->setting->{'ssl-decrypt'}->{'allow-forward-decrypted-content'};
       }
       else {
           $allow_forward_decrypted_content = "";
       }

       $projectdb->query("
                            INSERT INTO 
                               virtual_systems (
                                   template,source,name,display_name,interfaces,
                                   virtual_router,virtual_wire,vlan,max_application_override_rules,max_concurrent_ssl_vpn_tunnels,
                                   max_cp_rules,max_dos_rules,max_nat_rules,max_pbf_rules,max_qos_rules,
                                   max_security_rules,max_sessions,max_site_to_site_vpn_tunnels,max_ssl_decryption_rules,visible_vsys,
                                   dns_proxy,allow_forward_decrypted_content) 
                               VALUES (
                                   '$template','$source','$vsys','$displayName','$VsysInterface',
                                   '$VsysVR','$VsysVWire','$VsysVlan','$max_application_override_rules','$max_concurrent_ssl_vpn_tunnels',
                                   '$max_cp_rules','$max_dos_rules','$max_nat_rules','$max_pbf_rules','$max_qos_rules',
                                   '$max_security_rules','$max_sessions','$max_site_to_site_vpn_tunnels','$max_ssl_decryption_rules','$visible_vsys',
                                   '$dns_proxy','$allow_forward_decrypted_content');
                            ");



       /*echo "
                            INSERT INTO 
                               virtual_systems (
                                   template,source,name,display_name,interfaces,
                                   virtual_router,virtual_wire,vlan,max_application_override_rules,max_concurrent_ssl_vpn_tunnels,
                                   max_cp_rules,max_dos_rules,max_nat_rules,max_pbf_rules,max_qos_rules,
                                   max_security_rules,max_sessions,max_site_to_site_vpn_tunnels,max_ssl_decryption_rules,visible_vsys,
                                   dns_proxy,allow_forward_decrypted_content) 
                               VALUES (
                                   '$template','$source','$vsys','$displayName','$VsysInterface',
                                   '$VsysVR','$VsysVWire','$VsysVlan','$max_application_override_rules','$max_concurrent_ssl_vpn_tunnels',
                                   '$max_cp_rules','$max_dos_rules','$max_nat_rules','$max_pbf_rules','$max_qos_rules',
                                   '$max_security_rules','$max_sessions','$max_site_to_site_vpn_tunnels','$max_ssl_decryption_rules','$visible_vsys',
                                   '$dns_proxy','$allow_forward_decrypted_content');
                            \n";*/
   }



}

function xml_add_mgtconfig_users($projectdb,$source,$vsys='',$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $theProfileName = $profilesArray->attributes()->name;
        $content =  addslashes($profilesArray->asXML());
        $sql[] = "('$source','','$template','$theProfileName','$content')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO administrators (source,vsys,template,name,xml) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_tag($profiles,$source,$vsys,$devicegroup){
    global $projectdb;
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {

        // You can not use the function since you remove the ()
        //$theProfileName = normalizeNames($profilesArray->attributes()->name);
        $theProfileName = $profilesArray->attributes()->name;

        $theProfileName = normalizeTagNames($theProfileName);

        $comments = "";
        $color = "None";
        foreach ($profilesArray as $mykey => $myvalue) {
            if ($mykey == "comments") {
                $comments = addslashes($myvalue);
            } elseif ($mykey == "color") {
                $color = $myvalue;
            }
        }
        $sql[] = "('$source','$theProfileName','$color','$comments','$devicegroup', '$vsys')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO tag (source,name,color,comments,devicegroup,vsys) VALUES ".implode(",", $sql).";");
    }
}

function xml_add_address($shared_address,$source,$vsys,$devicegroup){
    global $projectdb;
    $sql = array();
    foreach ($shared_address as $child => $data) {
        $description = "";
        $ip = "";
        $type = "";
        $disable_override = "";
        $tag = array();
        $tag_out = "";
        $cidr = "";
        $address_name = $data->attributes()->name;

        foreach ($data as $field => $value) {
            if (($field == "ip-netmask") OR ( $field == "fqdn") OR ( $field == "ip-range") OR ( $field == "dynamic") OR ( $field == "ip-wildcard")) {
                if ($field == "ip-netmask") {
                    if ( strpos($value, '/') === FALSE){
                        $ip = $value;
                        $cidr = "";
                        $type = $field;
                    }
                    else{
                        list($ip, $cidr) = explode("/", $value);
                        $type = $field;
                    }
                }
                elseif ($field == "ip-range") {
                    $ip = $value;
                    $cidr = "";
                    $type = $field;
                }
                elseif ($field == "ip-wildcard") {
                    $ip = $value;
                    $cidr = "";
                    $type = $field;
                }
                else {
                    $ip_mask = $value;
                    if (preg_match("/\//",$ip_mask)){
                        list($ip, $cidr) = explode("/", $ip_mask);
                    }
                    else{
                        $ip=$ip_mask;
                    }

                    $type = $field;
                }
            }

            if ($field == "description") {
                $description = addslashes($value);
            }

            if ($field == "disable-override") {
                $disable_override=$value;
            }

            if ($field == "tag") {
                foreach ($value as $kkey => $vvalue) {
                    $tag[] = $vvalue;
                }
                if (count($tag) > 0) {
                    sort($tag, SORT_STRING);
                    $tag_out = implode(',', $tag);
                    unset($tag);
                }
            }

            $version0 = ip_version($ip);
            if($version0 == 'v6'){
                $v4=0;
                $v6=1;
            }else{
                $v4=1;
                $v6=0;
            }
        }
        $sql[] = "('$address_name','$address_name','$type','$ip','$cidr','$description','$devicegroup','$source','$tag_out','$vsys','$v4','$v6','$disable_override')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO address (name,name_ext,type,ipaddress,cidr,description,devicegroup,source,tag,vsys,v4,v6,disable_override) VALUES ".implode(",", $sql).";");
    }
}

function xml_add_services($address,$source,$vsys,$devicegroup){
    global $projectdb;
    $sql = array();
    foreach ($address as $child => $data) {
        $description = "";
        $dport = "";
        $protocol = "";
        $tag = array();
        $sport = "";
        $tag_out = "";
        $disable_override = "";
        $timeout = "";
        $halfclose_timeout = "";
        $timewait_timeout = "";
        $service_name = $data->attributes()->name;

        foreach ($data as $field => $value) {
            if ($field == "protocol") {
                foreach ($value as $proto => $dataplus) {
                    $protocol = $proto;
                    if (isset($dataplus->port)){
                        $dport = $dataplus->port;
                    }
                    if (isset($dataplus->{'source-port'})){
                        $sport = $dataplus->{'source-port'};
                    }
                    // New Version 8.1
                    if (isset($dataplus->override->yes)){
                        $override = "yes";

                        if(isset($dataplus->override->yes->timeout)){
                            $timeout = $dataplus->override->yes->timeout;
                        }else{
                            if($protocol == "tcp"){
                                $timeout = "3600";
                            }elseif($protocol == "udp"){
                                $timeout = "30";
                            }
                        }

                        if($protocol == "tcp"){
                            if(isset($dataplus->override->yes->{'halfclose-timeout'})){
                                $halfclose_timeout = $dataplus->override->yes->{'halfclose-timeout'};
                            }else{
                                $halfclose_timeout = "120";
                            }
                            if(isset($dataplus->override->yes->{'timewait-timeout'})){
                                $timewait_timeout = $dataplus->override->yes->{'timewait-timeout'};
                            }else{
                                $timewait_timeout = "15";
                            }
                        }
                    }
                    else{
                        $override = "no";
                    }
                }
            }
            if ($field == "description") {
                $description = addslashes($value);
            }
            if ($field == "disable-override"){
                $disable_override=$value;
            }
            if ($field == "tag") {
                foreach ($value as $kkey => $vvalue) {
                    $tag[] = $vvalue;
                }
                if (count($tag) > 0) {
                    sort($tag, SORT_STRING);
                    $tag_out = implode(',', $tag);
                    unset($tag);
                }
            }
        }

        $sql[] = "('$service_name','$service_name','$protocol','$dport','$description','$devicegroup','$source','$sport','$tag_out','$vsys','$disable_override', '$override', '$timeout', '$halfclose_timeout', '$timewait_timeout')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO services (name,name_ext,protocol,dport,description,devicegroup,source,sport,tag,vsys,disable_override, override, timeout, halfclose_timeout, timewait_timeout) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_address_groups(&$aglid,$address,$source,$vsys,$devicegroup){
    global $projectdb;
    $sql = array();
    $addGroup=array();
    $member=array();
    foreach ($address as $child => $data) {
        $tag = array();
        $member = array();
        $disable_override="no";
        $filter = "";

        if (isset($data->dynamic)) {
            $type = "dynamic";
        } else {
            $type = "static";
        }
        $address_name = $data->attributes()->name;
        if(isset($data->attributes()->expression)){
            $expression = addslashes($data->attributes()->expression);
        }
        else{
            $expression = '';
        }
        $tag_out = "";
        $description = "";
        foreach ($data as $field => $value) {
            if ($field == "tag") {
                foreach ($value as $kkey => $vvalue) {
                    $tag[] = $vvalue;
                }
                if (count($tag) > 0) {
                    sort($tag, SORT_STRING);
                    $tag_out = implode(',', $tag);
                    unset($tag);
                }
            } elseif ($field == "description") {
                $description = addslashes($value);
            } elseif ($field == "static") {
                foreach ($value as $kkey => $vvalue) {
                    $member[] = $vvalue;
                }
            } elseif ($field == "dynamic") {
                foreach ($value as $kkey => $vvalue) {
                    $filter = str_replace("\r", "", $vvalue);
                    $filter = str_replace("\n", "<br>", $filter);

                    // MT-1625 Removed Dynamic Address Groups Unused
                    $filter = normalizeTagNames($filter);

                    if( (substr($filter, 0, 1)) != (substr($filter, -1, 1))){
                        //echo "------------>IT IS NOT THE SAME: " .$filter. "\n";
                        if(((substr($filter, 0, 1)) == '"') && ((substr($filter, -1, 1)) == "'")){
                            $filter = str_replace('"', "'", $filter);
                        }
                        else{
                            $filter = "'".$filter."'";
                        }
                    }

                    $filter = addslashes($filter);
                }
            }
            elseif ($field=="disable-override"){
                $disable_override=$value;
            }
            else {
                #IS 5.X
                $member[] = $value;
            }
        }
        $addGroup[]="('$aglid','$address_name','$address_name','$devicegroup','$source','$vsys','$type','$description','$filter','$tag_out','$disable_override','$expression')";

        if (count($member) > 0) {
            foreach ($member as $keyM => $valueM) {
                $sql[] = "('$devicegroup','$vsys','$valueM','$aglid','$source')";
            }
        }
        $aglid++;
    }

    if (count($addGroup)>0){
        $uqey = "INSERT INTO address_groups_id (id,name,name_ext,devicegroup,source,vsys,type,description,filter,tag,disable_override, expression) VALUES ".implode(",",$addGroup).";";
        //echo $uqey."\n";
        $projectdb->query($uqey);
        if (count($sql) > 0) {
            $projectdb->query("INSERT INTO address_groups (devicegroup,vsys,member,lid,source) VALUES ".implode(",", $sql).";");
            unset($sql);
        }
        unset($addGroup);
    }

}

function xml_add_services_groups(&$sglid,$serviceGroups,$source,$vsys,$devicegroup){
    global $projectdb;
    $sql = array();
    $addGroup=array();
    foreach ($serviceGroups as $child => $serviceGroup) {
        $description = "";
        $tag = array();
        $member = array();
        $disable_override="no";
        if (isset($serviceGroup->dynamic)) {
            $type = "dynamic";
        } else {
            $type = "static";
        }
        $address_name = $serviceGroup->attributes()->name;
        $tag_out = "";
        $description = "";

        foreach ($serviceGroup as $field => $value) {
            if ($field == "tag") {
                foreach ($value as $kkey => $vvalue) {
                    $tag[] = $vvalue;
                }
                if (count($tag) > 0) {
                    sort($tag, SORT_STRING);
                    $tag_out = implode(',', $tag);
                    $tag = array();
                }
            } elseif ($field == "description") {
                $description = addslashes($value);
            } elseif ($field == "members") {
                foreach ($value as $kkey => $vvalue) {
                    $member[] = $vvalue;
                }
            }
            elseif ($field=="disable-override"){
                $disable_override=$value;
            }
            else {
                #IS 5.X
                $member[] = $value;
            }
        }
        $addGroup[]="('$sglid','$address_name','$address_name','$devicegroup','$source','$type','$vsys','$description','$tag_out','$disable_override')";

        if (count($member) > 0) {
            foreach ($member as $keyM => $valueM) {
                $sql[] = "('$devicegroup','$vsys','$valueM','$sglid','$source')";
            }
            $member = array();
        }
        $sglid++;
    }

    if (count($addGroup)>0){
        $projectdb->query("INSERT INTO services_groups_id (id,name,name_ext,devicegroup,source,type,vsys,description,tag,disable_override) VALUES ".implode(",",$addGroup).";");
        if (count($sql) > 0) {
            $projectdb->query("INSERT INTO services_groups (devicegroup,vsys,member,lid,source) VALUES ".implode(",", $sql).";");
            unset($sql);
        }
        unset($addGroup);
    }

}

function xml_add_schedule($profiles,$source,$vsys,$devicegroup){
    global $projectdb;
    $sql=array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$devicegroup','schedules', '$vsys')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO schedules (source,name,xml,devicegroup,type, vsys) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function GroupMember2IdApplications_improved($source){
    global $projectdb;

    if (!is_numeric($source)){
        $getSourceID = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$source' GROUP BY filename;");
        if ($getSourceID->num_rows == 1) {
            $data = $getSourceID->fetch_assoc();
            $source = $data['id'];
        } else {
            add_log('error', 'Mapping members with Applications Groups', 'Invalid Source File', $source, 'Process finished unexpectly');
            exit(0);
        }
    }

    $sqlgroups = $projectdb->query("SELECT member,vsys FROM applications_groups WHERE source='$source' AND member_lid='0' GROUP BY vsys;");
    if ($sqlgroups->num_rows>0) {
        while ($getmember = $sqlgroups->fetch_assoc()) {
            $vsys = $getmember['vsys'];
            $allVSYS=getVsyses($projectdb, $vsys, $source);
            $getMemberbyVsys=$projectdb->query("SELECT name,member FROM applications_groups WHERE source='$source' AND vsys='$vsys' GROUP BY member;");
            if ($getMemberbyVsys->num_rows>0){
                while($getMemberbyVsysData=$getMemberbyVsys->fetch_assoc()){
                    $memberA=$getMemberbyVsysData['member'];
                    $member=getAppId($projectdb, $source, $allVSYS, $memberA);
                    if ($member!=null){
                        $appid=$member->name;
                        $appid_table=$member->location;
                        $projectdb->query("UPDATE applications_groups SET member_lid='$appid', table_name='$appid_table' WHERE source='$source' AND vsys='$vsys' AND member='$memberA';");
                    }
                    else{
                        #Is not in the config create as a DUMMY
                        $projectdb->query("INSERT INTO applications (name, source, vsys, vtype, dummy, devicegroup) values('$memberA','$source','$vsys','dummy','1', 'MT_Panorama');");
                        $flid = $projectdb->insert_id;
                        $projectdb->query("UPDATE applications_groups SET member_lid='$flid', table_name='applications' WHERE BINARY member = '$memberA' AND source='$source' AND vsys='$vsys';");
                        $getAffected=$projectdb->query("SELECT name,lid FROM applications_groups WHERE BINARY member = '$memberA' AND source='$source' AND vsys='$vsys';");
                        if ($getAffected->num_rows>0){
                            while($getAffectedData=$getAffected->fetch_assoc()){
                                $GroupName=$getAffectedData['name'];
                                $GroupLid=$getAffectedData['lid'];
                                add_log2('error', 'Reading Members Applications Groups', 'Application not found in DB [' . $memberA . '] at Group ['.$GroupName.']', $source, 'Add the right Member on that Group', 'applications_groups', $GroupLid, 'applications_groups_id');
                            }
                        }
                    }
                }
            }

        }
    }

}


function xml_add_applications($projectdb,$profiles,$source,$vsys,$devicegroup,$version){
    $sql = array();
    foreach ($profiles as $profilesArray) {
        $icmp_type = "";
        $icmp_code = "";
        $default_value="";
        $default_type = "";
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
        if (isset($profilesArray->timeout)){
            $timeout = $profilesArray->timeout;
        }
        else{
            $timeout = '';
        }

        if (isset($profilesArray->{'tcp-timeout'})){
            $timeout_tcp = $profilesArray->{'tcp-timeout'};
        }
        else{
            $timeout_tcp = '';
        }

        if (isset($profilesArray->{'udp-timeout'})){
            $timeout_udp = $profilesArray->{'udp-timeout'};
        }
        else{
            $timeout_udp = '';
        }

        if($version >= 6){
            if (isset($profilesArray->{'tcp-half-closed-timeout'})){
                $tcp_half_closed_timeout = $profilesArray->{'tcp-half-closed-timeout'};
            }
            else{
                $tcp_half_closed_timeout = '';
            }

            if (isset($profilesArray->{'tcp-time-wait-timeout'})){
                $tcp_time_wait_timeout = $profilesArray->{'tcp-time-wait-timeout'};
            }
            else{
                $tcp_time_wait_timeout = '';
            }


        }else{
            $tcp_half_closed_timeout = "";
            $tcp_time_wait_timeout = "";
        }
        $content = addslashes($profilesArray->asXML());
        if (isset($profilesArray->default->port)) {
            $default_type = "port";
            $default_value_array = array();
            foreach ($profilesArray->default->port->member as $vvvalue) {
                $default_value_array[] = $vvvalue;
            }
            //$default_value = implode(",", $default_value_array);
        }
        elseif (isset($profilesArray->default->{'ident-by-ip-protocol'})) {
            $default_type = "ident-by-ip-protocol";
            $default_value = $profilesArray->default->{'ident-by-ip-protocol'};
        }
        elseif (isset($profilesArray->default->{'ident-by-icmp-type'})) {
            $default_type = "ident-by-icmp-type";

            //echo "La version es: " .$version. "\n";
            if($version < 7){
                $default_value = $profilesArray->default->{'ident-by-icmp-type'};
                $icmp_type = $default_value;
            }else{
                $icmp_type = $profilesArray->default->{'ident-by-icmp-type'}->type;
                $icmp_code = $profilesArray->default->{'ident-by-icmp-type'}->code;

                //echo "ICMP type: " .$icmp_type. "\n";
                //echo "ICMP code" .$icmp_code. "\n";
            }

        }
        elseif (isset($profilesArray->default->{'ident-by-icmp6-type'})) {
            $default_type = "ident-by-icmp6-type";
            $icmp_type = $profilesArray->default->{'ident-by-icmp6-type'}->type;
            $icmp_code = $profilesArray->default->{'ident-by-icmp6-type'}->code;
            $default_value = "";
        }
        elseif (!isset($profilesArray->default)) {
            $default_type = "None";
            $default_value = "";
        }

        if (isset($profilesArray->description)){
            $description=  addslashes($profilesArray->description);
        }
        else{
            $description="";
        }
        $projectdb->query("INSERT INTO applications (".
            "default_type,value,type,code,parent_app,source,name,devicegroup,subcategory,category,technology,".
            "risk,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,".
            "tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,".
            "spyware_ident,data_ident,timeout,tcp_timeout,udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout,description, vsys) ".
            "VALUES ('$default_type','$default_value','$icmp_type','$icmp_code','$parent_app','$source','$GroupName','$devicegroup','$subcategory','$category','$technology','$risk','$evasive_behavior','$consume_big_bandwidth','$used_by_malware','$able_to_transfer_file','$has_known_vulnerability','$tunnel_other_application','$tunnel_applications','$prone_to_misuse','$pervasive_use','$file_type_ident','$virus_ident','$spyware_ident','$data_ident','$timeout','$timeout_tcp','$timeout_udp', '$tcp_half_closed_timeout', '$tcp_time_wait_timeout','$description', '$vsys');");

        $appid = $projectdb->insert_id;

        $theSignatureName = "";

        if (isset($profilesArray->signature)) {
            foreach ($profilesArray->signature->entry as $signature) {
                $theSignatureName = $signature->attributes()->name;
                $signatureXML = addslashes($signature->asXML());
                $projectdb->query("INSERT INTO applications_signatures (name, member_lid,table_name,signature,vsys,devicegroup,source) VALUES ('$theSignatureName', '$appid','applications','$signatureXML','$vsys','$devicegroup','$source');");
            }
        }


        if($default_type == "port"){
            if (count($default_value_array) > 0) {
                foreach ($default_value_array as $port) {
                    $projectdb->query("INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$appid','applications','$port','$vsys','$devicegroup','$source');");
                    //echo "INSERT INTO applications_ports (member_lid, table_name, ports, vsys, devicegroup, source) VALUES ('$appid','applications','$port','$vsys','$devicegroup','$source');\n";
                }
            }
        }

    }
}


function xml_add_applications_tag($projectdb,$profiles,$source,$vsys,$devicegroup){

    $sql = array();

    foreach ($profiles as $key => $profilesArray) {

        $application_name = $profilesArray->attributes()->name;

        $getApp = $projectdb->query("SELECT id FROM applications WHERE name = '$application_name' AND vsys = '$vsys' AND source = '$source' ;");
        if($getApp->num_rows == 1){
            $dataApp = $getApp->fetch_assoc();
            $app_id = $dataApp['id'];

            if(!empty($profilesArray->tag->member)){
                foreach ($profilesArray->tag->member as $member) {

                    $getTag = $projectdb->query("SELECT id FROM tag WHERE name = '$member' AND vsys = '$vsys' AND source = '$source' ;");
                    if($getTag->num_rows == 1){
                        $dataTag = $getTag->fetch_assoc();
                        $tag_id = $dataTag['id'];
                    }

                    $sql[] = "('applications', '$app_id', '$tag_id')";
                }
            }
        }
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",", $sql).";");
    }
}


function xml_add_applications_filters($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $category_array = array();
        $subcategory_array = array();
        $technology_array = array();
        $tagging_array = array();
        $risk_array = array();
        $saas_certifications_array = array();
        $saas_risk_array = array();

        $filter_name = $profilesArray->attributes()->name;

        if(!empty($profilesArray->category->member)){
            foreach ($profilesArray->category->member as $member) {
                $category_array[] = $member;
            }
        }
        if(!empty($profilesArray->subcategory->member)){
            foreach ($profilesArray->subcategory->member as $member) {
                $subcategory_array[] = $member;
            }
        }
        if(!empty($profilesArray->technology->member)){
            foreach ($profilesArray->technology->member as $member) {
                $technology_array[] = $member;
            }
        }
        if(!empty($profilesArray->risk->member)){
            foreach ($profilesArray->risk->member as $member) {
                $risk_array[] = $member;
            }
        }

        $evasive = $profilesArray->{'evasive'};
        $excessive_bandwidth_use = $profilesArray->{'excessive-bandwidth-use'};
        $disable_override = $profilesArray->{'disable-override'};
        $prone_to_misuse = $profilesArray->{'prone-to-misuse'};

        if(!empty($profilesArray->tagging->tag)){
            foreach ($profilesArray->tagging->tag->member as $member) {
                $tagging_array[] = $member;
            }
        }

        $transfers_files = $profilesArray->{'transfers-files'};
        $tunnels_other_apps = $profilesArray->{'tunnels-other-apps'};
        $used_by_malware = $profilesArray->{'used-by-malware'};
        $has_known_vulnerabilities = $profilesArray->{'has-known-vulnerabilities'};
        $pervasive = $profilesArray->{'pervasive'};

        // New version 8.1
        if(!empty($profilesArray->{'saas-certifications'}->member)){
            foreach ($profilesArray->{'saas-certifications'}->member as $member) {
                $saas_certifications_array[] = $member;
            }
        }

        if(!empty($profilesArray->{'saas-risk'}->member)){
            foreach ($profilesArray->{'saas-risk'}->member as $member) {
                $saas_risk_array[] = $member;
            }
        }

        $content = addslashes($profilesArray->asXML());

        $category = implode(",", $category_array);
        $subcategory = implode(",", $subcategory_array);
        $technology = implode(",", $technology_array);
        $tagging = implode(",", $tagging_array);
        $risk = implode(",", $risk_array);

        // New version 8.1
        $saas_certifications = implode(",", $saas_certifications_array);
        $saas_risk = implode(",", $saas_risk_array);

        $sql[] = "('$source', '$filter_name', '$content', '$devicegroup', '$risk', '$category', '$subcategory', '$technology', '$evasive', '$excessive_bandwidth_use', '$prone_to_misuse', '$disable_override', '$tagging','$transfers_files', '$tunnels_other_apps', '$used_by_malware', '$has_known_vulnerabilities', '$pervasive', '$saas_certifications', '$saas_risk', '$vsys')";

    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO applications_filters (".
            "source, name, xml, devicegroup, risk, category, subcategory, technology, evasive_behavior, consume_big_bandwidth, ".
            "prone_to_misuse, disable_override, tagging, able_to_transfer_file, tunnel_other_application, used_by_malware, has_known_vulnerability, pervasive_use, saas_certifications, saas_risk, vsys) VALUES ".implode(",", $sql).";");
    }
}

function xml_add_applications_groups(&$appglid,$profiles,$source,$vsys,$devicegroup,$version){
    global $projectdb;
    $sql = array();
    $addGroup=array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content="";
        $addGroup[]="('$appglid','$GroupName', '$source', '$vsys', '$devicegroup')";

        $members_all = array();

        if($version >= 7){
            foreach ($profilesArray as $field => $value) {
                if ($field == "members") {
                    foreach ($value as $kkey => $memberss) {
                        $members_all[] = $memberss;
                    }
                }
            }
        }
        else{
            foreach ($profilesArray->member as $memberss) {
                $members_all[] = $memberss;
            }
        }

        foreach ($members_all as $member) {
            $sql[] = "('$source', '$content', '$member', '', '', '$appglid', '$vsys', '$devicegroup','$GroupName')";
        }
        $appglid++;
    }

    if (count($addGroup)>0){
        $projectdb->query("INSERT INTO applications_groups_id (id,name, source, vsys, devicegroup) VALUES ".implode(",",$addGroup).";");
        unset($addGroup);
        if (count($sql) > 0) {
            $projectdb->query("INSERT INTO applications_groups (source, xml, member, member_lid, table_name, lid, vsys, devicegroup,name) VALUES ".implode(",", $sql).";");
            unset($sql);
        }
    }

}

function xml_add_response_page($profiles,$source,$vsys,$template){
    global $projectdb;
    $sql=array();
    foreach ($profiles as $key => $profilesArray) {
        foreach ($profilesArray as $kkey => $vvalue) {
            if (!preg_match("/global-protect/", $kkey)) {
                $sql[] = "('$source','$vsys','$kkey','$vvalue','$template','')";
            } else {
                foreach ($vvalue->entry as $mmkey => $mmvalue) {
                    $responsePageName = $mmvalue->attributes()->name;
                    $content = $mmvalue->page;
                    $sql[] = "('$source','$vsys','$kkey','$content','$template','$responsePageName')";
                }
            }
        }
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO response_pages (source,vsys,type,html,template,name) VALUES " . implode(",", $sql) . ";");
    }
}

function xml_add_authentication_profile($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }

    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO authentication_profile (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_authentication_sequence($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO authentication_sequence (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_certificate($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO certificate (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_certificate_profile($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO certificate_profile (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_ocsp_responder($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO ocsp_responder (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
    }
}

function xml_add_log_settings($projectdb,$source,$vsys,$template,$profiles,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        foreach ($profilesArray as $profilesType => $profilesArrayEntry) {
            $theProfileType = $profilesType;
            foreach ($profilesArrayEntry as $entry => $profileArrayEntryContent) {
                $theProfileName = $profileArrayEntryContent->attributes()->name;
                $theProfilecontent = addslashes($profileArrayEntryContent->asXML());
                $sql[] = "('$source','$theProfileName','$theProfilecontent','$theProfileType','$vsys','$devicegroup','$template')";
            }
        }
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO log_settings (source,name,xml,type,vsys,devicegroup,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_dns_proxy($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO dns_proxy (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_userid_agent($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO user_id_agent (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_tsagent($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO ts_agent (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
    }
}

function xml_add_group_mapping($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO group_mapping (source,name,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_captive_portal($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO captive_portal (source,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_userid_collector($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$content','$vsys','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO user_id_collector (source,xml,vsys,template) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_zones($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $log_setting_table_name = "";
        $log_setting_id = "";
        $theProfileName = $profilesArray->attributes()->name;

        $version = calcVersion($source);
        $theProfileName = truncate_names_zones($theProfileName, $version);

        if (isset($profilesArray->{'enable-user-identification'})) {
            $enable_user_identification = $profilesArray->{'enable-user-identification'};
        } else {
            $enable_user_identification = "";
        }
        if (isset($profilesArray->network->{'zone-protection-profile'})) {
            $zone_protection_profile = $profilesArray->network->{'zone-protection-profile'};
        } else {
            $zone_protection_profile = "";
        }
        if (isset($profilesArray->{'user-acl'}->{'include-list'})) {
            $mem = array();
            foreach ($profilesArray->{'user-acl'}->{'include-list'}->member as $key => $vvalue) {
                $mem[] = $vvalue;
            }
            $include_list = implode(",", $mem);
        } else {
            $include_list = "";
        }
        if (isset($profilesArray->{'user-acl'}->{'exclude-list'})) {
            $mem = array();
            foreach ($profilesArray->{'user-acl'}->{'exclude-list'}->member as $key => $vvalue) {
                $mem[] = $vvalue;
            }
            $exclude_list = implode(",", $mem);
        } else {
            $exclude_list = "";
        }
        if (isset($profilesArray->network->{'log-setting'})) {
            $log_setting = $profilesArray->network->{'log-setting'};
            $getLog = $projectdb->query("SELECT id FROM log_settings WHERE source='$source' AND vsys='$vsys' AND name='$log_setting' AND template='$template';");
            if ($getLog->num_rows == 1) {
                $getData = $getLog->fetch_assoc();
                $log_setting_table_name = "log_settings";
                $log_setting_id = $getData['id'];
            } else {
                $getLog = $projectdb->query("SELECT id FROM log_settings WHERE source='$source' AND name='$log_setting' AND template='$template' AND vsys = 'shared';");
                if ($getLog->num_rows == 1) {
                    $getData = $getLog->fetch_assoc();
                    $log_setting_table_name = "log_settings";
                    $log_setting_id = $getData['id'];
                } else {
                    $getLog = $projectdb->query("SELECT id FROM log_settings WHERE source='$source' AND name='$log_setting' AND template='$template' AND vsys = 'shared';");
                    if ($getLog->num_rows == 1) {
                        $getData = $getLog->fetch_assoc();
                        $log_setting_table_name = "log_settings";
                        $log_setting_id = $getData['id'];
                    } else {
                        $getLog = $projectdb->query("SELECT id FROM log_settings WHERE source='$source' AND name='$log_setting' AND template='0' AND vsys = 'shared';");
                        if ($getLog->num_rows == 1) {
                            $getData = $getLog->fetch_assoc();
                            $log_setting_table_name = "log_settings";
                            $log_setting_id = $getData['id'];
                        } else {
                            #PRINT "NO LOG SETTINGS FOUND";
                        }
                    }
                }
            }
        }
        else {
            $log_setting_table_name = "";
            $log_setting_id = "";
        }
        if (isset($profilesArray->network->{'enable-packet-buffer-protection'})){
            $enable_packet_buffer_protection=$profilesArray->network->{'enable-packet-buffer-protection'};
        }
        else{
            $enable_packet_buffer_protection="";
        }

        $mem = array();
        $type = '';
        $interfaces = '';
        if (isset($profilesArray->network->{'virtual-wire'})) {
            $type = "virtual-wire";
            $mem = array();
            foreach ($profilesArray->network->{'virtual-wire'}->member as $key => $vvalue) {
                $mem[] = $vvalue;
            }
            $interfaces = implode(",", $mem);
        }
        elseif (isset($profilesArray->network->layer3)) {
            $type = "layer3";
            $mem = array();
            foreach ($profilesArray->network->layer3->member as $key => $vvalue) {
                $mem[] = $vvalue;
            }
            $interfaces = implode(",", $mem);
        }
        elseif (isset($profilesArray->network->layer2)) {
            $type = "layer2";
            $mem = array();
            foreach ($profilesArray->network->layer2->member as $key => $vvalue) {
                $mem[] = $vvalue;
            }
            $interfaces = implode(",", $mem);
        }
        elseif (isset($profilesArray->network->tap)) {
            $type = "tap";
            $mem = array();
            foreach ($profilesArray->network->tap->member as $key => $vvalue) {
                $mem[] = $vvalue;
            }
            $interfaces = implode(",", $mem);
        }
        elseif (isset($profilesArray->network->external)) {
            $type = "external";
            $mem = array();
            foreach ($profilesArray->network->external->member as $key => $vvalue) {
                $mem[] = $vvalue;
            }
            $interfaces = implode(",", $mem);
        }
        elseif (isset($profilesArray->network->tunnel)) {
            $type = "tunnel";
            $mem = array();
            foreach ($profilesArray->network->tunnel->member as $key => $vvalue) {
                $mem[] = $vvalue;
            }
            $interfaces = implode(",", $mem);
        }

        foreach ($mem as $m => $v) {
            $projectdb->query("UPDATE interfaces SET zone='$theProfileName' WHERE unitname='$v' AND source='$source' AND template='$template';");
        }

        $sql[] = "('$template','$source','$theProfileName','$interfaces','$type','$vsys','$zone_protection_profile','$log_setting_table_name','$log_setting_id','$include_list','$exclude_list','$enable_user_identification','$enable_packet_buffer_protection')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO zones (template,source,name,interfaces,type,vsys,zone_protection_profile,log_setting_table_name,log_setting_id,include_list,exclude_list,enable_user_identification,enable_packet_buffer_protection) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_server_profile($projectdb,$source,$vsys,$template,$profiles){
    $sql = array();
    foreach ($profiles as $kkey => $profilesArray) {
        foreach ($profilesArray as $server_type => $serverArray) {
            foreach ($serverArray->entry as $kk => $vvalue) {
                $theServerName = $vvalue->attributes()->name;
                $xxml = addslashes($vvalue->asXML());
                $sql[] = "('$template','$source','$vsys','$theServerName','$server_type','$xxml')";
            }
        }
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO server_profile (template,source,vsys,name,type,xml) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function pan_read_rules_nat2($preorpost, $address, $source, $vsys, $version, $devicegroup,&$objectsInMemory){
    global $projectdb;

    $natrules=array();

    $allVSYS=getVsyses($projectdb, $vsys, $source);

    $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $nat_lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM nat_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $nat_position = intval($getLID1['max']) + 1;

    $natrulesfrom=array();
    $natrulessrc=array();
    $natrulesdst=array();
    $nat_rules_translated_address_fallback=array();
    $nat_rules_translated_address=array();
    $natrulestag=array();
    $addTarget = array();
    $myArray=[];
    $member_name_array=[];
    $myArray_tag=[];
    $member_name_array_tag=[];
    $myArray_srv=[];
    $member_name_array_srv=[];
    $servicesArray=array();
    foreach ($address as $child => $data) {
        $tp_sat_type = "None";
        $is_dat = 0; // 0 NONE  1 DNAT  2 DYNAMIC DNAT
        $tp_dat_address_table="";
        $tp_dat_address_lid="";
        $tp_dat_port="";
        $natType="ipv4";
        $op_zone_to="";
        $active_active_device_binding="";
        $target="";
        $target_negate="no";
        $op_service_lid="";
        $op_service_table="";
        $tp_fallback_type="";
        $tp_sat_interface_fallback="";
        $tp_sat_address_type="";
        $tp_sat_interface="";
        $tp_sat_bidirectional="";
        $tp_sat_ipaddress="";
        $group_tag_id = "";
        $service="";
        $name = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $rule_disabled1 = $data->disabled;
        if ($rule_disabled1 == "yes") {
            $disabled = "1";
        } else {
            $disabled = "0";
        }
        $description = addslashes($data->description);
        $op_to_interface = $data->{'to-interface'};
        if (isset($data->{'active-active-device-binding'})){
            $active_active_device_binding=$data->{'active-active-device-binding'};
        }
        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate=$data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$vsys','$nat_lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$vsys','$nat_lid','$deviceName','')";
                    }
                }
            }
        }
        if (isset($data->{'source-translation'})) {
            if (isset($data->{'source-translation'}->{'dynamic-ip'})){
                $tp_sat_type="dynamic-ip";
                if (isset($data->{'source-translation'}->{'dynamic-ip'}->{'translated-address'})){
                    foreach ($data->{'source-translation'}->{'dynamic-ip'}->{'translated-address'}->member as $member) {
                        $memberA=(string) $member;
                        if (($memberA == "") OR ( $memberA == "any")) {}
                        else{
                            $myArray[$memberA]["translated_address"][]=$nat_lid;
                            $member_name_array[]=$memberA;
                        }
                    }
                }

                if (isset($data->{'source-translation'}->{'dynamic-ip'}->{'fallback'})){
                    if (isset($data->{'source-translation'}->{'dynamic-ip'}->{'fallback'}->{'translated-address'})){
                        $tp_fallback_type="translated-address";
                        foreach ($data->{'source-translation'}->{'dynamic-ip'}->{'fallback'}->{'translated-address'}->member as $member){
                            $memberA=(string) $member;
                            if (($memberA == "") OR ( $memberA == "any")) {}
                            else{
                                $myArray[$memberA]["translated_address_fallback"][]=$nat_lid;
                                $member_name_array[]=$memberA;
                            }
                        }
                    }
                    else{
                        if (isset($data->{'source-translation'}->{'dynamic-ip'}->{'fallback'}->{'interface-address'}->interface)){
                            $tp_fallback_type="interface";
                            $tp_sat_interface_fallback=(string) $data->{'source-translation'}->{'dynamic-ip'}->{'fallback'}->{'interface-address'}->interface;
                        }
                        if (isset($data->{'source-translation'}->{'dynamic-ip'}->{'fallback'}->{'interface-address'}->ip)){
                            $tp_fallback_type="ip";
                            $tp_sat_interface_fallback=(string) $data->{'source-translation'}->{'dynamic-ip'}->{'fallback'}->{'interface-address'}->ip;
                        }
                    }
                }
            }

            if (isset($data->{'source-translation'}->{'dynamic-ip-and-port'})){
                $tp_sat_type="dynamic-ip-and-port";
                if (isset($data->{'source-translation'}->{'dynamic-ip-and-port'}->{'translated-address'})){
                    $tp_sat_address_type="translated-address";
                    foreach ($data->{'source-translation'}->{'dynamic-ip-and-port'}->{'translated-address'}->member as $member) {
                        $memberA=(string) $member;
                        if (($memberA == "") OR ( $memberA == "any")) {}
                        else{
                            $myArray[$memberA]["translated_address"][]=$nat_lid;
                            $member_name_array[]=$memberA;
                        }
                    }
                }
                else{
                    if (isset($data->{'source-translation'}->{'dynamic-ip-and-port'}->{'interface-address'}->interface)){
                        $tp_sat_address_type="interface-address";
                        $tp_sat_interface=(string) $data->{'source-translation'}->{'dynamic-ip-and-port'}->{'interface-address'}->interface;
                    }
                    if (isset($data->{'source-translation'}->{'dynamic-ip-and-port'}->{'interface-address'}->ip)){
                        $tp_sat_address_type="interface-address";
                        $tp_sat_ipaddress=(string) $data->{'source-translation'}->{'dynamic-ip-and-port'}->{'interface-address'}->ip;
                    }
                }
            }

            if (isset($data->{'source-translation'}->{'static-ip'})){
                $tp_sat_type="static-ip";
                if (isset($data->{'source-translation'}->{'static-ip'}->{'translated-address'})){
                    $memberA=(string) $data->{'source-translation'}->{'static-ip'}->{'translated-address'};
                    if (($memberA == "") OR ( $memberA == "any")) {}
                    else{
                        $myArray[$memberA]["translated_address"][]=$nat_lid;
                        $member_name_array[]=$memberA;
                    }
                }
                if (isset($data->{'source-translation'}->{'static-ip'}->{'bi-directional'})){
                    $value=(string) $data->{'source-translation'}->{'static-ip'}->{'bi-directional'};
                    if ($value == "yes") {
                        $tp_sat_bidirectional = 1;
                    } else {
                        $tp_sat_bidirectional = "0";
                    }
                }
            }
        }
        if (isset($data->{'destination-translation'})) {
            if (isset($data->{'destination-translation'}->{'translated-address'})){
                $is_dat=1;
                $value=(string) $data->{'destination-translation'}->{'translated-address'};
                $tmp=calculate_member_and_table_from_memory("policy","address",$vsys,$source,$devicegroup, $value, $version,$objectsInMemory);
                if (count($tmp)>0){
                    $tp_dat_address_lid = $tmp['member_lid'];
                    $tp_dat_address_table = $tmp['table_name'];
                }
                else {
                    print "DNAT: ERROR NO ADDRESS for $value".PHP_EOL;
                }
            }
            if (isset($data->{'destination-translation'}->{'translated-port'})){
                $value = (integer) $data->{'destination-translation'}->{'translated-port'};
                $is_dat=1;
                $tp_dat_port=$value;
            }
        }
        if (isset($data->{'dynamic-destination-translation'})){
            if (isset($data->{'dynamic-destination-translation'}->{'translated-address'})){
                $is_dat=2;
                $value=(string) $data->{'dynamic-destination-translation'}->{'translated-address'};
                $tmp=calculate_member_and_table_from_memory("policy","address",$vsys,$source,$devicegroup, $value, $version,$objectsInMemory);
                if (count($tmp)>0){
                    $tp_dat_address_lid = $tmp['member_lid'];
                    $tp_dat_address_table = $tmp['table_name'];
                }
                else {
                    print "DYN DNAT: ERROR NO ADDRESS for $value".PHP_EOL;
                }
            }
            if (isset($data->{'dynamic-destination-translation'}->{'translated-port'})){
                $is_dat=2;
                $value = (integer) $data->{'dynamic-destination-translation'}->{'translated-port'};
                $tp_dat_port=$value;
            }
        }
        if (isset($data->{'nat-type'})) {
            $natType = $data->{'nat-type'};
        }
        if (isset($data->from)){
            foreach ($data->from->member as $zone_member) {
                $zone_member = (string) $zone_member;
                if (($zone_member == "") OR ( $zone_member == "any")) {}
                else {
                    $natrulesfrom[] = "('$devicegroup','$source','$vsys','$zone_member','$nat_lid')";
                }
            }
        }
        if (isset($data->to)){
            $memberA=(string) $data->to->member;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else {
                $op_zone_to=$memberA;
            }
        }
        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$nat_lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }

        if (isset($data->source)){
            foreach ($data->source->member as $memberA) {
                $memberA = (string) $memberA;
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray[$memberA]["src"][]=$nat_lid;
                    $member_name_array[]=$memberA;
                }

            }
        }
        if (isset($data->destination)){
            foreach ($data->destination->member as $memberA) {
                $memberA = (string) $memberA;
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray[$memberA]["dst"][]=$nat_lid;
                    $member_name_array[]=$memberA;
                }
            }
        }
        if (isset($data->service)){
            $service = (string) $data->service;
            if (($service == "") OR ( $service == "any")) {}
            else {
                $tmp=calculate_member_and_table_from_memory("policy","service",$vsys,$source,$devicegroup, $service, $version,$objectsInMemory);
                if (count($tmp)>0){
                    $op_service_lid = $tmp['member_lid'];
                    $op_service_table = $tmp['table_name'];
                }
                else {
                    print "NAT Service: ERROR NO SERVICE for $value".PHP_EOL;
                }
            }
        }

        $natrules[] = "('$target','$preorpost','$devicegroup','$nat_position','$nat_lid','$description','$name','$disabled','$vsys','$source','$op_to_interface','$tp_sat_type','$active_active_device_binding','$is_dat','$natType','$tp_dat_address_lid','$tp_dat_address_table','$tp_dat_port','$op_zone_to','$op_service_lid','$op_service_table','$tp_fallback_type','$tp_sat_interface_fallback','$tp_sat_address_type','$tp_sat_interface','$tp_sat_ipaddress','$tp_sat_bidirectional', '$target_negate', '$uuid', '$group_tag_id')";
        $nat_lid++;
        $nat_position++;

    }

    # Map in memory object names with table_name and member_lid for Address (source,destination,translated_address, and fallback)
    $calculate=calculate_members_and_table_from_memory("policy","address",$myArray,$vsys,$source,$devicegroup,$member_name_array,$version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];

    # Write the Output for Address
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];

            if (isset($valueArray['src'])){
                foreach ($valueArray['src'] as $lid){
                    if (($member_lid != "") AND ( $table_name != "")) {
                        $natrulessrc[] = "('$devicegroup','','','$table_name','$member_lid','$lid')";
                    }
                }
            }

            if (isset($valueArray['dst'])){
                foreach ($valueArray['dst'] as $lid){
                    if (($member_lid != "") AND ( $table_name != "")) {
                        $natrulesdst[] = "('$devicegroup','','','$table_name','$member_lid','$lid')";
                    }
                }
            }

            if (isset($valueArray['translated_address'])){
                foreach ($valueArray['translated_address'] as $lid){
                    if (($member_lid != "") AND ( $table_name != "")) {
                        $nat_rules_translated_address[] = "('$devicegroup','','','$table_name','$member_lid','$lid')";
                    }
                }
            }

            if (isset($valueArray['translated_address_fallback'])){
                foreach ($valueArray['translated_address_fallback'] as $lid){
                    if (($member_lid != "") AND ( $table_name != "")) {
                        $nat_rules_translated_address_fallback[] = "('$devicegroup','','','$table_name','$member_lid','$lid')";
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate=calc_members_and_table("policy","tag",$myArray_tag,$vsys,$source,$devicegroup,$member_name_array_tag, $version);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $natrulestag[] = "('$source','$member_lid','$table_name','$vsys','$lid','$devicegroup')";
                }
            }
        }
    }

    if (count($natrules)>0){
        $projectdb->query("INSERT INTO nat_rules (target,preorpost,devicegroup,position,id,description,name,disabled,vsys,source,op_to_interface,tp_sat_type,active_active_device_binding,is_dat,nat_type,tp_dat_address_lid,tp_dat_address_table,tp_dat_port,op_zone_to,op_service_lid,op_service_table,tp_fallback_type,tp_sat_interface_fallback,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_sat_bidirectional, target_negate, uuid, group_tag_id) VALUES ".implode(",",$natrules).";");
        unset($natrules);
        if (count($natrulesfrom)>0){
            $projectdb->query("INSERT INTO nat_rules_from (devicegroup,source,vsys,name,rule_lid) VALUES ".implode(",",$natrulesfrom).";");
            unset($natrulesfrom);
        }
        if (count($natrulessrc)>0){
            $projectdb->query("INSERT INTO nat_rules_src (devicegroup,source,vsys,table_name,member_lid,rule_lid) VALUES ".implode(",",$natrulessrc).";");
            unset($natrulessrc);
        }
        if (count($natrulesdst)>0){
            $projectdb->query("INSERT INTO nat_rules_dst (devicegroup,source,vsys,table_name,member_lid,rule_lid) VALUES ".implode(",",$natrulesdst).";");
            unset($natrulesdst);
        }

        if (count($nat_rules_translated_address_fallback)>0){
            $projectdb->query("INSERT INTO nat_rules_translated_address_fallback (devicegroup,source,vsys,table_name,member_lid,rule_lid) VALUES ".implode(",",$nat_rules_translated_address_fallback).";");
            unset($nat_rules_translated_address_fallback);
        }

        if (count($nat_rules_translated_address)>0){
            $projectdb->query("INSERT INTO nat_rules_translated_address (devicegroup,source,vsys,table_name,member_lid,rule_lid) VALUES ".implode(",",$nat_rules_translated_address).";");
            unset($nat_rules_translated_address);
        }

        if (count($natrulestag)>0){
            $projectdb->query("INSERT INTO nat_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES ".implode(",",$natrulestag).";");
            unset($natrulestag);
        }
        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO nat_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}

function pan_read_rules_nat($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;

    $natrules=array();

    $allVSYS=getVsyses($projectdb, $vsys, $source);

    $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $nat_lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM nat_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $nat_position = intval($getLID1['max']) + 1;

    $natrulesfrom=array();
    $natrulessrc=array();
    $natrulesdst=array();
    $nat_rules_translated_address_fallback=array();
    $nat_rules_translated_address=array();
    $natrulestag=array();

    foreach ($address as $child => $data) {
        $tp_sat_type = "None";
        $is_dat = 0;
        $tp_dat_address_table="";
        $tp_dat_address_lid="";
        $tp_dat_port="";
        $natType="ipv4";
        $op_zone_to="";
        $active_active_device_binding="";
        $target="";
        $op_service_lid="";
        $op_service_table="";
        $tp_fallback_type="";
        $tp_sat_interface_fallback="";
        $tp_sat_address_type="";
        $tp_sat_interface="";
        $tp_sat_bidirectional="";
        $tp_sat_ipaddress="";

        $name = $data->attributes()->name;
        $rule_disabled1 = $data->disabled;
        if ($rule_disabled1 == "yes") {
            $disabled = "1";
        } else {
            $disabled = "0";
        }
        $description = addslashes($data->description);
        $op_to_interface = $data->{'to-interface'};
        if (isset($data->{'active-active-device-binding'})){
            $active_active_device_binding=$data->{'active-active-device-binding'};
        }

        if (isset($data->target)) {
            $target = addslashes($data->target->asXML());
        }


        if (isset($data->{'source-translation'})) {
            foreach ($data->{'source-translation'} as $type1 => $natA) {
                foreach ($natA as $type => $nat0) {
                    $tp_sat_type=$type;
                    if ($type == "dynamic-ip") {
                        foreach ($nat0 as $falloraddress => $nat1) {
                            if ($falloraddress == "fallback") {
                                foreach ($nat1 as $falltype => $nat2) {
                                    if ($falltype == "translated-address") {
                                        $tp_fallback_type="translated-address";
                                        foreach ($nat2 as $m => $member) {
                                            $calc_member = getMemberId($projectdb, $source, $allVSYS, $member);
                                            if ($calc_member != null) {
                                                $nat_rules_translated_address_fallback[] = "('$devicegroup','$source','$vsys','$calc_member->location','$calc_member->name','$nat_lid')";
                                            }
                                            else {
                                                if (preg_match("/\//i", $member)) {
                                                    $vars = explode("/", $member);
                                                    $ipversion = ip_version($vars[0]);
                                                    $network = $vars[0];
                                                    $cidr = $vars[1];
                                                    $addressname = "$member";
                                                    $dummy = "1";
                                                    $vtype = "ip-netmask";
                                                } elseif (preg_match("/-/", $member)) {
                                                    $vars = explode("-", $member);
                                                    $ipversion = ip_version($vars[0]);
                                                    $network = $member;
                                                    $cidr = "";
                                                    $addressname = "$member";
                                                    $dummy = "1";
                                                    $vtype = "ip-range";
                                                } else {
                                                    $network = "$member";
                                                    $ipversion = ip_version($member);
                                                    //if ($ipversion=="v6"){$cidr = "128";}
                                                    //else{$cidr = "32";}
                                                    $cidr = "";
                                                    $addressname = "$member";
                                                    $dummy = "1";
                                                    $vtype = "ip-netmask";
                                                }

                                                $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$member';");
                                                if ($getDup->num_rows == 0) {
                                                    $projectdb->query("INSERT INTO address (devicegroup,name,name_ext,vsys,type,vtype,ipaddress,cidr,$ipversion,source,dummy) VALUES ('$devicegroup','$addressname','$addressname','$vsys','$vtype','$vtype','$network','$cidr','1','$source','$dummy');");
                                                    $lid2 = $projectdb->insert_id;
                                                } else {
                                                    $mynewdata = $getDup->fetch_assoc();
                                                    $lid2 = $mynewdata['id'];
                                                }
                                                $nat_rules_translated_address_fallback[] = "('$devicegroup','$source','$vsys','address','$lid2','$nat_lid')";
                                            }
                                        }
                                    }
                                    elseif ($falltype == "interface-address") {
                                        foreach ($nat2 as $falltype2 => $value) {
                                            if ($falltype2 == "interface") {
                                                $tp_fallback_type="interface";
                                                $tp_sat_interface_fallback=$value;
                                            }
                                            elseif ($falltype2 == "ip") {
                                                $tp_fallback_type="ip";
                                                $tp_sat_interface_fallback=$value;
                                            }
                                        }
                                    }
                                }
                            }
                            elseif ($falloraddress == "translated-address") {
                                foreach ($nat1 as $m => $member) {
                                    $calc_member = getMemberId($projectdb, $source, $allVSYS, $member);
                                    if ($calc_member != null) {
                                        $nat_rules_translated_address[] = "('$devicegroup','$source','$vsys','$calc_member->location','$calc_member->name','$nat_lid')";
                                    }
                                    else {
                                        if (preg_match("/\//i", $member)) {
                                            $vars = explode("/", $member);
                                            $ipversion = ip_version($vars[0]);
                                            $network = $vars[0];
                                            $cidr = $vars[1];
                                            $addressname = "$member";
                                            $dummy = "1";
                                            $vtype = "ip-netmask";
                                        } elseif (preg_match("/-/", $member)) {
                                            $vars = explode("-", $member);
                                            $ipversion = ip_version($vars[0]);
                                            $network = $member;
                                            $cidr = "";
                                            $addressname = "$member";
                                            $dummy = "1";
                                            $vtype = "ip-range";
                                        } else {
                                            $network = "$member";
                                            $ipversion = ip_version($member);
                                            //if ($ipversion=="v6"){$cidr = "128";}
                                            //else{$cidr = "32";}
                                            $cidr = "";
                                            $addressname = "$member";
                                            $dummy = "1";
                                            $vtype = "ip-netmask";
                                        }

                                        $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$member';");
                                        if ($getDup->num_rows == 0) {
                                            $projectdb->query("INSERT INTO address (devicegroup,name,name_ext,vsys,type,vtype,ipaddress,cidr,$ipversion,source,dummy) VALUES ('$devicegroup','$addressname','$addressname','$vsys','$vtype','$vtype','$network','$cidr','1','$source','$dummy');");
                                            $lid2 = $projectdb->insert_id;
                                        } else {
                                            $mynewdata = $getDup->fetch_assoc();
                                            $lid2 = $mynewdata['id'];
                                        }
                                        $nat_rules_translated_address[] = "('$devicegroup','$source','$vsys','address','$lid2','$nat_lid')";
                                    }
                                }
                            }
                        }
                    }
                    elseif ($type == "dynamic-ip-and-port") {
                        foreach ($nat0 as $falloraddress => $nat1) {
                            if ($falloraddress == "translated-address") {
                                $tp_sat_address_type="translated-address";
                                foreach ($nat1 as $m => $member) {
                                    $calc_member = getMemberId($projectdb, $source, $allVSYS, $member);
                                    if ($calc_member != null) {
                                        $nat_rules_translated_address[] = "('$devicegroup','$source','$vsys','$calc_member->location','$calc_member->name','$nat_lid')";
                                    }
                                    else {
                                        if (preg_match("/\//i", $member)) {
                                            $vars = explode("/", $member);
                                            $ipversion = ip_version($vars[0]);
                                            $network = $vars[0];
                                            $cidr = $vars[1];
                                            $addressname = "$member";
                                            $dummy = "1";
                                            $vtype = "ip-netmask";
                                        } elseif (preg_match("/-/", $member)) {
                                            $vars = explode("-", $member);
                                            $ipversion = ip_version($vars[0]);
                                            $network = $member;
                                            $cidr = "";
                                            $addressname = "$member";
                                            $dummy = "1";
                                            $vtype = "ip-range";
                                        } else {
                                            $network = "$member";
                                            $ipversion = ip_version($member);
                                            //if ($ipversion=="v6"){$cidr = "128";}
                                            //else{$cidr = "32";}
                                            $cidr = "";
                                            $addressname = "$member";
                                            $dummy = "1";
                                            $vtype = "ip-netmask";
                                        }

                                        $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$member';");
                                        if ($getDup->num_rows == 0) {
                                            $projectdb->query("INSERT INTO address (devicegroup,name,name_ext,vsys,type,vtype,ipaddress,cidr,$ipversion,source,dummy) VALUES ('$devicegroup','$addressname','$addressname','$vsys','$vtype','$vtype','$network','$cidr','1','$source','$dummy');");
                                            $lid2 = $projectdb->insert_id;
                                        } else {
                                            $mynewdata = $getDup->fetch_assoc();
                                            $lid2 = $mynewdata['id'];
                                        }
                                        $nat_rules_translated_address[] = "('$devicegroup','$source','$vsys','address','$lid2','$nat_lid')";
                                    }
                                }
                            }
                            elseif ($falloraddress == "interface-address") {
                                $tp_sat_address_type="interface-address";
                                foreach ($nat1 as $falltype2 => $value) {
                                    if ($falltype2 == "interface") {
                                        $tp_sat_interface=$value;
                                    } elseif ($falltype2 == "ip") {
                                        $tp_sat_ipaddress=$value;
                                    }
                                }
                            }
                        }
                    }
                    elseif ($type == "static-ip") {
                        foreach ($nat0 as $info => $value) {
                            if ($info == "bi-directional") {
                                if ($value == "yes") {
                                    $tp_sat_bidirectional = 1;
                                } else {
                                    $tp_sat_bidirectional = "0";
                                }
                            }
                            elseif ($info = "translated-address") {
                                $calc_member = getMemberId($projectdb, $source, $allVSYS, $value);
                                if ($calc_member != null) {
                                    $nat_rules_translated_address[] = "('$devicegroup','$source','$vsys','$calc_member->location','$calc_member->name','$nat_lid')";
                                }
                                else {
                                    if (preg_match("/\//i", $value)) {
                                        $vars = explode("/", $value);
                                        $ipversion = ip_version($vars[0]);
                                        $network = $vars[0];
                                        $cidr = $vars[1];
                                        $addressname = "$value";
                                        $dummy = "1";
                                        $vtype = "ip-netmask";
                                    } elseif (preg_match("/-/", $value)) {
                                        $vars = explode("-", $value);
                                        $ipversion = ip_version($vars[0]);
                                        $network = $value;
                                        $cidr = "";
                                        $addressname = "$value";
                                        $dummy = "1";
                                        $vtype = "ip-range";
                                    } else {
                                        $network = "$value";
                                        $ipversion = ip_version($value);
                                        //if ($ipversion=="v6"){$cidr = "128";}
                                        //else{$cidr = "32";}
                                        $cidr = "";
                                        $addressname = "$value";
                                        $dummy = "1";
                                        $vtype = "ip-netmask";
                                    }

                                    $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$value';");
                                    if ($getDup->num_rows == 0) {
                                        $projectdb->query("INSERT INTO address (devicegroup,name,name_ext,vsys,type,vtype,ipaddress,cidr,$ipversion,source,dummy) VALUES ('$devicegroup','$addressname','$addressname','$vsys','$vtype','$vtype','$network','$cidr','1','$source','$dummy');");
                                        $lid2 = $projectdb->insert_id;
                                    } else {
                                        $mynewdata = $getDup->fetch_assoc();
                                        $lid2 = $mynewdata['id'];
                                    }
                                    $nat_rules_translated_address[] = "('$devicegroup','$source','$vsys','address','$lid2','$nat_lid')";
                                }
                            }
                        }
                    }
                }
            }
        }
        $destination_translation = $data->{'destination-translation'};
        if (isset($destination_translation)) {
            foreach ($destination_translation as $type5 => $nat5) {
                foreach ($nat5 as $type => $value) {
                    if ($type == "translated-address") {
                        $is_dat=1;

                        $calc_member=getMemberId($projectdb, $source, $allVSYS, $value);
                        if ($calc_member!=null){
                            $tp_dat_address_lid = $calc_member->name;
                            $tp_dat_address_table = $calc_member->location;
                        }
                        else{
                            if (preg_match("/\//i", $value)) {
                                $vars = explode("/", $value);
                                $ipversion = ip_version($vars[0]);
                                $network = $vars[0];
                                $cidr = $vars[1];
                                $addressname = "$value";
                                $dummy="1";
                                $vtype="ip-netmask";
                            }
                            elseif (preg_match("/-/",$value)){
                                $vars = explode("-", $value);
                                $ipversion = ip_version($vars[0]);
                                $network = $value;
                                $cidr = "";
                                $addressname = "$value";
                                $dummy="1";
                                $vtype="ip-range";
                            }
                            else {
                                $network = "$value";
                                $ipversion = ip_version($value);
                                //if ($ipversion=="v6"){$cidr = "128";}
                                //else{$cidr = "32";}
                                $cidr = "";
                                $addressname = "$value";
                                $dummy = "1";
                                $vtype = "ip-netmask";
                            }

                            $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$value';");
                            if ($getDup->num_rows == 0) {
                                $projectdb->query("INSERT INTO address (devicegroup,name,name_ext,vsys,type,vtype,ipaddress,cidr,$ipversion,source,dummy) VALUES ('$devicegroup','$addressname','$addressname','$vsys','$vtype','$vtype','$network','$cidr','1','$source','$dummy');");
                                $lid2 = $projectdb->insert_id;
                            } else {
                                $mynewdata = $getDup->fetch_assoc();
                                $lid2 = $mynewdata['id'];
                            }
                            $tp_dat_address_lid = $lid2;
                            $tp_dat_address_table = "address";
                        }
                    }
                    elseif ($type == "translated-port") {
                        $is_dat=1;
                        $tp_dat_port=$value;
                    }
                }
            }
        }

        if (isset($data->{'nat-type'})) {
            $natType = $data->{'nat-type'};
        }

        foreach ($data->from->member as $k => $zone_member) {
            if (($zone_member == "") OR ( $zone_member == "any")) {}
            else {
                $natrulesfrom[] = "('$devicegroup','$source','$vsys','$zone_member','$nat_lid')";
            }
        }
        foreach ($data->to->member as $k => $memberA) {
            if (($memberA == "") OR ( $memberA == "any")) {}
            else {
                $op_zone_to=$memberA;
            }
        }
        foreach ($data->tag as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $member=getTagId($projectdb, $source, $allVSYS, $memberA);
                    if ($member!=null){
                        $tagId=$member->name;
                    }
                    else{
                        $projectdb->query("INSERT INTO tag (name,source,vsys,devicegroup, vtype, dummy) VALUES ('$memberA','$source','$vsys','MT_Panorama', 'dummy', '1');");
                        $tagId = $projectdb->insert_id;
                    }
                    $natrulestag[] = "('$source','$tagId','tag','$vsys','$nat_lid','$devicegroup')";
                }
            }
        }
        foreach ($data->source as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $member=getMemberId($projectdb, $source, $allVSYS, $memberA);
                    if ($member!=null){
                        $table_name=$member->location;
                        $member_lid=$member->name;
                    }
                    else{
                        $memberANetwork = explode("/",$memberA);
                        $memberAIPversion = ip_version($memberANetwork[0]);
                        if($memberAIPversion != "noip"){
                            $projectdb->query("INSERT INTO address (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,vtype, devicegroup) VALUES ('$source','shared',1,'ip-netmask','$memberA','$memberA','$memberANetwork[0]','','dummy', '$devicegroup');");
                        }else{
                            $projectdb->query("INSERT INTO address (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,vtype, devicegroup) VALUES ('$source','shared',1,'ip-netmask','$memberA','$memberA','','','dummy', 'MT_Panorama');");
                        }
                        $member_lid = $projectdb->insert_id;
                        $table_name = "address";
                    }
                    $natrulessrc[]="('$devicegroup','$source','$vsys','$table_name','$member_lid','$nat_lid')";
                }
            }
        }
        foreach ($data->destination as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $member=getMemberId($projectdb, $source, $allVSYS, $memberA);
                    if ($member!=null){
                        $table_name=$member->location;
                        $member_lid=$member->name;
                    }
                    else{
                        $memberANetwork = explode("/",$memberA);
                        $memberAIPversion = ip_version($memberANetwork[0]);
                        if($memberAIPversion != "noip"){
                            $projectdb->query("INSERT INTO address (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,vtype, devicegroup) VALUES ('$source','shared',1,'ip-netmask','$memberA','$memberA','$memberANetwork[0]','','dummy', '$devicegroup');");
                        }else{
                            $projectdb->query("INSERT INTO address (source,vsys,dummy,type,name,name_ext,ipaddress,cidr,vtype, devicegroup) VALUES ('$source','shared',1,'ip-netmask','$memberA','$memberA','','','dummy', 'MT_Panorama');");
                        }
                        $member_lid = $projectdb->insert_id;
                        $table_name = "address";
                    }
                    $natrulesdst[]="('$devicegroup','$source','$vsys','$table_name','$member_lid','$nat_lid')";
                }
            }
        }
        $service = $data->service;
        if (($service == "") OR ( $service == "any")) {}
        else {
            $calc_member=getServiceId($projectdb,$source,$allVSYS,$service);
            if ($calc_member!=null){
                $op_service_lid=$calc_member->name;
                $op_service_table=$calc_member->location;
            }
            else{
                $projectdb->query("INSERT INTO services (source,vsys,dummy,name,name_ext,vtype, devicegroup) VALUES ('$source','shared',1,'$service','$service','dummy', 'MT_Panorama');");
                $op_service_lid = $projectdb->insert_id;
                $op_service_table = "services";
            }
        }

        $natrules[] = "('$target','$preorpost','$devicegroup','$nat_position','$nat_lid','$description','$name','$disabled','$vsys','$source','$op_to_interface','$tp_sat_type','$active_active_device_binding','$is_dat','$natType','$tp_dat_address_lid','$tp_dat_address_table','$tp_dat_port','$op_zone_to','$op_service_lid','$op_service_table','$tp_fallback_type','$tp_sat_interface_fallback','$tp_sat_address_type','$tp_sat_interface','$tp_sat_ipaddress','$tp_sat_bidirectional')";
        $nat_lid++;
        $nat_position++;
    }

    if (count($natrules)>0){
        $projectdb->query("INSERT INTO nat_rules (target,preorpost,devicegroup,position,id,description,name,disabled,vsys,source,op_to_interface,tp_sat_type,active_active_device_binding,is_dat,nat_type,tp_dat_address_lid,tp_dat_address_table,tp_dat_port,op_zone_to,op_service_lid,op_service_table,tp_fallback_type,tp_sat_interface_fallback,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_sat_bidirectional) VALUES ".implode(",",$natrules).";");
        unset($natrules);
        if (count($natrulesfrom)>0){
            $projectdb->query("INSERT INTO nat_rules_from (devicegroup,source,vsys,name,rule_lid) VALUES ".implode(",",$natrulesfrom).";");
            unset($natrulesfrom);
        }
        if (count($natrulessrc)>0){
            $projectdb->query("INSERT INTO nat_rules_src (devicegroup,source,vsys,table_name,member_lid,rule_lid) VALUES ".implode(",",$natrulessrc).";");
            unset($natrulessrc);
        }
        if (count($natrulesdst)>0){
            $projectdb->query("INSERT INTO nat_rules_dst (devicegroup,source,vsys,table_name,member_lid,rule_lid) VALUES ".implode(",",$natrulesdst).";");
            unset($natrulesdst);
        }

        if (count($nat_rules_translated_address_fallback)>0){
            $projectdb->query("INSERT INTO nat_rules_translated_address_fallback (devicegroup,source,vsys,table_name,member_lid,rule_lid) VALUES ".implode(",",$nat_rules_translated_address_fallback).";");
            unset($nat_rules_translated_address_fallback);
        }
        if (count($nat_rules_translated_address)>0){
            $projectdb->query("INSERT INTO nat_rules_translated_address (devicegroup,source,vsys,table_name,member_lid,rule_lid) VALUES ".implode(",",$nat_rules_translated_address).";");
            unset($nat_rules_translated_address);
        }
        if (count($natrulestag)>0){
            $projectdb->query("INSERT INTO nat_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES ".implode(",",$natrulestag).";");
            unset($natrulestag);
        }
    }

}

function pan_read_rules_appoverride($preorpost, $address, $source, $vsys, $version, $devicegroup,&$objectsInMemory){
    global $projectdb;

    # Init vars
    $override=array();
    $overridefrom=array();
    $overrideto=array();
    $overridetag=array();
    $overridesrc=array();
    $overridedst=array();

    $addTarget = array();

    $myArray=[];
    $member_name_array=[];
    $myArray_tag=[];
    $member_name_array_tag=[];

    $allVSYS=getVsyses($projectdb, $vsys, $source);


    $getlastlid = $projectdb->query("SELECT max(id) as max FROM appoverride_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $appoverride_lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM appoverride_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $appoverride_position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {
        $target_negate="no";
        $group_tag_id = "";

        $name = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $rule_disabled1 = (string) $data->disabled;
        if ($rule_disabled1 == "yes") {
            $disabled = "1";
        } else {
            $disabled = "0";
        }
        $negate_source = (string) $data->{'negate-source'};
        $negate_destination = (string) $data->{'negate-destination'};
        if ($negate_source=="yes"){$negate_source=1;}
        elseif ($negate_source=="no"){$negate_source=0;}
        if ($negate_destination=="yes"){$negate_destination=1;}
        elseif ($negate_destination=="no"){$negate_destination=0;}
        $description = addslashes($data->description);

        foreach ($data->from->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else {
                $overridefrom[] = "('$source','$vsys','$memberA','$appoverride_lid','$devicegroup')";
            }
        }

        foreach ($data->to->member as $k => $memberA) {
            $memberA = (string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else {
                $overrideto[] = "('$source','$vsys','$memberA','$appoverride_lid','$devicegroup')";
            }
        }

        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string)$memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$appoverride_lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }

        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string)$memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else {
                $myArray[$memberA]["src"][]=$appoverride_lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string)$memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else {
                $myArray[$memberA]["dst"][]=$appoverride_lid;
                $member_name_array[]=$memberA;
            }
        }

        if (isset($data->application)) {
            $application=(string) $data->application;
            if (($application == "") OR ( $application == "any")) {}
            else {
                $tmp=calculate_member_and_table_from_memory("policy","application",$vsys,$source,$devicegroup, $application, $version,$objectsInMemory);
                if (count($tmp)>0){
                    $app_id = $tmp['member_lid'];
                    $app_table = $tmp['table_name'];
                }
                else {
                    print "App Override Application: ERROR NO APP for $application".PHP_EOL;
                }
            }
        }
        //if (isset($data->target)) {
        //    $target = addslashes($data->target->asXML());
        //}
        //else {
        //    $target = "";
        //}

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate = $data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$vsys','$appoverride_lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$vsys','$appoverride_lid','$deviceName','')";
                    }
                }
            }

            //$target = addslashes($data->target->asXML());
        }

        $override[]="('','$preorpost','$appoverride_position','$appoverride_lid','$negate_source','$negate_destination','$description','$name','$name','$disabled','$vsys','$source','$devicegroup','$data->protocol','$data->port','$app_id','$app_table', '$target_negate', '$uuid', '$group_tag_id')";
        $appoverride_lid++;
        $appoverride_position++;
    }

    # Map in memory object names with table_name and member_lid for Address (source,destination,translated_address, and fallback)
    $calculate=calculate_members_and_table_from_memory("policy","address",$myArray,$vsys,$source,$devicegroup,$member_name_array,$version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];

    # Write the Output for Address
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            if (isset($valueArray['src'])){
                foreach ($valueArray['src'] as $lid){
                    if (($member_lid != "") AND ( $table_name != "")) {
                        $overridesrc[] = "('','','$table_name','$member_lid','$lid','$devicegroup')";
                    }
                }
            }
            if (isset($valueArray['dst'])){
                foreach ($valueArray['dst'] as $lid){
                    if (($member_lid != "") AND ( $table_name != "")) {
                        $overridedst[] = "('','','$table_name','$member_lid','$lid','$devicegroup')";
                    }
                }
            }
        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate=calc_members_and_table("policy","tag",$myArray_tag,$vsys,$source,$devicegroup,$member_name_array_tag, $version);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $overridetag[] = "('$source','$member_lid','$table_name','$vsys','$lid','$devicegroup')";
                }
            }
        }
    }

    if (count($override)>0){
        $projectdb->query("INSERT INTO appoverride_rules (target,preorpost,position,id,negate_source,negate_destination,description,name,name_ext,disabled,vsys,source,devicegroup,protocol,port,app_id,app_table, target_negate, uuid, group_tag_id) VALUES ".implode(",",$override).";");
        unset($override);
        if (count($overridefrom)>0){
            $projectdb->query("INSERT INTO appoverride_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES ".implode(",",$overridefrom).";");
            unset($overridefrom);
        }
        if (count($overrideto)>0){
            $projectdb->query("INSERT INTO appoverride_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES ".implode(",",$overrideto).";");
            unset($overrideto);
        }
        if (count($overridetag)>0){
            $projectdb->query("INSERT INTO appoverride_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES ".implode(",",$overridetag).";");
            unset($overridetag);
        }
        if (count($overridesrc)>0){
            $projectdb->query("INSERT INTO appoverride_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES ".implode(",",$overridesrc).";");
            unset($overridesrc);
        }
        if (count($overridedst)>0){
            $projectdb->query("INSERT INTO appoverride_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES ".implode(",",$overridedst).";");
            unset($overridedst);
        }
        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO appoverride_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }

    }

}

function pan_read_rules_security($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $urldb,&$objectsInMemory) {
    global $projectdb;
    $quoted_vsyses = implode("," , getVsyses($projectdb, $new_vsys, $source, "quoted"));
    # Init vars
    $lid="";
    $rule_is_type = "universal";
    $secrules = array();
    $secrulesfrom = array();
    $secrulesto = array();
    $secrulestag = array();
    $secrulesusr = array();
    $secrulescategories = array();
    $secruleship = array();
    $secrulessrc = array();
    $secrulesdst = array();
    $secrulesapp = array();
    $secrulessrv = array();
    $secrulesprofiles = array();
    $addTarget = array();
    $myArray=array();
    $member_name_array=array();
    $schedulesA=array();
    $log_forwardingsA=array();
    $myArray_srv=array();
    $member_name_array_srv=array();
    $myArray_app=array();
    $member_name_array_app=array();
    $myArray_tag=array();
    $member_name_array_tag=array();
    $myArray_profiles=array();
    $member_name_array_profiles=array();
    $myArray_profiles_groups=array();
    $member_name_array_profiles_groups=array();

    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {
        # Initialize vars
        $profile_type = "None";
        $qos = "None";
        $qos_value = "";
        $disabled = "0";
        $negate_source = 0;
        $negate_destination = 0;
        $log_start = 0;
        $log_end = 1;
        $dsri = 0;
        $schedule="";
        $log_forwarding="";
        $group_tag_id = "";
//        $description="";
        $rule_is_type = "universal";
        $icmp_unreachable = "";
        $target="";
        $target_negate="no";
        # Start Reading Rule
        $name_ext = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $name_int = $name_ext;
        $action = $data->action;
        $description = addslashes($data->description);
 
        if ($data->disabled == "yes") {$disabled = "1";} 
        if ($data->{'negate-source'} == "yes") {$negate_source = 1;} 
        if ($data->{'negate-destination'} == "yes") {$negate_destination = 1;} 
        if ($data->{'log-start'} == "yes") {$log_start = 1;}
        if ($data->{'log-end'} == "yes") {$log_end = 1;}elseif($data->{'log-end'} == "no"){$log_end = 0;}
        if ($data->option->{'disable-server-response-inspection'} == "yes") {$dsri = 1;} 
        if (isset($data->{'rule-type'})) {$rule_is_type = $data->{'rule-type'};} 
        if (isset($data->{'icmp-unreachable'})) {$icmp_unreachable = $data->{'icmp-unreachable'};} 
        if (isset($data->schedule)) {
            $schedule = (string) $data->schedule;
            $schedulesA[]=$schedule;
        }
        if (isset($data->{'log-setting'})) {
            $log_forwarding = $data->{'log-setting'};
            $log_forwardingsA[]=$log_forwarding;
        }

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate=$data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$new_vsys','$lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$new_vsys','$lid','$deviceName','')";
                    }
                }
            }

            //$target = addslashes($data->target->asXML());
        }
        if (isset($data->qos->marking)) {
            foreach ($data->qos->marking as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    if (($memberA == "") OR ( $memberA == "any")) {
                        
                    } else {
                        $qos = $m;
                        $qos_value = $memberA;
                    }
                }
            }
        }
        foreach ($data->from as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} 
                else {
                    $secrulesfrom[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }
        foreach ($data->to as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} 
                else {
                    $secrulesto[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }
        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA = (string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {} 
                else {
                    $myArray_tag[$memberA]["lid"][]=$lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $new_vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }

        foreach ($data->{'source-user'} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $memberB = addslashes($memberA);
                    //$memberB = $memberA;
                    $secrulesusr[] = "('$source','$new_vsys','$memberB','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->category as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $secrulescategories[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        $hip_profile_field =     ($version >= 10)? 'source-hip':'hip-profiles';
        foreach ($data->{$hip_profile_field} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} 
                elseif ($memberA == "no-hip") {
                    $secruleship[] = "('$source','0','default','$new_vsys','$lid','$devicegroup','no-hip')";
                } else {
                    $getHP = $projectdb->query("/*qc=on*/SELECT id FROM profiles WHERE source='$source' AND BINARY name='$memberA' AND vsys in ($quoted_vsyses) AND type='hip-profiles';");
                    if ($getHP->num_rows >= 1) {
                        $tagData = $getHP->fetch_assoc();
                        $tagId = $tagData['id'];
                        $secruleship[] = "('$source','$tagId','profiles','$new_vsys','$lid','$devicegroup','')";
                    }
                    else {  //TODO: DELETE: This may not be necessary
                        #Shared 
                        //$getHP = $projectdb->query("/*qc=on*/SELECT id FROM shared_profiles WHERE source='$source' AND BINARY name='$memberA' AND type='hip-profiles';");
                        $getHP = $projectdb->query("/*qc=on*/SELECT id FROM profiles WHERE source='$source' AND BINARY name='$memberA' AND type='hip-profiles' AND vsys = 'shared';");
                        if ($getHP->num_rows == 1) {
                            $tagData = $getHP->fetch_assoc();
                            $tagId = $tagData['id'];
                            //$secruleship[] = "('$source','$tagId','shared_profiles','$new_vsys','$lid','$devicegroup','')";
                            $secruleship[] = "('$source','$tagId','profiles','shared','$lid','$devicegroup','')";
                        } else {
                            // if hip-profile does not exist then create it
                            $sql_insert = "INSERT into profiles (source, type, vsys, name, devicegroup) values ('$source', 'hip-profiles', '$new_vsys', '$memberA', '$devicegroup')";
                            $projectdb->query($sql_insert);
                            $tagId = $projectdb->insert_id;
                            $secruleship[] = "('$source','$tagId','profiles','$new_vsys','$lid','$devicegroup','')";
                        }
                    }
                }
            }
        }      
        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {} 
            else{
                $myArray[$memberA]["src"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }
        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {} 
            else{
                $myArray[$memberA]["dst"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }
        foreach ($data->application->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {} 
            else {
                $myArray_app[$memberA]["lid"][]=$lid;
                $member_name_array_app[]=$memberA;    
            }
            
        }
        foreach ($data->service->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {} 
            else{
                $myArray_srv[$memberA]["lid"][]=$lid;
                $member_name_array_srv[]=$memberA;
            } 
        }
        if (isset($data->{'profile-setting'})) {
            if (isset($data->{'profile-setting'}->{'group'})){
                $profile_type = "group";
                if (isset($data->{'profile-setting'}->{'group'}->member)){
                    $profile_group= (string) $data->{'profile-setting'}->{'group'}->member;
                    $myArray_profiles_groups[$profile_group]["lid"][]=$lid;
                    $member_name_array_profiles_groups[]=$profile_group;
                }

            }
            elseif(isset($data->{'profile-setting'}->{'profiles'})){
                $profile_type = "profiles";
                if (count($data->{'profile-setting'}->{'profiles'})>0){
                    foreach($data->{'profile-setting'}->{'profiles'} as $profiletype){
                        foreach($profiletype as $type=>$profile){
                            $profile = (string) $profile->member;
                            $type=(string) $type;
                            $myArray_profiles[$type][$profile]["lid"][]=$lid;
                            $member_name_array_profiles[$type][]=$profile;
                        }
                    }
                }

            }
        }
        
        $secrules[] = "('$target_negate','$icmp_unreachable','$rule_is_type','$target','$preorpost','$position','$lid','$negate_source','$negate_destination','$description','$name_ext','$name_int','$action','$schedule','$disabled','$log_start','$log_end','$log_forwarding','$new_vsys','$source','$dsri','$qos','$qos_value','$devicegroup','$profile_type', '$uuid', '$group_tag_id')";
        $lid++;
        $position++;
    }
    
    # Mapping Sources and Destination
    $calculate=calculate_members_and_table_from_memory("policy","address",$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray as $pos=>$lidArray){
                if ($pos=="src"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $secrulessrc[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
                elseif ($pos=="dst"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $secrulesdst[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Profiles
    $calculate=calculate_members_and_table_from_memory("policy","profiles_groups",$myArray_profiles_groups,$new_vsys,$source,$devicegroup,$member_name_array_profiles_groups, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $secrulesprofiles[] = "('$source','$new_vsys','$member_lid','$lid','profiles_groups','','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    $calculate=calculate_members_and_table_from_memory("policy","profiles",$myArray_profiles,$new_vsys,$source,$devicegroup,$member_name_array_profiles, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];

    if (count($member_name_array) == 0) {
        foreach ($myArray as $type=>$memberArray){
            foreach ($memberArray as $member => $valueArray) {
                $member_lid = $valueArray["member_lid"];
                $table_name = $valueArray["table_name"];
                foreach ($valueArray["lid"] as $lid){
                    if (($member_lid != "") AND ( $table_name != "")) {
                        $secrulesprofiles[] = "('$source','$new_vsys','$member_lid','$lid','profiles','$type','$devicegroup')";
                    }
                }
            }
        }

        unset($myArray);
    }

    # Mapping Services
    $calculate=calculate_members_and_table_from_memory("policy","service",$myArray_srv,$new_vsys,$source,$devicegroup,$member_name_array_srv, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $secrulessrv[] = "('$source','$new_vsys','$table_name','$member_lid','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }
    
    # Mapping Applications
    $calculate=calculate_members_and_table_from_memory("policy","application",$myArray_app,$new_vsys,$source,$devicegroup,$member_name_array_app, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $secrulesapp[] = "('$source','$new_vsys','$lid','$table_name','$member_lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }
    
    # Mapping Tags
    $calculate=calculate_members_and_table_from_memory("policy","tag",$myArray_tag,$new_vsys,$source,$devicegroup,$member_name_array_tag, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $secrulestag[] = "('$source','$member_lid','$table_name','$new_vsys','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }
    
    # Create Dummy for Schedules
//    $calculate=calc_members_and_table("policy","schedule",'',$new_vsys,$source,$devicegroup,$schedulesA, $version);
    calculate_members_and_table_from_memory("policy","schedule",'',$new_vsys,$source,$devicegroup,$schedulesA, $version,$objectsInMemory);

    # Create Dummy for Log FWD Profiles
//    $calculate=calc_members_and_table("policy","log_setting",'',$new_vsys,$source,$devicegroup,$log_forwardingsA, $version);
    calculate_members_and_table_from_memory("policy","log_setting",'',$new_vsys,$source,$devicegroup,$log_forwardingsA, $version,$objectsInMemory);

    # INSERT SECURITY RULES INTO DB
    if (count($secrules) > 0) {
        $projectdb->query("INSERT INTO security_rules (target_negate,icmp_unreachable,rule_type,target,preorpost,position,id,negate_source,negate_destination,description,name_ext,name,action,schedule,disabled,log_start,log_end,log_forwarding,vsys,source,dsri,qos,qos_value,devicegroup,profile_type, uuid, group_tag_id) VALUES " . implode(",", $secrules) . ";");
        unset($secrules);
        
        if (count($secrulesfrom) > 0) {
            //echo "INSERT INTO security_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesfrom) . ";\n";
            $projectdb->query("INSERT INTO security_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesfrom) . ";");
            unset($secrulesfrom);
        }
        if (count($secrulesto) > 0) {
            $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesto) . ";");
            unset($secrulesto);
        }
        if (count($secrulestag) > 0) {
            $projectdb->query("INSERT INTO security_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $secrulestag) . ";");
            unset($secrulestag);
        }
        if (count($secrulesusr) > 0) {
            $projectdb->query("INSERT INTO security_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesusr) . ";");
            unset($secrulesusr);
        }
        if (count($secrulescategories) > 0) {
            $projectdb->query("INSERT INTO security_rules_categories (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulescategories) . ";");
            unset($secrulescategories);
        }
        if (count($secruleship) > 0) {
            $projectdb->query("INSERT INTO security_rules_hip (source,member_lid,table_name,vsys,rule_lid,devicegroup,name) VALUES " . implode(",", $secruleship) . ";");
            unset($secruleship);
        }
        if (count($secrulessrc) > 0) {
            $projectdb->query("INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulessrc) . ";");
            unset($secrulessrc);
        }
        if (count($secrulesdst) > 0) {
            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulesdst) . ";");
            unset($secrulesdst);
        }
        if (count($secrulesapp) > 0) {
            $projectdb->query("INSERT INTO security_rules_app (source,vsys,rule_lid,table_name,member_lid,devicegroup) VALUES " . implode(",", $secrulesapp) . ";");
            unset($secrulesapp);
        }
        if (count($secrulessrv) > 0) {
            $projectdb->query("INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulessrv) . ";");
            unset($secrulessrv);
        }
        if (count($secrulesprofiles) > 0) {
            $projectdb->query("INSERT INTO security_rules_profiles (source,vsys,member_lid,rule_lid,table_name,type,devicegroup) VALUES " . implode(",", $secrulesprofiles) . ";");
            unset($secrulesprofiles);
        }
        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO security_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}

function calc_members_and_table($type,$element,$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version){
    global $projectdb;
//    global $project;

    $member_name_array1=array_unique($member_name_array);
    $member_name_array=$member_name_array1;
    unset($member_name_array1);

    require_once INC_ROOT.'/libs/common/lib-objects.php';

    $vsyses = getVsyses($projectdb, $new_vsys, $source);
    if ($type == "policy") {
        if ($element == "source_and_destination") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses

                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM regions WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "regions";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM default_regions WHERE BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "default_regions";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "address";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "address_groups_id";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }

                }

                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM external_list WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "external_list";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }
            }

            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM address;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $ip_version0 = ip_version($member_name);
                    if (($ip_version0 != "noip") OR (preg_match("/\//", $member_name))) {
                        $memberANetwork = explode("/", $member_name);
                        $ip_version = ip_version($memberANetwork[0]);
                        if (!isset($memberANetwork[1])) {
                            if ($ip_version == "v4") {
                                $memberAmask = "32";
                            } else {
                                $memberAmask = "128";
                            }
                        }
                        else {
                            $memberAmask = $memberANetwork[1];
                        }
                        if ($ip_version == "v4") {
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$new_vsys',1,'$devicegroup','$memberANetwork[0]','$memberAmask',1,0)";
                        }
                        elseif ($ip_version == "v6") {
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$new_vsys',1,'$devicegroup','$memberANetwork[0]','$memberAmask',0,1)";
                        }
                        $myArray[$member_name]["member_lid"] = $max;
                        $myArray[$member_name]["table_name"] = "address";
                        $max++;
                    }
                    else {
                        $split = explode("-", $member_name);
                        if ((ip_version($split[0]) != "noip") AND (ip_version($split[1]) != "noip")) {
                            $ip_version = ip_version($split[0]);
                            if ($ip_version == "v4") {
                                $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'ip-range','$member_name','',1,0)";
                            }
                            elseif ($ip_version == "v6") {
                                $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'ip-range','$member_name','',0,1)";
                            }
                            $myArray[$member_name]["member_lid"] = $max;
                            $myArray[$member_name]["table_name"] = "address";
                            $max++;
                        }
                        else {
//                            $ip_version = "v4";
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'MT_Panorama','','',1,0)";
                            $myArray[$member_name]["member_lid"] = $max;
                            $myArray[$member_name]["table_name"] = "address";
                            $max++;
                        }
                    }
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy,devicegroup,ipaddress,cidr,v4,v6) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "service") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses

                # Case is Shared Services
                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "services";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                # Case is Shared Services Groups
                if (count($member_name_array) > 0) {
                    //$getAddress = $projectdb->query("SELECT id,name FROM shared_services_groups_id WHERE source='$source' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    $getAddress = $projectdb->query("SELECT id,name FROM services_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "services_groups_id";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }
            }

            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM services;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','$member_name','dummy', 'MT_Panorama', '')";
                    $myArray[$member_name]["member_lid"] = $max;
                    $myArray[$member_name]["table_name"] = "services";
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO services (id,source,vsys,dummy,name_ext,name,vtype, devicegroup, protocol) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "application") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses

                # Case is Default Applications
                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM default_applications WHERE BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "default_applications";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                # Case is Shared Applications
                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM applications WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "applications";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                # Case is Shared Applications Groups
                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM applications_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "applications_groups_id";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }

                # Case is Shared Applications Filters
                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM applications_filters WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "applications_filters";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }
            }

            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM applications;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','dummy', 'MT_Panorama')";
                    $myArray[$member_name]["member_lid"] = $max;
                    $myArray[$member_name]["table_name"] = "applications";
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO applications (id,source,vsys,dummy,name,vtype, devicegroup) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "tag") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses

                # Case is Shared Tag
                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
                            $address_array[] = $data['name'];
                            $myArray[$data['name']]["member_lid"] = $data['id'];
                            $myArray[$data['name']]["table_name"] = "tag";
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }
            }

            # If its version 5 Create them into the shared Tag Table
            $addHost = array();
            if (count($member_name_array) != 0) {
                if ($version <= 5) {
                    # Objects needs to be added
                    $max = 1;
                    $getMaxID = $projectdb->query("SELECT max(id) as max FROM tag;");
                    if ($getMaxID->num_rows == 1) {
                        $max1 = $getMaxID->fetch_assoc();
                        $max = $max1['max'];
                        $max++;
                    }
                    foreach ($member_name_array as $key => $member_name) {
                        $addHost[] = "('$max','$source','$new_vsys',0,'$member_name','', '$devicegroup')";
                        $myArray[$member_name]["member_lid"] = $max;
                        //$myArray[$member_name]["table_name"] = "shared_tag";
                        $myArray[$member_name]["table_name"] = "tag";
                        $max++;
                    }
                }
                else {
                    # Objects needs to be added
                    $max = 1;
                    $getMaxID = $projectdb->query("SELECT max(id) as max FROM tag;");
                    if ($getMaxID->num_rows == 1) {
                        $max1 = $getMaxID->fetch_assoc();
                        $max = $max1['max'];
                        $max++;
                    }
                    foreach ($member_name_array as $key => $member_name) {
                        $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','dummy', 'MT_Panorama')";
                        $myArray[$member_name]["member_lid"] = $max;
                        //$myArray[$member_name]["table_name"] = "shared_tag";
                        $myArray[$member_name]["table_name"] = "tag";
                        $max++;
                    }
                }
                if (count($addHost) > 0) {
                    //$projectdb->query("INSERT INTO shared_tag (id,source,vsys,dummy,name,vtype, devicegroup) VALUES " . implode(",", $addHost) . ";");
                    $projectdb->query("INSERT INTO tag (id,source,vsys,dummy,name,vtype, devicegroup) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "schedule") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses

                # Case is Shared Schedule
                if (count($member_name_array) > 0) {
                    $getAddress = $projectdb->query("SELECT id,name FROM schedules WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
//                            $member_name = $data['name'];
//                            $member_lid = $data['id'];
//                            $table_name = "schedules";
                            $address_array[] = $data['name'];
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }
            }

            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM schedules;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$member_name', '$source', '$new_vsys', 'MT_Panorama', 'schedules', 'dummy', '1')";
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO schedules (id,name, source, vsys, devicegroup, type, vtype, dummy) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "log_setting") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses

                # Case is Shared Log Settings
                if (count($member_name_array) > 0) {
                    //$getAddress = $projectdb->query("SELECT id,name FROM shared_log_settings WHERE source='$source' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    $getAddress = $projectdb->query("SELECT id,name FROM log_settings WHERE source='$source' AND vsys='$vsys' AND BINARY name IN ('" . implode("','", $member_name_array) . "');");
                    if ($getAddress->num_rows > 0) {
                        $address_array = array();
                        while ($data = $getAddress->fetch_assoc()) {
//                            $member_name = $data['name'];
//                            $member_lid = $data['id'];
//                            $table_name = "log_settings";
                            $address_array[] = $data['name'];
                        }
                        $member_name_array = array_diff($member_name_array, $address_array);
                        unset($address_array);
                    }
                }
            }

            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM log_settings;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$member_name', '$source', '$new_vsys', 'MT_Panorama', 'profiles', 'dummy', '1')";
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO log_settings (id,name, source, vsys, devicegroup, type, vtype, dummy) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
    }

    return array($myArray,$member_name_array);
}

function calculate_member_and_table_from_memory($type,$element,$new_vsys,$source,$devicegroup, $nameToCheck, $version,&$objectsInMemory){
    global $projectdb;
    require_once INC_ROOT.'/libs/common/lib-objects.php';

    $vsyses = getVsyses($projectdb, $new_vsys, $source);
    if ($type == "policy") {
        if ($element == "address") {
            $member_name_array[]=$nameToCheck;
            while (count($vsyses) > 0 && count($member_name_array) > 0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                $address_array = array();

                if (isset($objectsInMemory['regions'][$vsys][$nameToCheck])) {
                    $address_array[] = $nameToCheck;
                    $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['regions'][$vsys][$nameToCheck];
                    $myArray[$nameToCheck]["table_name"] = "regions";
                    return array("member_lid"=>$objectsInMemory['regions'][$vsys][$nameToCheck],"table_name"=>"regions");
                }
                elseif (isset($objectsInMemory['default_regions'][$nameToCheck])) {
                    $address_array[] = $nameToCheck;
                    $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['default_regions'][$nameToCheck];
                    $myArray[$nameToCheck]["table_name"] = "default_regions";
                    return array("member_lid"=>$objectsInMemory['default_regions'][$nameToCheck],"table_name"=>"default_regions");
                }
                elseif (isset($objectsInMemory['address'][$vsys][$nameToCheck])) {
                    $address_array[] = $nameToCheck;
                    $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['address'][$vsys][$nameToCheck];
                    $myArray[$nameToCheck]["table_name"] = "address";
                    return array("member_lid"=>$objectsInMemory['address'][$vsys][$nameToCheck],"table_name"=>"address");
                }
                elseif (isset($objectsInMemory['address_groups_id'][$vsys][$nameToCheck])) {
                    $address_array[] = $nameToCheck;
                    $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['address_groups_id'][$vsys][$nameToCheck];
                    $myArray[$nameToCheck]["table_name"] = "address_groups_id";
                    return array("member_lid"=>$objectsInMemory['address_groups_id'][$vsys][$nameToCheck],"table_name"=>"address_groups_id");
                }
                elseif (isset($objectsInMemory['external_list'][$vsys][$nameToCheck])) {
                    $address_array[] = $nameToCheck;
                    $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['external_list'][$vsys][$nameToCheck];
                    $myArray[$nameToCheck]["table_name"] = "external_list";
                    return array("member_lid"=>$objectsInMemory['external_list'][$vsys][$nameToCheck],"table_name"=>"external_list");
                }

                $member_name_array = array_diff($member_name_array, $address_array);
            }

            # Objects doesnt exist and need to be added
            if (count($member_name_array) > 0) {
                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM address;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $ip_version0 = ip_version($member_name);
                    if (($ip_version0 != "noip") OR (preg_match("/\//", $member_name))) {
                        $memberANetwork = explode("/", $member_name);
                        $ip_version = ip_version($memberANetwork[0]);
                        if (!isset($memberANetwork[1])) {
                            if ($ip_version == "v4") {
                                $memberAmask = "32";
                            } else {
                                $memberAmask = "128";
                            }
                        } else {
                            $memberAmask = $memberANetwork[1];
                        }
                        if ($ip_version == "v4") {
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$new_vsys',1,'$devicegroup','$memberANetwork[0]','$memberAmask',1,0)";
                        } elseif ($ip_version == "v6") {
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$new_vsys',1,'$devicegroup','$memberANetwork[0]','$memberAmask',0,1)";
                        }
                        $myArray[$member_name]["member_lid"] = $max;
                        $myArray[$member_name]["table_name"] = "address";
                        //$max++;
                    }
                    else {
                        $split = explode("-", $member_name);
                        if ((ip_version($split[0]) != "noip") AND (ip_version($split[1]) != "noip")) {
                            $ip_version = ip_version($split[0]);
                            if ($ip_version == "v4") {
                                $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'ip-range','$member_name','',1,0)";
                            } elseif ($ip_version == "v6") {
                                $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'ip-range','$member_name','',0,1)";
                            }
                            $myArray[$member_name]["member_lid"] = $max;
                            $myArray[$member_name]["table_name"] = "address";
                            //$max++;
                        } else {
//                            $ip_version = "v4";
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'MT_Panorama','','',1,0)";
                            $myArray[$member_name]["member_lid"] = $max;
                            $myArray[$member_name]["table_name"] = "address";
                            //$max++;
                        }
                    }
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy,devicegroup,ipaddress,cidr,v4,v6) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                    $objectsInMemory['address'][$vsys][$nameToCheck]=$max;
                    return array("member_lid"=>$max,"table_name"=>"address");
                }
                $member_name_array = [];
            }

        }
        elseif ($element == "service") {
            $member_name_array[] = $nameToCheck;
            while (count($vsyses) > 0 && count($member_name_array) > 0) {
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        if (isset($objectsInMemory['services'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['services'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "services";
                            return array("member_lid"=>$objectsInMemory['services'][$vsys][$nameToCheck],"table_name"=>"services");
                        }
                        elseif (isset($objectsInMemory['services_groups_id'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['services_groups_id'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "services_groups_id";
                            return array("member_lid"=>$objectsInMemory['services_groups_id'][$vsys][$nameToCheck],"table_name"=>"services_groups_id");
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM services;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','$member_name','dummy', 'MT_Panorama', '')";
                    $myArray[$member_name]["member_lid"] = $max;
                    $myArray[$member_name]["table_name"] = "services";
                    $objectsInMemory['services'][$new_vsys][$nameToCheck]=$max;

                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO services (id,source,vsys,dummy,name_ext,name,vtype, devicegroup, protocol) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                    $objectsInMemory['services'][$vsys][$nameToCheck]=$max;
                    return array("member_lid"=>$max,"table_name"=>"services");
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "application") {
            $member_name_array[] = $nameToCheck;
            while (count($vsyses) > 0 && count($member_name_array) > 0) {
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        if (isset($objectsInMemory['default_applications'][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['default_applications'][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "default_applications";
                            return array("member_lid"=>$objectsInMemory['default_applications'][$nameToCheck],"table_name"=>"default_applications");
                        }
                        elseif (isset($objectsInMemory['applications'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['applications'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "applications";
                            return array("member_lid"=>$objectsInMemory['applications'][$vsys][$nameToCheck],"table_name"=>"applications");
                        }
                        elseif (isset($objectsInMemory['applications_groups_id'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['applications_groups_id'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "applications_groups_id";
                            return array("member_lid"=>$objectsInMemory['applications_groups_id'][$vsys][$nameToCheck],"table_name"=>"applications_groups_id");
                        }
                        elseif (isset($objectsInMemory['applications_filters'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['applications_filters'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "applications_filters";
                            return array("member_lid"=>$objectsInMemory['applications_filters'][$vsys][$nameToCheck],"table_name"=>"applications_filters");
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }
            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM applications;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','dummy', 'MT_Panorama')";
                    $myArray[$member_name]["member_lid"] = $max;
                    $myArray[$member_name]["table_name"] = "applications";
                    $objectsInMemory['applications'][$new_vsys][$nameToCheck]=$max;

                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO applications (id,source,vsys,dummy,name,vtype, devicegroup) VALUES " . implode(",", $addHost) . ";");
                    return array("member_lid"=>$objectsInMemory['applications'][$new_vsys][$nameToCheck],"table_name"=>"applications");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "tag") {
            $member_name_array[] = $nameToCheck;
            while (count($vsyses) > 0 && count($member_name_array) > 0) {
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck2){
                        if (isset($objectsInMemory['tag'][$vsys][$nameToCheck2])){
                            $address_array[] = $nameToCheck2;
                            $myArray[$nameToCheck2]["member_lid"] = $objectsInMemory['tag'][$vsys][$nameToCheck2];
                            $myArray[$nameToCheck2]["table_name"] = "tag";
                            return array("member_lid"=>$objectsInMemory['tag'][$vsys][$nameToCheck2],"table_name"=>"tag");
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM tag;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','dummy', 'MT_Panorama')";
                    $myArray[$member_name]["member_lid"] = $max;
                    $myArray[$member_name]["table_name"] = "tag";
                    $objectsInMemory['tag'][$new_vsys][$nameToCheck]=$max;

                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO tag (id, source, vsys, dummy, name, vtype, devicegroup) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                    $objectsInMemory['tag'][$vsys][$nameToCheck]=$max;
                    return array("member_lid"=>$max,"table_name"=>"tag");
                }
                $member_name_array = [];
            }
        }
    }
}

function calculate_members_and_table_from_memory($type,$element,$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,&$objectsInMemory){
    global $projectdb;

    // Callers often pass '' when they only need dummy-object creation side effects.
    // Writing $myArray[$name]["member_lid"] on a string fatals on PHP 7.4+.
    if (!is_array($myArray)) {
        $myArray = array();
    }
    if (!is_array($member_name_array)) {
        $member_name_array = array();
    }

    if ($element=="profiles"){
        $new_member_name_array=array();
        foreach($member_name_array as $typeObj=>$newmember){
            $new_member_name_array[$typeObj]=array_unique($newmember);
        }
        $member_name_array=$new_member_name_array;
    }
    else{
        $member_name_array1=array_unique($member_name_array);
        $member_name_array=$member_name_array1;
        unset($member_name_array1);
    }


    require_once INC_ROOT.'/libs/common/lib-objects.php';
    $new_vsys=(string) $new_vsys;
    $vsyses = getVsyses($projectdb, $new_vsys, $source);

    if ($type == "policy") {
        if ($element == "address") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        if (isset($objectsInMemory['regions'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['regions'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "regions";
                        }
                        elseif (isset($objectsInMemory['default_regions'][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['default_regions'][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "default_regions";
                        }
                        elseif (isset($objectsInMemory['address'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['address'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "address";
                        }
                        elseif (isset($objectsInMemory['address_groups_id'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['address_groups_id'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "address_groups_id";
                        }
                        elseif (isset($objectsInMemory['external_list'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['external_list'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "external_list";
                        }

                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }
            # Objects doesnt exist and need to be added
            if (count($member_name_array) > 0) {
                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM address;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    # Todo: Have to check because an ip 1.1.1.1/32 is created as object instead of vtype=dummy
                    $member_name=(string) $member_name;
                    $ip_version0 = ip_version($member_name);
                    if (($ip_version0 != "noip") OR (preg_match("/\//", $member_name))) {
                        $memberANetwork = explode("/", $member_name);
                        $ip_version = ip_version($memberANetwork[0]);
                        if (!isset($memberANetwork[1])) {
                            if ($ip_version == "v4") {
                                $memberAmask = "32";
                            } else {
                                $memberAmask = "128";
                            }
                        }
                        else {
                            $memberAmask = $memberANetwork[1];
                        }
                        if ($ip_version == "v4") {
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$new_vsys',1,'$devicegroup','$memberANetwork[0]','$memberAmask',1,0)";
                        }
                        elseif ($ip_version == "v6") {
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$new_vsys',1,'$devicegroup','$memberANetwork[0]','$memberAmask',0,1)";
                        }
                        $myArray[$member_name]["member_lid"] = $max;
                        $myArray[$member_name]["table_name"] = "address";
                        $objectsInMemory['address'][$new_vsys][$member_name]=$max;
                        $max++;
                    }
                    else {
                        $split = explode("-", $member_name);
                        if ((ip_version($split[0]) != "noip") AND (ip_version($split[1]) != "noip")) {
                            $ip_version = ip_version($split[0]);
                            if ($ip_version == "v4") {
                                $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'ip-range','$member_name','',1,0)";
                            }
                            elseif ($ip_version == "v6") {
                                $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'ip-range','$member_name','',0,1)";
                            }
                            $myArray[$member_name]["member_lid"] = $max;
                            $myArray[$member_name]["table_name"] = "address";
                            $objectsInMemory['address'][$new_vsys][$member_name]=$max;
                            $max++;
                        }
                        else {
//                            $ip_version = "v4";
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'MT_Panorama','','',1,0)";
                            $myArray[$member_name]["member_lid"] = $max;
                            $myArray[$member_name]["table_name"] = "address";
                            $objectsInMemory['address'][$new_vsys][$member_name]=$max;
                            $max++;
                        }
                    }
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy,devicegroup,ipaddress,cidr,v4,v6) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "service") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        if (isset($objectsInMemory['services'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['services'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "services";
                        }
                        elseif (isset($objectsInMemory['services_groups_id'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['services_groups_id'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "services_groups_id";
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }
            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM services;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','$member_name','dummy', 'MT_Panorama', '')";
                    $myArray[$member_name]["member_lid"] = $max;
                    $myArray[$member_name]["table_name"] = "services";
                    $objectsInMemory['services'][$new_vsys][$member_name]=$max;
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO services (id,source,vsys,dummy,name_ext,name,vtype, devicegroup, protocol) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "application") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                # Case is Default Applications
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        if (isset($objectsInMemory['default_applications'][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['default_applications'][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "default_applications";
                        }
                        elseif (isset($objectsInMemory['applications'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['applications'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "applications";
                        }
                        elseif (isset($objectsInMemory['applications_groups_id'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['applications_groups_id'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "applications_groups_id";
                        }
                        elseif (isset($objectsInMemory['applications_filters'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['applications_filters'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "applications_filters";
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }

            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                # Objects needs to be added
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM applications;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','dummy', 'MT_Panorama')";
                    $myArray[$member_name]["member_lid"] = $max;
                    $myArray[$member_name]["table_name"] = "applications";
                    $objectsInMemory['applications'][$new_vsys][$member_name]=$max;
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO applications (id,source,vsys,dummy,name,vtype, devicegroup) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "tag") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        if (isset($objectsInMemory['tag'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['tag'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "tag";
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }

            # If its version 5 Create them into the shared Tag Table
            $addHost = array();
            if (count($member_name_array) != 0) {
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM tag;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                if ($version <= 5) {
                    # Objects needs to be added
                    foreach ($member_name_array as $key => $member_name) {
                        $addHost[] = "('$max','$source','$new_vsys',0,'$member_name','', '$devicegroup')";
                        $myArray[$member_name]["member_lid"] = $max;
                        $myArray[$member_name]["table_name"] = "tag";
                        $objectsInMemory['tag'][$new_vsys][$member_name]=$max;
                        $max++;
                    }
                }
                else {
                    # Objects needs to be added
                    foreach ($member_name_array as $key => $member_name) {
                        $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','dummy', 'MT_Panorama')";
                        $myArray[$member_name]["member_lid"] = $max;
                        $myArray[$member_name]["table_name"] = "tag";
                        $objectsInMemory['tag'][$new_vsys][$member_name]=$max;
                        $max++;
                    }
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO tag (id,source,vsys,dummy,name,vtype, devicegroup) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "schedule") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        if (isset($objectsInMemory['schedules'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['schedules'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "schedules";
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }

            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM schedules;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $member_name=(string) $member_name;
                    $addHost[] = "('$max','$member_name', '$source', '$new_vsys', 'MT_Panorama', 'schedules', 'dummy', '1')";
                    $objectsInMemory['schedules'][$new_vsys][$member_name]=$max;
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO schedules (id,name, source, vsys, devicegroup, type, vtype, dummy) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "log_setting") {
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                $vsys=(string) $vsys;
                if (count($member_name_array) > 0) {
                    //$address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        $nameToCheck= (string) $nameToCheck;
                        if ($nameToCheck!=""){
                            if (isset($objectsInMemory['log_settings'][$vsys][$nameToCheck])){
                                //$address_array[] = $nameToCheck;
                                if (($key = array_search($nameToCheck, $member_name_array)) !== false) {
                                    unset($member_name_array[$key]);
                                }
                                $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['log_settings'][$vsys][$nameToCheck];
                                $myArray[$nameToCheck]["table_name"] = "log_settings";
                            }

                        }

                    }
                    //$member_name_array = array_diff($member_name_array, $address_array);
                }
            }
            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM log_settings;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $member_name= (string) $member_name;
                    $addHost[] = "('$max','$member_name', '$source', '$new_vsys', 'MT_Panorama', 'profiles', 'dummy', '1')";
                    $objectsInMemory['log_settings'][$new_vsys][$member_name]=$max;
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO log_settings (id,name, source, vsys, devicegroup, type, vtype, dummy) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "profiles_groups"){
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                $vsys=(string) $vsys;
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        $nameToCheck= (string) $nameToCheck;
                        if (isset($objectsInMemory['profiles_groups'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['profiles_groups'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "profiles_groups";
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }
            # Objects doesnt exist and need to be added
            if (count($member_name_array) != 0) {
                $max = 1;
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM profiles_groups;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    $member_name= (string) $member_name;
                    $addHost[] = "('$max','$source','$new_vsys',1,'$member_name','$member_name','profiles_groups','dummy', 'MT_Panorama')";
                    $objectsInMemory['profiles_groups'][$new_vsys][$member_name]=$max;
                    $myArray[$member_name]["member_lid"] = $max;
                    $myArray[$member_name]["table_name"] = "profiles_groups";
                    $max++;
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO profiles_groups (id,source, vsys, dummy, name, name_ext, type, vtype, devicegroup) VALUES ". implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }
        }
        elseif ($element == "profiles"){
            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                $vsys=(string) $vsys;

                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $type=>$member_name_array1){
                        foreach($member_name_array1 as $nameToCheck){
                            $nameToCheck= (string) $nameToCheck;
                            if (isset($objectsInMemory['profiles'][$type][$vsys][$nameToCheck])){
                                $myArray[$type][$nameToCheck]["member_lid"] = $objectsInMemory['profiles'][$type][$vsys][$nameToCheck];
                                $myArray[$type][$nameToCheck]["table_name"] = "profiles";
                            }
                        }
                    }
                }
            }

            $max = 1;
            $getMaxID = $projectdb->query("SELECT max(id) as max FROM profiles;");
            if ($getMaxID->num_rows == 1) {
                $max1 = $getMaxID->fetch_assoc();
                $max = $max1['max'];
                $max++;
            }
            $addHost = array();
            foreach($myArray as $type=>$memberArray){
                foreach($memberArray as $nameToCheck=>$propertyArray){
                    if (!isset($propertyArray['member_lid'])){
                        $addHost[] = "('$max''$source','$new_vsys',1,'$nameToCheck','$nameToCheck','$type','dummy', 'MT_Panorama')";
                        $objectsInMemory['profiles'][$type][$new_vsys][$nameToCheck]=$max;
                        $myArray[$type][$nameToCheck]["member_lid"] = $objectsInMemory['profiles'][$type][$new_vsys][$nameToCheck];
                        $myArray[$type][$nameToCheck]["table_name"] = "profiles";
                        $max++;
                    }
                }
            }

            if (count($addHost) > 0) {
                $projectdb->query("INSERT INTO profiles (id,source, vsys, dummy, name, name_ext, type, vtype, devicegroup) VALUES ". implode(",", $addHost) . ";");
                unset($addHost);
            }
            $member_name_array = [];
        }
    }
    return array($myArray,$member_name_array);
}

function calculate_members_in_addressTable_from_memory($myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,&$objectsInMemory){
    global $projectdb;

    $member_name_array1=array_unique($member_name_array);
    $member_name_array=$member_name_array1;
    unset($member_name_array1);


    require_once INC_ROOT.'/libs/common/lib-objects.php';
    $new_vsys=(string) $new_vsys;
    $vsyses = getVsyses($projectdb, $new_vsys, $source);

            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                if (count($member_name_array) > 0) {
                    $address_array = array();
                    foreach($member_name_array as $nameToCheck){
                        if(isset($objectsInMemory['address'][$vsys][$nameToCheck])){
                            $address_array[] = $nameToCheck;
                            $myArray[$nameToCheck]["member_lid"] = $objectsInMemory['address'][$vsys][$nameToCheck];
                            $myArray[$nameToCheck]["table_name"] = "address";
                        }
                    }
                    $member_name_array = array_diff($member_name_array, $address_array);
                }
            }
            # Objects doesnt exist and need to be added
            if (count($member_name_array) > 0) {
                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM address;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                $addHost = array();
                foreach ($member_name_array as $key => $member_name) {
                    # Todo: Have to check because an ip 1.1.1.1/32 is created as object instead of vtype=dummy
                    $member_name=(string) $member_name;
                    $ip_version0 = ip_version($member_name);
                    if (($ip_version0 != "noip") OR (preg_match("/\//", $member_name))) {
                        $memberANetwork = explode("/", $member_name);
                        $ip_version = ip_version($memberANetwork[0]);
                        if (!isset($memberANetwork[1])) {
                            if ($ip_version == "v4") {
                                $memberAmask = "32";
                            } else {
                                $memberAmask = "128";
                            }
                        }
                        else {
                            $memberAmask = $memberANetwork[1];
                        }
                        if ($ip_version == "v4") {
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$new_vsys',1,'$devicegroup','$memberANetwork[0]','$memberAmask',1,0)";
                        }
                        elseif ($ip_version == "v6") {
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$new_vsys',1,'$devicegroup','$memberANetwork[0]','$memberAmask',0,1)";
                        }
                        $myArray[$member_name]["member_lid"] = $max;
                        $myArray[$member_name]["table_name"] = "address";
                        $objectsInMemory['address'][$new_vsys][$member_name]=$max;
                        $max++;
                    }
                    else {
                        $split = explode("-", $member_name);
                        if ((ip_version($split[0]) != "noip") AND (ip_version($split[1]) != "noip")) {
                            $ip_version = ip_version($split[0]);
                            if ($ip_version == "v4") {
                                $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'ip-range','$member_name','',1,0)";
                            }
                            elseif ($ip_version == "v6") {
                                $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'ip-range','$member_name','',0,1)";
                            }
                            $myArray[$member_name]["member_lid"] = $max;
                            $myArray[$member_name]["table_name"] = "address";
                            $objectsInMemory['address'][$new_vsys][$member_name]=$max;
                            $max++;
                        }
                        else {
//                            $ip_version = "v4";
                            $addHost[] = "('$max','ip-netmask','$member_name','$member_name','1','$source','0','dummy','$new_vsys',1,'MT_Panorama','','',1,0)";
                            $myArray[$member_name]["member_lid"] = $max;
                            $myArray[$member_name]["table_name"] = "address";
                            $objectsInMemory['address'][$new_vsys][$member_name]=$max;
                            $max++;
                        }
                    }
                }
                if (count($addHost) > 0) {
                    $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy,devicegroup,ipaddress,cidr,v4,v6) VALUES " . implode(",", $addHost) . ";");
                    unset($addHost);
                }
                $member_name_array = [];
            }

    return array($myArray,$member_name_array);
}

function getMemberIdFromAddressInMemory($projectdb, $source, $allVSYS, $addressName, &$objectsInMemory){
    require_once INC_ROOT.'/libs/common/MemberObject.php';

    //print_r($objectsInMemory);
    foreach ($allVSYS as $vsys){
        if(isset($objectsInMemory[$vsys]['address'][$addressName])){
            return $objectsInMemory[$vsys]['address'][$addressName];
        }
    }

    //Didn't find the object
    //echo "We could not find the object $addressName\n";
    return null;
    return new MemberObject('0', 'address', '', '0');

    //die();

}

function GroupMember2IdPanos(STRING $type,$source,&$objectsInMemory){
    global $projectdb;
    $myArray=array();
    $member_name_array=array();
    $addMap=array();
    switch($type){
        case "address":
            #Group Address Groups with Members
            $getV=$projectdb->query("SELECT vsys FROM address_groups_id WHERE source='$source' AND type='static' GROUP BY vsys");
            if ($getV->num_rows>0){
                $addMap=array();
                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM address;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }
                while($getVData=$getV->fetch_assoc()){
                    $vsysO=$getVData['vsys'];
                    $getG=$projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsysO' AND type='static';");
                    if ($getG->num_rows>0){
                        $lids=array();
                        while($getGData=$getG->fetch_assoc()){
                            $lids[]=$getGData['id'];
                        }
                        $vsyses = getVsyses($projectdb, $vsysO, $source);
                        $getA=$projectdb->query("SELECT * from address_groups WHERE lid IN (".implode(",",$lids).");");
                        if ($getA->num_rows>0){
                            $myArray=array();
                            while($getAData=$getA->fetch_assoc()){
                                $memberName=$getAData['member'];
                                $lid=$getAData['lid'];
                                $myArray[$memberName][]=$lid;
                                $member_name_array[]=$memberName;
                            }

                            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                                if (count($member_name_array) > 0) {
                                    $address_array = array();
                                    foreach($member_name_array as $nameToCheck){
                                        if (isset($objectsInMemory['address'][$vsys][$nameToCheck])){
                                            $address_array[] = $nameToCheck;
                                            foreach($myArray[$nameToCheck] as $glid){
                                                $addMap[]="('$glid','".$objectsInMemory['address'][$vsys][$nameToCheck]."','address')";
                                            }
                                        }
                                        elseif (isset($objectsInMemory['address_groups_id'][$vsys][$nameToCheck])){
                                            $address_array[] = $nameToCheck;
                                            foreach($myArray[$nameToCheck] as $glid){
                                                $addMap[]="('$glid','".$objectsInMemory['address_groups_id'][$vsys][$nameToCheck]."','address_groups_id')";
                                            }
                                        }
                                    }
                                    $member_name_array = array_diff($member_name_array, $address_array);
                                }
                            }
                            if (count($member_name_array)==0){
                                $projectdb->query("DELETE FROM address_groups WHERE lid IN (".implode(",",$lids).");");
                                $member_name_array=array();
                            }
                            else{
                                print "ERROR SOME ADDRESS OBJECTS HAS NOT BEEN CAPTURED".PHP_EOL;
                                print_r($member_name_array );
                                # Objects doesnt exist and need to be added
                                $addHost = array();
                                foreach ($member_name_array as $key => $member_name) {
                                    if ($member_name != ""){
                                        $member_name=(string) $member_name;
                                        $ip_version0 = ip_version($member_name);
                                        if (($ip_version0 != "noip") OR (preg_match("/\//", $member_name))) {
                                            $memberANetwork = explode("/", $member_name);
                                            $ip_version = ip_version($memberANetwork[0]);
                                            if (!isset($memberANetwork[1])) {
                                                if ($ip_version == "v4") {
                                                    $memberAmask = "32";
                                                } else {
                                                    $memberAmask = "128";
                                                }
                                            }
                                            else {
                                                $memberAmask = $memberANetwork[1];
                                            }
                                            if ($ip_version == "v4") {
                                                $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$vsysO',1,'MT_Panorama','$memberANetwork[0]','$memberAmask',1,0)";
                                            }
                                            elseif ($ip_version == "v6") {
                                                $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$vsysO',1,'MT_Panorama','$memberANetwork[0]','$memberAmask',0,1)";
                                            }
                                            foreach($myArray[$member_name] as $glid){
                                                $addMap[]="('$glid','$max','address')";
                                            }
                                            $objectsInMemory['address'][$vsysO][$member_name]=$max;
                                            $max++;
                                        }
                                        else {
                                            $split = explode("-", $member_name);
                                            if ((ip_version($split[0]) != "noip") AND (ip_version($split[1]) != "noip")) {
                                                $ip_version = ip_version($split[0]);
                                                if ($ip_version == "v4") {
                                                    $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$vsysO',1,'MT_Panorama','$member_name','',1,0)";
                                                }
                                                elseif ($ip_version == "v6") {
                                                    $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','dummy','$vsysO',1,'MT_Panorama','$member_name','',0,1)";
                                                }
                                                foreach($myArray[$member_name] as $glid){
                                                    $addMap[]="('$glid','$max','address')";
                                                }
                                                $objectsInMemory['address'][$vsysO][$member_name]=$max;
                                                $max++;
                                            }
                                            else {
//                                          $ip_version = "v4";
                                                $addHost[] = "('$max','ip-netmask','$member_name','$member_name','1','$source','0','dummy','$vsysO',1,'MT_Panorama','','',1,0)";
                                                foreach($myArray[$member_name] as $glid){
                                                    $addMap[]="('$glid','$max','address')";
                                                }
                                                $objectsInMemory['address'][$vsysO][$member_name]=$max;
                                                $max++;
                                            }
                                        }
                                    }
                                }
                                $projectdb->query("DELETE FROM address_groups WHERE lid IN (".implode(",",$lids).");");
                                if (count($addHost) > 0) {
                                    $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy,devicegroup,ipaddress,cidr,v4,v6) VALUES " . implode(",", $addHost) . ";");
                                    unset($addHost);
                                }
                                $member_name_array = "";

                            }
                        }

                    }
                }
            }

            # Let's do inserts by vsys/dg
            if (count($addMap) > 0) {
                $unique=array_unique($addMap);
                $projectdb->query("INSERT INTO address_groups (lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                unset($addMap);
            }

            break;
        case "service":
            #Group Services Groups with Members
            $getV=$projectdb->query("SELECT vsys FROM services_groups_id WHERE source='$source' GROUP BY vsys");
            if ($getV->num_rows>0){
                $addMap=array();

                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM services;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }

                while($getVData=$getV->fetch_assoc()){
                    $vsysO=$getVData['vsys'];
                    $getG=$projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsysO';");
                    if ($getG->num_rows>0){
                        $lids=array();
                        while($getGData=$getG->fetch_assoc()){
                            $lids[]=$getGData['id'];
                        }
                        $vsyses = getVsyses($projectdb, $vsysO, $source);
                        $getA=$projectdb->query("SELECT * from services_groups WHERE lid IN (".implode(",",$lids).");");
                        if ($getA->num_rows>0){
                            $myArray=array();
                            while($getAData=$getA->fetch_assoc()){
                                $memberName=$getAData['member'];
                                $lid=$getAData['lid'];
                                $myArray[$memberName][]=$lid;
                                $member_name_array[]=$memberName;
                            }

                            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                                if (count($member_name_array) > 0) {
                                    $address_array = array();
                                    foreach($member_name_array as $nameToCheck){
                                        if (isset($objectsInMemory['services'][$vsys][$nameToCheck])){
                                            $address_array[] = $nameToCheck;
                                            foreach($myArray[$nameToCheck] as $glid){
                                                $addMap[]="('$glid','".$objectsInMemory['services'][$vsys][$nameToCheck]."','services')";
                                            }
                                        }
                                        elseif (isset($objectsInMemory['services_groups_id'][$vsys][$nameToCheck])){
                                            $address_array[] = $nameToCheck;
                                            foreach($myArray[$nameToCheck] as $glid){
                                                $addMap[]="('$glid','".$objectsInMemory['services_groups_id'][$vsys][$nameToCheck]."','services_groups_id')";
                                            }
                                        }
                                    }
                                    $member_name_array = array_diff($member_name_array, $address_array);
                                }
                            }
                            if (count($member_name_array)==0){
                                $projectdb->query("DELETE FROM services_groups WHERE lid IN (".implode(",",$lids).");");
                                $member_name_array=array();
                            }
                            else{
                                print "ERROR SOME SERVICES OBJECTS HAS NOT BEEN CAPTURED".PHP_EOL;
                                # Objects doesnt exist and need to be added
                                $addHost = array();
                                foreach ($member_name_array as $key => $member_name) {
                                    $member_name=(string) $member_name;
                                    if ($member_name!=''){
                                        $addHost[] = "('$max','$source','$vsysO',1,'$member_name','$member_name','dummy', 'MT_Panorama', '')";
                                        foreach($myArray[$member_name] as $glid){
                                            $addMap[]="('$glid','$max','services')";
                                        }
                                        $max++;
                                    }

                                }
                                $projectdb->query("DELETE FROM services_groups WHERE lid IN (".implode(",",$lids).");");
                                if (count($addHost) > 0) {
                                    $projectdb->query("INSERT INTO services (id,source,vsys,dummy,name_ext,name,vtype, devicegroup, protocol) VALUES " . implode(",", $addHost) . ";");
                                    unset($addHost);
                                }
                                $member_name_array = array();

                            }
                        }

                    }
                }
            }

            # Let's do inserts by vsys/dg
            if (count($addMap) > 0) {
                $unique=array_unique($addMap);
                $projectdb->query("INSERT INTO services_groups (lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                unset($addMap);
            }

            break;
        case "application":
            #Group Services Groups with Members
            $getV=$projectdb->query("SELECT vsys FROM applications_groups_id WHERE source='$source' GROUP BY vsys");
            if ($getV->num_rows>0){
                $addMap=array();

                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM applications;");
                if ($getMaxID->num_rows == 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }

                while($getVData=$getV->fetch_assoc()){
                    $vsysO=$getVData['vsys'];
                    $getG=$projectdb->query("SELECT id FROM applications_groups_id WHERE source='$source' AND vsys='$vsysO';");
                    if ($getG->num_rows>0){
                        $lids=array();
                        while($getGData=$getG->fetch_assoc()){
                            $lids[]=$getGData['id'];
                        }
                        $vsyses = getVsyses($projectdb, $vsysO, $source);
                        $getA=$projectdb->query("SELECT * from applications_groups WHERE lid IN (".implode(",",$lids).");");
                        if ($getA->num_rows>0){
                            $myArray=array();
                            while($getAData=$getA->fetch_assoc()){
                                $memberName=$getAData['member'];
                                $lid=$getAData['lid'];
                                $myArray[$memberName][]=$lid;
                                $member_name_array[]=$memberName;
                            }
                            while(count($vsyses)>0 && count($member_name_array)>0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses
                                if (count($member_name_array) > 0) {
                                    $address_array = array();
                                    foreach($member_name_array as $nameToCheck){

                                        if ($nameToCheck!=""){
                                            if (isset($objectsInMemory['default_applications'][$nameToCheck])){
                                                $address_array[] = $nameToCheck;
                                                foreach($myArray[$nameToCheck] as $glid){
                                                    $addMap[]="('$glid','".$objectsInMemory['default_applications'][$nameToCheck]."','default_applications')";
                                                }
                                            }
                                            elseif (isset($objectsInMemory['applications'][$vsys][$nameToCheck])){
                                                $address_array[] = $nameToCheck;
                                                foreach($myArray[$nameToCheck] as $glid){
                                                    $addMap[]="('$glid','".$objectsInMemory['applications'][$vsys][$nameToCheck]."','applications')";
                                                }
                                            }
                                            elseif (isset($objectsInMemory['applications_groups_id'][$vsys][$nameToCheck])){
                                                $address_array[] = $nameToCheck;
                                                foreach($myArray[$nameToCheck] as $glid){
                                                    $addMap[]="('$glid','".$objectsInMemory['applications_groups_id'][$vsys][$nameToCheck]."','applications_groups_id')";
                                                }
                                            }
                                            elseif (isset($objectsInMemory['applications_filters'][$vsys][$nameToCheck])){
                                                $address_array[] = $nameToCheck;
                                                foreach($myArray[$nameToCheck] as $glid){
                                                    $addMap[]="('$glid','".$objectsInMemory['applications_filters'][$vsys][$nameToCheck]."','applications_filters')";
                                                }
                                            }
                                        }


                                    }
                                    $member_name_array = array_diff($member_name_array, $address_array);

                                }
                            }
                            if (count($member_name_array)==0){
                                $projectdb->query("DELETE FROM applications_groups WHERE lid IN (".implode(",",$lids).");");
                                $member_name_array=array();
                            }
                            else{
                                print "ERROR SOME APPLICATIONS OBJECTS HAS NOT BEEN CAPTURED".PHP_EOL;
                                # Objects doesnt exist and need to be added
                                $addHost = array();
                                foreach ($member_name_array as $key => $member_name) {
                                    $member_name=(string) $member_name;
                                    if ($member_name!=''){
                                        $addHost[] = "('$max','$source','$vsysO',1,'$member_name','dummy', 'MT_Panorama')";
                                        foreach($myArray[$member_name] as $glid){
                                            $addMap[]="('$glid','$max','applications')";
                                        }
                                        $max++;
                                    }

                                }
                                $projectdb->query("DELETE FROM applications_groups WHERE lid IN (".implode(",",$lids).");");
                                if (count($addHost) > 0) {
                                    $projectdb->query("INSERT INTO applications (id,source,vsys,dummy,name,vtype, devicegroup) VALUES " . implode(",", $addHost) . ";");
                                    unset($addHost);
                                }
                                $member_name_array = array();

                            }
                        }

                    }
                }
            }

            # Let's do inserts by vsys/dg
            if (count($addMap) > 0) {
                $unique=array_unique($addMap);
                $projectdb->query("INSERT INTO applications_groups (lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                unset($addMap);
            }

            break;
    }
}

function xml_add_network_monitor_profile($projectdb,$profiles,$source,$template){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $monitor_action = "wait-recover";
        $monitor_interval = "3";
        $monitor_threshold = "5";
        $theProfileName = $profilesArray->attributes()->name;

        if (isset($profilesArray->action)) {
            $monitor_action = $profilesArray->action;
        }
        if (isset($profilesArray->interval)) {
            $monitor_interval = $profilesArray->interval;
        }
        if (isset($profilesArray->threshold)) {
            $monitor_threshold = $profilesArray->threshold;
        }

        $sql[] = "('$source','','$template','$theProfileName','$monitor_action','$monitor_interval','$monitor_threshold')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO monitor_profile (source,vsys,template,name,m_action,interva,threshold) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_network_zone_protection($projectdb,$profiles,$source,$vsys='',$template){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $theProfileName = $profilesArray->attributes()->name;
        $xxml = "";
        $xxml = addslashes($profilesArray->asXML());

        $sql[] = "('$source','$vsys','$template','$theProfileName','$xxml')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO zone_protection_profile (source,vsys,template,name,xml) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_network_qos_profile($projectdb,$profiles,$source,$vsys,$template){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $theProfileName = $profilesArray->attributes()->name;
        $xxml = "";
        $xxml = addslashes($profilesArray->asXML());

        $sql[] = "('$source','','$template','$theProfileName','$xxml')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO qos_profile (source,vsys,template,name,xml) VALUES ".implode(",", $sql).";");
    }
}

function xml_add_network_qos_interface($projectdb,$profiles,$source,$vsys,$template){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $theProfileName = $profilesArray->attributes()->name;
        $xxml = "";
        $xxml = addslashes($profilesArray->asXML());

        $sql[] = "('$source','$vsys','$template','$theProfileName','$xxml')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO qos_interface (source,vsys,template,name,xml) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_network_dhcp($projectdb,$profiles,$source,$vsys,$template){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $theProfileName = $profilesArray->attributes()->name;
        $xxml = "";
        $dhcp_type = "";
        if (isset($profilesArray->relay)) {
            $dhcp_type = "relay";
        } else {
            $dhcp_type = "server";
        }
        $xxml = addslashes($profilesArray->asXML());

        $sql[] = "('$source','$vsys','$template','$theProfileName','$xxml','$dhcp_type')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO dhcp (source,vsys,template,name,xml,dhcp_type) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_network_virtual_router($projectdb,$profiles,$source,$vsys,$template,$version){
    $vrs = array();

    //foreach ($value->devices->entry->network->{'virtual-router'}->entry as $mkey => $mvalue) {
    foreach ($profiles as $mkey => $mvalue) {
        $vrName = $mvalue->attributes()->name;
        //echo "VR name: " .$vrName. "\n";
        $protocol = addslashes($mvalue->protocol->asXML());

        $rip_interfaces = "";

        if (isset($mvalue->protocol->rip->interface)) {
            $interfaces_rip_names = array();
            foreach ($mvalue->protocol->rip->interface->entry as $rips_interfaces) {
                $interfaces_rip_names[] = $rips_interfaces->attributes()->name;
            }
            $rip_interfaces = implode(",", $interfaces_rip_names);
            unset($interfaces_rip_names);
        }

        $ecmp = addslashes($mvalue->ecmp->asXML());
        if (isset($mvalue->{'admin-dists'})) {
            $admin_dist_static = $mvalue->{'admin-dists'}->{'static'};
            $admin_dist_ospf_int = $mvalue->{'admin-dists'}->{'ospf-int'};
            $admin_dist_ospf_ext = $mvalue->{'admin-dists'}->{'ospf-ext'};
            $admin_dist_ibgp = $mvalue->{'admin-dists'}->{'ibgp'};
            $admin_dist_ebgp = $mvalue->{'admin-dists'}->{'ebgp'};
            $admin_dist_rip = $mvalue->{'admin-dists'}->{'rip'};

            #Added on 6.X
            if ($version > 5) {
                $admin_dist_static_ipv6 = $mvalue->{'admin-dists'}->{'static-ipv6'};
                $admin_dist_ospfv3_int = $mvalue->{'admin-dists'}->{'ospfv3-int'};
                $admin_dist_ospfv3_ext = $mvalue->{'admin-dists'}->{'ospfv3-ext'};
            }
        }
        else {
            $admin_dist_static = "";
            $admin_dist_ospf_int = "";
            $admin_dist_ospf_ext = "";
            $admin_dist_ibgp = "";
            $admin_dist_ebgp = "";
            $admin_dist_rip = "";

            if ($version > 5) {
                $admin_dist_static_ipv6 = "";
                $admin_dist_ospfv3_int = "";
                $admin_dist_ospfv3_ext = "";
            }
        }
        if (isset($mvalue->interface)) {
            $interfaces = array();
            foreach ($mvalue->interface->member as $mmkey => $mmvalue) {
                $interfaces[] = $mmvalue;
            }
            $interface = implode(",", $interfaces);
            unset($interfaces);
        } else {
            $interface = "";
        }
        if (isset($mvalue->multicast)) {
            $multicast = addslashes($mvalue->multicast->asXML());
        } else {
            $multicast = "";
        }

        $projectdb->query("INSERT INTO virtual_routers (ecmp,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext,protocol,multicast,source,template,name,interfaces,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,rip_interfaces) 
                    VALUES ('$ecmp','$admin_dist_static_ipv6','$admin_dist_ospfv3_int','$admin_dist_ospfv3_ext','$protocol','$multicast','$source','$template','$vrName','$interface','$admin_dist_static','$admin_dist_ospf_int','$admin_dist_ospf_ext','$admin_dist_ibgp','$admin_dist_ebgp','$admin_dist_rip', '$rip_interfaces');");

        $vr_id = $projectdb->insert_id;

        if ($interface != "") {
            $all = explode(",", $interface);
            foreach ($all as $k => $v) {
                $projectdb->query("UPDATE interfaces SET vr_id='$vr_id' WHERE unitname ='$v' AND source='$source' AND template='$template';");
            }
        }

        if (isset($mvalue->{'routing-table'})) {
            $getMax=$projectdb->query("SELECT max(id) as max FROM routes_static;");
            if ($getMax->num_rows==1){
                $getMaxData=$getMax->fetch_assoc();
                $routeID=intval($getMaxData['max'])+1;
            }
            else{
                $routeID=1;
            }
            #IP Static Route
            if (isset($mvalue->{'routing-table'}->ip->{'static-route'})) {
                $routes = array();
                $monitorDestination = array();
                foreach ($mvalue->{'routing-table'}->ip->{'static-route'}->entry as $skey => $svalue) {
                    $staticName = $svalue->attributes()->name;
                    $destination = $svalue->destination;
                    $net = explode("/", $destination);
                    $ip_version = ip_version($net[0]);
                    $admin_dist="";
                    $metric="";
                    $nexthop_value_member_lid = "";

                    if (isset($svalue->option->{'no-install'})) {
                        $option_no_install = 1;
                    } else {
                        $option_no_install = 0;
                    }
                    if (isset($svalue->metric)) {
                        $metric = $svalue->metric;
                    }
                    if (isset($svalue->{'admin-dist'})) {
                        $admin_dist = $svalue->{'admin-dist'};
                    }
                    if (isset($svalue->interface)) {
                        $tointerface = $svalue->interface;
                    } else {
                        $tointerface = "";
                    }

                    if (isset($svalue->nexthop->{'ip-address'})) {
                        $nexthop = "ip-address";
                        $nexthop_value = $svalue->nexthop->{'ip-address'};

                        // The address objects are not yet loaded in the BBDD.

                        //$calc_member = getMemberId($projectdb, $source, $allVSYS, $nexthop_value);
                        //if ($calc_member != null){
                        //    $nexthop_value_member_lid = $calc_member->name;
                        //}

                    }
                    elseif (isset($svalue->nexthop->discard)) {
                        $nexthop = "discard";
                        $nexthop_value = "";
                    }
                    elseif (isset($svalue->nexthop->{'next-vr'})) {
                        $nexthop = "next-vr";
                        $nexthop_value = $svalue->nexthop->{'next-vr'};
                    }
                    elseif (isset($svalue->nexthop->fqdn)) {
                        $nexthop = "fqdn";
                        $nexthop_value = $svalue->nexthop->fqdn;

                        // The address objects are not yet loaded in the BBDD.

                        //$calc_member = getMemberId($projectdb, $source, $allVSYS, $nexthop_value);
                        //if ($calc_member != null){
                        //    $nexthop_value_member_lid = $calc_member->name;
                        //}
                    }
                    else {
                        $nexthop = "None";
                        $nexthop_value = "";
                    }
                    # Panos 8 and higher
                    $pm_enable = "no";
                    $pm_failure_condition = "any";
                    $pm_hold_time = 2;
                    $bfd_profile = "None";
                    $route_table = "unicast";
                    //$monitorDestination = array();
                    if (isset($svalue->{'path-monitor'})){
                        if (isset($svalue->{'path-monitor'}->enable)){
                            $pm_enable = $svalue->{'path-monitor'}->enable;
                        }
                        if (isset($svalue->{'path-monitor'}->{'failure-condition'})){
                            $pm_failure_condition = $svalue->{'path-monitor'}->{'failure-condition'};
                        }
                        if (isset($svalue->{'path-monitor'}->{'hold-time'})){
                            $pm_hold_time = $svalue->{'path-monitor'}->{'hold-time'};
                        }
                        if (isset($svalue->{'path-monitor'}->{'monitor-destinations'})){
                            foreach($svalue->{'path-monitor'}->{'monitor-destinations'}->entry as $kk => $MD){
                                $MDname = $MD->attributes()->name;
                                $MDenable = $MD->enable;
                                $MDsrc = $MD->source;
                                $MDdst = $MD->destination;
                                $MDdstID = "0";

                                // The address objects are not yet loaded in the BBDD.

                                //$getID = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$MDdst' LIMIT 1");
                                //if ($getID->num_rows == 1){
                                //    $getIDData = $getID->fetch_assoc();
                                //    $MDdstID = $getIDData['id'];
                                //}
                                //else{
                                //    $MDdstID = "0";
                                //}
                                $MDinterval = $MD->interval;
                                $MDcount = $MD->count;
                                $monitorDestination[] = "('$routeID','$MDname','$MDenable','$MDsrc','$MDdst','$MDinterval','$MDcount','$MDdstID')";
                            }
                        }
                    }
                    if (isset($svalue->bfd)){
                        if (isset($svalue->bfd->profile)){
                            $bfd_profile=$svalue->bfd->profile;
                        }
                    }
                    if (isset($svalue->{'route-table'})){
                        if (isset($svalue->{'route-table'}->unicast)){$route_table = "unicast";}
                        elseif(isset($svalue->{'route-table'}->multicast)){$route_table = "multicast";}
                        elseif(isset($svalue->{'route-table'}->both)){$route_table = "both";}
                        elseif(isset($svalue->{'route-table'}->{'no-install'})){$route_table = "no-install";}
                        else{$route_table = "unicast";}
                    }

                    $routes[] = "('$routeID','$staticName','$source','$template','$vr_id','$ip_version','$destination','$tointerface','$nexthop','$nexthop_value','$nexthop_value_member_lid','$metric','$admin_dist','$option_no_install','$pm_enable','$pm_failure_condition','$pm_hold_time','$bfd_profile','$route_table')";
                    $routeID++;
                }
                if (count($routes) > 0) {
                    $out = implode(",", $routes);
                    $projectdb->query("INSERT INTO routes_static (id,name,source,template,vr_id,ip_version,destination,tointerface,nexthop,nexthop_value,nexthop_value_member_lid,metric,admin_dist,option_no_install,pm_enable,pm_failure_condition,pm_hold_time,bfd_profile,route_table) VALUES " . $out . ";");
                    unset($routes);
                    if (count($monitorDestination)>0){
                        $projectdb->query("INSERT INTO routes_static_monitor_destinations (route_id,name,enable,src,dst,mp_interval,mp_count,dst_member_lid) VALUES ".implode(",",$monitorDestination).";");
                        unset($monitorDestination);
                    }
                }
            }

            if (isset($mvalue->{'routing-table'}->ipv6->{'static-route'})) {
                $routes = array();
                $monitorDestination = array();
                foreach ($mvalue->{'routing-table'}->ipv6->{'static-route'}->entry as $skey => $svalue) {
                    $staticName = $svalue->attributes()->name;
                    $destination = $svalue->destination;
                    $net = explode("/", $destination);
                    $ip_version = ip_version($net[0]);
                    $metric="";
                    $admin_dist="";

                    if (isset($svalue->option->{'no-install'})) {
                        $option_no_install = 1;
                    } else {
                        $option_no_install = 0;
                    }
                    if (isset($svalue->metric)) {
                        $metric = $svalue->metric;
                    }
                    if (isset($svalue->{'admin-dist'})) {
                        $admin_dist = $svalue->{'admin-dist'};
                    }
                    if (isset($svalue->interface)) {
                        $tointerface = $svalue->interface;
                    } else {
                        $tointerface = "";
                    }

                    if (isset($svalue->nexthop->{'ipv6-address'})) {
                        $nexthop = "ipv6-address";
                        $nexthop_value = $svalue->nexthop->{'ipv6-address'};
                    } elseif (isset($svalue->nexthop->discard)) {
                        $nexthop = "discard";
                        $nexthop_value = "";
                    } elseif (isset($svalue->nexthop->{'next-vr'})) {
                        $nexthop = "next-vr";
                        $nexthop_value = $svalue->nexthop->{'next-vr'};
                    } elseif (isset($svalue->nexthop->fqdn)) {
                        $nexthop = "fqdn";
                        $nexthop_value = $svalue->nexthop->fqdn;
                    }
                    else {
                        $nexthop = "None";
                        $nexthop_value = "";
                    }
                    # Panos 8 and higher
                    $pm_enable="no";
                    $pm_failure_condition="any";
                    $pm_hold_time=2;
                    $bfd_profile="None";
                    $route_table="unicast";
                    //$monitorDestination=array();
                    if (isset($svalue->{'path-monitor'})){
                        if (isset($svalue->{'path-monitor'}->enable)){
                            $pm_enable=$svalue->{'path-monitor'}->enable;
                        }
                        if (isset($svalue->{'path-monitor'}->{'failure-condition'})){
                            $pm_failure_condition=$svalue->{'path-monitor'}->{'failure-condition'};
                        }
                        if (isset($svalue->{'path-monitor'}->{'hold-time'})){
                            $pm_hold_time=$svalue->{'path-monitor'}->{'hold-time'};
                        }
                        if (isset($svalue->{'path-monitor'}->{'monitor-destinations'})){
                            foreach($svalue->{'path-monitor'}->{'monitor-destinations'}->entry as $kk => $MD){
                                $MDname=$MD->attributes()->name;
                                $MDenable=$MD->enable;
                                $MDsrc=$MD->source;
                                $MDdst=$MD->destination;
                                $MDdstID="0";

                                // The address objects are not yet loaded in the BBDD.

                                //$getID=$projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$MDdst' LIMIT 1");
                                //if ($getID->num_rows==1){
                                //    $getIDData=$getID->fetch_assoc();
                                //    $MDdstID=$getIDData['id'];
                                //}
                                //else{
                                //    $MDdstID="0";
                                //}
                                $MDinterval=$MD->interval;
                                $MDcount=$MD->count;
                                $monitorDestination[]="('$routeID','$MDname','$MDenable','$MDsrc','$MDdst','$MDinterval','$MDcount','$MDdstID')";
                            }
                        }
                    }
                    if (isset($svalue->bfd)){
                        if (isset($svalue->bfd->profile)){
                            $bfd_profile=$svalue->bfd->profile;
                        }
                    }
                    if (isset($svalue->{'route-table'})){
                        if (isset($svalue->{'route-table'}->unicast)){$route_table="unicast";}
                        elseif(isset($svalue->{'route-table'}->multicast)){$route_table="multicast";}
                        elseif(isset($svalue->{'route-table'}->both)){$route_table="both";}
                        elseif(isset($svalue->{'route-table'}->{'no-install'})){$route_table="no-install";}
                        else{$route_table="unicast";}
                    }
                    $routes[] = "('$staticName','$source','$template','$vr_id','$ip_version','$destination','$tointerface','$nexthop','$nexthop_value','$metric','$admin_dist','$option_no_install','$pm_enable','$pm_failure_condition','$pm_hold_time','$route_table')";
                    $routeID++;
                }
                if (count($routes) > 0) {
                    $out = implode(",", $routes);
                    $projectdb->query("INSERT INTO routes_static (name,source,template,vr_id,ip_version,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,pm_failure_condition,pm_hold_time,route_table) VALUES " . $out . ";");
                    unset($routes);
                    if (count($monitorDestination)>0){
                        $projectdb->query("INSERT INTO routes_static_monitor_destinations (route_id,name,enable,src,dst,mp_interval,mp_count,dst_member_lid)  VALUES ".implode(",",$monitorDestination).";");
                        unset($monitorDestination);
                    }
                }
            }
        }
    }
}

function xml_add_network_interface_management_profiles($projectdb,$profiles,$source,$vsys,$template,$version){
    $vrs = array();
    foreach ($profiles as $mkey => $mvalue) {
        //foreach ($value->devices->entry->network->profiles->{'interface-management-profile'}->entry as $mkey => $mvalue) {
        $http="";$https="";
        $http_ocsp="";$ssh="";$snmp="";$userid_service="";
        $ping="";$telnet="";$response_pages="";$userid_syslog_listener_ssl="";
        $userid_syslog_listener_udp="";
        $vrName = $mvalue->attributes()->name;

        if (isset($mvalue->http)) {
            $http = $mvalue->http;
        }
        if (isset($mvalue->https)) {
            $https = $mvalue->https;
        }
        if (isset($mvalue->{'http-ocsp'})) {
            $http_ocsp = $mvalue->{'http-ocsp'};
        }
        if (isset($mvalue->ssh)) {
            $ssh = $mvalue->ssh;
        }
        if (isset($mvalue->snmp)) {
            $snmp = $mvalue->snmp;
        }
        if (isset($mvalue->{'userid-service'})) {
            $userid_service = $mvalue->{'userid-service'};
        }
        if (isset($mvalue->ping)) {
            $ping = $mvalue->ping;
        }
        if (isset($mvalue->telnet)) {
            $telnet = $mvalue->telnet;
        }
        if (isset($mvalue->{'response-pages'})) {
            $response_pages = $mvalue->{'response-pages'};
        }

        #Added on 6.X
        if ($version > 5) {
            if (isset($mvalue->{'userid-syslog-listener-ssl'})) {
                $userid_syslog_listener_ssl = $mvalue->{'userid-syslog-listener-ssl'};
            }
            if (isset($mvalue->{'userid-syslog-listener-udp'})) {
                $userid_syslog_listener_udp = $mvalue->{'userid-syslog-listener-udp'};
            }
        }


        if (isset($mvalue->{'permitted-ip'})) {
            $interfaces = array();
            foreach ($mvalue->{'permitted-ip'}->entry as $mmkey => $mmvalue) {
                $interfaces[] = $mmvalue->attributes()->name;
            }
            $interface = implode(",", $interfaces);
            unset($interfaces);
        } else {
            $interface = "";
        }

        $projectdb->query("INSERT INTO interface_management_profile (vsys,source,template,name,permitted_ip,http,https,http_ocsp,ssh,snmp,userid_service,userid_syslog_listener_ssl,userid_syslog_listener_udp,ping,response_pages,telnet) VALUES ('$vsys','$source','$template','$vrName','$interface','$http','$https','$http_ocsp','$ssh','$snmp','$userid_service','$userid_syslog_listener_ssl','$userid_syslog_listener_udp','$ping','$response_pages','$telnet');");
    }
}

function xml_add_network_ike_crypto_profile($projectdb,$profiles,$source,$vsys,$template,$version){
    foreach ($profiles as $mkey => $mvalue) {
        //foreach ($value->devices->entry->network->ike->{'crypto-profiles'}->{'ike-crypto-profiles'}->entry as $mkey => $mvalue) {
        $ike_crypto_name = $mvalue->attributes()->name;
        if (isset($mvalue->encryption)) {
            foreach ($mvalue->encryption->member as $member_ike) {
                $ike_encryption_array[] = $member_ike;
            }
            $ike_encryption = implode(",", $ike_encryption_array);
            unset($ike_encryption_array);
        }
        else {
            $ike_encryption = "";
        }

        if (isset($mvalue->hash)) {
            foreach ($mvalue->hash->member as $member_ike) {
                $ike_hash_array[] = $member_ike;
            }
            $ike_hash = implode(",", $ike_hash_array);
            unset($ike_hash_array);
        }
        else {
            $ike_hash = "";
        }

        if (isset($mvalue->{'dh-group'})) {
            foreach ($mvalue->{'dh-group'}->member as $member_ike) {
                $ike_dh_group_array[] = $member_ike;
            }
            $ike_dh_group = implode(",", $ike_dh_group_array);
            unset($ike_dh_group_array);
        }
        else {
            $ike_dh_group = "";
        }

        $seconds = 0;
        $minutes = 0;
        $hours = 0;
        $days = 0;

        if (isset($mvalue->lifetime->seconds)) {
            $seconds = $mvalue->lifetime->seconds;
        }
        if (isset($mvalue->lifetime->minutes)) {
            $minutes = $mvalue->lifetime->minutes;
        }
        if (isset($mvalue->lifetime->hours)) {
            $hours = $mvalue->lifetime->hours;
        }
        if (isset($mvalue->lifetime->days)) {
            $days = $mvalue->lifetime->days;
        }
        if ($version >= 7 ) {
            $authentication_multiple="";
            if (isset($mvalue->{'authentication-multiple'})) {
                $authentication_multiple = $mvalue->{'authentication-multiple'};
            }
        }

        $projectdb->query("INSERT INTO ike_crypto_profiles (vsys, source, template, name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple) VALUES ('$vsys','$source','$template','$ike_crypto_name','$ike_encryption','$ike_hash','$ike_dh_group','$seconds','$minutes','$hours','$days','$authentication_multiple');");

    }
}

function xml_add_network_ike_crypto_ipsec_profile($projectdb,$profiles,$source,$vsys,$template,$version){
    foreach ($profiles as $mkey => $mvalue) {
        //foreach ($value->devices->entry->network->ike->{'crypto-profiles'}->{'ipsec-crypto-profiles'}->entry as $mkey => $mvalue) {
        $ipsec_crypto_name = $mvalue->attributes()->name;
        // Protocol ESP
        if (isset($mvalue->esp)) {

            $protocol = "ESP";

            if (isset($mvalue->esp->encryption)) {
                foreach ($mvalue->esp->encryption->member as $member_ike) {
                    $ipsec_encryption_array[] = $member_ike;
                }
                $ipsec_encryption = implode(",", $ipsec_encryption_array);
                unset($ipsec_encryption_array);
            }
            else {
                $ipsec_encryption = "";
            }

            if (isset($mvalue->esp->authentication)) {
                foreach ($mvalue->esp->authentication->member as $member_ike) {
                    $ipsec_hash_array[] = $member_ike;
                }
                $ipsec_hash = implode(",", $ipsec_hash_array);
                unset($ipsec_hash_array);
            }
            else {
                $ipsec_hash = "";
            }

        }

        // Protocol AH
        if (isset($mvalue->ah)) {

            $protocol = "AH";

            if (isset($mvalue->ah->encryption)) {
                foreach ($mvalue->ah->encryption->member as $member_ike) {
                    $ipsec_encryption_array[] = $member_ike;
                }
                $ipsec_encryption = implode(",", $ipsec_encryption_array);
                unset($ipsec_encryption_array);
            }
            else {
                $ipsec_encryption = "";
            }

            if (isset($mvalue->ah->authentication)) {
                foreach ($mvalue->ah->authentication->member as $member_ike) {
                    $ipsec_hash_array[] = $member_ike;
                }
                $ipsec_hash = implode(",", $ipsec_hash_array);
                unset($ipsec_hash_array);
            }
            else {
                $ipsec_hash = "";
            }

        }

        if (isset($mvalue->{'dh-group'})) {
            $ipsec_dh_group = $mvalue->{'dh-group'};
        }
        else {
            $ipsec_dh_group = "";
        }

        $seconds = 0;
        $minutes = 0;
        $hours = 0;
        $days = 0;

        if (isset($mvalue->lifetime->seconds)) {
            $seconds = $mvalue->lifetime->seconds;
        }
        if (isset($mvalue->lifetime->minutes)) {
            $minutes = $mvalue->lifetime->minutes;
        }
        if (isset($mvalue->lifetime->hours)) {
            $hours = $mvalue->lifetime->hours;
        }
        if (isset($mvalue->lifetime->days)) {
            $days = $mvalue->lifetime->days;
        }

        $kb = 0;
        $mb = 0;
        $gb = 0;
        $tb = 0;

        if (isset($mvalue->lifesize->kb)) {
            $kb = $mvalue->lifesize->kb;
        }
        if (isset($mvalue->lifesize->mb)) {
            $mb = $mvalue->lifesize->mb;
        }
        if (isset($mvalue->lifesize->gb)) {
            $gb = $mvalue->lifesize->gb;
        }
        if (isset($mvalue->lifesize->tb)) {
            $tb = $mvalue->lifesize->tb;
        }

        $projectdb->query("INSERT INTO ipsec_crypto_profiles (vsys, source, template, name, encryption, hash, dh_group, seconds, minutes, hours, days, protocol, kb, mb, gb, tb) VALUES ('$vsys','$source','$template','$ipsec_crypto_name','$ipsec_encryption','$ipsec_hash','$ipsec_dh_group','$seconds','$minutes','$hours','$days','$protocol','$kb','$mb','$gb','$tb');");
    }
}

function xml_add_network_ike_gateway($projectdb,$profiles,$source,$vsys,$template,$version){
    $peer_ip_type="";
    $peer_ip_address="";
    foreach ($profiles as $mkey => $mvalue) {
        $ike_gateways_name = $mvalue->attributes()->name;
        //echo "Name ike: " .$ike_gateways_name. "\n";
        if (isset($mvalue->protocol->version)) {
            $version_ike = $mvalue->protocol->version;
        }
        else{
            $version_ike = "ikev1";
        }

        if (isset($mvalue->protocol->ikev1)) {
            $dpd_ikev1 = $mvalue->protocol->ikev1->dpd->enable;
            if (isset($mvalue->protocol->ikev1->dpd->interval)) {
                $interval_ikev1 = $mvalue->protocol->ikev1->dpd->interval;
            }else{
                $interval_ikev1 = "5";
            }

            if (isset($mvalue->protocol->ikev1->dpd->retry)) {
                $retry_ikev1 = $mvalue->protocol->ikev1->dpd->retry;
            }else{
                $retry_ikev1 = "5";
            }
            if (isset($mvalue->protocol->ikev1->{'ike-crypto-profile'})) {
                $ike_crypto_profile_ikev1 = $mvalue->protocol->ikev1->{'ike-crypto-profile'};
                //$getIKECrypto = $projectdb->query("SELECT id FROM ike_crypto_profiles WHERE name = '$ike_crypto_profile';");
                //if ($getIKECrypto->num_rows == 1) {
                //    $dataIKE = $getIKECrypto->fetch_assoc();
                //    $ike_crypto_profile_id = $dataIKE['id'];
                //}
            }else{
                $ike_crypto_profile_ikev1 = "";
                $getIKECryptoExistDefault = $projectdb->query("SELECT id FROM ike_crypto_profiles WHERE name = 'default';");
                if ($getIKECryptoExistDefault->num_rows == 1) {
                    $ike_crypto_profile_ikev1 = "default";
                }
            }
            if (isset($mvalue->protocol->ikev1->{'exchange-mode'})) {
                $exchange_mode_ikev1 = $mvalue->protocol->ikev1->{'exchange-mode'};
            }else{
                $exchange_mode_ikev1 = "auto";
            }
        }

        $interval_ikev2 = "5";
        $ike_crypto_profile_ikev2 = "";
        $require_cookie_ikev2 = "";
        $dpd_ikev2 = "";
        $nat_traversal = "";
        $passive_mode = "";
        $fragmentation = "";

        // NEW VERSION 7.
        if (isset($mvalue->protocol->ikev2)) {
            $dpd_ikev2 = $mvalue->protocol->ikev2->dpd->enable;
            if (isset($mvalue->protocol->ikev2->dpd->interval)) {
                $interval_ikev2 = $mvalue->protocol->ikev2->dpd->interval;
            }else{
                $interval_ikev2 = "5";
            }
            if (isset($mvalue->protocol->ikev2->{'ike-crypto-profile'})) {
                $ike_crypto_profile_ikev2 = $mvalue->protocol->ikev2->{'ike-crypto-profile'};
                //$getIKECrypto = $projectdb->query("SELECT id FROM ike_crypto_profiles WHERE name = '$ike_crypto_profile';");
                //if ($getIKECrypto->num_rows == 1) {
                //    $dataIKE = $getIKECrypto->fetch_assoc();
                //    $ike_crypto_profile_id = $dataIKE['id'];
                //}
            }else{
                $ike_crypto_profile_ikev2 = "";
                $getIKECryptoExistDefault = $projectdb->query("SELECT id FROM ike_crypto_profiles WHERE name = 'default';");
                if ($getIKECryptoExistDefault->num_rows == 1) {
                    $ike_crypto_profile_ikev2 = "default";
                }
            }
            if (isset($mvalue->protocol->ikev2->{'require-cookie'})) {
                $require_cookie_ikev2 = $mvalue->protocol->ikev2->{'require-cookie'};
            }else{
                $require_cookie_ikev2 = "";
            }
        }

        if (isset($mvalue->{'local-address'})) {
            if (isset($mvalue->{'local-address'}->ip)){
                $local_address_ip = $mvalue->{'local-address'}->ip;
            }else{
                $local_address_ip = "";
            }
            if (isset($mvalue->{'local-address'}->interface)){
                $interface = $mvalue->{'local-address'}->interface;
            }else{
                $interface = "";
            }
        }

        if (isset($mvalue->authentication->{'pre-shared-key'})) {
            $pre_shared_key = $mvalue->authentication->{'pre-shared-key'}->key;
            $type_authentication = "pre-shared-key";
        }else{
            $pre_shared_key = "";
        }

        if (isset($mvalue->authentication->certificate)) {
            $type_authentication = "certificate";
            $allow_id_payload_mismatch = $mvalue->authentication->certificate->{'allow-id-payload-mismatch'};

            if ($version >= 7) {
                $local_certificate = $mvalue->authentication->certificate->{'local-certificate'}->name;
            }else{
                $local_certificate = $mvalue->authentication->certificate->{'local-certificate'};
            }

            $certificate_profile = $mvalue->authentication->certificate->{'certificate-profile'};
            $strict_validation_revocation = $mvalue->authentication->certificate->{'strict-validation-revocation'};

            if ($version >= 7) {
                if (isset($mvalue->authentication->certificate->{'local-certificate'}->{'hash-and-url'})) {
                    $hash_and_url = $mvalue->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->enable;
                    $base_url = $mvalue->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->{'base-url'};
                }else{
                    $hash_and_url = "";
                    $base_url = "";
                }
            }

        }else{
            $allow_id_payload_mismatch = "no";
            $local_certificate = "";
            $certificate_profile = "";
            $strict_validation_revocation = "no";
            $hash_and_url = "";
            $base_url = "";
        }

        if (isset($mvalue->{'protocol-common'})) {
            if (isset($mvalue->{'protocol-common'}->{'nat-traversal'})){
                $nat_traversal = $mvalue->{'protocol-common'}->{'nat-traversal'}->enable;
            }else{
                $nat_traversal = "";
            }
            if (isset($mvalue->{'protocol-common'}->{'passive-mode'})){
                $passive_mode = $mvalue->{'protocol-common'}->{'passive-mode'};
            }else{
                $passive_mode = "";
            }
            if (isset($mvalue->{'protocol-common'}->fragmentation)){
                $fragmentation = $mvalue->{'protocol-common'}->fragmentation->enable;
            }else{
                $fragmentation = "";
            }
        }

        if (isset($mvalue->{'peer-address'})) {
            if(isset($mvalue->{'peer-address'}->ip)){
                $peer_ip_address = $mvalue->{'peer-address'}->ip;
                $peer_ip_type = "static";
            }else{
                $peer_ip_address = "";
                $peer_ip_type = "dynamic";
            }
        }

        if (isset($mvalue->{'local-id'})) {
            $local_id = $mvalue->{'local-id'}->id;
            $local_id_type = $mvalue->{'local-id'}->type;
        }else{
            $local_id = "";
            $local_id_type = "";
        }

        if (isset($mvalue->{'peer-id'})) {
            $peer_id = $mvalue->{'peer-id'}->id;
            $peer_id_type = $mvalue->{'peer-id'}->type;
            $peer_id_matching = $mvalue->{'peer-id'}->matching;
        }else{
            $peer_id = "";
            $peer_id_type = "";
            $peer_id_matching = "";
        }

        $address_type = "";
        $ipv6 = "";
        if (isset($mvalue->{'ipv6'})) {
            $ipv6 = $mvalue->{'ipv6'};
            if($ipv6 == "yes"){
                $address_type = "ipv6";
            }
        }else{
            $address_type = "ipv4";
        }

        $projectdb->query("INSERT INTO ike_gateways_profiles (vsys, source, template, name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, allow_id_payload_mismatch, local_certificate, certificate_profile, strict_validation_revocation, hash_and_url, base_url, nat_traversal, passive_mode, fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type) VALUES ('$vsys','$source','$template','$ike_gateways_name','$version_ike','$dpd_ikev1', '$interval_ikev1', '$retry_ikev1', '$ike_crypto_profile_ikev1', '$exchange_mode_ikev1', '$dpd_ikev2', '$interval_ikev2', '$ike_crypto_profile_ikev2', '$require_cookie_ikev2','$local_address_ip', '$interface', '$type_authentication', '$pre_shared_key', '$allow_id_payload_mismatch', '$local_certificate', '$certificate_profile', '$strict_validation_revocation', '$hash_and_url', '$base_url', '$nat_traversal', '$passive_mode', '$fragmentation', '$peer_ip_type', '$peer_ip_address', '$local_id', '$local_id_type', '$peer_id', '$peer_id_type', '$peer_id_matching', '$address_type');");

    }
}

function xml_add_network_tunnel_ipsec($projectdb,$profiles,$source,$vsys,$template,$version){
    $getID=$projectdb->query("select max(id) as max FROM ipsec_tunnel;");
    if ($getID->num_rows==1){
        $getIDdata=$getID->fetch_assoc();
        $getIDMax=$getIDdata['max'];
        $i=$getIDMax+1;
    }
    else{
        $i=1;
    }
    foreach ($profiles as $mkey => $mvalue) {
        //:00000001FF[-:00000001FF]
        //&#x2019;[-&#x2019;]
        //$i = 1;
        $protocol="";
        $ipsec_tunnel_name = $mvalue->attributes()->name;
        $ipsec_crypto_profile = "";
        $proxy_id_array = array();
        $local_address_ip = "";
        $interface = "";
        $peer_ip_address = "";
        $local_spi = "";
        $local_port = "";
        $remote_spi="";
        $remote_port = "";
        $number = "";
        $external_ca = "";
        $certificate_profile = "";
        $local_certificate = "";
        $portal_address = "";
        $ike_gateway = "";
        $authentication = "";
        $encryption = "";
        $key_encry = "";
        $key_auth = "";
        $publish_connected_routes = "";
        $publish_routes = "";
        $tunnel_monitor = "";
        $destination_ip = "";
        $tunnel_monitor_profile = "";
        $disabled = "no";

        if (isset($mvalue->{'disabled'})) {
            if( $mvalue->{'disabled'}== "yes"){
                $disabled = "yes";
            }
            else{
                $disabled = "no";
            }
        }
        if (isset($mvalue->{'auto-key'})) {
            $type = "auto-key";

            if (isset($mvalue->{'auto-key'}->{'ike-gateway'}->entry)){
                $ike_gateway = $mvalue->{'auto-key'}->{'ike-gateway'}->entry->attributes()->name;
            }

            if (isset($mvalue->{'auto-key'}->{'proxy-id'})) {
                foreach ($mvalue->{'auto-key'}->{'proxy-id'}->entry as $mmkey => $mvalueproxy) {

                    $type_proxy = "v4";
                    $proxy_id_name = $mvalueproxy->attributes()->name;
                    $local_port = "";
                    $remote_port = "";
                    $local = "";
                    $remote = "";
                    $number = "";

                    if (isset($mvalueproxy->protocol->tcp)) {
                        $proxy_id_protocol = "TCP";
                        $local_port = $mvalueproxy->protocol->tcp->{'local-port'};
                        $remote_port = $mvalueproxy->protocol->tcp->{'remote-port'};
                    }
                    if (isset($mvalueproxy->protocol->udp)) {
                        $proxy_id_protocol = "UDP";
                        $local_port = $mvalueproxy->protocol->udp->{'local-port'};
                        $remote_port = $mvalueproxy->protocol->udp->{'remote-port'};
                    }
                    if (isset($mvalueproxy->protocol->number)) {
                        $proxy_id_protocol = "Number";
                        $number = $mvalueproxy->protocol->number;
                    }
                    if (isset($mvalueproxy->protocol->any)) {
                        $proxy_id_protocol = "Any";
                    }
                    if (isset($mvalueproxy->local)) {
                        $local = $mvalueproxy->local;
                    }
                    if (isset($mvalueproxy->remote)) {
                        $remote = $mvalueproxy->remote;
                    }

                    $proxy_id_array[] = "('$proxy_id_name','$vsys','$source','$template','$i','$proxy_id_protocol','$local_port','$remote_port','$number','$local','$remote', '$type_proxy')";
                }
            }

            if (isset($mvalue->{'auto-key'}->{'proxy-id-v6'})) {
                foreach ($mvalue->{'auto-key'}->{'proxy-id-v6'}->entry as $mmkey => $mvalueproxy) {

                    $type_proxy = "v6";
                    $proxy_id_name = $mvalueproxy->attributes()->name;
                    $local_port = "";
                    $remote_port = "";
                    $local = "";
                    $remote = "";
                    $number = "";

                    if (isset($mvalueproxy->protocol->tcp)) {
                        $proxy_id_protocol = "TCP";
                        $local_port = $mvalueproxy->protocol->tcp->{'local-port'};
                        $remote_port = $mvalueproxy->protocol->tcp->{'remote-port'};
                    }
                    if (isset($mvalueproxy->protocol->udp)) {
                        $proxy_id_protocol = "UDP";
                        $local_port = $mvalueproxy->protocol->udp->{'local-port'};
                        $remote_port = $mvalueproxy->protocol->udp->{'remote-port'};
                    }
                    if (isset($mvalueproxy->protocol->number)) {
                        $proxy_id_protocol = "Number";
                        $number = $mvalueproxy->protocol->number;
                    }
                    if (isset($mvalueproxy->protocol->any)) {
                        $proxy_id_protocol = "Any";
                    }
                    if (isset($mvalueproxy->local)) {
                        $local = $mvalueproxy->local;
                    }
                    if (isset($mvalueproxy->remote)) {
                        $remote = $mvalueproxy->remote;
                    }

                    $proxy_id_array[] = "('$proxy_id_name','$vsys','$source','$template','$i','$proxy_id_protocol','$local_port','$remote_port','$number','$local','$remote', '$type_proxy')";
                }
            }

            if (isset($mvalue->{'auto-key'}->{'ipsec-crypto-profile'})) {
                $ipsec_crypto_profile = $mvalue->{'auto-key'}->{'ipsec-crypto-profile'};
            }
            else{
                $ipsec_crypto_profile = "default";
            }

        }

        if (isset($mvalue->{'manual-key'})) {

            $type = "manual-key";

            if (isset($mvalue->{'manual-key'}->esp)) {
                $protocol = "ESP";
                if (isset($mvalue->{'manual-key'}->esp->authentication->none)) {
                    $authentication = "none";
                    $key_auth = "";
                }
                if (isset($mvalue->{'manual-key'}->esp->authentication->md5)) {
                    $authentication = "md5";
                    $key_auth = $mvalue->{'manual-key'}->esp->authentication->md5->key;
                }
                if (isset($mvalue->{'manual-key'}->esp->authentication->sha1)) {
                    $authentication = "sha1";
                    $key_auth = $mvalue->{'manual-key'}->esp->authentication->sha1->key;
                }
                if (isset($mvalue->{'manual-key'}->esp->authentication->sha256)) {
                    $authentication = "sha256";
                    $key_auth = $mvalue->{'manual-key'}->esp->authentication->sha256->key;
                }
                if (isset($mvalue->{'manual-key'}->esp->authentication->sha384)) {
                    $authentication = "sha384";
                    $key_auth = $mvalue->{'manual-key'}->esp->authentication->sha384->key;
                }
                if (isset($mvalue->{'manual-key'}->esp->authentication->sha512)) {
                    $authentication = "sha512";
                    $key_auth = $mvalue->{'manual-key'}->esp->authentication->sha512->key;
                }

                $encryption = $mvalue->{'manual-key'}->esp->encryption->algorithm;
                if (isset($mvalue->{'manual-key'}->esp->encryption->key)){
                    $key_encry = $mvalue->{'manual-key'}->esp->encryption->key;
                }
            }
            if (isset($mvalue->{'manual-key'}->ah)) {
                $protocol = "AH";
                if (isset($mvalue->{'manual-key'}->ah->authentication->none)) {
                    $authentication = "none";
                    $key_auth = "";
                }
                if (isset($mvalue->{'manual-key'}->ah->authentication->md5)) {
                    $authentication = "md5";
                    $key_auth = $mvalue->{'manual-key'}->ah->authentication->md5->key;
                }
                if (isset($mvalue->{'manual-key'}->ah->authentication->sha1)) {
                    $authentication = "sha1";
                    $key_auth = $mvalue->{'manual-key'}->ah->authentication->sha1->key;
                }
                if (isset($mvalue->{'manual-key'}->ah->authentication->sha256)) {
                    $authentication = "sha256";
                    $key_auth = $mvalue->{'manual-key'}->ah->authentication->sha256->key;
                }
                if (isset($mvalue->{'manual-key'}->ah->authentication->sha384)) {
                    $authentication = "sha384";
                    $key_auth = $mvalue->{'manual-key'}->ah->authentication->sha384->key;
                }
                if (isset($mvalue->{'manual-key'}->ah->authentication->sha512)) {
                    $authentication = "sha512";
                    $key_auth = $mvalue->{'manual-key'}->ah->authentication->sha512->key;
                }
            }
            if (isset($mvalue->{'manual-key'}->{'local-address'})) {
                $local_address_ip = $mvalue->{'manual-key'}->{'local-address'}->ip;
                $interface = $mvalue->{'manual-key'}->{'local-address'}->interface;
            }
            if (isset($mvalue->{'manual-key'}->{'peer-address'})) {
                $peer_ip_address = $mvalue->{'manual-key'}->{'peer-address'}->ip;
            }
            if (isset($mvalue->{'manual-key'}->{'local-spi'})) {
                $local_spi = $mvalue->{'manual-key'}->{'local-spi'};
            }
            if (isset($mvalue->{'manual-key'}->{'remote-spi'})) {
                $remote_spi = $mvalue->{'manual-key'}->{'remote-spi'};
            }
        }

        if (isset($mvalue->{'global-protect-satellite'})) {
            $type = "global-protect-satellite";

            if (isset($mvalue->{'global-protect-satellite'}->{'local-address'})) {
                $local_address_ip = $mvalue->{'global-protect-satellite'}->{'local-address'}->ip;
                $interface = $mvalue->{'global-protect-satellite'}->{'local-address'}->interface;
            }
            if (isset($mvalue->{'global-protect-satellite'}->{'publish-routes'})) {
                foreach ($mvalue->{'global-protect-satellite'}->{'publish-routes'}->member as $member_publish) {
                    $publish_routes_array[] = $member_publish;
                }
                $publish_routes = implode(",", $publish_routes_array);
                unset($publish_routes_array);
            }
            else{
                $publish_routes = "";
            }

            if (isset($mvalue->{'global-protect-satellite'}->{'external-ca'})) {
                $external_ca = "yes";
                if (isset($mvalue->{'global-protect-satellite'}->{'external-ca'}->{'certificate-profile'})) {
                    $certificate_profile = $mvalue->{'global-protect-satellite'}->{'external-ca'}->{'certificate-profile'};
                    $local_certificate = $mvalue->{'global-protect-satellite'}->{'external-ca'}->{'local-certificate'};
                }
            }
            if (isset($mvalue->{'global-protect-satellite'}->{'publish-connected-routes'})) {
                $publish_connected_routes = $mvalue->{'global-protect-satellite'}->{'publish-connected-routes'}->enable;
            }
            if (isset($mvalue->{'global-protect-satellite'}->{'portal-address'})) {
                $portal_address = $mvalue->{'global-protect-satellite'}->{'portal-address'};
            }
        }

        if (isset($mvalue->{'tunnel-monitor'})) {
            $tunnel_monitor = $mvalue->{'tunnel-monitor'}->enable;
            $destination_ip = "";
            $tunnel_monitor_profile = "";
            if (isset($mvalue->{'tunnel-monitor'}->{'destination-ip'})) {
                $destination_ip = $mvalue->{'tunnel-monitor'}->{'destination-ip'};
            }
            if (isset($mvalue->{'tunnel-monitor'}->{'tunnel-monitor-profile'})) {
                $tunnel_monitor_profile = $mvalue->{'tunnel-monitor'}->{'tunnel-monitor-profile'};
            }
        }

        $copy_tos = "no";
        if (isset($mvalue->{'copy-tos'})) {
            $copy_tos = $mvalue->{'copy-tos'};
        }

        $anti_replay = "yes";
        if (isset($mvalue->{'anti-replay'})) {
            $anti_replay = $mvalue->{'anti-replay'};
        }

        $tunnel_interface = "";
        if (isset($mvalue->{'tunnel-interface'})) {
            $tunnel_interface = $mvalue->{'tunnel-interface'};
        }

        $address_type = "";
        $ipv6 = "";
        if (isset($mvalue->{'ipv6'})) {
            $ipv6 = $mvalue->{'ipv6'};
            if($ipv6 == "yes"){
                $address_type = "ipv6";
            }
        }
        else{
            $address_type = "ipv4";
        }

        $projectdb->query("INSERT INTO ipsec_tunnel (id,vsys, source, template, name, disabled, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, encryption, key_encry, local_address_ip, interface, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, local_certificate, publish_connected_routes, portal_address, publish_routes) "
            . " VALUES ('$i','$vsys','$source','$template', '$ipsec_tunnel_name', '$disabled','$anti_replay', '$copy_tos', '$tunnel_monitor', '$destination_ip', '$tunnel_monitor_profile', '$tunnel_interface', '$address_type', '$type', '$ike_gateway', '$ipsec_crypto_profile', '$protocol', '$authentication', '$key_auth', '$encryption', '$key_encry', '$local_address_ip', '$interface', '$peer_ip_address', '$local_spi', '$remote_spi', '$external_ca', '$certificate_profile', '$local_certificate', '$publish_connected_routes', '$portal_address', '$publish_routes');");

        $ipsec_tunnel_id = $projectdb->insert_id;
        if($i === $ipsec_tunnel_id){
            $sql1 = "INSERT INTO proxy_id_ipsec_tunnel (name,vsys,source,template,ipsec_tunnel_id,protocol,local_port, remote_port, number, local, remote, type) VALUES ";
            if (count($proxy_id_array) > 0) {
                $output = implode(",", $proxy_id_array);
                $sql0 = $sql1 . $output;
                $projectdb->query($sql0);
            }
        }

        $i++;
    }
}


function xml_add_network_tunnel_gre($projectdb,$profiles,$source,$vsys,$template,$version){

    $getID=$projectdb->query("select max(id) as max FROM gre_tunnel;");
    if ($getID->num_rows==1){
        $getIDdata=$getID->fetch_assoc();
        $getIDMax=$getIDdata['max'];
        $i=$getIDMax+1;
    }
    else{
        $i=1;
    }
    
    foreach ($profiles as $mkey => $mvalue) {

        $gre_tunnel_name = $mvalue->attributes()->name;
        $local_address_ip = "";
        $interface = "";
        $peer_ip_address = "";
        $keep_alive = "";
        $keep_alive_interval = "10";
        $keep_alive_retry = "3";
        $keep_alive_hold_timer = "5";
        $tunnel_interface = "";

        if (isset($mvalue->{'local-address'})) {
            $local_address_ip = $mvalue->{'local-address'}->ip;
            $interface = $mvalue->{'local-address'}->interface;
        }

        if (isset($mvalue->{'peer-address'})) {
            $peer_ip_address = $mvalue->{'peer-address'}->ip;
        }

        if (isset($mvalue->{'keep-alive'})) {
            $keep_alive = $mvalue->{'keep-alive'}->enable;

            if($keep_alive == "yes"){
                $keep_alive_interval = $mvalue->{'keep-alive'}->interval;
                $keep_alive_retry = $mvalue->{'keep-alive'}->retry;
                $keep_alive_hold_timer = $mvalue->{'keep-alive'}->{'hold-timer'};
            }
        }

        $copy_tos = "no";
        if (isset($mvalue->{'copy-tos'})) {
            $copy_tos = $mvalue->{'copy-tos'};
        }

        if (isset($mvalue->{'tunnel-interface'})) {
            $tunnel_interface = $mvalue->{'tunnel-interface'};
        }

        $projectdb->query("INSERT INTO gre_tunnel (id, vsys, source, template, name, local_address_ip, interface, peer_ip_address, keep_alive, keep_alive_interval, keep_alive_retry, keep_alive_hold_timer, tunnel_interface,  copy_tos) "
            . " VALUES ('$i','$vsys','$source','$template', '$gre_tunnel_name', '$local_address_ip', '$interface', '$peer_ip_address', '$keep_alive', '$keep_alive_interval', '$keep_alive_retry', '$keep_alive_hold_timer', '$tunnel_interface', '$copy_tos');");

        $i++;
    }
}


function xml_add_network_gp_app_crypto_profiles($projectdb,$profiles,$source,$vsys,$template){
    foreach ($profiles as $mkey => $mvalue) {
        //foreach ($value->devices->entry->network->ike->{'crypto-profiles'}->{'global-protect-app-crypto-profiles'}->entry as $mkey => $mvalue) {

        $global_protect_app_crypto_name = $mvalue->attributes()->name;

        if (isset($mvalue->encryption)) {
            foreach ($mvalue->encryption->member as $member_ike) {
                $ipsec_encryption_array[] = $member_ike;
            }
            $ipsec_encryption = implode(",", $ipsec_encryption_array);
            unset($ipsec_encryption_array);
        }
        else {
            $ipsec_encryption = "";
        }

        if (isset($mvalue->authentication)) {
            foreach ($mvalue->authentication->member as $member_ike) {
                $ipsec_hash_array[] = $member_ike;
            }
            $ipsec_hash = implode(",", $ipsec_hash_array);
            unset($ipsec_hash_array);
        }
        else {
            $ipsec_hash = "";
        }

        $projectdb->query("INSERT INTO global_protect_app_ipsec_crypto_profiles (vsys, source, template, name, encryption, hash) VALUES ('$vsys','$source','$template','$global_protect_app_crypto_name','$ipsec_encryption','$ipsec_hash');");
    }
}

function xml_add_admin_role($projectdb,$profiles,$source,$template){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $theProfileName = $profilesArray->attributes()->name;
        $theProfilecontent = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$theProfileName','$theProfilecontent','$template')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO admin_role (source,name,xml,template) VALUES ".implode(",", $sql));
        unset($sql);
    }
}

function xml_add_gp_portal($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$devicegroup','global-protect-portal','$vsys')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO global_protect_portal (source,name,xml,devicegroup,type,vsys) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_gp_gateway($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$devicegroup','global-protect-gateway','$vsys')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO global_protect_gateway (source,name,xml,devicegroup,type,vsys) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_gp_mdm($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $GroupName = $profilesArray->attributes()->name;
        $content = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$GroupName','$content','$devicegroup','global-protect-mdm','$vsys')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO global_protect_mdm (source,name,xml,devicegroup,type,vsys) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_profiles($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        foreach ($profilesArray as $profilesType => $profilesArrayEntry) {
            $theProfileType = $profilesType;
            foreach ($profilesArrayEntry as $entry => $profileArrayEntryContent) {
                $theProfileName = $profileArrayEntryContent->attributes()->name;
                $theProfilecontent = addslashes($profileArrayEntryContent->asXML());
                $getDup = $projectdb->query("SELECT id FROM profiles WHERE source='$source' AND name='$theProfileName' AND type='$theProfileType' AND vsys='$vsys'");
                if ($getDup->num_rows == 0) {
                    $sql[] = "('$source','$theProfileName','$theProfilecontent','$theProfileType','$devicegroup','$vsys')";
                }
            }
        }
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO profiles (source,name,xml,type,devicegroup, vsys) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_profiles_groups($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        $theProfileName = $profilesArray->attributes()->name;
        $theProfilecontent = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$theProfileName','$theProfilecontent','','$devicegroup','$vsys')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO profiles_groups (source,name,xml,type,devicegroup,vsys) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_regions($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();$longitude="";$latitude="";$regionMemberArray2="";
    foreach ($profiles as $key => $profilesArray) {
        $theProfileName = $profilesArray->attributes()->name;
        $regionMemberArray=array();
        if (isset($profilesArray->address)){
            foreach($profilesArray->address->member as $regionMember){
                $regionMemberArray[]=$regionMember;
            }
            asort($regionMemberArray);
            $regionMemberArray2=implode(",",$regionMemberArray);
        }
        if (isset($profilesArray->{'geo-location'})){
            $latitude=$profilesArray->{'geo-location'}->latitude;
            $longitude=$profilesArray->{'geo-location'}->longitude;
        }
        $sql[] = "('$source','$theProfileName','$vsys','$devicegroup','$regionMemberArray2','$latitude','$longitude')";
        $longitude="";$latitude="";$regionMemberArray2="";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO regions (source,name,vsys,devicegroup,address,latitude,longitude) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_external_lists($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
        if (isset($profilesArray->type->ip)){
            $profileType="ip";
        }
        elseif (isset($profilesArray->type->url)){
            $profileType="url";
        }
        elseif (isset($profilesArray->type->domain)){
            $profileType="domain";
        }
        else{
            $profileType="ip";
        }
        $theProfileName = $profilesArray->attributes()->name;
        $theProfilecontent = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$theProfileName','$theProfilecontent','$devicegroup','$profileType','$vsys')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO external_list (source,name,xml,devicegroup,type,vsys) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_custom_url_category($projectdb,$profiles,$source,$vsys,$devicegroup){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {

        $theProfileName = $profilesArray->attributes()->name;
        $theProfilecontent = addslashes($profilesArray->asXML());
        $sql[] = "('$source','$theProfileName','$theProfileName','$theProfilecontent','$devicegroup','custom_url_category','$vsys')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO custom_url_category (source,name,name_ext,xml,devicegroup,type,vsys) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function xml_add_reports($projectdb,$profiles,$source,$vsys){
    $sql = array();
    foreach ($profiles as $key => $profilesArray) {
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
        $report_description="";
        if (isset($profilesArray->type)) {
            $report_type = addslashes($profilesArray->type->asXML());
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
        if (isset($profilesArray->{'description'})) {
            $report_description = addslashes($profilesArray->{'description'});
        }
        $sql[] = "('$source','$theProfileName','$report_type','$report_period','$report_topn','$report_topm','$report_caption','$report_starttime','$report_endtime','$report_query','$report_frequency','$vsys','$report_description')";
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO reports (source,name,type,period,topn,topm,caption,starttime,endtime,query,frequency,vsys,description) VALUES ".implode(",", $sql).";");
        unset($sql);
    }
}

function pan_read_rules_pbf_other_rules($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;
    if (isset($address[0]->rules)) {
        foreach ($address[0]->rules as $data) {
            $rule_type = "pbf";
            $pbf = addslashes($data->asXML());
            if ($pbf != "<rules/>") {
                $projectdb->query("INSERT INTO other_rules (source,vsys,type,xml,preorpost) VALUES ('$source','$vsys','$rule_type','$pbf','$preorpost');");
            }
        }
    }
}


function pan_read_rules_pbf($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $urldb, &$objectsInMemory) {
    global $projectdb;

    # Init vars
    $lid = "";
    $pbfrules = array();
    $pbfrulesfrom = array();
    $pbfrulestag = array();
    $pbfrulesusr = array();
    $pbfrulessrc = array();
    $pbfrulesdst = array();
    $pbfrulesapp = array();
    $pbfrulessrv = array();
    $addTarget = array();
    $myArray = array();
    $member_name_array = array();
    $schedulesA = array();
    $myArray_srv = array();
    $member_name_array_srv = array();
    $myArray_app = array();
    $member_name_array_app = array();
    $myArray_tag = array();
    $member_name_array_tag = array();

    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM pbf_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM pbf_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {

        # Initialize vars
        $disabled = "0";
        $negate_source = 0;
        $negate_destination = 0;
        $schedule = "";
        $target = "";
        $target_negate = "no";
        $action = "";
        $enforce_symmetric_return = "";
        $from_type = "";
        $monitor_profile = "";
        $disable_if_unreachable = "";
        $ip_address = "";
        $nexthop = "";
        $egress_interface = "";
        $group_tag_id = "";

        # Start Reading Rule
        $name_ext = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $name_int = $name_ext;
        $description = addslashes($data->description);


        if ($data->disabled == "yes") {$disabled = "1";}
        if ($data->{'negate-source'} == "yes") {$negate_source = 1;}
        if ($data->{'negate-destination'} == "yes") {$negate_destination = 1;}

        if (isset($data->schedule)) {
            $schedule = (string) $data->schedule;
            $schedulesA[] = $schedule;
        }

        if (isset($data->{'action'})) {
            //$action = $data->{'action'}->asXML();
            if($data->{'action'}->{'discard'}){
                $action = "discard";
            }else if($data->{'action'}->{'forward'}){
                $action = "forward";
            }else if($data->{'action'}->{'no-pbf'}){
                $action = "no-pbf";
            }
            else if($data->{'action'}->{'forward-to-vsys'}){
                $action = "forward-to-vsys;".$data->{'action'}->{'forward-to-vsys'};
            }
        }

        if(isset($data->action->forward)){
            if(isset($data->action->forward->monitor)) {

                $monitor_profile = $data->action->forward->monitor->profile;

                if(isset($data->action->forward->monitor->{'disable-if-unreachable'})){
                    $disable_if_unreachable = $data->action->forward->monitor->{'disable-if-unreachable'};
                }

                if(isset($data->action->forward->monitor->{'ip-address'})){
                    $ip_address = $data->action->forward->monitor->{'ip-address'};
                }
            }

            if(isset($data->action->forward->nexthop)){
                $nexthop = $data->action->forward->nexthop->asXML();
            }

            if(isset($data->action->forward->{'egress-interface'})){
                $egress_interface = $data->action->forward->{'egress-interface'};
            }
        }

        if (isset($data->{'enforce-symmetric-return'})) {
            $enforce_symmetric_return = $data->{'enforce-symmetric-return'}->asXML();
        }

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate=$data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$new_vsys','$lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$new_vsys','$lid','$deviceName','')";
                    }
                }
            }
        }

        foreach ($data->from->zone as $k => $zone_member) {
            $from_type = "zone";
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $pbfrulesfrom[] = "('$source','$new_vsys','$memberA','$lid', 'zone','$devicegroup')";
                }
            }
        }

        foreach ($data->from->interface as $k => $interface_member) {
            $from_type = "interface";
            foreach ($interface_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $pbfrulesfrom[] = "('$source','$new_vsys','$memberA','$lid', 'interface','$devicegroup')";
                }
            }
        }

        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $new_vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }

        foreach ($data->{'source-user'} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $memberB = addslashes($memberA);
                    $pbfrulesusr[] = "('$source','$new_vsys','$memberB','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["src"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["dst"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        if(isset($data->application->member)) {
            foreach ($data->application->member as $k => $memberA) {
                $memberA = (string)$memberA;
                if (($memberA == "") or ($memberA == "any")) {
                } else {
                    $myArray_app[$memberA]["lid"][] = $lid;
                    $member_name_array_app[] = $memberA;
                }

            }
        }

        foreach ($data->service->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray_srv[$memberA]["lid"][]=$lid;
                $member_name_array_srv[]=$memberA;
            }
        }

        $pbfrules[] = "('$target_negate','$target','$preorpost','$position','$lid','$negate_source','$negate_destination', '$enforce_symmetric_return', '$description','$name_ext','$name_int','$action','$schedule','$disabled','$new_vsys','$source','$devicegroup', '$from_type', '$monitor_profile', '$disable_if_unreachable', '$ip_address', '$nexthop', '$egress_interface', '$uuid', '$group_tag_id')";

        $lid++;
        $position++;
    }

    # Mapping Sources and Destination
    $calculate = calculate_members_and_table_from_memory("policy","address",$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray as $pos=>$lidArray){
                if ($pos=="src"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $pbfrulessrc[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
                elseif ($pos=="dst"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $pbfrulesdst[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Services
    $calculate = calculate_members_and_table_from_memory("policy","service",$myArray_srv,$new_vsys,$source,$devicegroup,$member_name_array_srv, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $pbfrulessrv[] = "('$source','$new_vsys','$table_name','$member_lid','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Applications
    $calculate = calculate_members_and_table_from_memory("policy","application",$myArray_app,$new_vsys,$source,$devicegroup,$member_name_array_app, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $pbfrulesapp[] = "('$source','$new_vsys','$lid','$table_name','$member_lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate = calculate_members_and_table_from_memory("policy","tag",$myArray_tag,$new_vsys,$source,$devicegroup,$member_name_array_tag, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $pbfrulestag[] = "('$source','$member_lid','$table_name','$new_vsys','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Create Dummy for Schedules
    calculate_members_and_table_from_memory("policy","schedule",'',$new_vsys,$source,$devicegroup,$schedulesA, $version,$objectsInMemory);

    # INSERT PBF RULES INTO DB
    if (count($pbfrules) > 0) {
        $projectdb->query("INSERT INTO pbf_rules (target_negate,target,preorpost,position,id,negate_source,negate_destination, enforce_symmetric_return, description,name_ext,name,action,schedule,disabled,vsys,source,devicegroup, from_type, monitor_profile, monitor_disable_if_unreachable, monitor_ipaddress, nexthop, egress_interface, uuid, group_tag_id) VALUES " . implode(",", $pbfrules) . ";");
        unset($pbfrules);

        if (count($pbfrulesfrom) > 0) {
            $projectdb->query("INSERT INTO pbf_rules_from (source,vsys,name,rule_lid,type,devicegroup) VALUES " . implode(",", $pbfrulesfrom) . ";");
            unset($pbfrulesfrom);
        }
        if (count($pbfrulestag) > 0) {
            $projectdb->query("INSERT INTO pbf_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $pbfrulestag) . ";");
            unset($pbfrulestag);
        }
        if (count($pbfrulesusr) > 0) {
            $projectdb->query("INSERT INTO pbf_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $pbfrulesusr) . ";");
            unset($pbfrulesusr);
        }
        if (count($pbfrulessrc) > 0) {
            $projectdb->query("INSERT INTO pbf_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $pbfrulessrc) . ";");
            unset($pbfrulessrc);
        }
        if (count($pbfrulesdst) > 0) {
            $projectdb->query("INSERT INTO pbf_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $pbfrulesdst) . ";");
            unset($pbfrulesdst);
        }
        if (count($pbfrulesapp) > 0) {
            $projectdb->query("INSERT INTO pbf_rules_app (source,vsys,rule_lid,table_name,member_lid,devicegroup) VALUES " . implode(",", $pbfrulesapp) . ";");
            unset($pbfrulesapp);
        }
        if (count($pbfrulessrv) > 0) {
            $projectdb->query("INSERT INTO pbf_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $pbfrulessrv) . ";");
            unset($pbfrulessrv);
        }
        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO pbf_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}



function pan_read_rules_decryption_other_rules($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;
    if (isset($address[0]->rules)) {
        foreach ($address[0]->rules as $data) {
            $rule_type = "decryption";
            $pbf = addslashes($data->asXML());
            if ($pbf != "<rules/>") {
                $projectdb->query("INSERT INTO other_rules (source,vsys,type,xml,preorpost) VALUES ('$source','$vsys','$rule_type','$pbf','$preorpost');");
            }
        }
    }
}


function pan_read_rules_decryption($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $urldb, &$objectsInMemory) {
    global $projectdb;

    # Init vars
    $lid = "";
    $decrules = array();
    $decrulesfrom = array();
    $decrulesto = array();
    $decrulestag = array();
    $decrulesusr = array();
    $decrulescategories = array();
    $decrulessrc = array();
    $decrulesdst = array();
    $decrulessrv = array();
    $addTarget = array();
    $myArray=array();
    $member_name_array=array();
    $myArray_srv=array();
    $member_name_array_srv=array();
    $myArray_tag=array();
    $member_name_array_tag=array();
    $log_forwardingsA = array();

    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM decryption_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM decryption_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {

        # Initialize vars
        $disabled = "0";
        $negate_source = 0;
        $negate_destination = 0;
        $type = "";
        $profile = "";

        $target = "";
        $target_negate = "no";
        # Start Reading Rule
        $name_ext = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $name_int = $name_ext;
        $action = $data->action;
        $log_forwarding = "";
        $description = addslashes($data->description);
        $type_content = "";
        $group_tag_id = "";

        if ($data->disabled == "yes") {$disabled = "1";}
        if ($data->{'negate-source'} == "yes") {$negate_source = 1;}
        if ($data->{'negate-destination'} == "yes") {$negate_destination = 1;}

        if (isset($data->profile)) {
            $profile = $data->profile;
        }

        if (isset($data->{'type'})) {
            //$type = $data->{'type'}->asXML();
            $type = $data->{'type'};
            if($data->{'type'}->{'ssl-forward-proxy'}){
                $type = "ssl-forward-proxy";
            }else if($data->{'type'}->{'ssl-inbound-inspection'}){
                $type = "ssl-inbound-inspection";
                $type_content = $data->{'type'}->{'ssl-inbound-inspection'};
            }else if ($data->{'type'}->{'ssh-proxy'}){
                $type = "ssh-proxy";
            }
        }

        if (isset($data->{'log-setting'})) {
            $log_forwarding = $data->{'log-setting'};
            $log_forwardingsA[]=$log_forwarding;
        }

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate=$data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$new_vsys','$lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$new_vsys','$lid','$deviceName','')";
                    }
                }
            }
        }

        foreach ($data->from as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $decrulesfrom[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->to as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $decrulesto[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $new_vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }

        foreach ($data->{'source-user'} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $memberB = addslashes($memberA);
                    $decrulesusr[] = "('$source','$new_vsys','$memberB','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->category as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $decrulescategories[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["src"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["dst"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->service->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray_srv[$memberA]["lid"][]=$lid;
                $member_name_array_srv[]=$memberA;
            }
        }


        $decrules[] = "('$target_negate','$target','$preorpost','$position','$lid','$negate_source','$negate_destination','$description','$name_ext','$name_int','$action','$profile','$disabled','$new_vsys','$source','$devicegroup', '$type', '$type_content', '$log_forwarding', '$uuid', '$group_tag_id')";
        $lid++;
        $position++;
    }

    # Mapping Sources and Destination
    $calculate = calculate_members_and_table_from_memory("policy","address",$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray as $pos=>$lidArray){
                if ($pos=="src"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $decrulessrc[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
                elseif ($pos=="dst"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $decrulesdst[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Services
    $calculate = calculate_members_and_table_from_memory("policy","service",$myArray_srv,$new_vsys,$source,$devicegroup,$member_name_array_srv, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $decrulessrv[] = "('$source','$new_vsys','$table_name','$member_lid','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate = calculate_members_and_table_from_memory("policy","tag",$myArray_tag,$new_vsys,$source,$devicegroup,$member_name_array_tag, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $decrulestag[] = "('$source','$member_lid','$table_name','$new_vsys','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Create Dummy for Log FWD Profiles
    calculate_members_and_table_from_memory("policy","log_setting",'',$new_vsys,$source,$devicegroup,$log_forwardingsA, $version,$objectsInMemory);


    # INSERT DECRYPTION RULES INTO DB
    if (count($decrules) > 0) {
        $projectdb->query("INSERT INTO decryption_rules (target_negate,target,preorpost,position,id,negate_source,negate_destination,description,name_ext,name,action,profile,disabled,vsys,source,devicegroup, type, type_content,log_forwarding, uuid, group_tag_id) VALUES " . implode(",", $decrules) . ";");
        unset($decrules);

        if (count($decrulesfrom) > 0) {
            $projectdb->query("INSERT INTO decryption_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $decrulesfrom) . ";");
            unset($decrulesfrom);
        }
        if (count($decrulesto) > 0) {
            $projectdb->query("INSERT INTO decryption_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $decrulesto) . ";");
            unset($decrulesto);
        }
        if (count($decrulestag) > 0) {
            $projectdb->query("INSERT INTO decryption_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $decrulestag) . ";");
            unset($decrulestag);
        }
        if (count($decrulesusr) > 0) {
            $projectdb->query("INSERT INTO decryption_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $decrulesusr) . ";");
            unset($decrulesusr);
        }
        if (count($decrulescategories) > 0) {
            $projectdb->query("INSERT INTO decryption_rules_categories (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $decrulescategories) . ";");
            unset($decrulescategories);
        }
        if (count($decrulessrc) > 0) {
            $projectdb->query("INSERT INTO decryption_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $decrulessrc) . ";");
            unset($decrulessrc);
        }
        if (count($decrulesdst) > 0) {
            $projectdb->query("INSERT INTO decryption_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $decrulesdst) . ";");
            unset($decrulesdst);
        }
        if (count($decrulessrv) > 0) {
            $projectdb->query("INSERT INTO decryption_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $decrulessrv) . ";");
            unset($decrulessrv);
        }

        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO decryption_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}



function pan_read_rules_qos_other_rules($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;
    if (isset($address[0]->rules)) {
        foreach ($address[0]->rules as $data) {
            $rule_type = "qos";
            $pbf = addslashes($data->asXML());
            if ($pbf != "<rules/>") {
                $projectdb->query("INSERT INTO other_rules (source,vsys,type,xml,preorpost) VALUES ('$source','$vsys','$rule_type','$pbf','$preorpost');");
            }
        }
    }
}


function pan_read_rules_qos($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $urldb, &$objectsInMemory) {
    global $projectdb;

    # Init vars
    $lid = "";
    $qosrules = array();
    $qosrulesfrom = array();
    $qosrulesto = array();
    $qosrulestag = array();
    $qosrulesusr = array();
    $qosrulescategories = array();
    $qosruleship = array();
    $qosrulessrc = array();
    $qosrulesdst = array();
    $qosrulesapp = array();
    $qosrulessrv = array();
    $addTarget = array();
    $myArray = array();
    $member_name_array = array();
    $schedulesA = array();
    $myArray_srv = array();
    $member_name_array_srv = array();
    $myArray_app = array();
    $member_name_array_app = array();
    $myArray_tag = array();
    $member_name_array_tag = array();

    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM qos_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM qos_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {

        # Initialize vars
        $dscp_tos = "yes";
        $disabled = "0";
        $negate_source = 0;
        $negate_destination = 0;
        $schedule = "";
        $target = "";
        $target_negate="no";
        $group_tag_id = "";
        # Start Reading Rule
        $name_ext = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $name_int = $name_ext;
        $action = $data->action->class;
        $description = addslashes($data->description);

        if ($data->disabled == "yes") {$disabled = "1";}
        if ($data->{'negate-source'} == "yes") {$negate_source = 1;}
        if ($data->{'negate-destination'} == "yes") {$negate_destination = 1;}

        if (isset($data->schedule)) {
            $schedule = (string) $data->schedule;
            $schedulesA[] = $schedule;
        }

        if (isset($data->{'dscp-tos'})) {
            $codepoints = $data->{'dscp-tos'}->asXML();
        }

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate = $data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$new_vsys','$lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$new_vsys','$lid','$deviceName','')";
                    }
                }
            }
        }

        foreach ($data->from as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $qosrulesfrom[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->to as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $qosrulesto[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $new_vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }

        foreach ($data->{'source-user'} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $memberB = addslashes($memberA);
                    $qosrulesusr[] = "('$source','$new_vsys','$memberB','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->category as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $qosrulescategories[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["src"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["dst"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->application->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else {
                $myArray_app[$memberA]["lid"][]=$lid;
                $member_name_array_app[]=$memberA;
            }

        }

        foreach ($data->service->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray_srv[$memberA]["lid"][]=$lid;
                $member_name_array_srv[]=$memberA;
            }
        }

        $qosrules[] = "('$target_negate','$target','$preorpost','$position','$lid','$negate_source','$negate_destination','$description','$name_ext','$name_int','$action','$schedule','$disabled','$new_vsys','$source','$devicegroup', '$dscp_tos', '$codepoints', '$uuid', '$group_tag_id')";
        $lid++;
        $position++;
    }

    # Mapping Sources and Destination
    $calculate = calculate_members_and_table_from_memory("policy","address",$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray as $pos=>$lidArray){
                if ($pos=="src"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $qosrulessrc[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
                elseif ($pos=="dst"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $qosrulesdst[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Services
    $calculate = calculate_members_and_table_from_memory("policy","service",$myArray_srv,$new_vsys,$source,$devicegroup,$member_name_array_srv, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $qosrulessrv[] = "('$source','$new_vsys','$table_name','$member_lid','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Applications
    $calculate = calculate_members_and_table_from_memory("policy","application",$myArray_app,$new_vsys,$source,$devicegroup,$member_name_array_app, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $qosrulesapp[] = "('$source','$new_vsys','$lid','$table_name','$member_lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate = calculate_members_and_table_from_memory("policy","tag",$myArray_tag,$new_vsys,$source,$devicegroup,$member_name_array_tag, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $qosrulestag[] = "('$source','$member_lid','$table_name','$new_vsys','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Create Dummy for Schedules
    calculate_members_and_table_from_memory("policy","schedule",'',$new_vsys,$source,$devicegroup,$schedulesA, $version,$objectsInMemory);

    # INSERT QOS RULES INTO DB
    if (count($qosrules) > 0) {
        $projectdb->query("INSERT INTO qos_rules (target_negate,target,preorpost,position,id,negate_source,negate_destination,description,name_ext,name,action,schedule,disabled,vsys,source,devicegroup, dscp_tos, codepoints, uuid, group_tag_id) VALUES " . implode(",", $qosrules) . ";");
        unset($qosrules);

        if (count($qosrulesfrom) > 0) {
            $projectdb->query("INSERT INTO qos_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $qosrulesfrom) . ";");
            unset($qosrulesfrom);
        }
        if (count($qosrulesto) > 0) {
            $projectdb->query("INSERT INTO qos_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $qosrulesto) . ";");
            unset($qosrulesto);
        }
        if (count($qosrulestag) > 0) {
            $projectdb->query("INSERT INTO qos_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $qosrulestag) . ";");
            unset($qosrulestag);
        }
        if (count($qosrulesusr) > 0) {
            $projectdb->query("INSERT INTO qos_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $qosrulesusr) . ";");
            unset($qosrulesusr);
        }
        if (count($qosrulescategories) > 0) {
            $projectdb->query("INSERT INTO qos_rules_categories (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $qosrulescategories) . ";");
            unset($qosrulescategories);
        }
        if (count($qosruleship) > 0) {
            $projectdb->query("INSERT INTO qos_rules_hip (source,member_lid,table_name,vsys,rule_lid,devicegroup,name) VALUES " . implode(",", $qosruleship) . ";");
            unset($qosruleship);
        }
        if (count($qosrulessrc) > 0) {
            $projectdb->query("INSERT INTO qos_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $qosrulessrc) . ";");
            unset($qosrulessrc);
        }
        if (count($qosrulesdst) > 0) {
            $projectdb->query("INSERT INTO qos_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $qosrulesdst) . ";");
            unset($qosrulesdst);
        }
        if (count($qosrulesapp) > 0) {
            $projectdb->query("INSERT INTO qos_rules_app (source,vsys,rule_lid,table_name,member_lid,devicegroup) VALUES " . implode(",", $qosrulesapp) . ";");
            unset($qosrulesapp);
        }
        if (count($qosrulessrv) > 0) {
            $projectdb->query("INSERT INTO qos_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $qosrulessrv) . ";");
            unset($qosrulessrv);
        }

        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO qos_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}



function pan_read_rules_captiveportal_other_rules($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;
    if (isset($address[0]->rules)) {
        foreach ($address[0]->rules as $data) {
            $rule_type = "captive-portal";
            $pbf = addslashes($data->asXML());
            if ($pbf != "<rules/>") {
                $projectdb->query("INSERT INTO other_rules (source,vsys,type,xml,preorpost) VALUES ('$source','$vsys','$rule_type','$pbf','$preorpost');");
            }
        }
    }
}

function pan_read_rules_dos_other_rules($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;
    if (isset($address[0]->rules)) {
        foreach ($address[0]->rules as $data) {
            $rule_type = "dos";
            $pbf = addslashes($data->asXML());
            if ($pbf != "<rules/>") {
                $projectdb->query("INSERT INTO other_rules (source,vsys,type,xml,preorpost) VALUES ('$source','$vsys','$rule_type','$pbf','$preorpost');");
            }
        }
    }
}


function pan_read_rules_dos($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $urldb, &$objectsInMemory) {
    global $projectdb;

    # Init vars
    $lid = "";
    $dosrules = array();
    $dosrulesfrom = array();
    $dosrulesto = array();
    $dosrulestag = array();
    $dosrulesusr = array();
    $dosrulessrc = array();
    $dosrulesdst = array();
    $dosrulessrv = array();
    $addTarget = array();
    $myArray = array();
    $member_name_array = array();
    $schedulesA = array();
    $myArray_srv = array();
    $member_name_array_srv = array();
    $myArray_app = array();
    $member_name_array_app = array();
    $myArray_tag = array();
    $member_name_array_tag = array();
    $log_forwardingsA = array();

    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM dos_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM dos_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {

        # Initialize vars
        $disabled = "0";
        $negate_source = 0;
        $negate_destination = 0;
        $schedule = "";
        $target = "";
        $target_negate = "no";
        $action = "";
        $protection = "";
        $from_type = "";
        $to_type = "";
        $log_forwarding = "";
        $group_tag_id = "";

        # Start Reading Rule
        $name_ext = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $name_int = $name_ext;
        $description = addslashes($data->description);

        if ($data->disabled == "yes") {$disabled = "1";}
        if ($data->{'negate-source'} == "yes") {$negate_source = 1;}
        if ($data->{'negate-destination'} == "yes") {$negate_destination = 1;}

        if (isset($data->schedule)) {
            $schedule = (string) $data->schedule;
            $schedulesA[] = $schedule;
        }

        if (isset($data->{'action'})) {
            //$action = $data->{'action'}->asXML();
            if($data->{'action'}->{'deny'}){
                $action = "deny";
            }else if($data->{'action'}->{'protect'}){
                $action = "protect";
            }else if($data->{'action'}->{'allow'}){
                $action = "allow";
            }
        }

        if (isset($data->protection)) {
            $protection = $data->protection->asXML();
        }

        if (isset($data->{'log-setting'})) {
            $log_forwarding = $data->{'log-setting'};
            $log_forwardingsA[]=$log_forwarding;
        }

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate=$data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$new_vsys','$lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$new_vsys','$lid','$deviceName','')";
                    }
                }
            }
        }

        foreach ($data->from->zone as $k => $zone_member) {
            $from_type = "zone";
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $dosrulesfrom[] = "('$source','$new_vsys','$memberA','$lid', 'zone','$devicegroup')";
                }
            }
        }

        foreach ($data->from->interface as $k => $interface_member) {
            $from_type = "interface";
            foreach ($interface_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $dosrulesfrom[] = "('$source','$new_vsys','$memberA','$lid', 'interface','$devicegroup')";
                }
            }
        }

        foreach ($data->to->zone as $k => $zone_member) {
            $to_type = "zone";
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $dosrulesto[] = "('$source','$new_vsys','$memberA','$lid', 'zone','$devicegroup')";
                }
            }
        }

        foreach ($data->to->interface as $k => $interface_member) {
            $from_to = "interface";
            foreach ($interface_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $dosrulesto[] = "('$source','$new_vsys','$memberA','$lid', 'interface','$devicegroup')";
                }
            }
        }

        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $new_vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }

        foreach ($data->{'source-user'} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $memberB = addslashes($memberA);
                    $dosrulesusr[] = "('$source','$new_vsys','$memberB','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["src"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["dst"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->service->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray_srv[$memberA]["lid"][]=$lid;
                $member_name_array_srv[]=$memberA;
            }
        }

        $dosrules[] = "('$target_negate','$target','$preorpost','$position','$lid','$negate_source','$negate_destination', '$protection', '$description','$name_ext','$name_int','$action','$schedule','$disabled','$new_vsys','$source','$devicegroup', '$from_type', '$to_type', '$log_forwarding', '$uuid', '$group_tag_id')";
        $lid++;
        $position++;
    }

    # Mapping Sources and Destination
    $calculate = calculate_members_and_table_from_memory("policy","address",$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray as $pos=>$lidArray){
                if ($pos=="src"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $dosrulessrc[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
                elseif ($pos=="dst"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $dosrulesdst[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Services
    $calculate = calculate_members_and_table_from_memory("policy","service",$myArray_srv,$new_vsys,$source,$devicegroup,$member_name_array_srv, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $dosrulessrv[] = "('$source','$new_vsys','$table_name','$member_lid','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate = calculate_members_and_table_from_memory("policy","tag",$myArray_tag,$new_vsys,$source,$devicegroup,$member_name_array_tag, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $dosrulestag[] = "('$source','$member_lid','$table_name','$new_vsys','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Create Dummy for Schedules
    calculate_members_and_table_from_memory("policy","schedule",'',$new_vsys,$source,$devicegroup,$schedulesA, $version,$objectsInMemory);

    # Create Dummy for Log FWD Profiles
    calculate_members_and_table_from_memory("policy","log_setting",'',$new_vsys,$source,$devicegroup,$log_forwardingsA, $version,$objectsInMemory);

    # INSERT PBF RULES INTO DB
    if (count($dosrules) > 0) {
        $projectdb->query("INSERT INTO dos_rules (target_negate,target,preorpost,position,id,negate_source,negate_destination, protection, description,name_ext,name,action,schedule,disabled,vsys,source,devicegroup, from_type, to_type, log_forwarding, uuid, group_tag_id) VALUES " . implode(",", $dosrules) . ";");
        unset($dosrules);

        if (count($dosrulesfrom) > 0) {
            $projectdb->query("INSERT INTO dos_rules_from (source,vsys,name,rule_lid,type,devicegroup) VALUES " . implode(",", $dosrulesfrom) . ";");
            unset($dosrulesfrom);
        }
        if (count($dosrulesto) > 0) {
            $projectdb->query("INSERT INTO dos_rules_to (source,vsys,name,rule_lid,type,devicegroup) VALUES " . implode(",", $dosrulesto) . ";");
            unset($dosrulesto);
        }
        if (count($dosrulestag) > 0) {
            $projectdb->query("INSERT INTO dos_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $dosrulestag) . ";");
            unset($dosrulestag);
        }
        if (count($dosrulesusr) > 0) {
            $projectdb->query("INSERT INTO dos_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $dosrulesusr) . ";");
            unset($dosrulesusr);
        }
        if (count($dosrulessrc) > 0) {
            $projectdb->query("INSERT INTO dos_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $dosrulessrc) . ";");
            unset($dosrulessrc);
        }
        if (count($dosrulesdst) > 0) {
            $projectdb->query("INSERT INTO dos_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $dosrulesdst) . ";");
            unset($dosrulesdst);
        }
        if (count($dosrulessrv) > 0) {
            $projectdb->query("INSERT INTO dos_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $dosrulessrv) . ";");
            unset($dosrulessrv);
        }
        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO dos_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}


function pan_read_rules_default($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;
    if (isset($address[0]->rules)) {
        foreach ($address[0]->rules as $data) {
            $rule_type = "default-security-rules";
            $pbf = addslashes($data->asXML());
            if ($pbf != "<rules/>") {
                $projectdb->query("INSERT INTO other_rules (source,vsys,type,xml,preorpost) VALUES ('$source','$vsys','$rule_type','$pbf','$preorpost');");
            }
        }
    }
}

function pan_read_rules_tunnel_inspect_other_rules($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;
    if (isset($address[0]->rules)) {
        foreach ($address[0]->rules as $data) {
            $rule_type = "tunnel-inspect";
            $pbf = addslashes($data->asXML());
            if ($pbf != "<rules/>") {
                $projectdb->query("INSERT INTO other_rules (source,vsys,type,xml,preorpost) VALUES ('$source','$vsys','$rule_type','$pbf','$preorpost');");
            }
        }
    }
}


function pan_read_rules_tunnel_inspect($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $urldb, &$objectsInMemory) {
    global $projectdb;

    # Init vars
    $lid = "";
    $tunnelrules = array();
    $tunnelrulesfrom = array();
    $tunnelrulesto = array();
    $tunnelrulestag = array();
    $tunnelrulesusr = array();
    $tunnelrulessrc = array();
    $tunnelrulesdst = array();
    $tunnelrulesapp = array();
    $addTarget = array();
    $myArray = array();
    $member_name_array = array();
    $myArray_app = array();
    $member_name_array_app = array();
    $myArray_tag = array();
    $member_name_array_tag = array();
    $log_forwardingsA = array();

    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM tunnel_inspect_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM tunnel_inspect_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {

        # Initialize vars
        $disabled = "0";
        $negate_source = 0;
        $negate_destination = 0;
        $target = "";
        $target_negate="no";
        $group_tag_id = "";
        # Start Reading Rule
        $name_ext = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $name_int = $name_ext;
        $monitor_options = "";
        $inspect_options = "";
        $log_forwarding = "";
        $enable_log_setting = "";
        $log_start_log_setting = "";
        $log_end_log_setting = "";
        $monitor_name_tunnel = "";
        $monitor_id_tunnel = "";

        $description = addslashes($data->description);

        if ($data->disabled == "yes") {$disabled = "1";}
        if ($data->{'negate-source'} == "yes") {$negate_source = 1;}
        if ($data->{'negate-destination'} == "yes") {$negate_destination = 1;}

        if (isset($data->{'monitor-options'})) {

            if (isset($data->{'monitor-options'}->{'log-setting-override'}->{'log-setting'})) {
                $log_forwarding = $data->{'monitor-options'}->{'log-setting-override'}->{'log-setting'};
                $log_forwardingsA[] = $log_forwarding;
            }

            if (isset($data->{'monitor-options'}->{'log-setting-override'}->enable)) {
                $enable_log_setting = $data->{'monitor-options'}->{'log-setting-override'}->enable;
            }

            if (isset($data->{'monitor-options'}->{'log-setting-override'}->{'log-start'})) {
                $log_start_log_setting = $data->{'monitor-options'}->{'log-setting-override'}->{'log-start'};
            }

            if (isset($data->{'monitor-options'}->{'log-setting-override'}->{'log-end'})) {
                $log_end_log_setting = $data->{'monitor-options'}->{'log-setting-override'}->{'log-end'};
            }

            if (isset($data->{'monitor-options'}->{'monitor-name'})) {
                $monitor_name_tunnel = $data->{'monitor-options'}->{'monitor-name'};
            }

            if (isset($data->{'monitor-options'}->{'monitor-id'})) {
                $monitor_id_tunnel = $data->{'monitor-options'}->{'monitor-id'};
            }
            //$monitor_options = $data->{'monitor-options'}->asXML();
        }

        if (isset($data->{'inspect-options'})) {
            $inspect_options = $data->{'inspect-options'}->asXML();
        }

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate = $data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$new_vsys','$lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$new_vsys','$lid','$deviceName','')";
                    }
                }
            }
        }

        foreach ($data->from as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $tunnelrulesfrom[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->to as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $tunnelrulesto[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $new_vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }


        foreach ($data->{'source-user'} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $memberB = addslashes($memberA);
                    $tunnelrulesusr[] = "('$source','$new_vsys','$memberB','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["src"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["dst"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->application->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else {
                $myArray_app[$memberA]["lid"][]=$lid;
                $member_name_array_app[]=$memberA;
            }

        }

        $tunnelrules[] = "('$target_negate','$target','$preorpost','$position','$lid','$negate_source','$negate_destination','$description','$name_ext','$name_int','$disabled','$new_vsys','$source','$devicegroup', '$inspect_options', '$log_forwarding', '$enable_log_setting', '$log_start_log_setting', '$log_end_log_setting', '$monitor_name_tunnel', '$monitor_id_tunnel', '$uuid', '$group_tag_id')";
        $lid++;
        $position++;
    }

    # Mapping Sources and Destination
    $calculate = calculate_members_and_table_from_memory("policy","address",$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray as $pos=>$lidArray){
                if ($pos=="src"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $tunnelrulessrc[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
                elseif ($pos=="dst"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $tunnelrulesdst[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Applications
    $calculate = calculate_members_and_table_from_memory("policy","application",$myArray_app,$new_vsys,$source,$devicegroup,$member_name_array_app, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $tunnelrulesapp[] = "('$source','$new_vsys','$lid','$table_name','$member_lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate = calculate_members_and_table_from_memory("policy","tag",$myArray_tag,$new_vsys,$source,$devicegroup,$member_name_array_tag, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $tunnelrulestag[] = "('$source','$member_lid','$table_name','$new_vsys','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Create Dummy for Log FWD Profiles
    calculate_members_and_table_from_memory("policy","log_setting",'',$new_vsys,$source,$devicegroup,$log_forwardingsA, $version,$objectsInMemory);


    # INSERT TUNNEL INSPECT RULES INTO DB
    if (count($tunnelrules) > 0) {
        $projectdb->query("INSERT INTO tunnel_inspect_rules (target_negate,target,preorpost,position,id,negate_source,negate_destination,description,name_ext,name,disabled,vsys,source,devicegroup, inspect_options, log_forwarding, enable_log_setting, log_start_log_setting, log_end_log_setting, monitor_name_tunnel, monitor_id_tunnel, uuid, group_tag_id) VALUES " . implode(",", $tunnelrules) . ";");
        unset($tunnelrules);

        if (count($tunnelrulesfrom) > 0) {
            $projectdb->query("INSERT INTO tunnel_inspect_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $tunnelrulesfrom) . ";");
            unset($tunnelrulesfrom);
        }
        if (count($tunnelrulesto) > 0) {
            $projectdb->query("INSERT INTO tunnel_inspect_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $tunnelrulesto) . ";");
            unset($tunnelrulesto);
        }
        if (count($tunnelrulestag) > 0) {
            $projectdb->query("INSERT INTO tunnel_inspect_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $tunnelrulestag) . ";");
            unset($tunnelrulestag);
        }
        if (count($tunnelrulesusr) > 0) {
            $projectdb->query("INSERT INTO tunnel_inspect_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $tunnelrulesusr) . ";");
            unset($tunnelrulesusr);
        }
        if (count($tunnelrulessrc) > 0) {
            $projectdb->query("INSERT INTO tunnel_inspect_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $tunnelrulessrc) . ";");
            unset($tunnelrulessrc);
        }
        if (count($tunnelrulesdst) > 0) {
            $projectdb->query("INSERT INTO tunnel_inspect_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $tunnelrulesdst) . ";");
            unset($tunnelrulesdst);
        }
        if (count($tunnelrulesapp) > 0) {
            $projectdb->query("INSERT INTO tunnel_inspect_rules_app (source,vsys,rule_lid,table_name,member_lid,devicegroup) VALUES " . implode(",", $tunnelrulesapp) . ";");
            unset($tunnelrulesapp);
        }

        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO tunnel_inspect_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}


function pan_read_rules_authentication_other_rules($preorpost, $address, $source, $vsys, $version, $devicegroup){
    global $projectdb;
    if (isset($address[0]->rules)) {
        foreach ($address[0]->rules as $data) {
            $rule_type = "authentication";
            $pbf = addslashes($data->asXML());
            if ($pbf != "<rules/>") {
                $projectdb->query("INSERT INTO other_rules (source,vsys,type,xml,preorpost) VALUES ('$source','$vsys','$rule_type','$pbf','$preorpost');");
            }
        }
    }
}


function pan_read_rules_authentication($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $urldb, &$objectsInMemory) {
    global $projectdb;

    # Init vars
    $lid = "";
    $authenticationrules = array();
    $authenticationrulesfrom = array();
    $authenticationrulesto = array();
    $authenticationrulestag = array();
    $authenticationrulesusr = array();
    $authenticationrulescategories = array();
    $authenticationrulessrc = array();
    $authenticationrulesdst = array();
    $authenticationrulessrv = array();
    $authenticationruleship = array();
    $addTarget = array();
    $myArray = array();
    $member_name_array = array();
    $myArray_srv = array();
    $member_name_array_srv = array();
    $myArray_tag = array();
    $member_name_array_tag = array();
    $log_forwardingsA = array();

    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM authentication_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM authentication_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {

        # Initialize vars
        $disabled = "0";
        $negate_source = 0;
        $negate_destination = 0;
        $timeout = "60";
        $authentication_enforcement = "";
        $log_authentication_timeout = "";
        $group_tag_id = "";

        $target = "";
        $target_negate = "no";
        # Start Reading Rule
        $name_ext = $data->attributes()->name;
        $uuid = $data->attributes()->uuid;
        $name_int = $name_ext;
        $log_forwarding = "";
        $description = addslashes($data->description);

        if ($data->disabled == "yes") {$disabled = "1";}
        if ($data->{'negate-source'} == "yes") {$negate_source = 1;}
        if ($data->{'negate-destination'} == "yes") {$negate_destination = 1;}

        if (isset($data->timeout)) {
            $timeout = $data->timeout;
        }

        if (isset($data->{'authentication-enforcement'})) {
            $authentication_enforcement = $data->{'authentication-enforcement'};
        }

        if (isset($data->{'log-authentication-timeout'})) {
            $log_authentication_timeout = $data->{'log-authentication-timeout'};
        }

        if (isset($data->{'log-setting'})) {
            $log_forwarding = $data->{'log-setting'};
            $log_forwardingsA[]=$log_forwarding;
        }

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate=$data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$new_vsys','$lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$new_vsys','$lid','$deviceName','')";
                    }
                }
            }
        }

        $hip_profile_field =     ($version >= 10)? 'source-hip':'hip-profiles';
        foreach ($data->{$hip_profile_field} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                elseif ($memberA == "no-hip") {
                    $authenticationruleship[] = "('$source','0','default','$new_vsys','$lid','$devicegroup','no-hip')";
                } else {
                    $getHP = $projectdb->query("/*qc=on*/SELECT id FROM profiles WHERE source='$source' AND BINARY name='$memberA' AND vsys='$new_vsys' AND type='hip-profiles';");
                    if ($getHP->num_rows == 1) {
                        $tagData = $getHP->fetch_assoc();
                        $tagId = $tagData['id'];
                        $authenticationruleship[] = "('$source','$tagId','profiles','$new_vsys','$lid','$devicegroup','')";
                    } else {
                        #Shared
                        //$getHP = $projectdb->query("/*qc=on*/SELECT id FROM shared_profiles WHERE source='$source' AND BINARY name='$memberA' AND type='hip-profiles';");
                        $getHP = $projectdb->query("/*qc=on*/SELECT id FROM profiles WHERE source='$source' AND BINARY name='$memberA' AND type='hip-profiles' AND vsys = 'shared';");
                        if ($getHP->num_rows == 1) {
                            $tagData = $getHP->fetch_assoc();
                            $tagId = $tagData['id'];
                            //$secruleship[] = "('$source','$tagId','shared_profiles','$new_vsys','$lid','$devicegroup','')";
                            $authenticationruleship[] = "('$source','$tagId','profiles','shared','$lid','$devicegroup','')";
                        }
                    }
                }
            }
        }

        foreach ($data->from as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $authenticationrulesfrom[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->to as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $authenticationrulesto[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        if (isset($data->{'group-tag'})) {
            $group_tag = (string) $data->{'group-tag'};
            $tmp = calculate_member_and_table_from_memory("policy","tag", $new_vsys, $source, $devicegroup, $group_tag, $version,$objectsInMemory);
            if (count($tmp)>0){
                $group_tag_id = $tmp['member_lid'];
            }
            else {
                print "GROUP TAG Security Rules: ERROR NO GROUP-TAG for $group_tag".PHP_EOL;
            }
        }

        foreach ($data->{'source-user'} as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $memberB = addslashes($memberA);
                    $authenticationrulesusr[] = "('$source','$new_vsys','$memberB','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->category as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $authenticationrulescategories[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["src"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["dst"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->service->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray_srv[$memberA]["lid"][]=$lid;
                $member_name_array_srv[]=$memberA;
            }
        }


        $authenticationrules[] = "('$target_negate','$target','$preorpost','$position','$lid','$negate_source','$negate_destination','$description','$name_ext','$name_int','$disabled','$new_vsys','$source','$devicegroup', '$timeout', '$authentication_enforcement', '$log_authentication_timeout', '$log_forwarding', '$uuid', '$group_tag_id')";
        $lid++;
        $position++;
    }

    # Mapping Sources and Destination
    $calculate = calculate_members_and_table_from_memory("policy","address",$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray as $pos=>$lidArray){
                if ($pos=="src"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $authenticationrulessrc[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
                elseif ($pos=="dst"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $authenticationrulesdst[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Services
    $calculate = calculate_members_and_table_from_memory("policy","service",$myArray_srv,$new_vsys,$source,$devicegroup,$member_name_array_srv, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $authenticationrulessrv[] = "('$source','$new_vsys','$table_name','$member_lid','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate = calculate_members_and_table_from_memory("policy","tag",$myArray_tag,$new_vsys,$source,$devicegroup,$member_name_array_tag, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $authenticationrulestag[] = "('$source','$member_lid','$table_name','$new_vsys','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Create Dummy for Log FWD Profiles
    calculate_members_and_table_from_memory("policy","log_setting",'',$new_vsys,$source,$devicegroup,$log_forwardingsA, $version,$objectsInMemory);


    # INSERT AUTHENTICATION RULES INTO DB
    if (count($authenticationrules) > 0) {
        $projectdb->query("INSERT INTO authentication_rules (target_negate,target,preorpost,position,id,negate_source,negate_destination,description,name_ext,name,disabled,vsys,source,devicegroup, timeout, authentication_enforcement, log_authentication_timeout, log_forwarding, uuid, group_tag_id) VALUES " . implode(",", $authenticationrules) . ";");
        unset($authenticationrules);

        if (count($authenticationrulesfrom) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $authenticationrulesfrom) . ";");
            unset($authenticationrulesfrom);
        }
        if (count($authenticationrulesto) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $authenticationrulesto) . ";");
            unset($authenticationrulesto);
        }
        if (count($authenticationrulestag) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $authenticationrulestag) . ";");
            unset($authenticationrulestag);
        }
        if (count($authenticationrulesusr) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $authenticationrulesusr) . ";");
            unset($authenticationrulesusr);
        }
        if (count($authenticationrulescategories) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_categories (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $authenticationrulescategories) . ";");
            unset($authenticationrulescategories);
        }
        if (count($authenticationrulessrc) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $authenticationrulessrc) . ";");
            unset($authenticationrulessrc);
        }
        if (count($authenticationrulesdst) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $authenticationrulesdst) . ";");
            unset($authenticationrulesdst);
        }
        if (count($authenticationrulessrv) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $authenticationrulessrv) . ";");
            unset($authenticationrulessrv);
        }
        if (count($authenticationruleship) > 0) {
            $projectdb->query("INSERT INTO authentication_rules_hip (source,member_lid,table_name,vsys,rule_lid,devicegroup,name) VALUES " . implode(",", $authenticationruleship) . ";");
            unset($authenticationruleship);
        }

        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO authentication_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}


function pan_read_rules_captiveportal($preorpost, $address, $source, $new_vsys, $version, $devicegroup, $urldb, &$objectsInMemory) {
    global $projectdb;

    # Init vars
    $lid = "";
    $captiveportalrules = array();
    $captiveportalrulesfrom = array();
    $captiveportalrulesto = array();
    $captiveportalrulestag = array();
    $captiveportalrulessrc = array();
    $captiveportalrulesdst = array();
    $captiveportalrulessrv = array();
    $captiveportalrulescategories = array();
    $addTarget = array();
    $myArray = array();
    $member_name_array = array();
    $myArray_srv = array();
    $member_name_array_srv = array();
    $myArray_tag = array();
    $member_name_array_tag = array();
    $log_forwardingsA = array();

    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM captiveportal_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM captiveportal_rules WHERE preorpost='$preorpost';");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;

    foreach ($address as $child => $data) {

        # Initialize vars
        $disabled = "0";
        $negate_source = 0;
        $negate_destination = 0;

        $target = "";
        $target_negate = "no";
        # Start Reading Rule
        $name_ext = $data->attributes()->name;
        $name_int = $name_ext;
        $description = addslashes($data->description);

        $action = $data->action;

        if ($data->disabled == "yes") {$disabled = "1";}
        if ($data->{'negate-source'} == "yes") {$negate_source = 1;}
        if ($data->{'negate-destination'} == "yes") {$negate_destination = 1;}

        if (isset($data->target)) {
            if (isset($data->target->negate)){
                $target_negate=$data->target->negate;
            }
            if (isset($data->target->devices)){
                foreach($data->target->devices->entry as $xmldevice){
                    $deviceName=$xmldevice->attributes()->name;
                    if (isset($xmldevice->vsys)){
                        foreach($xmldevice->vsys->entry as $xmldevicevsys){
                            $deviceVsys=$xmldevicevsys->attributes()->name;
                            $addTarget[]="('$source','$new_vsys','$lid','$deviceName','$deviceVsys')";
                        }
                    }
                    else{
                        $addTarget[]="('$source','$new_vsys','$lid','$deviceName','')";
                    }
                }
            }
        }

        foreach ($data->from as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $captiveportalrulesfrom[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->to as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $captiveportalrulesto[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        if (isset($data->tag)){
            foreach ($data->tag->member as $memberA) {
                $memberA=(string) $memberA;
                $memberA = normalizeTagNames($memberA);
                if (($memberA == "") OR ( $memberA == "any")) {}
                else {
                    $myArray_tag[$memberA]["lid"][]=$lid;
                    $member_name_array_tag[]=$memberA;
                }
            }
        }

        foreach ($data->category as $k => $zone_member) {
            foreach ($zone_member as $m => $memberA) {
                if (($memberA == "") OR ( $memberA == "any")) {} else {
                    $captiveportalrulescategories[] = "('$source','$new_vsys','$memberA','$lid','$devicegroup')";
                }
            }
        }

        foreach ($data->source->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["src"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->destination->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray[$memberA]["dst"][]=$lid;
                $member_name_array[]=$memberA;
            }
        }

        foreach ($data->service->member as $k => $memberA) {
            $memberA=(string) $memberA;
            if (($memberA == "") OR ( $memberA == "any")) {}
            else{
                $myArray_srv[$memberA]["lid"][]=$lid;
                $member_name_array_srv[]=$memberA;
            }
        }


        $captiveportalrules[] = "('$target_negate','$target','$preorpost','$position','$lid','$negate_source','$negate_destination','$description','$name_ext','$name_int','$disabled','$new_vsys','$source','$devicegroup', '$action')";
        $lid++;
        $position++;
    }

    # Mapping Sources and Destination
    $calculate = calculate_members_and_table_from_memory("policy","address",$myArray,$new_vsys,$source,$devicegroup, $member_name_array, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray as $pos=>$lidArray){
                if ($pos=="src"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $captiveportalrulessrc[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
                elseif ($pos=="dst"){
                    foreach ($lidArray as $lid){
                        if (($member_lid != "") AND ( $table_name != "")) {
                            $captiveportalrulesdst[] = "('$source','','$table_name','$member_lid','$lid','$devicegroup')";
                        }
                    }
                }
            }

        }
        unset($myArray);
    }

    # Mapping Services
    $calculate = calculate_members_and_table_from_memory("policy","service",$myArray_srv,$new_vsys,$source,$devicegroup,$member_name_array_srv, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $captiveportalrulessrv[] = "('$source','$new_vsys','$table_name','$member_lid','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Mapping Tags
    $calculate = calculate_members_and_table_from_memory("policy","tag",$myArray_tag,$new_vsys,$source,$devicegroup,$member_name_array_tag, $version,$objectsInMemory);
    $member_name_array=$calculate[1];
    $myArray=$calculate[0];
    # Write the Output
    if (count($member_name_array) == 0) {
        foreach ($myArray as $member => $valueArray) {
            $member_lid = $valueArray["member_lid"];
            $table_name = $valueArray["table_name"];
            foreach ($valueArray["lid"] as $lid){
                if (($member_lid != "") AND ( $table_name != "")) {
                    $captiveportalrulestag[] = "('$source','$member_lid','$table_name','$new_vsys','$lid','$devicegroup')";
                }
            }
        }
        unset($myArray);
    }

    # Create Dummy for Log FWD Profiles
    calculate_members_and_table_from_memory("policy","log_setting",'',$new_vsys,$source,$devicegroup,$log_forwardingsA, $version,$objectsInMemory);


    # INSERT AUTHENTICATION RULES INTO DB
    if (count($captiveportalrules) > 0) {
        $projectdb->query("INSERT INTO captiveportal_rules (target_negate,target,preorpost,position,id,negate_source,negate_destination,description,name_ext,name,disabled,vsys,source,devicegroup,action) VALUES " . implode(",", $captiveportalrules) . ";");
        unset($authenticationrules);

        if (count($captiveportalrulesfrom) > 0) {
            $projectdb->query("INSERT INTO captiveportal_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $captiveportalrulesfrom) . ";");
            unset($captiveportalrulesfrom);
        }
        if (count($captiveportalrulesto) > 0) {
            $projectdb->query("INSERT INTO captiveportal_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $captiveportalrulesto) . ";");
            unset($captiveportalrulesto);
        }
        if (count($captiveportalrulestag) > 0) {
            $projectdb->query("INSERT INTO captiveportal_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $captiveportalrulestag) . ";");
            unset($captiveportalrulestag);
        }
        if (count($captiveportalrulescategories) > 0) {
            $projectdb->query("INSERT INTO captiveportal_rules_categories (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $captiveportalrulescategories) . ";");
            unset($captiveportalrulescategories);
        }
        if (count($captiveportalrulessrc) > 0) {
            $projectdb->query("INSERT INTO captiveportal_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $captiveportalrulessrc) . ";");
            unset($captiveportalrulessrc);
        }
        if (count($captiveportalrulesdst) > 0) {
            $projectdb->query("INSERT INTO captiveportal_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $captiveportalrulesdst) . ";");
            unset($captiveportalrulesdst);
        }
        if (count($captiveportalrulessrv) > 0) {
            $projectdb->query("INSERT INTO captiveportal_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $captiveportalrulessrv) . ";");
            unset($captiveportalrulessrv);
        }

        # Write the Target
        if (count($addTarget)>0){
            $projectdb->query("INSERT INTO captiveportal_rules_target (source,vsys,rule_lid,name,device_vsys) VALUES ".implode(",",$addTarget).";");
            unset($addTarget);
        }
    }
}



function RelationsTagsObjects($source){

    global $projectdb;

    if (!is_numeric($source)){
        $getSourceID = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$source' GROUP BY filename;");
        if ($getSourceID->num_rows == 1) {
            $data = $getSourceID->fetch_assoc();
            $source = $data['id'];
        } else {
            add_log('error', 'Mapping Tag members', 'Invalid Source File', $source, 'Process finished unexpectly');
            exit(0);
        }
    }

    $tables_names = array("address", "address_groups_id", "services", "services_groups_id");

    foreach ($tables_names as $table_name) {

        $inserts_tag = array();

        $sql = $projectdb->query("SELECT id, tag, vsys FROM $table_name WHERE source = '$source' AND tag != '';");

        if ($sql->num_rows>0) {

            while ($data = $sql->fetch_assoc()) {

                $id = $data['id'];
                $tag = $data['tag'];
                $vsys = $data['vsys'];

                $allVSYS = getVsyses($projectdb, $vsys, $source);

                $objects_tag_exp = explode(",", $tag);

                foreach ($objects_tag_exp AS $member_tag){

                    $member = getTagId($projectdb, $source, $allVSYS, $member_tag);
                    if ($member!=null){
                        $tag_id = $member->name;
                    }
                    else{
                        $projectdb->query("INSERT INTO tag (name, source, vsys, devicegroup, vtype, dummy) VALUES ('$member_tag','$source','$vsys','MT_Panorama', 'dummy', '1');");
                        $tag_id = $projectdb->insert_id;
                    }
                    $inserts_tag[] = "('$table_name', '$id', '$tag_id')";
                }
            }
        }

        if (count($inserts_tag) > 0){
            $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",",$inserts_tag).";");
            //echo "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",",$inserts_tag).";\n";
            unset($inserts_tag);
        }
    }
}


function setUrlCategories($source, $urldb){

    global $projectdb;

    $urls = array();

    if($urldb == "paloaltonetworks"){
        $xml_categories = "pan_url_categories.xml";
    }
    else if($urldb == "brightcloud"){
        $xml_categories = "url_categories.xml";
    }

    $xml5 = simplexml_load_file(INC_ROOT.'/contents/'.$xml_categories.'');

    /*if ((file_exists(USERSPACE_PATH.'/devices/'.$source.'/'.$xml_categories.'')) AND
        (filesize(USERSPACE_PATH.'/devices/'.$source.'/'.$xml_categories.'') != 0)) {
        $xml5 = simplexml_load_file(USERSPACE_PATH.'/devices/'.$source.'/'.$xml_categories.'');
    } else {
        $xml5 = simplexml_load_file(INC_ROOT.'/contents/'.$xml_categories.'');
    }*/

    if (isset($xml5->result->{'pan-url-categories'})){

        foreach ($xml5->result->{'pan-url-categories'}->entry as $value) {
            $name = $value->attributes()->name;
            if ($name != "") {
                $urls[] = "('$name')";
            }
        }
    }
    elseif (isset($xml5->result->{'url-categories'})){
        foreach ($xml5->result->{'url-categories'}->entry as $value) {
            $name = $value->attributes()->name;
            if ($name != "") {
                $urls[] = "('$name')";
            }
        }
    }

    if (count($urls) > 0) {
        $out = implode(",", $urls);
        $projectdb->query("INSERT INTO default_url_categories (name) VALUES " . $out . ";");
    }

}


function update_routes_static_with_member_lid($projectdb, $template, $source, &$objectsInMemory){
    global $projectdb;
//    $start = microtime(true);
//    echo date("Y-m-d H:i:s"). ": Updating routes\n";;
    $vsysesMapping = array();  //For each vsys gives you the all vsys under it

    $sql_routes = $projectdb->query("SELECT id, destination, nexthop_value, vsys FROM routes_static WHERE source = '$source'; ");

    if($sql_routes->num_rows > 0){
        while($dataRS = $sql_routes->fetch_assoc()){
            $destination_member_lid = "";
            $nexthop_value_member_lid = "";
            $route_static_id = $dataRS['id'];

            $allVSYS = getVsyses($projectdb, $dataRS['vsys'], $source);
//            if(!isset($vsysesMapping[$dataRS['vsys']])){
//                $vsysesMapping[$dataRS['vsys']] = getVsyses($projectdb, $dataRS['vsys'], $source);
//            }
//            $allVSYS = $vsysesMapping[$dataRS['vsys']];

            //$calc_member = getMemberId($projectdb, $source, $allVSYS, $dataRS['destination']); //TODO: Remove this
            $calc_member = getMemberIdFromAddressInMemory($projectdb, $source, $allVSYS, $dataRS['destination'], $objectsInMemory);
            //echo $dataRS['destination']." is ".print_r($calc_member)."\n";
            if ($calc_member != null){
                $destination_member_lid = $calc_member->name;
            }

            if($dataRS['nexthop_value'] != ""){
                //$calc_member = getMemberId($projectdb, $source, $allVSYS, $dataRS['nexthop_value']); //TODO: remove this
                $calc_member = getMemberIdFromAddressInMemory($projectdb, $source, $allVSYS, $dataRS['nexthop_value'], $objectsInMemory);
                if ($calc_member != null){
                    $nexthop_value_member_lid = $calc_member->name;
                }
            }

            $query = "UPDATE routes_static SET destination_member_lid = '$destination_member_lid', nexthop_value_member_lid = '$nexthop_value_member_lid' WHERE id = '$route_static_id' ;";
            //echo "$query \n";
            $projectdb->query($query);
        }
    }

//    echo date("Y-m-d H:i:s"). ": HALF Updating routes\n";

    $sql_monitor = $projectdb->query("SELECT m.id, m.route_id, m.name, m.dst, r.vsys FROM routes_static_monitor_destinations m, routes_static r WHERE r.id = m.route_id AND r.source = '$source';");
    if($sql_monitor->num_rows > 0){
        while($dataM = $sql_monitor->fetch_assoc()){
            $dst_member_lid = "";
            $monitor_routes_id = $dataM['id'];

            $allVSYS = getVsyses($projectdb, $dataM['vsys'], $source);

            $calc_member = getMemberId($projectdb, $source, $allVSYS, $dataM['dst']);
            if ($calc_member != null){
                $dst_member_lid = $calc_member->name;
            }

            $projectdb->query("UPDATE routes_static_monitor_destinations SET dst_member_lid = '$dst_member_lid' WHERE id = '$monitor_routes_id'; ");
        }
    }

//    $time_elapsed_secs = microtime(true) - $start;
//    echo date("Y-m-d H:i:s"). ": DONE Updating routes\n";
 //   echo "TOTAL: $time_elapsed_secs\n\n";

}


function update_zones_with_member_lid($projectdb, $template, $source){

    global $projectdb;

    $sql_exclude_list = array();
    $sql_include_list = array();

    $sql_zones = $projectdb->query("SELECT id, include_list, exclude_list, vsys FROM zones WHERE source = '$source'; ");

    if($sql_zones->num_rows > 0){

        while($dataRS = $sql_zones->fetch_assoc()){

            $zones_lid = $dataRS['id'];

            $allVSYS = getVsyses($projectdb, $dataRS['vsys'], $source);

            if($dataRS['include_list'] != ""){

                $zones_include_list = explode(",", $dataRS['include_list']);

                foreach ($zones_include_list AS $member){
                    $calc_member = getMemberId($projectdb, $source, $allVSYS, $member);

                    if ($calc_member != null){
                        $member_lid = $calc_member->name;
                        $table_name = $calc_member->location;
                        $sql_include_list[] = "('$zones_lid', '$member_lid', '$table_name')";
                    }
                    else{
                        $sql_include_list[] = "('$zones_lid', '', '$member')";
                    }
                }
            }

            if($dataRS['exclude_list'] != ""){

                $zones_exclude_list = explode(",", $dataRS['exclude_list']);

                foreach ($zones_exclude_list AS $member){
                    $calc_member = getMemberId($projectdb, $source, $allVSYS, $member);

                    if ($calc_member != null){
                        $member_lid = $calc_member->name;
                        $table_name = $calc_member->location;
                        $sql_exclude_list[] = "('$zones_lid', '$member_lid', '$table_name')";
                    }else{
                        $sql_exclude_list[] = "('$zones_lid', '', '$member')";
                    }
                }
            }
        }
    }

    if (count($sql_include_list) > 0){
        $projectdb->query("INSERT INTO zones_include_list (zones_lid, member_lid, table_name) VALUES ".implode(",",$sql_include_list).";");
        //echo "INSERT INTO zones_include_list (zones_lid, member_lid, table_name) VALUES ".implode(",",$sql_include_list).";\n";
        unset($sql_include_list);
    }

    if (count($sql_exclude_list) > 0){
        $projectdb->query("INSERT INTO zones_exclude_list (zones_lid, member_lid, table_name) VALUES ".implode(",",$sql_exclude_list).";");
        //echo "INSERT INTO zones_include_list (zones_lid, member_lid, table_name) VALUES ".implode(",",$sql_exclude_list).";\n";
        unset($sql_exclude_list);
    }



}