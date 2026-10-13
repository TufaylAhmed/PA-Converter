<?php

require_once INC_ROOT.'/libs/shared.php';

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

function import_discovered_address($project,$params){
    global $projectdb;
    global $app;

    $projectdb = selectDatabase($project);
    $source=$params['source'];
    $vsys=$params['vsys'];
    $message=array();

    $DEBUG=isset($params['debug'])?$params['debug']:'false';


    if ($source!=0){

        if ($params['shared']=="true"){
            $vsys="shared";
        }

        if ($vsys!="all"){

            $add_tag=$addressv4=$addressv6=array();
            $unique=array();

            if ($params['selection']=="all"){
                $get_SRCDST=$projectdb->query("SELECT source,seenSourceNetworks,destination,seenDestinationNetworks FROM ML_NewRules;");
            }
            else{
                if ($params['ids']!=""){
                    $get_SRCDST=$projectdb->query("SELECT source,seenSourceNetworks,destination,seenDestinationNetworks FROM ML_NewRules WHERE id IN (".$params['ids'].");");
                }
                else{
                    $message['msg']="No Rules Selected";
                    $message['code']=false;
                    return $message;
                }
            }

            if ($get_SRCDST->num_rows>0){
                $rawSource=array();
                $rawDestination=array();
                /* @var array $data is each one of the suggested Rules */
                while($data=$get_SRCDST->fetch_assoc()){
                    $replaceableSourceNetworks=array();
                    $rawNetworks=explode(",",$data['seenSourceNetworks']);
                    foreach ($rawNetworks as $rawNetwork){
                        $netWorkArr = explode(":",$rawNetwork);
                        if(isset($netWorkArr[1]) && $netWorkArr[1]>=$params['sourceDensity']){
                            $octets = explode(".", $netWorkArr[0]);
                            $replaceableSourceNetworks[]=$octets[0].".".$octets[1].".".$octets[2];
                            $rawSource[]=$netWorkArr[0];
                        }
                    }
                    if ($data['source']!="any" && $data['source']!=''){
                        $raw=explode(",",$data['source']);
                        foreach($raw as $record){
                            $octets = explode(".", $record);
                            $hostingNetwork=$octets[0].".".$octets[1].".".$octets[2];
                            if(!in_array($hostingNetwork,$replaceableSourceNetworks)) {
                                $rawSource[] = $record;
                            }
                        }
                    }

                    $replaceableDestinationNetworks=array();
                    $rawNetworks=explode(",",$data['seenDestinationNetworks']);
                    foreach ($rawNetworks as $rawNetwork){
                        $netWorkArr = explode(":",$rawNetwork);
                        if(isset($netWorkArr[1]) && $netWorkArr[1]>=$params['destinationDensity']){
                            $octets = explode(".", $netWorkArr[0]);
                            $replaceableDestinationNetworks[]=$octets[0].".".$octets[1].".".$octets[2];
                            $rawDestination[]=$netWorkArr[0];
                        }
                    }


                    if ($data['destination']!="any" && $data['destination']!=''){
                        $raw=explode(",",$data['destination']);
                        foreach ($raw as $record){
                            $octets = explode(".", $record);
                            $hostingNetwork=$octets[0].".".$octets[1].".".$octets[2];
                            if(!in_array($hostingNetwork,$replaceableDestinationNetworks)) {
                                $rawDestination[] = $record;
                            }
                        }
                    }
                }

                $rawSourceU=array_unique($rawSource);
                $rawDestinationU=array_unique($rawDestination);
                $address=array_merge($rawDestinationU,$rawSourceU);
                $unique=array_unique($address);

                $vsysesq = getVsyses($projectdb, $vsys, $source, 'quoted');
                $vsysesqunique=array_unique($vsysesq); // In case shared = true can be shared shared reduce to shared only once
                $addVsys=" AND vsys IN (".implode(",",$vsysesqunique).") ";

                $loadAllIP=$projectdb->query("SELECT ipaddress FROM address WHERE source='$source' $addVsys GROUP BY ipaddress;");
                $allIP=array();
                if ($loadAllIP->num_rows>0){
                    while($loadAllIPData=$loadAllIP->fetch_assoc()){
                        $allIP[$loadAllIPData['ipaddress']]=$loadAllIPData['ipaddress'];
                    }
                }

                # Remove the known IP address
                $strictNew=array_diff($unique,$allIP);

                $getlastlid=$projectdb->query("SELECT max(id) as max FROM address;");
                $address_max=$getlastlid->fetch_assoc();
                $address_lid = $address_max['max']+1;
                $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');

                foreach($strictNew as $key=>$value){

                    if ($value!=""){

                        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)){
                            $addressv4[]="($address_lid,'$value','$value','ip-netmask','$source','$vsys','$value','',1,1)";
                            $add_tag[] = "('address',$address_lid,$tag_id)";
                            $address_lid++;
                        }
                        elseif (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
                            $addressv6[]="($address_lid,'$value','$value','ip-netmask','$source','$vsys','$value','',1,1)";
                            $add_tag[] = "('address',$address_lid,$tag_id)";
                            $address_lid++;
                        }
                        elseif (preg_match("/-/",$value)){
                            $split=explode("-",$value);
                            if (filter_var($split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)){
                                $addressv4[]="($address_lid,'$value','$value','ip-range','$source','$vsys','$value','',1,1)";
                                $add_tag[] = "('address',$address_lid,$tag_id)";
                                $address_lid++;
                            }
                            elseif (filter_var($split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
                                $addressv6[]="($address_lid,'$value','$value','ip-range','$source','$vsys','$value','',1,1)";
                                $add_tag[] = "('address',$address_lid,$tag_id)";
                                $address_lid++;
                            }
                            else{
                                print "Is not IP-Range v4/v6 ".$value.PHP_EOL;
                            }
                        }
                        elseif(preg_match("/\//",$value)){
                            $split=explode("/",$value);
                            if (filter_var($split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)){
                                $netName = "N-".$split[0]."-".$split[1];
                                $addressv4[]="($address_lid,'$netName','$netName','ip-netmask','$source','$vsys','$split[0]','$split[1]',1,1)";
                                $add_tag[] = "('address',$address_lid,$tag_id)";
                                $address_lid++;
                            }
                            elseif (filter_var($split[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
                                $netName = "N-".$split[0]."-".$split[1];
                                $addressv6[]="($address_lid,'$netName','$netName','ip-netmask','$source','$vsys','$split[0]','$split[1]',1,1)";
                                $add_tag[] = "('address',$address_lid,$tag_id)";
                                $address_lid++;
                            }
                            else{
                                print "Is not IP-Range v4/v6 ".$value.PHP_EOL;
                            }
                        }
                        else{
                            print "Is not IP-Address or IP-Range".$value.PHP_EOL;
                        }
                    }
                }
                if (count($addressv4)>0){
                    $projectdb->query("INSERT INTO address (id,name,name_ext,type,source,vsys,ipaddress,cidr,v4,used) VALUES ".implode(",",$addressv4).";");
                    unset($addressv4);
                    unset($unique);
                }

                if (count($addressv6)>0){
                    $projectdb->query("INSERT INTO address (id,name,name_ext,type,source,vsys,ipaddress,cidr,v6,used) VALUES ".implode(",",$addressv6).";");
                    unset($addressv6);
                    unset($unique);
                }

                if (count($add_tag) > 0) {
                    $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) VALUES " . implode(",", $add_tag) . ";");
                    unset($add_tag);
                }

                $message['msg']="Imported Objects successfuly";
                $message['code']=true;
            }
        }
        else{
            $message['msg']="Select Source and Vsys";
            $message['code']=false;
        }
    }
    else{
        $message['msg']="Select Source and Vsys";
        $message['code']=false;
    }

    return $message;

}

function import_discovered_services($project,$params){
    global $projectdb;
    global $app;

    $projectdb = selectDatabase($project);
    $source=$params['source'];
    $vsys=$params['vsys'];
    $message=array();

    $DEBUG=isset($params['debug'])?$params['debug']:'false';

    if ($source!=0){

        if ($params['shared']=="true"){
            $vsys="shared";
        }

        if ($vsys!="all"){

            $address=array();
            $add_tag= $addressv4=array();
            $rawService=array();

            if ($params['selection']=="all"){
                $get_SRCDST=$projectdb->query("SELECT service FROM ML_NewRules;");
            }
            else{
                if (!isset($params['ids'])){
                    $message['msg']="Select Source and Vsys";
                    $message['code']=false;
                    return $message;
                }

                $get_SRCDST=$projectdb->query("SELECT service FROM ML_NewRules WHERE id IN (".$params['ids'].");");
            }

            if ($get_SRCDST->num_rows>0){
                while($data=$get_SRCDST->fetch_assoc()){
                    if (($data['service']!="application-default")){
                        $raw=explode(",",$data['service']);
                        foreach($raw as $record){
                            if ($record!="any"){
                                $rawService[]=$record;
                            }

                        }
                    }
                }

                $unique=array_unique($rawService);

                $vsysesq = getVsyses($projectdb, $vsys, $source, 'quoted');
                $vsysesqunique=array_unique($vsysesq); // In case shared = true can be shared shared reduce to shared only once
                $addVsys=" AND vsys IN (".implode(",",$vsysesqunique).") ";
                $loadAllIP=$projectdb->query("SELECT protocol,dport FROM services WHERE source='$source' $addVsys GROUP BY protocol,dport;");
                $allIP=array();
                if ($loadAllIP->num_rows>0){
                    $allIP=array();
                    while($loadAllIPData=$loadAllIP->fetch_assoc()){
                        $allIP[$loadAllIPData['protocol']."/".$loadAllIPData['dport']]=$loadAllIPData['protocol']."/".$loadAllIPData['dport'];
                    }
                }

                # Remove the known IP address
                $strictNew=array_diff($unique,$allIP);

                $getlastlid=$projectdb->query("SELECT max(id) as max FROM services;");
                $services_max=$getlastlid->fetch_assoc();
                $services_lid=$services_max['max']+1;
                $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');

                foreach($strictNew as $key=>$value){

                    list($protocol,$dport)=explode("/",$value);

                    switch($protocol){
                        case "tcp":
                            $newName=truncate_names($protocol."-".$dport);
                            $addressv4[]="($services_lid,'$newName','$newName','service','$source','$vsys','$dport','$protocol',1)";
                            $add_tag[] = "('services',$services_lid,$tag_id)";
                            $services_lid++;
                            break;
                        case "udp":
                            $newName=truncate_names($protocol."-".$dport);
                            $addressv4[]="($services_lid,'$newName','$newName','service','$source','$vsys','$dport','$protocol',1)";
                            $add_tag[] = "('services',$services_lid,$tag_id)";
                            $services_lid++;
                            break;
                        default:
                            print $value.PHP_EOL;
                            break;
                    }


                }
                if (count($addressv4)>0){
                    $projectdb->query("INSERT INTO services (id,name,name_ext,type,source,vsys,dport,protocol,used) VALUES ".implode(",",$addressv4).";");
                    unset($addressv4);
                    unset($unique);
                }

                if (count($add_tag) > 0) {
                    $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) VALUES " . implode(",", $add_tag) . ";");
                    unset($add_tag);
                }

                $message['msg']="Imported Objects successfuly";
                $message['code']=true;
            }
        }
    }
    else{
        $message['msg']="Select Source and Vsys";
        $message['code']=false;
    }

    return $message;

}

function import_discovered_rules($project,$params,$obj){
    global $projectdb;
    global $app;

    $projectdb = selectDatabase($project);
    $source=$params['source'];
    $vsys=$params['vsys'];
    $message=array();

    $DEBUG=isset($params['debug'])?$params['debug']:'false';

    if ($source!=0){

        if ($vsys!="all"){
            $vsysesq = getVsyses($projectdb, $vsys, $source, 'quoted');
            $vsyses = getVsyses($projectdb, $vsys, $source);
            $vsysesqunique=array_unique($vsysesq); // In case shared = true can be shared shared reduce to shared only once
            $address=array();
            $addressv4=array();
            $unique=array();
            if ($params['selection']=="all"){
                $getRules=$projectdb->query("SELECT * FROM ML_NewRules ORDER BY application;");
                $getTags=$projectdb->query("SELECT tag FROM ML_NewRules GROUP BY tag;");
                $getFlow=$projectdb->query("SELECT communicationType FROM ML_NewRules GROUP BY communicationType;");
            }
            else{
                $getRules=$projectdb->query("SELECT * FROM ML_NewRules WHERE id IN (".$params['ids'].") ORDER BY application;");
                $getTags=$projectdb->query("SELECT tag FROM ML_NewRules WHERE id IN (".$params['ids'].") GROUP BY tag;");
                $getFlow=$projectdb->query("SELECT communicationType FROM ML_NewRules WHERE id IN (".$params['ids'].") GROUP BY communicationType;");
            }



            if ($getRules->num_rows>0){
                # Init vars
                $rule_is_type = "universal";
                $add_tag = $secrules = array();
                $secrulesfrom = array();
                $secrulesto = array();
                $secrulestag = array();
                $secrulesusr = array();
                $secrulescategories = array();
                $secrulessrc = array();
                $secrulesSrcNetworks = array();
                $secrulesdst = array();
                $secrulesDstNetworks = array();
                $secrulesapp = array();
                $secrulessrv = array();
                $preorpost=0;

                # Load Objects in Memory
                $mytablesNoSource=array(
                    "default_applications"
                );

                foreach($mytablesNoSource as $key=>$table_name){
                    $loadObjects=$projectdb->query("SELECT id,name FROM $table_name;");
                    if ($loadObjects->num_rows>0){
                        while($data=$loadObjects->fetch_assoc()){
                            $lid=$data['id'];
                            $name=$data['name'];
                            $objectsInMemory['shared'][$table_name][$name]['id']=$lid;
                        }
                    }
                }

                $mytablesSource=array(
                    "address",
                    "services",
                    "applications",
                    "external_list",
                    "tag"
                );

                foreach($mytablesSource as $key=>$table_name){
                    $loadObjects=$projectdb->query("SELECT id,name,vsys FROM $table_name WHERE source='$source' AND vsys IN (".implode(",",$vsysesq).");");
                    if ($loadObjects->num_rows>0){
                        while($data=$loadObjects->fetch_assoc()){
                            $lid=$data['id'];
                            $name=$data['name'];
                            $objvsys=$data['vsys'];
                            $objectsInMemory[$objvsys][$table_name][$name]['id']=$lid;
                        }
                    }
                }

                # Check TAGS
                $color=2;
                if ($getTags->num_rows>0){

                    while($getTagsData=$getTags->fetch_assoc()){
                        $tagName=$getTagsData['tag'];
                        if ($tagName!="any"){
                            if (!isset($objectsInMemory[$vsys]["tag"][$tagName])){
                                if (preg_match_all("/rsp/",$tagName)){
                                    $color="1";
                                }
                                $projectdb->query("INSERT INTO tag (name,name_ext,color,comments,vsys,devicegroup,source) VALUES ('$tagName','$tagName','color$color','M.Learning','$vsys','M.Learning','$source');");
                                $objectsInMemory[$vsys]["tag"][$tagName]['id']=$projectdb->insert_id; $color++;
                            }
                        }

                    }
                }

                $tag_id = create_tag($projectdb, $source, $vsys, 'M.Learning');
                $objectsInMemory[$vsys]['tag']['M.Learning']['id']= $tag_id;

                if ($getFlow->num_rows>0){
                    while($getTagsData=$getFlow->fetch_assoc()){
                        $tagName=$getTagsData['communicationType'];
                        if ($tagName!="any"){
                            if (!isset($objectsInMemory[$vsys]["tag"][$tagName])){
                                if (preg_match_all("/rsp/",$tagName)){
                                    $color="1";
                                    $projectdb->query("INSERT INTO tag (name,name_ext,color,comments,vsys,devicegroup,source) VALUES ('$tagName','$tagName','color1','M.Learning','$vsys','M.Learning','$source');");
                                }
                                else{
                                    $projectdb->query("INSERT INTO tag (name,name_ext,color,comments,vsys,devicegroup,source) VALUES ('$tagName','$tagName','color$color','M.Learning','$vsys','M.Learning','$source');");
                                    $color++;
                                }
                                $objectsInMemory[$vsys]["tag"][$tagName]['id']=$projectdb->insert_id;
//                                $obj->log("INSERT INTO tag (name,name_ext,color,comments,vsys,devicegroup,source) VALUES ('$tagName','$tagName','color$color','M.Learning','$vsys','M.Learning','$source');");
                            }
                        }

                    }
                }

                # Load address by IPaddress
                $loadAddresses=$projectdb->query("SELECT id,ipaddress as name,vsys FROM address WHERE source='$source' AND vsys IN (".implode(",",$vsysesqunique).") AND ipaddress!='';");
                if ($loadAddresses->num_rows>0){
                    while($data=$loadAddresses->fetch_assoc()){
                        $lid=$data['id'];
                        $name=$data['name'];
                        $objvsys=$data['vsys'];
                        $objectsInMemory[$objvsys]['address'][$name]['id']=$lid;
                    }
                }

                # Load Services by Port
                $loadServices=$projectdb->query("SELECT id,dport,vsys,protocol,name FROM services WHERE source='$source' AND vsys IN (".implode(",",$vsysesqunique).") AND protocol IN ('tcp','udp') AND sport='' GROUP BY dport,vsys,protocol;");
                if ($loadServices->num_rows>0){
                    while($data=$loadServices->fetch_assoc()){
                        $lid=$data['id'];
                        if ($data['name']=="application-default"){
                            $objectsInMemory["shared"]["services"]["application-default"]["all"]['id']=$lid;
                        }
                        else{
                            $dport=$data['dport'];
                            $objvsys=$data['vsys'];
                            $protocol=$data['protocol'];
                            $objectsInMemory[$objvsys]["services"][$protocol][$dport]['id']=$lid;
                        }

                    }
                }

                # Get Last ID from Security Rules
                $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
                $getLID1 = $getlastlid->fetch_assoc();
                $lid = intval($getLID1['max']) + 1;
                # GEt Position from Security Rules
                $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules WHERE preorpost='0';");
                $getLID1 = $getlastlid->fetch_assoc();
                $position = intval($getLID1['max']) + 1;

                while($getRulesData=$getRules->fetch_assoc()){

                    if ($params['address']=="true"){
                        $replaceableSourceNetworks=array();
                        $rawNetworks=explode(",",$getRulesData['seenSourceNetworks']);
                        foreach ($rawNetworks as $rawNetwork){
                            $netWorkArr = explode(":",$rawNetwork);
                            if(isset($netWorkArr[1]) && $netWorkArr[1]>=$params['sourceDensity']){
                                $octets = explode(".", $netWorkArr[0]);
                                $replaceableSourceNetworks[]=$octets[0].".".$octets[1].".".$octets[2];
                                $rawSource[]=$netWorkArr[0];
                            }
                        }
                        if ($getRulesData['source']!="any" && $getRulesData['source']!=''){
                            $sources=explode(",",$getRulesData['source']);
                            foreach($sources as $key=>$value){
                                $octets = explode(".", $value);
                                $hostingNetwork=$octets[0].".".$octets[1].".".$octets[2];
                                if(!in_array($hostingNetwork,$replaceableSourceNetworks)) {
                                    foreach ($vsyses as $vkey => $checkvsys) {
                                        if (isset($objectsInMemory[$checkvsys]['address'][$value])) {
                                            $member_lid = $objectsInMemory[$checkvsys]['address'][$value]['id'];
                                            $secrulessrc[] = "('$source','$checkvsys','address','$member_lid','$lid','M.Learning')";
                                            break;
                                        }
                                    }
                                }
                                else{
                                    foreach ($vsyses as $vkey => $checkvsys) {
                                        if (isset($objectsInMemory[$checkvsys]['address']["N-".$hostingNetwork.".0-24"])) {
                                            $member_lid = $objectsInMemory[$checkvsys]['address']["N-".$hostingNetwork.".0-24"]['id'];
                                            $secrulessrc[] = "('$source','$checkvsys','address','$member_lid','$lid','M.Learning')";
                                            break;
                                        }
                                    }
                                }

                            }
                        }

                        $replaceableDestinationNetworks=array();
                        $rawNetworks=explode(",",$getRulesData['seenDestinationNetworks']);
                        foreach ($rawNetworks as $rawNetwork){
                            $netWorkArr = explode(":",$rawNetwork);
                            if(isset($netWorkArr[1]) && $netWorkArr[1]>=$params['destinationDensity']){
                                $octets = explode(".", $netWorkArr[0]);
                                $replaceableDestinationNetworks[]=$octets[0].".".$octets[1].".".$octets[2];
                                $rawDestination[]=$netWorkArr[0];
                            }
                        }
                        if ($getRulesData['destination']!="any" && $getRulesData['destination']!= '') {
                            $destinations = explode(",", $getRulesData['destination']);
                            foreach ($destinations as $key => $value) {
                                $octets = explode(".", $value);
                                $hostingNetwork = $octets[0] . "." . $octets[1] . "." . $octets[2];
                                if (!in_array($hostingNetwork, $replaceableDestinationNetworks)) {
                                    foreach ($vsyses as $vkey => $checkvsys) {
                                        if (isset($objectsInMemory[$checkvsys]['address'][$value])) {
                                            $member_lid = $objectsInMemory[$checkvsys]['address'][$value]['id'];
                                            $secrulesdst[] = "('$source','$checkvsys','address','$member_lid','$lid','M.Learning')";
                                            break;
                                        }
                                    }
                                }
                                else{
                                    foreach ($vsyses as $vkey => $checkvsys) {
                                        if (isset($objectsInMemory[$checkvsys]['address']["N-".$hostingNetwork.".0-24"])) {
                                            $member_lid = $objectsInMemory[$checkvsys]['address']["N-".$hostingNetwork.".0-24"]['id'];
                                            $secrulesdst[] = "('$source','$checkvsys','address','$member_lid','$lid','M.Learning')";
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if ($params['services']=="true"){
                        if ($getRulesData['service']=="application-default"){
                                $member_lid=$objectsInMemory["shared"]["services"]["application-default"]["all"]['id'];
                                $secrulessrv[] = "('$source','shared','services','$member_lid','$lid','M.Learning')";
                        }
                        elseif ($getRulesData['service']!="any"){
                            $services=explode(",",$getRulesData['service']);
                            foreach($services as $key=>$value){

                                if ($value=="any"){
                                    continue;
                                }

//                                if ($value=="application-default"){
//                                    $member_lid=$objectsInMemory["shared"]["services"]["application-default"]["all"]['id'];
//                                    $secrulessrv[] = "('$source','$checkvsys','services','$member_lid','$lid','M.Learning')";
//                                    break;
//                                }
                                list($protocol,$dport)=explode("/",$value);
                                $processed=false;
                                foreach ($vsyses as $vkey=>$checkvsys){
                                    if ((isset($objectsInMemory[$checkvsys]['services'][$protocol][$dport])) AND ($processed==false)){
                                        $member_lid=$objectsInMemory[$checkvsys]['services'][$protocol][$dport]['id'];
                                        $secrulessrv[] = "('$source','$checkvsys','services','$member_lid','$lid','M.Learning')";
                                        $processed=true;
                                        break;
                                    }

                                }
                                if ($processed==false){
                                    print "NOT FOUND SERVICE IN DB: ".$value.PHP_EOL;
                                }
                            }
                        }
                    }

                    if ($params['zones']=="true"){
                        $zonesSRC=explode(",",$getRulesData['Source_Zone']);
                        foreach ($zonesSRC as $key=>$value){
                            if ($value=="any"){
                                continue;
                            }
                            $secrulesfrom[]="('$source','$vsys','$value','$lid','M.Learning')";
                        }

                        $zonesDST=explode(",",$getRulesData['Destination_Zone']);
                        foreach ($zonesDST as $key=>$value){
                            if ($value=="any"){
                                continue;
                            }
                            $secrulesto[]="('$source','$vsys','$value','$lid','M.Learning')";
                        }
                    }

                    if ($getRulesData['tag']!=""){
                        $tagName=$getRulesData['tag'];
                        $member_lid=$objectsInMemory[$vsys]["tag"][$tagName]['id'];
                        $secrulestag[]="('$source','$member_lid','tag','$vsys','$lid','M.Learning')";
                    }
                    if ($getRulesData['communicationType']!=""){
                        $tagName=$getRulesData['communicationType'];
                        if ($tagName!="any"){
                            $member_lid=$objectsInMemory[$vsys]["tag"][$tagName]['id'];
                            $secrulestag[]="('$source','$member_lid','tag','$vsys','$lid','M.Learning')";
                        }
                    }

                    if ($params['apps']=="true"){
                        if ($getRulesData['application']!="any"){
                            $apps=explode(",",$getRulesData['application']);
                            foreach($apps as $key=>$value){
                                $processed=false;
                                foreach ($vsyses as $vkey=>$checkvsys){

                                    if ((isset($objectsInMemory[$checkvsys]['default_applications'][$value])) AND ($processed==false)){
                                        $member_lid=$objectsInMemory[$checkvsys]['default_applications'][$value]['id'];
                                        $secrulesapp[] = "('$source','$checkvsys','$lid','default_applications','$member_lid','M.Learning')";
                                        $processed=true;
                                        break;
                                    }

                                    if ((isset($objectsInMemory[$checkvsys]['applications'][$value])) AND ($processed==false)){
                                        $member_lid=$objectsInMemory[$checkvsys]['applications'][$value]['id'];
                                        $secrulesapp[] = "('$source','$checkvsys','$lid','applications','$member_lid','M.Learning')";
                                        $processed=true;
                                        break;
                                    }

                                }
                                if ($processed==false){
                                    $projectdb->query("INSERT INTO applications (name,name_ext,dummy,source,vsys) VALUES ('$value','$value','1','$source','shared');");
                                    $member_lid=$projectdb->insert_id;
                                    $secrulesapp[] = "('$source','shared','$lid','applications','$member_lid','M.Learning')";
                                    $processed=true;
                                }
                            }
                        }

                    }

                    if ($params['users']=="true"){
                        if ($getRulesData['sourceUser']!="any"){
                            $users=explode(",",$getRulesData['sourceUser']);
                            foreach($users as $key=>$value){
                                $newName=addslashes($value);
                                if ($newName!=""){
                                    $secrulesusr[] = "('$source','$vsys','$newName','$lid','M.Learning')";
                                }
                            }
                        }
                    }

                    $secrules[] = "('$rule_is_type','$preorpost','$position','$lid','EX $lid','allow','$vsys','$source','M.Learning','None')";
                    $secrulestag[]="('$source',$tag_id,'tag','$vsys','$lid','M.Learning')";
                    $lid++;
                    $position++;

                }

                # INSERT SECURITY RULES INTO DB
                if (count($secrules) > 0) {
                    $unique=array_unique($secrules);
                    $r=$projectdb->query("INSERT INTO security_rules (rule_type,preorpost,position,id,name,action,vsys,source,devicegroup,profile_type) VALUES " . implode(",", $unique) . ";");
                    unset($secrules);unset($unique);

                    if (count($secrulesfrom) > 0) {
                        $unique=array_unique($secrulesfrom);
                        $r=$projectdb->query("INSERT INTO security_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $unique) . ";");
                        unset($secrulesfrom);unset($unique);
                    }
                    if (count($secrulesto) > 0) {
                        $unique=array_unique($secrulesto);
                        $r=$projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $unique) . ";");
                        unset($secrulesto);unset($unique);
                    }
                    if (count($secrulestag) > 0) {
                        $unique=array_unique($secrulestag);
                        $r=$projectdb->query("INSERT INTO security_rules_tag (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $unique) . ";");
                        unset($secrulestag);unset($unique);
                    }
                    if (count($secrulesusr) > 0) {
                        $unique=array_unique($secrulesusr);
                        $r=$projectdb->query("INSERT INTO security_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $unique) . ";");
                        unset($secrulesusr);unset($unique);
                    }

                    if (count($secrulessrc) > 0) {
                        $unique=array_unique($secrulessrc);
                        $r=$projectdb->query("INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $unique) . ";");
                        unset($secrulessrc);unset($unique);
                    }
                    if (count($secrulesapp) > 0) {
                        $unique=array_unique($secrulesapp);
                        $r=$projectdb->query("INSERT INTO security_rules_app (source,vsys,rule_lid,table_name,member_lid,devicegroup) VALUES " . implode(",", $unique) . ";");
                        unset($secrulesapp);unset($unique);
                    }
                    if (count($secrulessrv) > 0) {
                        $unique=array_unique($secrulessrv);
                        $r=$projectdb->query("INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $unique) . ";");
                        unset($secrulessrv);unset($unique);
                    }

                    if (count($secrulesdst) > 0) {
                        $unique=array_unique($secrulesdst);
                        $r=$projectdb->query("INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $unique) . ";");
                        unset($secrulesdst);unset($unique);
                    }


                }

                $message['msg']="Imported Objects successfuly";
                $message['code']=true;
            }
        }
    }
    else{
        $message['msg']="Select Source and Vsys";
        $message['code']=false;
    }

    return $message;

}