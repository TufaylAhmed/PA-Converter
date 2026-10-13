<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 126/11/19 - 15:45
 */

require_once INC_ROOT.'/libs/projectdb.php';  //to be able to set a DB connection
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/backups.php';
require_once INC_ROOT.'/libs/shared.php';

class CalculateUnusedObjects extends AbstractProcess
{

    public function __construct(ARRAY $params){
        parent::__construct($params);
    }

    public function execute(){
        /* @var $app \Slim\Slim */
        global $app;
        $successful = true;

        $this->log(json_encode($this->params));

        //Set a session with the user provided
        if(isset($this->sender)){
            //$user = $app->sentinel->findById($this->sender);  //Provided user for CLI executions
            $userID = $this->params['userId'];

            if($user = $app->user->where('id',$userID)->where('api_key',$this->params['key'])->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
                $app->sentinel->login($user);
            }
        }
        else {
            $user = $app->container->sentinel->getUser();  //Get it from the Sentinel session, if coming from a browser.
            $app->sentinel->login($user);
        }

        if(!$app->container->sentinel->check() || !isset($user)){
            $className = get_class($this);
            $this->log($className. " - Invalid Credentials to execute the process");
            $this->setFailed("Invalid Credentials to execute the process", "Export Cancelled by user invalid credentials");
            return;
        }

        $this->setStarted();
        $this->log("Action:\t\tCalculate Unused Objects\n".
            "User:\t\t".$user->email."\n".
            "Project:\t".$this->params['project']."\n".
            "Source:\t\t".$this->params['source']
        );
        $this->take_snapshot();
        $this->check_used_objects_new();
        //$this->increaseCompleted();

        if(!$successful){
            $this->setFailedSilent();
        }
        else {
            $this->setCompletedSilent();
        }
    }

    protected function take_snapshot(){
        take_snapshot_last($this->params['project']);
    }

    protected function check_used_objects_new() {

        global $projectdb;
        $projectdb = selectDatabase($this->params['project']);

        $source = $this->params['source'];

        $array_address = array();
        $array_address_groups = array();
        $array_services = array();
        $array_services_groups = array();
        $array_regions = array();
        $array_default_regions = array();
        $array_applications = array();
        $array_applications_groups = array();
        $array_applications_filters = array();
        $array_default_applications = array();
        $array_tag = array();

        if($source != '') {
            $sourceScope = $source;
            $sourceScopeWhere = " WHERE source in ($sourceScope) ";
            $sourceScopeAnd = " AND source in ($sourceScope) ";
            $sourceScopeAndA = " AND a.source in ($sourceScope) ";
            $sourceScopeIDWhere = " WHERE id in ($sourceScope) ";
            $sourceScopeIDAnd = " AND id in ($sourceScope) ";
            $sourceScopeIDAndTable = "AND relation.member_lid=a.id AND a.source in ($sourceScope)";
        }
        else{
            $sourceScopeWhere = '';
            $sourceScopeAnd = '';
            $sourceScopeAndA = '';
            $sourceScopeIDWhere = '';
            $sourceScopeIDAnd = '';
            $sourceScopeIDAndTable = '';
        }

        /*       $addressReferingTables = array(
                   "security_rules_src",  "security_rules_dst",
                   "nat_rules_src", "nat_rules_dst", "nat_rules_translated_address", "nat_rules_translated_address_fallback",
                   "appoverride_rules_dst", "appoverride_rules_src", "authentication_rules_src",
                   "authentication_rules_dst",
                   "decryption_rules_dst", "decryption_rules_src",
                   "dos_rules_dst", "dos_rules_src", "pbf_rules_src",
                   "pbf_rules_dst", "qos_rules_dst", "qos_rules_src", "qos_rules_srv",
                   "tunnel_inspect_rules_dst", "tunnel_inspect_rules_src",
                   "captiveportal_rules_dst", "captiveportal_rules_src"
               );

               $serviceReferingTables = array(
                   "security_rules_srv",
                   "authentication_rules_srv",
                   "decryption_rules_srv",
                   "dos_rules_srv",
                   "pbf_rules_srv",
                   "captiveportal_rules_srv"
               );

               $appsReferingTables = array(
                   "pbf_rules_app",
                   "qos_rules_app",
                   "tunnel_inspect_rules_app",
                   "security_rules_app"
               );

               $tagReferingTables = array(
                   "security_rules_tag",
                   "nat_rules_tag",
                   "appoverride_rules_tag",
                   "dos_rules_tag",
                   "pbf_rules_tag",
                   "qos_rules_tag",
                   "tunnel_inspect_rules_tag",
                   "captiveportal_rules_tag",
                    "authentication_rules_tag",
                    "decryption_rules_tag"
               );

               $FILE_GROUP_TAGS = array(
                   "security_rules",
                   "nat_rules",
                   "appoverride_rules",
                   "authentication_rules",
                   "decryption_rules",
                   "dos_rules",
                   "pbf_rules",
                   "qos_rules",
                   "tunnel_inspect_rules"
               );*/

        $addressReferingTables = array();
        $serviceReferingTables = array();
        $appsReferingTables = array();
        $tagReferingTables = array();
        $addressReferingTables[] = "security_rules_src";
        $addressReferingTables[] = "security_rules_dst";
        $serviceReferingTables[] = "security_rules_srv";
        $appsReferingTables[] = "security_rules_app";
        $tagReferingTables[] = "security_rules_tag";
        $FILE_GROUP_TAGS[] = "security_rules";
        $addressReferingTables[] = "nat_rules_src";
        $addressReferingTables[] = "nat_rules_dst";
        $addressReferingTables[] = "nat_rules_translated_address";
        $addressReferingTables[] = "nat_rules_translated_address_fallback";
        $tagReferingTables[] = "nat_rules_tag";
        $FILE_GROUP_TAGS[] = "nat_rules";
        $addressReferingTables[] = "appoverride_rules_dst";
        $addressReferingTables[] = "appoverride_rules_src";
        $tagReferingTables[] = "appoverride_rules_tag";
        $FILE_GROUP_TAGS[] = "appoverride_rules";

        # NEW OTHER RULES
        $addressReferingTables[] = "authentication_rules_src";
        $addressReferingTables[] = "authentication_rules_dst";
        $serviceReferingTables[] = "authentication_rules_srv";
        $tagReferingTables[] = "authentication_rules_tag";
        $FILE_GROUP_TAGS[] = "authentication_rules";
        $addressReferingTables[] = "decryption_rules_dst";
        $addressReferingTables[] = "decryption_rules_src";
        $serviceReferingTables[] = "decryption_rules_srv";
        $tagReferingTables[] = "decryption_rules_tag";
        $FILE_GROUP_TAGS[] = "decryption_rules";
        $addressReferingTables[] = "dos_rules_dst";
        $addressReferingTables[] = "dos_rules_src";
        $serviceReferingTables[] = "dos_rules_srv";
        $tagReferingTables[] = "dos_rules_tag";
        $FILE_GROUP_TAGS[] = "dos_rules";
        $addressReferingTables[] = "pbf_rules_src";
        $addressReferingTables[] = "pbf_rules_dst";
        $appsReferingTables[] = "pbf_rules_app";
        $serviceReferingTables[] = "pbf_rules_srv";
        $tagReferingTables[] = "pbf_rules_tag";
        $FILE_GROUP_TAGS[] = "pbf_rules";
        $addressReferingTables[] = "qos_rules_dst";
        $addressReferingTables[] = "qos_rules_src";
        $serviceReferingTables[] = "qos_rules_srv";
        $appsReferingTables[] = "qos_rules_app";
        $tagReferingTables[] = "qos_rules_tag";
        $FILE_GROUP_TAGS[] = "qos_rules";
        $addressReferingTables[] = "tunnel_inspect_rules_dst";
        $addressReferingTables[] = "tunnel_inspect_rules_src";
        $appsReferingTables[] = "tunnel_inspect_rules_app";
        $tagReferingTables[] = "tunnel_inspect_rules_tag";
        $FILE_GROUP_TAGS[] = "tunnel_inspect_rules";
        $addressReferingTables[] = "captiveportal_rules_dst";
        $addressReferingTables[] = "captiveportal_rules_src";
        $serviceReferingTables[] = "captiveportal_rules_srv";
        $tagReferingTables[] = "captiveportal_rules_tag";

        # New include list and exclude list from zones
        $addressReferingTables[] = "zones_include_list";
        $addressReferingTables[] = "zones_exclude_list";
        //$FILE[] = "tag_relations";

        $this->increaseCompleted();
        #Clean all Used Objects
        $projectdb->query("UPDATE address SET used='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE services SET used='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE address_groups_id SET used='0',checkit='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE services_groups_id SET used='0',checkit='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE applications SET used='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE applications_groups_id SET used='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE applications_filters SET used='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE default_applications SET used='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE regions SET used='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE default_regions SET used='0' $sourceScopeWhere;");
        $projectdb->query("UPDATE tag SET used='0' $sourceScopeWhere;");

        $this->increaseCompleted();

        foreach ($addressReferingTables as $key => $value) {
            $DATA = $projectdb->query(
                "SELECT member_lid,table_name 
            FROM $value relation,
                 address a 
            WHERE table_name = 'address' $sourceScopeIDAndTable
            GROUP BY member_lid,table_name;");

            /*if($value == "nat_rules_translated_address"){
                echo "SELECT member_lid,table_name 
                FROM $value relation,
                     address a 
                WHERE table_name = 'address' $sourceScopeIDAndTable
                GROUP BY member_lid,table_name;\n";
            }*/

            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_address[] = $member_id;
                }
            }
        }

        foreach ($addressReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
            FROM $value relation,
            address_groups_id a 
            WHERE table_name = 'address_groups_id' $sourceScopeIDAndTable
            GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_address_groups[] = $member_id;
                }
            }
        }

        $this->increaseCompleted();

        foreach ($serviceReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
              services a
              WHERE table_name = 'services' $sourceScopeIDAndTable 
              GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_services[] = $member_id;
                }
            }
        }

        foreach ($serviceReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                  services_groups_id a
              WHERE table_name = 'services_groups_id' $sourceScopeIDAndTable 
              GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_services_groups[] = $member_id;
                }
            }
        }

        $this->increaseCompleted();

        foreach ($addressReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   regions a
              WHERE table_name = 'regions' $sourceScopeIDAndTable 
              GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_regions[] = $member_id;
                }
            }
        }

        foreach ($addressReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value 
              WHERE table_name = 'default_regions' 
              GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_default_regions[] = $member_id;
                }
            }
        }

        $this->increaseCompleted();

        foreach ($appsReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   applications a
              WHERE table_name = 'applications' $sourceScopeIDAndTable 
              GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_applications[] = $member_id;
                }
            }
        }

        foreach ($appsReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   applications_groups_id a
              WHERE table_name = 'applications_groups_id' $sourceScopeIDAndTable  
              GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_applications_groups[] = $member_id;
                }
            }
        }

        foreach ($appsReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   applications_filters a
              WHERE table_name = 'applications_filters' $sourceScopeIDAndTable  
              GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_applications_filters[] = $member_id;
                }
            }
        }

        foreach ($appsReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value 
              WHERE table_name = 'default_applications'   
              GROUP BY member_lid,table_name;");
            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_default_applications[] = $member_id;
                }
            }
        }

        $this->increaseCompleted();

        foreach ($tagReferingTables as $key => $value) {
            $DATA = $projectdb->query("SELECT member_lid,table_name 
              FROM $value relation,
                   tag a
              WHERE table_name = 'tag'   $sourceScopeIDAndTable
              GROUP BY member_lid,table_name;");

            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["member_lid"];
                    $array_tag[] = $member_id;
                }
            }
        }

        # PanOS 9 Group Tags
        foreach ($FILE_GROUP_TAGS as $key => $value) {
            $DATA = $projectdb->query("SELECT group_tag_id 
                  FROM $value relation,
                       tag a
                  WHERE relation.group_tag_id = a.id   $sourceScopeAndA
                  GROUP BY group_tag_id;");

            if ($DATA->num_rows > 0) {
                while ($getRuleSourceData = $DATA->fetch_array()) {
                    $member_id = $getRuleSourceData["group_tag_id"];
                    $array_tag[] = $member_id;
                }
            }
        }

        $this->increaseCompleted();

        $getVsys = $projectdb->query("SELECT id,filename FROM device_mapping $sourceScopeIDWhere GROUP BY filename;");
        if ($getVsys->num_rows > 0) {

            while ($theVsys = $getVsys->fetch_assoc()) {
                $filename = $theVsys['filename'];
                $source = $theVsys['id'];
                $getVsysAll = $projectdb->query("SELECT vsys FROM device_mapping WHERE filename='$filename';");
                //echo "SELECT vsys FROM device_mapping WHERE filename='$filename' $sourceScopeIDAnd;\n";

                while ($data = $getVsysAll->fetch_assoc()) {
                    $vsys = $data['vsys'];
                    $addVsys = " AND vsys='$vsys'";

                    #get from nats
                    $query = "SELECT op_service_lid,op_service_table,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE source='$source' AND vsys='$vsys';";
                    $getFromNat = $projectdb->query($query);
                    //echo "SELECT op_service_lid,op_service_table,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE source='$source' AND vsys='$vsys';\n";
                    while ($DATA = $getFromNat->fetch_assoc()) {
                        $op_service_lid = $DATA['op_service_lid'];
                        $op_service_table = $DATA['op_service_table'];
                        $tp_dat_address_lid = $DATA['tp_dat_address_lid'];
                        $tp_dat_address_table = $DATA['tp_dat_address_table'];
                        if (($op_service_lid != "") and ($op_service_table != "")) {
                            if ($op_service_table == "services") {
                                $array_services[] = $op_service_lid;
                            } elseif ($op_service_table == "services_groups_id") {
                                $array_services_groups[] = $op_service_lid;
                            }
                        }
                        if (($tp_dat_address_lid != "") and ($tp_dat_address_table != "")) {
                            if ($tp_dat_address_table == "address") {
                                $array_address[] = $tp_dat_address_lid;
                            } elseif ($tp_dat_address_table == "address_groups_id") {
                                $array_address_groups[] = $tp_dat_address_lid;
                            }
                        }
                    }

                    // Search in Interfaces
                    $getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE source = '$source' $addVsys AND unitipaddress != '';");

                    if ($getInterface->num_rows > 0) {

                        while ($dataI = $getInterface->fetch_array()) {

                            $all_interfaces = $dataI['unitipaddress'];
                            $interfaces_exp = explode(",", $all_interfaces);

                            foreach ($interfaces_exp AS $name_int) {

                                $get_mem_table = get_member_and_lid_name_int($name_int, $source, $vsys, "address");

                                if ($get_mem_table != "") {
                                    $member_id = $get_mem_table["member_lid"];
                                    $table_name = $get_mem_table["table_name"];
                                    if ($table_name == "address") {
                                        $array_address[] = $member_id;
                                    } elseif ($table_name == "address_groups_id") {
                                        $array_address_groups[] = $member_id;
                                    }
                                }
                            }
                        }
                    }

                    // Search in Zones
                    $getZones = $projectdb->query("SELECT include_list, exclude_list FROM zones WHERE source = '$source' $addVsys AND (include_list != '' OR exclude_list != '');");

                    if ($getZones->num_rows > 0) {

                        while ($dataZ = $getZones->fetch_array()) {

                            $all_include_list = $dataZ['include_list'];
                            $all_exclude_list = $dataZ['exclude_list'];
                            $incl_exp = explode(",", $all_include_list);
                            $exc_exp = explode(",", $all_exclude_list);
                            $final_zone = array_merge($incl_exp, $exc_exp);

                            foreach ($final_zone AS $name_int) {

                                $get_mem_table = get_member_and_lid_name_int($name_int, $source, $vsys, "address");

                                if ($get_mem_table != "") {
                                    $member_id = $get_mem_table["member_lid"];
                                    $table_name = $get_mem_table["table_name"];
                                    if ($table_name == "address") {
                                        $array_address[] = $member_id;
                                    } elseif ($table_name == "address_groups_id") {
                                        $array_address_groups[] = $member_id;
                                    }
                                }
                            }
                        }
                    }

                    #get from appoverride rules app
                    $getFromNat = $projectdb->query("SELECT app_id, app_table FROM appoverride_rules WHERE source='$source' AND vsys='$vsys';");
                    //echo "2. SELECT app_id, app_table FROM appoverride_rules WHERE source='$source' AND vsys='$vsys';\n";
                    while ($DATA = $getFromNat->fetch_assoc()) {
                        $app_id = $DATA['app_id'];
                        $app_table = $DATA['app_table'];
                        if (($app_id != "") and ($app_table != "")) {
                            if ($app_table == "applications") {
                                $array_applications[] = $app_id;
                            } elseif ($app_table == "applications_groups_id") {
                                $array_applications_groups[] = $app_id;
                            } elseif ($app_table == "applications_filters") {
                                $array_applications_filters[] = $app_id;
                            } elseif ($app_table == "default_applications") {
                                $array_default_applications[] = $app_id;
                            }
                        }
                    }

                    #Panos 8
                    # Check in Static Routes Path Monitoring
                    $getStatic = $projectdb->query("SELECT dst_member_lid FROM routes_static_monitor_destinations;");
                    if ($getStatic->num_rows > 0) {
                        while ($getStaticData = $getStatic->fetch_assoc()) {
                            $array_address[] = $getStaticData['dst_member_lid'];
                        }
                    }

                    #Panos 9
                    # Check in Static Routes
                    $getStatic = $projectdb->query("SELECT destination_member_lid, nexthop_value_member_lid FROM routes_static;");
                    if ($getStatic->num_rows > 0) {
                        while ($getStaticData = $getStatic->fetch_assoc()) {
                            $array_address[] = $getStaticData['destination_member_lid'];
                            $array_address[] = $getStaticData['nexthop_value_member_lid'];
                        }
                    }

                    # Check on tag_relations
                    $getTagRelations = $projectdb->query("SELECT DISTINCT(tr.tag_id) FROM tag_relations tr, tag t WHERE t.id = tr.tag_id AND t.source = '$source' AND t.vsys = '$vsys';");

                    if ($getTagRelations->num_rows > 0) {
                        while ($dataTR = $getTagRelations->fetch_array()) {
                            $array_tag[] = $dataTR['tag_id'];
                        }
                    }
                }
            }

            //echo "ADDRESS: \n";
            //print_r($array_address);
            //echo "El count: ".count($array_address)."";

            //Calculating dynamic groups
            $done = false;
            while (!$done) {
                $oldGroups = array_unique($array_address_groups);
                $tagNames = array();

                if (count($array_address_groups) > 0) {
                    $query = "SELECT distinct filter
                  FROM address_groups_id group1
                  WHERE group1.type='dynamic' AND id in (" . implode(',', array_unique($array_address_groups)) . ");";
                    $dynamicTagsR = $projectdb->query($query);
                    if ($dynamicTagsR->num_rows > 0) {
                        //$tagNames = array();
                        while ($row = $dynamicTagsR->fetch_assoc()) {
                            $tagSet = $row['filter'];
                            $tagNames = array_merge($tagNames, explode(",", $tagSet));
                        }
                    }
                }

                //Mark as used all the address and group objects that use the tags in filters
                if (count($tagNames) > 0) {
                    $query = "SELECT table_name, member_lid 
                      FROM tag_relations relations, tag 
                      WHERE tag.id=relations.tag_id AND tag.name in (" . implode(',', array_unique($tagNames)) . " )";
                    $objectsR = $projectdb->query($query);
                    if ($objectsR->num_rows > 0) {
                        $objects = array();
                        while ($data = $objectsR->fetch_array()) {
                            $objects[] = $data;
                        }

                        foreach ($objects AS $object) {
                            if ($object["table_name"] == "address") {
                                $array_address[] = $object["member_lid"];
                            } elseif ($object["table_name"] == "address_groups_id") {
                                $array_address_groups[] = $object["member_lid"];
                            }
                        }
                    }
                }
                $array_address = array_unique($array_address);
                $array_address_groups = array_unique($array_address_groups);
                if(count(array_diff($array_address_groups, $oldGroups))==0){
                    $done = true;
                }

                //We got new used groups. Let's check if these make new ones to get included!
            }

            //echo "ADDRESS GROUPS: \n";
            //print_r($array_address_groups);
            if (count($array_address_groups) > 0) {
                $unique = array_unique($array_address_groups);
                $this->updateUsedSameName($projectdb, 'address_groups_id', $unique, $source);
                //$projectdb->query("UPDATE address_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            }

            if (count($array_address) > 0) {
                $unique = array_unique($array_address);
                //echo "EL UNIQUE DEL ADDRESS \n";
                //print_r($unique);
                //echo "El count unique: ".count($unique)."";
                $this->updateUsedSameName($projectdb, 'address', $unique, $source);
                //$projectdb->query("UPDATE address SET used='1' WHERE name in (select * from (select name from address WHERE id IN (" . implode(',', $unique) . ") )t);");
            }

            //echo "SERVICES: \n";
            //print_r($array_services);
            if (count($array_services) > 0) {
                $unique = array_unique($array_services);
                //echo "UNIQUE de SERVICES: \n";
                //print_r($unique);
                //$projectdb->query("UPDATE services SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
                $this->updateUsedSameName($projectdb, 'services', $unique, $source);
            }

            //echo "SERVICES GROUPS ID: \n";
            //print_r($array_services_groups);
            if (count($array_services_groups) > 0) {
                $unique = array_unique($array_services_groups);
                //$projectdb->query("UPDATE services_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
                $this->updateUsedSameName($projectdb, 'services_groups_id', $unique, $source);
            }

            if (count($array_regions) > 0) {
                $unique = array_unique($array_regions);
                $projectdb->query("UPDATE regions SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            }

            if (count($array_default_regions) > 0) {
                $unique = array_unique($array_default_regions);
                $projectdb->query("UPDATE default_regions SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            }

            //echo "APPLICATIONS: ";
            //print_r($array_applications);
            if (count($array_applications) > 0) {
                $unique = array_unique($array_applications);
                $projectdb->query("UPDATE applications SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            }

            if (count($array_applications_groups) > 0) {
                $unique = array_unique($array_applications_groups);
                $projectdb->query("UPDATE applications_groups_id SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            }

            if (count($array_applications_filters) > 0) {
                $unique = array_unique($array_applications_filters);
                $projectdb->query("UPDATE applications_filters SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            }

            if (count($array_default_applications) > 0) {
                $unique = array_unique($array_default_applications);
                $projectdb->query("UPDATE default_applications SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            }

            if (count($array_tag) > 0) {
                $unique = array_unique($array_tag);
                $projectdb->query("UPDATE tag SET used='1' WHERE id IN (" . implode(',', $unique) . ")");
            }

            # Calculate nested Groups Used
            $mytables = array();
            $mytables[] = array("tablename" => "address_groups_id", "tablename2" => "address_groups");
            $mytables[] = array("tablename" => "services_groups_id", "tablename2" => "services_groups");
            $mytables[] = array("tablename" => "applications_groups_id", "tablename2" => "applications_groups");

            foreach ($mytables as $thekey => $thevalue) {
                $tablename = $mytables[$thekey]['tablename'];
                $tablename2 = $mytables[$thekey]['tablename2'];
                $name = array();
                $setused = array();
                $getGR = $projectdb->query("SELECT id,name FROM $tablename WHERE used='1' AND checkit='0' $sourceScopeAnd;");
                if ($getGR->num_rows > 0) {
                    while ($data = $getGR->fetch_assoc()) {
                        $lid = $data['id'];
                        $name[] = array("id" => $data['id']);
                    }
                }

                $x = 0;
                $alreadyseen=array();
                while (count($name) > 0) {
                    $grplid = $name[$x]['id'];
                    $getMember = $projectdb->query("SELECT table_name,member_lid FROM $tablename2 WHERE lid='$grplid';");
                    if ($getMember->num_rows > 0) {
                        while ($data2 = $getMember->fetch_assoc()) {
                            $member_lid = $data2['member_lid'];
                            $table_name = $data2['table_name'];
                            if ($table_name == $tablename) {
                                if (!in_array($member_lid,$alreadyseen)){
                                    $name[] = array("id" => $data2['member_lid']);
                                    $setused[$table_name][] = $member_lid;
                                    $alreadyseen[]=$member_lid;
                                }
                            } else {
                                $setused[$table_name][] = $member_lid;
                            }
                        }
                    }
                    unset($name[$x]);
                    $x++;
                }
                foreach ($setused as $key => $value) {
                    $unique_tablename = array_unique($value);
                    $projectdb->query("UPDATE $key SET used=1 WHERE id IN (" . implode(',', $unique_tablename) . ");");
                }
            }

            $start=0;
            $end=1;
            while($start!=$end){
                #Check for Dynamic Address Groups based on Tags
                $getDyn = $projectdb->query("SELECT id,filter,source,vsys FROM address_groups_id WHERE used='1' AND checkit='0' AND type='dynamic' AND filter!='' $sourceScopeAnd;");
                $start1=$getDyn->num_rows;
                if ($getDyn->num_rows > 0) {
                    while ($getDyndata = $getDyn->fetch_assoc()) {
                        $filter = $getDyndata['filter'];
                        $new_sql=generate_sql_query_bytag($filter);
                        //$filter = str_replace("'", "", $filter);
                        $lid = $getDyndata['id'];
                        $source = $getDyndata['source'];
                        $vsys = $getDyndata['vsys'];

                        #Update Address
                        $projectdb->query("UPDATE address SET used=1 WHERE source='$source' AND vsys='$vsys' $new_sql;");

                        #Update Address_groups_id
                        $projectdb->query("UPDATE address_groups_id SET used=1 WHERE source='$source' AND vsys='$vsys' $new_sql;");

                    }
                }

                $start=$start1;
                # Calculate nested Groups Used after tags
                $mytables = array();
                $mytables[] = array("tablename" => "address_groups_id", "tablename2" => "address_groups");

                foreach ($mytables as $thekey => $thevalue) {
                    $tablename = $mytables[$thekey]['tablename'];
                    $tablename2 = $mytables[$thekey]['tablename2'];
                    $name = array();
                    $setused = array();
                    $getGR = $projectdb->query("SELECT id,name FROM $tablename WHERE used='1' AND checkit='0' $sourceScopeAnd;");
                    if ($getGR->num_rows > 0) {
                        while ($data = $getGR->fetch_assoc()) {
                            $lid = $data['id'];
                            $name[] = array("id" => $data['id']);
                        }
                    }

                    $x = 0;
                    $alreadyseen=array();
                    while (count($name) > 0) {
                        $grplid = $name[$x]['id'];
                        $getMember = $projectdb->query("SELECT table_name,member_lid FROM $tablename2 WHERE lid='$grplid';");
                        if ($getMember->num_rows > 0) {
                            while ($data2 = $getMember->fetch_assoc()) {
                                $member_lid = $data2['member_lid'];
                                $table_name = $data2['table_name'];
                                if ($table_name == $tablename) {
                                    if (!in_array($member_lid,$alreadyseen)){
                                        $name[] = array("id" => $data2['member_lid']);
                                        $setused[$table_name][] = $member_lid;
                                        $alreadyseen[]=$member_lid;
                                    }
                                } else {
                                    $setused[$table_name][] = $member_lid;
                                }
                            }
                        }
                        unset($name[$x]);
                        $x++;
                    }
                    foreach ($setused as $key => $value) {
                        $unique_tablename = array_unique($value);
                        $projectdb->query("UPDATE $key SET used=1 WHERE id IN (" . implode(',', $unique_tablename) . ");");
                    }
                }

                #calc end
                $getDyn = $projectdb->query("SELECT id,filter,source,vsys FROM address_groups_id WHERE used='1' AND checkit='0' AND type='dynamic' AND filter!='' $sourceScopeAnd;");
                $end1=$getDyn->num_rows;
                $end=$end1;
            }
        }

        // When we are setting an object as used, we need also to find if it has duplicates by name
        // and flag all findings as used (maybe defined on other vsys)
        sharedUpdateUsedBySameName($projectdb, "address_groups_id", $source);
        sharedUpdateUsedBySameName($projectdb, "address", $source);
        sharedUpdateUsedBySameName($projectdb, "services", $source);
        sharedUpdateUsedBySameName($projectdb, "services_groups_id", $source);

        $this->increaseCompleted();
    }

    /***
     * Provided an array of ids and a type of objects to update, marks as Used all the objects within the id list and any other that has the same name
     * @param mysqli $projectdb
     * @param string $table
     * @param array $ids
     * @param int $source
     */
    private function updateUsedSameName(mysqli $projectdb, string $table, array $ids, int $source)
    {
        // This query works on both Ubuntu 20.x and Ubuntu 16.x
        $query = "UPDATE $table SET used='1' WHERE name in (select * from (select name from $table WHERE id IN (" . implode(',', $ids) . ") )t) AND source=$source;";
        $projectdb->query($query);
    }


}