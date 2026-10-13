<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 10/6/16 - 15:45
 */

require_once INC_ROOT.'/libs/common/MemberObject.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/shared.php';

use PaloaltoNetworks\Policy\Objects\MemberObject;

class AutoZonePolicy
    extends AbstractProcess
{

    public function __construct(ARRAY $params){
        parent::__construct($params);
    }

    public function calculate_default_zone(ARRAY $params, STRING $ip_version="ipv4"){
        foreach ($params as $data) {
            //print_r($data);
            if ($data['network'] == '0.0.0.0/0')
                return $data['zone'];
        }
        return '';
    }

    public function execute(){
//    function fix_Zones_Policy($jobid, STRING $projectName, STRING $source, STRING $vsys, $vr,
//                              ARRAY $ruleIds, ARRAY $tags = null,
//                              bool $applyNat=true,  bool $doFrom = true, bool $doTo=true){

        //Set max execution times
        ini_set('max_execution_time', PARSER_max_execution_time);
        ini_set("memory_limit",PARSER_max_execution_memory);

        global $projectdb;
        global $app;

        $userID = $this->params['userId'];

        if($user = $app->user->where('id',$userID)->where('api_key',$this->params['key'])->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
            $app->sentinel->login($user);
        }

        if(!$app->container->sentinel->check() || !isset($user)){
            $className = get_class($this);
            $this->log($className. " - Invalid Credentials to execute the process");
            $this->setFailed("Invalid Credentials to execute the process", "Export Cancelled by user invalid credentials");
            return;
        }

        $natted_rules_partially = array();
        $params = $this->params;
        $taskId = $params['taskId'];
        $data = $params['data'];
//        Echo "Parameters for the Autonat:";
//        print_r($data);
        $projectName = $data->project;
        $projectdb = selectDatabase($projectName);


        $vsys = $data->vsys;
        $templateID = isset($data->templateID)?$data->templateID:null;
        $source = $data->source;
        $vr = $data->vr;

        $ruleIds = $data->ruleIds;

        $tags = $data->tags;

        $applyNat = ($data->applyNat==1 || $data->applyNat==true)?true:false;
        $applyNatString = ($data->applyNat==1 || $data->applyNat==true)?'true':'false';

        $doFrom = $data->doFrom;
        $doTo = $data->doTo;

//        $this->log("Action:\t\tImporting Discovered Rules\nConvert to Shared:\t".$this->params['shared']."\nvsys:\t".$this->params['vsys']."\nsource Density:\t".$this->params['sourceDensity']."\ndest. Density:\t".$this->params['destinationDensity']."\n");

        $this->log("Action:\t\tAutozone\n".
            "ApplyNat:\t$applyNatString\n".
            "Do From:\t$doFrom\n".
            "Do To:\t\t$doTo\n".
            "Project:\t$projectName\n".
            "Source:\t\t$source\n".
            "Template:\t$templateID\n".
            "Vsys:\t\t$vsys\n".
            "Vir.Rout:\t$vr\n".
            "Rules:\t\t".implode(',',$ruleIds)."\n".
            "Tags:\t\t'".implode(',',$tags)."' ");

        $date = date("Y-m-d_H.i.s");
        //take_snapshot($projectName, "AutoBackup-BeforeAutozone-$date");
        take_snapshot_last($projectName);

        //echo "Getting RouteMapping for vsys:$vsys, source:$source, vr:$vr, template:$templateID\n";
        $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr, $templateID);
        //print_r($ipMapping);

        //echo "Mapping done\n";

        $getDefaultZoneipv4='';
        $getDefaultZoneipv6=''; # Todo: Future use
        //Check we have routing information to be able to calculate Zones

        if(count($ipMapping['ipv4'])==0){
            $this->log( 'Routing information is missing. Not possible to calculate policy Zones');
            $this->updateTaskStatus('Routing information is missing. Not possible to calculate policy Zones','-1','1', false);
            add_log2('error', 'Auto Zone Assign', 'Routing information is missing.', $source, 'Not possible to calculate policy Zones', 'rules', '', 'security_rules');
            return;
        }

        $getDefaultZoneipv4=$this->calculate_default_zone($ipMapping['ipv4'],'ipv4');

        if ($getDefaultZoneipv4==''){
            $this->log("A default gateway is mandatory in order to correctly calculate the zones. Add one to your virtual router and try it again.\n");
            $this->updateTaskStatus('A default gateway is mandatory in order to correctly calculate the zones. Add one to your virtual router and try it again.','-1','1', true);
            add_log2('error', 'Auto Zone Assign', 'A default gateway is mandatory in order to correctly calculate the zones.', $source, 'Add a Default Gateway to your virtual router and try it again', 'rules', '', 'security_rules');
            return;
        }

        $natted_rules = null;   //IDs of the modified rules
        $security_rules = array();
        $captureIds=false;
        $captureIdsData=array();

        if(count($ruleIds)>0) {
            $conditionIds = " AND id IN (".implode(',', $ruleIds).")";
            $conditionRelaIds = " AND rule_lid IN ('".implode(',', $ruleIds)."')";
            $captureIds=false;
        }
        else{
            $conditionIds ='';
            $conditionRelaIds ='';
            $captureIds=true;
        }

        if(count($tags)>0) {
            $partial_conditionTags = array();
            foreach ($tags as $tag){
                $partial_conditionTags[] = " (tag LIKE '$tag') ";
            }
            $conditionTags = implode(' OR ', $partial_conditionTags);
            $conditionTags = ' AND '.$conditionTags;
        }
        else{
            $conditionTags='';
        }

        if($vsys == 'all'){
            $conditionVsys = '';
        }
        else{
            $conditionVsys = " AND vsys='$vsys' ";
        }

        /***
         * COLLECT ALL THE POLICY RULES AS OBJECTS
         */
        //Initialize a 2Dim associative array for the security rules with the size of the rules we have.
        $query = "SELECT id, devicegroup, negate_source, negate_destination  FROM security_rules WHERE source='$source' $conditionVsys $conditionIds $conditionTags ORDER BY position;";
//        echo "Query1: " .$query. "\n";
        $rules = $projectdb->query($query);
        $number_of_rules = $rules->num_rows;
        if ($number_of_rules > 0) {
            while ($getINData = $rules->fetch_assoc()){
                $captureIdsData[]=$getINData['id'];
                $id = $getINData['id'];
                $security_rules[$id]['from']=array();
                $security_rules[$id]['src']=array();    //List of Members that are sources
                $security_rules[$id]['Nsrc']=$getINData['negate_source'];
                $security_rules[$id]['dst']=array();    //List of Members that are destinations
                $security_rules[$id]['Ndst']=$getINData['negate_destination'];
                $security_rules[$id]['srv']=array();    //List of Members that are services
                $security_rules[$id]['modified']=false; //Flag to mark if this rule has been corrected or not
                $security_rules[$id]['devicegroup']=$getINData['devicegroup'];
            }
        }
        else{
            $this->updateTaskStatus('No rules fit the criteria','1','1', true);
            return;
        }

        //Get all the Security_Rules Sources and Destinations and group them by Rule_lid

        $conditionRelaIds = " rule_lid IN (".implode(",", $captureIdsData).")";
        $query = "SELECT name, rule_lid FROM security_rules_from WHERE $conditionRelaIds;";
        $getRulesFrom = $projectdb->query($query);
        if ($getRulesFrom->num_rows > 0) {
            while ($getINData = $getRulesFrom->fetch_assoc()){
                $member = $getINData['name'];
                $rule_lid = $getINData['rule_lid'];
                $security_rules[$rule_lid]['from'][]=$member;
            }
        }

        $query = "SELECT member_lid, table_name, rule_lid FROM security_rules_src WHERE $conditionRelaIds;";
        $getRulesSrc = $projectdb->query($query);
        if ($getRulesSrc->num_rows > 0) {
            while ($getINData = $getRulesSrc->fetch_assoc()){
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];
                $rule_lid = $getINData['rule_lid'];
                $member = new MemberObject($member_lid, $table_name);
                $security_rules[$rule_lid]['src'][]=$member;
            }
        }

        $getRulesDst = $projectdb->query("SELECT member_lid, table_name, rule_lid FROM security_rules_dst WHERE  $conditionRelaIds;");
        if ($getRulesDst->num_rows > 0) {
            while ($getINData = $getRulesDst->fetch_assoc()){
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];
                $rule_lid = $getINData['rule_lid'];
                $member = new MemberObject($member_lid, $table_name);
                $security_rules[$rule_lid]['dst'][]=$member;
            }
        }

        $getRulesDst = $projectdb->query("SELECT member_lid, table_name, rule_lid FROM security_rules_srv WHERE  $conditionRelaIds;");
        if ($getRulesDst->num_rows > 0) {
            while ($getINData = $getRulesDst->fetch_assoc()){
                $member_lid = $getINData['member_lid'];
                $table_name = $getINData['table_name'];
                $rule_lid = $getINData['rule_lid'];
                $member = new MemberObject($member_lid, $table_name);
                $security_rules[$rule_lid]['srv'][]=$member;
            }
        }

//        update_progress($projectName, '0.05', 'Security Rules Loaded.',$jobid);
        $this->updateTaskStatus('Security Rules Loaded.','0','0.05', true);

        //Expand the Members that we have founds for each rule
        foreach($security_rules as $key=>&$security_rule){
            $members_src = $security_rule['src'];
            $members_dst = $security_rule['dst'];
            $members_srv = $security_rule['srv'];
            $security_rule['src'] = explodeGroups2Members($members_src,  $projectdb, $source, $vsys);
            $security_rule['dst'] = explodeGroups2Members($members_dst,  $projectdb, $source, $vsys);
            $security_rule['srv'] = explodeGroups2Services($members_srv, $projectdb, $source, $vsys);
        }

        //Some rules did not get any specific source or destination. Those were ANY. Let's fill it with the ANY member
        $anyMember = new MemberObject('any', '','0.0.0.0', '0');
        $anyMemberSrv = new MemberObject('any', '','0', '');
        foreach ($security_rules as &$security_rule){
            if(count($security_rule['src'])==0){
                $security_rule['src'][]=$anyMember;
            }
            if(count($security_rule['dst'])==0){
                $security_rule['dst'][]=$anyMember;
            }
            if(count($security_rule['srv'])==0){
                $security_rule['srv'][]=$anyMemberSrv;
            }
        }

//        echo "Rules to process expanded:";
//        print_r($security_rules);
//        update_progress($projectName, '0.10', 'Security Rules Expanded.',$jobid);
        $this->updateTaskStatus('Security Rules Expanded.','0','0.10', true);

        //Calculate the ZONES TO to the all the security rules in the selection


        if($doFrom) {
//            echo "Let's do From\n";
            $count_security_rules = count($security_rules);
            $count_i = 0;

            $addFrom=array();
            foreach ($security_rules as $rule_lid => $sec_rule) {
                $count_i++;
                $date = date('Y-m-d H:i:s');
                $this->log("Calculating From from rule_lid $rule_lid  [$count_i/$count_security_rules] - now: $date" );

                $negate_source = $sec_rule['Nsrc'];
                $zones = array();

                foreach ($sec_rule['src'] as $sec_source) {
                    $member_lid = $sec_source->name;
                    $table_name = $sec_source->location;
                    if ($member_lid == 'any') {
                        $zones = array();
                        break;
                    }
                    else {
                        if($table_name=="default_regions"){
                            $zones=array_merge($zones,[$getDefaultZoneipv4]);
                        }
                        else{
                            $zones = array_merge($zones,getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source));
                        }
                    }
                }

                $projectdb->query("DELETE FROM security_rules_from WHERE rule_lid='$rule_lid';");
                $unique=array_unique($zones);
                foreach ($unique as $zone) {
                    if(count($unique)>1){
                        if($getDefaultZoneipv4!=$zone){
                            $addFrom[]="('$rule_lid', '$zone')";
                        }
                    }
                    else{
                        $addFrom[]="('$rule_lid', '$zone')";
                    }
                }
            }
            if (count($addFrom)>0){
                //echo "INSERT INTO security_rules_from (rule_lid, name) VALUES ".implode(",",$addFrom)."\n";
                $projectdb->query("INSERT INTO security_rules_from (rule_lid, name) VALUES ".implode(",",$addFrom).";");
            }
        }
        $this->updateTaskStatus('Zone TO calculated.','0','0.15', true);

        if($doTo) {

            $this->log("Calculating To:" );

            $query_clean_to = "DELETE FROM security_rules_to WHERE rule_lid IN (".implode(",", $captureIdsData).");";
            $projectdb->query($query_clean_to);
            $addTo=array();
            if ($applyNat) {
                //Select the NAT rules that are Not disabled
                $getDAT = $projectdb->query("SELECT id, tp_dat_address_lid, tp_dat_address_table, devicegroup, is_dat, op_zone_to, position, tp_sat_bidirectional 
                                     FROM nat_rules 
                                     WHERE disabled='0' AND source='$source' $conditionVsys AND op_zone_to != '' 
                                     ORDER BY position;");
                $number_of_nats = $getDAT->num_rows;
//                $natted_rules_partially = array();
                $processed_nat=1;
                $mapping_natted_rules_dst = array();
                while ($getSRCData = $getDAT->fetch_assoc()) {
                    $percentage = 0.2 + 0.7* $processed_nat/$number_of_nats;
//                    update_progress($projectName, $percentage, "Checking NAT Rule ($processed_nat of $number_of_nats).",$jobid);
                   // $this->updateTaskStatus('Checking NAT Rule ('.$processed_nat.' of '.$number_of_nats.').','0',$percentage, true);

                    //For each NAT rule that makes DAT, we will check the Security Rules that are affected, and update its TO_ZONE
                    $member_lid_dat = $getSRCData['tp_dat_address_lid'];
                    $table_name_dat = $getSRCData['tp_dat_address_table'];
                    $nat_rule_lid = $getSRCData['id'];
                    $is_dat = $getSRCData['is_dat'];
                    $is_bidirectional = $getSRCData['tp_sat_bidirectional'];


                    //Initialize Sources and Destinations for mapping
                    $nat_src_members = array();
                    $exploded_nat_src_Members = array();

                    $nat_dst_members = array();
                    $nat_TP_dst_members = array();
                    $exploded_nat_dst_Members = array();
                    $exploded_nat_TP_dst_Members=array();

                    $nat_srv_members = array();
                    $exploded_nat_srv_Members = array();

                    $exploded_nat_from_Members=array();

                    //Get the source before applying NAT
                    $getSrc = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid='$nat_rule_lid';");
                    if ($getSrc->num_rows > 0) {
                        while ($getINData = $getSrc->fetch_assoc()) {
                            $member = new MemberObject($getINData['member_lid'], $getINData['table_name']);
                            $nat_src_members[] = $member;
                        }
                        $exploded_nat_src_Members = explodeGroups2Members($nat_src_members, $projectdb, $source, $vsys);
                    }
                    else {
                        $exploded_nat_src_Members[] = new MemberObject('', '', '0.0.0.0', '0');
                    }

                    //Get the destination before applying NAT
                    $getDst = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid='$nat_rule_lid';");
                    if ($getDst->num_rows > 0) {
                        while ($getINData = $getDst->fetch_assoc()) {
                            $member = new MemberObject($getINData['member_lid'], $getINData['table_name']);
                            $nat_dst_members[] = $member;
                        }
                        $exploded_nat_dst_Members = explodeGroups2Members($nat_dst_members, $projectdb, $source, $vsys);
                    }
                    else {
                        $exploded_nat_dst_Members[] = new MemberObject('', '', '0.0.0.0', '0');
                    }

                    //Get the services defined in the NAT
                    $getDst = $projectdb->query("SELECT op_service_lid, op_service_table FROM nat_rules WHERE id='$nat_rule_lid';");
                    if ($getDst->num_rows > 0) {
                        while ($getINData = $getDst->fetch_assoc()) {
                            if ($getINData['op_service_lid'] > 0 && $getINData['op_service_table'] != '') {
                                $member = new MemberObject($getINData['op_service_lid'], $getINData['op_service_table']);
                            }
                            else {
                                $member = new MemberObject('any', '', '0', '');
                            }
                            $nat_srv_members[] = $member;
                        }
                        $exploded_nat_srv_Members = explodeGroups2Services($nat_srv_members, $projectdb, $source, $vsys);
                    }
                    else {
                        $exploded_nat_srv_Members[] = new MemberObject('any', '', '0', '');
                    }

                    //Get the FROM defined in the NAT
                    $getDst = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$nat_rule_lid';");
                    if ($getDst->num_rows > 0) {
                        while ($getINData = $getDst->fetch_assoc()) {
                            $exploded_nat_from_Members[] = $getINData['name'];
                        }
                    }
                    else {
                        $exploded_nat_from_Members = ["any"];
                    }



                    /* Now we have For this NAT rule:
                     *  1- the NAT origins (in $exploded_nat_src_Members)
                     *  2- the NAT destinations (in $exploded_nat_dst_Members)
                     *  3- the NAT services (in $exploded_nat_srv_Members)
                     *  3-1 the NAT FROM in ($exploded_nat_from_Members)
                     *  4- all the sources for all the security rules (in $security_rule[ruleID]['src'])
                     *  5- all the destina for all the security rules (in $security_rule[ruleID]['dst'])
                     *  6- all the service for all the security rules (in $security_rule[ruleID]['srv'])
                     *
                     * Ready for doing the matching
                     */

//                    update_progress($projectName, $percentage, "Checking NAT Rule ($processed_nat of $number_of_nats). Rule Expanded",$jobid);
                  //  $this->updateTaskStatus('Checking NAT Rule ('.$processed_nat.' of '.$number_of_nats.'). Rule Expanded','0',$percentage, true);

                    //Find the Security rules that are affected by this NAT
                    if ($is_dat > 0) {
                        //DNAT Logic applies here
                        $natted_rules = array();

                        //$unprocesses_sec_rules = count($security_rules);

                        $this->applyDNAT(
                            $projectdb, $source,
                            $ipMapping, $nat_rule_lid, $member_lid_dat, $table_name_dat,
                            $security_rules, $natted_rules,$natted_rules_partially,
                            $exploded_nat_src_Members, $exploded_nat_dst_Members, $exploded_nat_srv_Members,$mapping_natted_rules_dst);

                        if (count($natted_rules) > 0) {
                            removeKeysFromArray($security_rules, $natted_rules);
                        }

                    }
                    else {
                        //NAT Logic applies here
                        $natted_rules = array();
//                        $natted_rules_partially = array();
                        //Find the Security rules that are affected by this NAT
                        $unprocesses_sec_rules = count($security_rules);

                        $this->applyNAT(
                            $projectdb, $source,
                            $ipMapping, $getDefaultZoneipv4,
                            $nat_rule_lid, $member_lid_dat, $table_name_dat,
                            $security_rules,$natted_rules, $natted_rules_partially,
                            $exploded_nat_src_Members, $exploded_nat_dst_Members, $exploded_nat_srv_Members, $exploded_nat_from_Members);

                        if (count($natted_rules) > 0) {
                            //Remove those Security Rules from the Associative array, as they have already found a NAT match
                            removeKeysFromArray($security_rules, $natted_rules);
                        }

                        $natted_rules = array();

                        //If it is a static bidirectional NAT, apply the looped DNAT
                        if($is_bidirectional) {

                            //Get the destination AFTER applying NAT
                            $getDst = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid='$nat_rule_lid';");
                            if ($getDst->num_rows > 0) {
                                while ($getINData = $getDst->fetch_assoc()) {
                                    $member = new MemberObject($getINData['member_lid'], $getINData['table_name']);
                                    $nat_TP_dst_members[] = $member;
                                }
                                $exploded_nat_TP_dst_Members = explodeGroups2Members($nat_TP_dst_members, $projectdb, $source, $vsys);
                            }
                            else {
                                $exploded_nat_TP_dst_Members[] = new MemberObject('', '', '0.0.0.0', '0');
                            }

                            $this->applyReturnBidirectionalNAT(
                                $projectdb, $source,
                                $ipMapping, $nat_rule_lid, $member_lid_dat, $table_name_dat,
                                $security_rules, $natted_rules, $natted_rules_partially,
                                $exploded_nat_TP_dst_Members, $exploded_nat_dst_Members, $exploded_nat_srv_Members, $exploded_nat_from_Members);


                            if (count($natted_rules) > 0) {
                                //Remove those Security Rules from the Associative array, as they have already found a NAT match
                                removeKeysFromArray($security_rules, $natted_rules);
                            }
                        }
                    }

                    //Free Memory
                    $exploded_nat_src_Members = null;
                    $exploded_nat_dst_Members = null;

                    //Checking if this NAT actually affects any Security Rule or
                    //  (a) it is shadowed by prior NATS
                    //  (b) it is too restrictive
                    if (count($natted_rules) == 0) {
//                        add_log2('info', 'NAT Analysis', 'NAT Rule [' . $nat_rule_lid . '] does not affect any of the existing security rules. Or affects only ranges inside a security rule.', $source, 'No Action Required. Suggestion to review and/or remove. If partial matching, you may consider split the security rule.', 'rules', $nat_rule_lid, 'nat_rules');
                    }

                    $processed_nat++;
                }

                foreach ($security_rules as $rule_lid=>$sec_rule) {
                    if (in_array($rule_lid,$natted_rules_partially)){
                        $negate_destination = $sec_rule['Ndst'];
                        //$projectdb->query("DELETE FROM security_rules_to WHERE rule_lid = '$rule_lid';");
                        $zones = array();
                        foreach ($sec_rule['dst'] as $sec_destination) {
                            $member_lid = $sec_destination->name;
                            $table_name = $sec_destination->location;
                            if ($member_lid == "any") {
                                $zones = array();
                            }
                            else {
                                if($table_name=="default_regions"){
                                    $zones = array_merge($zones,[$getDefaultZoneipv4]);
                                }
                                else{
                                    //print_r($ipMapping['ipv4']);
                                    $zones = array_merge($zones,getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination));
                                }

                            }
                        }
                        foreach ($zones as $zone) {
                            $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                            if ($getZone->num_rows == 0) {
                                $projectdb->query("INSERT INTO security_rules_to (rule_lid, name) VALUES ('$rule_lid', '$zone');");
                            }
                        }
                    }
                    // Add to zones for dst without NAT
                    if(isset($mapping_natted_rules_dst[$rule_lid])){
                        $zones = array();
                        $negate_destination = $sec_rule['Ndst'];
                        foreach ($sec_rule['dst'] as $sec_destination) {
                            $member_lid = $sec_destination->name;
                            $table_name = $sec_destination->location;
                            if (!isset($mapping_natted_rules_dst[$rule_lid][$sec_destination->name])) {
                                if($table_name=="default_regions"){
                                    $zones = array_merge($zones,[$getDefaultZoneipv4]);
                                } else {
                                    $zones = array_merge($zones, getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination));
                                }
                                foreach ($zones as $zone) {
                                    $projectdb->query("INSERT INTO security_rules_to (rule_lid, name) VALUES ('$rule_lid', '$zone');");
                                }
                                removeKeysFromArray($security_rules,[$rule_lid]);
                            }

                        }
                    }
                }
                //Calculate the ZONES TO to the remaining the security rules in the selection
                if (count($natted_rules_partially) > 0) {
                    removeKeysFromArray($security_rules, $natted_rules_partially);
                }
                foreach ($security_rules as $rule_lid=>$sec_rule) {
                    $negate_destination = $sec_rule['Ndst'];
                    $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid = '$rule_lid';");
                    $zones = array();
                    foreach ($sec_rule['dst'] as $sec_source) {
                        $member_lid = $sec_source->name;
                        $table_name = $sec_source->location;
                        if ($member_lid == "any") {
                            $zones = array();
                        }
                        else {
                            if($table_name=="default_regions"){
                                $zones = array_merge($zones,[$getDefaultZoneipv4]);
                            }
                            else{
                                //print_r($ipMapping['ipv4']);
                                $zones = array_merge($zones,getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination));
                            }

                        }
                    }
                    foreach ($zones as $zone) {
                        if(count($zones)>1){
                            if($getDefaultZoneipv4!=$zone){
                                $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                                if ($getZone->num_rows == 0) {
                                    $projectdb->query("INSERT INTO security_rules_to (rule_lid, name) VALUES ('$rule_lid', '$zone');");
                                }
                            }
                        }
                        else{
                            $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                            if ($getZone->num_rows == 0) {
                                $projectdb->query("INSERT INTO security_rules_to (rule_lid, name) VALUES ('$rule_lid', '$zone');");
                            }
                        }
                    }
                }
            }
            else {
                //Calculate the ZONES TO to the all the security rules in the selection without NATs considered
                $processed_rule = 1;
                $number_of_rules = count($security_rules);
                foreach ($security_rules as $rule_lid => $sec_rule) {
                    $negate_destination = $sec_rule['Ndst'];
                    $percentage = 0.2 + 0.7*$processed_rule/$number_of_rules;
                    $processed_rule++;

//                    update_progress($projectName, $percentage, "Checking NAT Rule ($processed_rule of $number_of_rules).",$jobid);
                   // $this->updateTaskStatus('Checking NAT Rule ('.$processed_rule.' of '.$number_of_rules.').','0',$percentage, true);
                    $zones = array();
                    foreach ($sec_rule['dst'] as $sec_source) {
                        $member_lid = $sec_source->name;
                        $table_name = $sec_source->location;
                        if ($member_lid == 'any') {
                            $zones = array();
                            break;
                        }
                        else {
                            if($table_name=="default_regions"){
                                $zones = array_merge($zones,[$getDefaultZoneipv4]);
                            }
                            else{
                                $zones = array_merge($zones,getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination));
                            }

                        }
                    }
                    $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$rule_lid';");
                    $unique=array_unique($zones);
                    foreach ($unique as $zone) {

                        if(count($unique)>1){
                            if($getDefaultZoneipv4!=$zone){
                                $addTo[]="('$rule_lid', '$zone')";
                            }
                        }
                        else{
                            $addTo[]="('$rule_lid', '$zone')";
                        }

                    }
                }
            }

            if (count($addTo)>0){
                $projectdb->query("INSERT INTO security_rules_to (rule_lid, name) VALUES ".implode(",",$addTo).";");
            }

        }

        # Fix Duplicated Zones
        if (count($natted_rules_partially)>0){
            $getDup=$projectdb->query("SELECT distinct name, rule_lid FROM security_rules_to WHERE rule_lid IN (".implode(",",$natted_rules_partially).");");
            //Bucle en array
            while($dataZones = $getDup->fetch_assoc())
            {
                $finalZones[] = "('".$dataZones['name']."', '".$dataZones['rule_lid']."')";
            }
            $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid IN (".implode(",",$natted_rules_partially).");");
            $projectdb->query("INSERT INTO security_rules_to (name, rule_lid) VALUES ".implode(",",$finalZones));
        }

        //make sure we do not have duplicated zones
        $query=     "DELETE t1 FROM security_rules_to t1
                    INNER JOIN security_rules_to t2 
                    WHERE 
                        t1.id < t2.id AND
                        t1.rule_lid = t2.rule_lid AND
                        t1.vsys = t2.vsys AND
                        t1.name = t2.name;";
        $projectdb->query($query);

        $this->updateTaskStatus('Finished.','0','1.00', true);

    }

    function negateAddresses($addresses){
        $fakeMapping['map'][] = Array('start' => 0, 'end' => ip2long('255.255.255.255'));
        foreach ($addresses as $address){
            $objectsMapping = getIP4Mapping("", $address->name, $address->location);
            foreach ($objectsMapping['map'] as $entry){
                removeNetworkFromIP4Mapping($fakeMapping['map'], $entry);
            }
        }

        $newAddresses = array();
        foreach ($fakeMapping['map'] as $fakeRange){
            $ipRange = long2ip($fakeRange['start'])."-".long2ip($fakeRange['end']);
            $newAddresses[] = new MemberObject('','',$ipRange,'');
        }

        return $newAddresses;
    }

    private function applyDNAT(
        mysqli $projectdb,
        int $source,
        array $ipMapping,
        int $nat_rule_lid,
        int $member_lid_dat,
        string $table_name_dat,
        array $security_rules,
        array &$natted_rules,
        array &$natted_rules_partially,
        array $exploded_nat_src_Members,
        array $exploded_nat_dst_Members,
        array $exploded_nat_srv_Members,
        array &$mapping_natted_rules_dst
    ){
//        $unprocesses_sec_rules = count($security_rules);
//        $this->log("DNAT $nat_rule_lid. Number of unprocess rules: $unprocesses_sec_rules", 1);
        $xx = 1;
        $count_security_rules = count($security_rules);
        $count_i=0;
        foreach ($security_rules as $sec_rule_lid => $sec_rule) {

            $count_i++;
            $date = date('Y-m-d H:i:s');
            $this->log("\t DNAT: Checking if NAT rule $nat_rule_lid matches with Sec rule $sec_rule_lid  [$count_i/$count_security_rules] - now: $date" );

            $negate_source = $sec_rule['Nsrc'];
            $negate_destination = $sec_rule['Ndst'];

            if($negate_source == '1'){
                $sec_rule_src = $this->negateAddresses($sec_rule['src']);
            }
            else{
                $sec_rule_src = $sec_rule['src'];
            }

            if($negate_destination == '1'){
                $sec_rule_dst = $this->negateAddresses($sec_rule['dst']);
            }
            else{
                $sec_rule_dst = $sec_rule['dst'];
            }

            //If destination of the rule is "any", there is no need to calculate zones on NATs. Zone should also be "any"

            if(in_array("any", array_column($sec_rule_dst, 'name'))) {
                  $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$sec_rule_lid';");
                  continue;
            }

            //$percentage = 0.2 + round(0.8* $processed_nat/$number_of_nats, 2);
            //$this->updateTaskStatus('Checking NAT Rule ('.$processed_nat.' of '.$number_of_nats.'). Matching Security Rules ('.$xx.' of '.$unprocesses_sec_rules.')','0',$percentage, true);
            $xx++;
            $full_dst_match=true;
            // Check the NAT policy over each destination on the security rule
            foreach ($sec_rule_dst as $sec_rule_dst_item) {

                $isDSTCovered = isAinB([$sec_rule_dst_item], $exploded_nat_dst_Members);
                if (!$isDSTCovered) {
                    //If sec rule dst is not covered by NAT dst and it was not found previously, then the sec rule is not completed matched
                    if(!isset($mapping_natted_rules_dst[$sec_rule_lid][$sec_rule_dst_item->name])){
                        $full_dst_match=false;
                    }
                }

                $isSCRCovered = isAinB($sec_rule_src, $exploded_nat_src_Members);
                if (!$isSCRCovered) {
                    //No need to further check if the NAT matches
                }
                $isSRVCovered = isAinB_service($sec_rule['srv'], $exploded_nat_srv_Members);

                if (($isDSTCovered == 1) && ($isSCRCovered == 1) && ($isSRVCovered == 1)) {
                    //Calculate destination Zone after NAT MATCH 100%
                    $correct_zones_to = getAutoZone($ipMapping['ipv4'], $member_lid_dat, $table_name_dat, 0);  //This will provide all the zones that this NAT has as destination AFTER NAT

                    // Add the sec rule dst into the list of matched dst for the sec rule
                    $mapping_natted_rules_dst[$sec_rule_lid][$sec_rule_dst_item->name]=$sec_rule_dst_item;

                    if (!in_array($sec_rule_lid, $natted_rules_partially)) {
                        //$projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$sec_rule_lid';");
                    }
                    $values = array();
                    foreach ($correct_zones_to as $zone) {
                        $values[] = "('$sec_rule_lid', '$zone')";
                    }
                    $listValues = implode(',', $values);
                    $query = "INSERT INTO security_rules_to (rule_lid, name) VALUES $listValues;";
                    $projectdb->query($query);
                    add_log2('ok', 'Auto Zone Assign', 'Rule [' . $sec_rule_lid . ']. Updating "TO Zones" as [' . implode(',', $correct_zones_to) . '] based on DAT defined in NAT rule [' . $nat_rule_lid . ']', $source, 'No Action Required', 'rules', $sec_rule_lid, 'security_rules');
//                $this->log("-$sec_rule_lid matched", 2);

                } else {
                    if (($isDSTCovered + $isSCRCovered + $isSRVCovered) > 3 &&
                        ($isDSTCovered != 0) && ($isSCRCovered != 0) && ($isSRVCovered != 0)
                    ) { //These are partial matches
                        $natted_rules_partially[] = $sec_rule_lid;
                        $correct_zones_to = getAutoZone($ipMapping['ipv4'], $member_lid_dat, $table_name_dat, 0);
                        $values = array();
                        foreach ($correct_zones_to as $zone) {
                            $values[] = "('$sec_rule_lid', '$zone')";
                        }
                        $listValues = implode(',', $values);
                        $query = "INSERT INTO security_rules_to (rule_lid, name) VALUES $listValues;";
                        $projectdb->query($query);
                        add_log2('warning', 'Auto Zone Assign', 'Rule [' . $sec_rule_lid . ']. This security Rule is partially covered by NAT rule [' . $nat_rule_lid . ']. Added the following "TO Zones": [' . implode(',', $correct_zones_to) . '].', $source, ' Suggestion to split the rule and assign the following "TO Zones": [' . implode(',', $correct_zones_to) . '] ', 'rules', $sec_rule_lid, 'security_rules');
//                    $this->log("-$sec_rule_lid PARTIALLY matched", 2);
                    } else {
                        if($isDSTCovered == 0 || $isSCRCovered == 0 || $isSRVCovered == 0){
                            $full_dst_match = false;
                        }
                    }
                }

            }//end foreach dst
            // if all dst on the sec rule has been covered by a NAT then we do not need to process it again.

            if($full_dst_match){
                $natted_rules[] = $sec_rule_lid; //Add this rule in the list of modified rules, so we do not need to process it again.
                $this->log("\t\t DNAT: It matches - now: $date" );
            }
        }//end foreach sec_rule
    }

    private function applyReturnBidirectionalNAT(
        mysqli $projectdb,
        int $source,
        array $ipMapping,
        int $nat_rule_lid,
        int $member_lid_dat,
        string $table_name_dat,
        array $security_rules,
        array &$natted_rules,
        array &$natted_rules_partially,
        array $exploded_nat_TP_dst_Members,
        array $exploded_nat_dst_Members,
        array $exploded_nat_srv_Members,
        array $exploded_nat_from_Members
    ){
        $unprocesses_sec_rules = count($security_rules);
//        $this->log("ReturnBidirectionalNAT $nat_rule_lid. Number of unprocess rules: $unprocesses_sec_rules", 1);

        $count_security_rules = count($security_rules);
        $count_i = 0;

        foreach ($security_rules as $sec_rule_lid => $sec_rule) {

            $count_i++;
            $date = date('Y-m-d H:i:s');
            $this->log("\t NAT: Checking if Bidirectional NAT rule $nat_rule_lid matches with Sec rule $sec_rule_lid  [$count_i/$count_security_rules] - now: $date" );


            $negate_source = $sec_rule['Nsrc'];
            $negate_destination = $sec_rule['Ndst'];

            if($negate_source == '1'){
                $sec_rule_src = $this->negateAddresses($sec_rule['src']);
            }
            else{
                $sec_rule_src = $sec_rule['src'];
            }

            if($negate_destination == '1'){
                $sec_rule_dst = $this->negateAddresses($sec_rule['dst']);
            }
            else{
                $sec_rule_dst = $sec_rule['dst'];
            }

            $isDSTCovered = isAinB($sec_rule_dst, $exploded_nat_TP_dst_Members);
            $isSRCCovered = isAinB($sec_rule_src, $exploded_nat_dst_Members);
//            $isSRVCovered = isAinB_service($sec_rule['srv'], $exploded_nat_srv_Members);


            if (($isDSTCovered == 1)
                && ($isSRCCovered == 1)
                //&& ($isSRVCovered == 1)
            ) {
                //Calculate destination Zone after NAT MATCH 100%
                $correct_zones_to = $exploded_nat_from_Members;

                $natted_rules[] = $sec_rule_lid;  //Add this rule in the list of modified rules, so we do not need to process it again.
                $this->log("\t\t NAT: It matches - now: $date" );

                if(!in_array($sec_rule_lid, $natted_rules_partially)) {
                    $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$sec_rule_lid';");
                }
                $values = array();
                foreach ($correct_zones_to as $zone) {
                    $values[] = "('$sec_rule_lid', '$zone')";
                }
                $listValues = implode(',',$values);
                $query = "INSERT INTO security_rules_to (rule_lid, name) VALUES $listValues;";
                $projectdb->query($query);
                add_log2('ok', 'Auto Zone Assign', 'Rule [' . $sec_rule_lid . ']. Updating "TO Zones" as [' . implode(',', $correct_zones_to) . '] based on Static Bidirectional NAT defined in NAT rule [' . $nat_rule_lid . ']', $source, 'No Action Required', 'rules', $sec_rule_lid, 'security_rules');
//                $this->log("-$sec_rule_lid matched", 2);
            }
            else {
//                if (($isDSTCovered + $isSCRCovered + $isSRVCovered) > 3 &&
//                    ($isDSTCovered != 0) && ($isSCRCovered != 0) && ($isSRVCovered != 0)
                if (($isDSTCovered + $isSRCCovered) > 2 &&
                    ($isDSTCovered != 0) && ($isSRCCovered != 0)
                ) { //These are partial matches
                    $natted_rules_partially[] = $sec_rule_lid;
                    $correct_zones_to = $exploded_nat_from_Members;
                    $values = array();
                    foreach ($correct_zones_to as $zone) {
                        $values[] = "('$sec_rule_lid', '$zone')";
                    }
                    $listValues = implode(',',$values);
                    $query = "INSERT INTO security_rules_to (rule_lid, name) VALUES $listValues;";
                    $projectdb->query($query);
                    add_log2('warning', 'Auto Zone Assign', 'Rule [' . $sec_rule_lid . ']. This security Rule is partially covered by Static Bidirectional NAT rule [' . $nat_rule_lid . ']. Added the following "TO Zones": [' . implode(',', $correct_zones_to) . '].', $source, ' Suggestion to split the rule and assign the following "TO Zones": [' . implode(',', $correct_zones_to) . '] ', 'rules', $sec_rule_lid, 'security_rules');
//                    $this->log("-$sec_rule_lid PARTIALLY matched", 2);
                }
            }
        }
    }

    private function applyNAT(
        mysqli $projectdb,
        int $source,
        array $ipMapping,
        $getDefaultZoneipv4,
        int $nat_rule_lid,
        int $member_lid_dat,
        string $table_name_dat,
        array $security_rules,
        array &$natted_rules,
        array &$natted_rules_partially,
        array $exploded_nat_src_Members,
        array $exploded_nat_dst_Members,
        array $exploded_nat_srv_Members,
        array $exploded_nat_from_Members
    ){

//        $unprocesses_sec_rules = count($security_rules);
//        $this->log("NAT $nat_rule_lid. Number of unprocess rules: $unprocesses_sec_rules", 1);

        //$xx = 1;

        $count_security_rules = count($security_rules);
        $count_i = 0;

        foreach ($security_rules as $sec_rule_lid => $sec_rule) {

            $count_i++;
            $date = date('Y-m-d H:i:s');
            $this->log("\t NAT: Checking if NAT rule $nat_rule_lid matches with Sec rule $sec_rule_lid  [$count_i/$count_security_rules] - now: $date" );

            //$percentage = 0.2 + round(0.8* $processed_nat/$number_of_nats, 2);
            //$this->updateTaskStatus('Checking NAT Rule ('.$processed_nat.' of '.$number_of_nats.'). Matching Security Rules ('.$xx.' of '.$unprocesses_sec_rules.')','0',$percentage, true);
            //$xx++;
            $isDSTCovered       = isAinB($sec_rule['dst'], $exploded_nat_dst_Members);
            $isSCRCovered       = isAinB($sec_rule['src'], $exploded_nat_src_Members);
            $isSRVCovered       = isAinB_service($sec_rule['srv'], $exploded_nat_srv_Members);
            $isZoneFromCovered  = isAinB_Zones($sec_rule['from'], $exploded_nat_from_Members,$foundZones);

            if (empty($sec_rule['from'])){$sec_rule['from']=["any"];}

            $foundZones=array();

            if (($isDSTCovered == 1) && ($isSCRCovered == 1) && ($isSRVCovered == 1) && ($isZoneFromCovered == 1)) {
                $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid = '$sec_rule_lid';");

                $natted_rules[] = $sec_rule_lid;
                $this->log("\t\t NAT: It matches - now: $date" );

                $negate_destination = $sec_rule['Ndst'];
                $zones = array();
                foreach ($sec_rule['dst'] as $sec_dest) {
                    $member_lid = $sec_dest->name;
                    $table_name = $sec_dest->location;
                    if ($member_lid == 'any') {
                        $zones = array();
                        break;
                    }
                    else {
                        if($table_name=="default_regions"){
                            $zones=array_merge($zones,[$getDefaultZoneipv4]);
                        }
                        else{
                            $zones = array_merge($zones,getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_destination));
                        }

                    }
                }
                foreach ($zones as $zone) {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$sec_rule_lid';");
                    if ($getZone->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_to (rule_lid, name) VALUES ('$sec_rule_lid', '$zone');");
                    }
                }
//                $this->log("-$sec_rule_lid matched", 2);
            }
        }

    }
}