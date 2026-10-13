<?php

require_once INC_ROOT.'/libs/common/MemberObject.php';

use PaloaltoNetworks\Policy\Objects\MemberObject as MemberObject;


class GetRules
{

    public function __construct()
    {
    }

    public static function createTempViewRules(mysqli $projectdb, int $source, string $vsys, string $destinationTable){

        $groups = GetRules::getGroups($projectdb, $source, $vsys);
        $groupsSubquery = array();
        foreach ($groups as $key => $group){
            /* @var MemberObject $member */
            foreach ($group['members'] as $member ){
                $groupsSubquery[] = "('".$key."','".$member->name."','".$member->value."','".$member->cidr."')";
            }
        }
        if(count($groupsSubquery)>0){
            $projectdb->query("DROP TABLE IF EXISTS `${destinationTable}_groups`;");
            $projectdb->query("CREATE TABLE IF NOT EXISTS `${destinationTable}_groups` (
                                                `groupID` INT NULL,
                                                `address_id` INT NULL,
                                                `ipaddress` VARCHAR(255) NULL,
                                                `cidr` INT NULL);"                );
            $projectdb->query("INSERT INTO ${destinationTable}_groups (groupID, address_id, ipaddress, cidr) VALUES ".implode(", ",$groupsSubquery).";" );
        }

        $security_rules = GetRules::getRules($projectdb, $source, $vsys);

        $sourceSubquery = array();
        $destinationSubquery = array();
        $serviceSubquery = array();
        foreach ($security_rules as $key => $security_rule){
            /* @var MemberObject $ruleSrc */

            foreach ($security_rule['src'] as $ruleSrc){
                $sourceSubquery[] = "('".$key."','".$ruleSrc->name ."','".$ruleSrc->value."','".$ruleSrc->cidr."')";
            }

            foreach ($security_rule['dst'] as $ruleDst){
                $destinationSubquery[] = "('".$key."','".$ruleDst->name ."','".$ruleDst->value."','".$ruleDst->cidr."')";
            }

            foreach ($security_rule['srv'] as $ruleSrv){
                $serviceSubquery[] = "('".$key."','".$ruleSrv->name ."','".$ruleSrv->value."','".$ruleSrv->cidr."')";
            }
        }

        if(count($sourceSubquery)>0){
            $projectdb->query("DROP TABLE IF EXISTS `${destinationTable}_src`;");
            $projectdb->query("CREATE TABLE IF NOT EXISTS `${destinationTable}_src` (
                                                `ruleID` INT NULL,
                                                `address_id` INT NULL,
                                                `ipaddress` VARCHAR(255) NULL,
                                                `cidr` INT NULL);"                );
            $projectdb->query("INSERT INTO ${destinationTable}_src (ruleID, address_id, ipaddress, cidr) VALUES ".implode(", ",$sourceSubquery).";" );
            //echo "INSERT INTO ${destinationTable}_src (ruleID, address_id, ipaddress, cidr) VALUES ".implode(", ",$sourceSubquery).";";
        }

        if(count($destinationSubquery)>0){
            $projectdb->query("DROP TABLE IF EXISTS `${destinationTable}_dst`;");
            $projectdb->query("CREATE TABLE IF NOT EXISTS `${destinationTable}_dst` (
                                                `ruleID` INT NULL,
                                                `address_id` INT NULL,
                                                `ipaddress` VARCHAR(255) NULL,
                                                `cidr` INT NULL);"                );
            $projectdb->query("INSERT INTO ${destinationTable}_dst (ruleID, address_id, ipaddress, cidr) VALUES ".implode(", ",$destinationSubquery).";" );
            //echo "INSERT INTO ${destinationTable}_dst (ruleID, address_id, ipaddress, cidr) VALUES ".implode(", ",$sourceSubquery).";";
        }

        if(count($serviceSubquery)>0){
            $projectdb->query("DROP TABLE IF EXISTS `${destinationTable}_srv`;");
            $projectdb->query("CREATE TABLE IF NOT EXISTS `${destinationTable}_srv` (
                                                `ruleID` INT NULL,
                                                `service_id` INT NULL,
                                                `port` VARCHAR(255) NULL,
                                                `protocol` INT NULL);"                );
            $projectdb->query("INSERT INTO ${destinationTable}_srv (ruleID, service_id, port, protocol) VALUES ".implode(", ",$serviceSubquery).";" );
            //echo "INSERT INTO ${destinationTable}_srv (ruleID, address_id, ipaddress, cidr) VALUES ".implode(", ",$sourceSubquery).";";
        }
    }


    public static function getGroups(mysqli $projectdb, int $source, string $vsys):array{
        $listAddress = array();
        $listGroups = array();
        $processedGroups = array();

        $conditionIds = $conditionTags = '';
        if($vsys == 'all')  $conditionVsys = '';
        else                $conditionVsys = " AND vsys='$vsys' ";

        $addressGroups=array();
        $queryGroups = "SELECT id, devicegroup, type  FROM address_groups_id WHERE source='$source' $conditionVsys $conditionIds $conditionTags;";
        $addressGroupsData = $projectdb->query($queryGroups);
        $number_of_groups = $addressGroupsData->num_rows;
        if ($number_of_groups > 0) {
            $ids = array();
            while($addressGroup = $addressGroupsData->fetch_assoc()){
                $id = $addressGroup['id'];
                $ids[]=$id;
                $addressGroups[$id] = $addressGroup;
                $addressGroups[$id]['members'] = array();
            }

            $queryMembers = "SELECT member_lid, table_name, lid  FROM address_groups WHERE lid in (".implode(",",$ids).") $conditionVsys $conditionIds $conditionTags;";
            $addressGMembers = $projectdb->query($queryMembers);
            if ($addressGMembers->num_rows>0){
                while ($addressGroupMember = $addressGMembers->fetch_object()){
                    $addressGroups[$addressGroupMember->lid]['members'][]=new MemberObject($addressGroupMember->member_lid, $addressGroupMember->table_name);
                }
            }

            foreach ($addressGroups as $key => &$addressGroup) {
                if(isset($addressGroup['members'])) {
                    $members = $addressGroup['members'];
                    $addressGroup['members'] = GetRules::explodeGroups2Members($members, $projectdb, 0, $processedGroups, $listAddress, $listGroups);
                    usort($addressGroup['members'], "GetRules::cmp");
                }
            }

            return $addressGroups;
        }
        else{
            return [];
        }
    }

    public static function getRules(mysqli $projectdb, int $source, string $vsys):array{

        $captureIdsData = array();
        $conditionIds = $conditionTags = '';
        $security_rules = array();

        if($vsys == 'all')  $conditionVsys = '';
        else                $conditionVsys = " AND vsys='$vsys' ";

        $query = "SELECT id, devicegroup, negate_source, negate_destination  FROM security_rules WHERE source='$source' $conditionVsys $conditionIds $conditionTags ORDER BY position;";

        $rules = $projectdb->query($query);
        $number_of_rules = $rules->num_rows;
        if ($number_of_rules > 0) {
            while ($getINData = $rules->fetch_assoc()){
                $captureIdsData[]=$getINData['id'];
                $id = $getINData['id'];
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
            return $security_rules;
        }

        //Get all the Security_Rules Sources and Destinations and group them by Rule_lid
        $conditionRelaIds = "rule_lid IN (".implode(",", $captureIdsData).")";

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

        $listAddress = array();
        $listGroups = array();
        $processedGroups = array();
        foreach($security_rules as $key=>&$security_rule){
            $members_src = $security_rule['src'];
            $members_dst = $security_rule['dst'];
            $members_srv = $security_rule['srv'];
            $security_rule['src'] = GetRules::explodeGroups2Members($members_src,  $projectdb, 0, $processedGroups, $listAddress, $listGroups);
            $security_rule['dst'] = GetRules::explodeGroups2Members($members_dst,  $projectdb, 0, $processedGroups, $listAddress, $listGroups);
//            $security_rule['srv'] = $this->explodeGroups2Services($members_srv, $projectdb, 0, $vsys);
        }

        return $security_rules;
    }

    private static function explodeGroups2Members(Array $members, mysqli $projectdb, INT $level=NULL, ARRAY &$processedGroups = array(),  ARRAY $listAddress=array(), ARRAY $listGroups=array()){

        if(is_null($members)) {
            $members = array();
        }
        if(is_null($level)){
            $level=0;
        }
        $tmp_members=array();
        foreach($members as $member){
            //Not a group. Let's add it directly
            if(strcmp($member->location, 'address')==0){
                //Check if we already have this member
                if(!in_array($member->name, $listAddress)){
                    $name = $member->name.'_'.$member->location;
                    if(isset($processedGroups[$name])){
                        $tmp_members[] = $processedGroups[$name];
                        $listAddress[] = $member->name;
                    }
                    else {
                        if (!isset($member->value) || !isset($member->cidr)) {
                            $query = "SELECT id, ipaddress, cidr FROM address WHERE id='$member->name' "; //."AND source='$source' AND vsys='$vsys';";
                            $getMember = $projectdb->query($query);
                            if ($getMember->num_rows == 1) {
                                $row = $getMember->fetch_assoc();
                                $member->value = $row['ipaddress'];
                                if($row['ipaddress']!='' && ($row['cidr']==0 || $row['cidr']=='')) $row['cidr'] = 32;
                                $member->cidr = $row['cidr'];

                            }
                        }
                        $processedGroups[$name] = $member;
                        $tmp_members[] = $member;
                        $listAddress[] = $member->name;
                    }
                }
//                else{
//                }
            }

            elseif(strcmp($member->location, 'default_regions')==0){
                //Check if we already have this member
                if(!in_array($member->name, $listAddress)){
                    $name = $member->name.'_'.$member->location;
                    if(isset($processedGroups[$name])){
                        $tmp_members[] = $processedGroups[$name];
                        $listAddress[] = $member->name;
                    }
                    else {
                        if (!isset($member->value) || !isset($member->cidr)) {
                            $member->cidr = '32';
                            $member->value = '0.0.0.0';
                        }
                        $processedGroups[$name] = $member;
                        $tmp_members[] = $member;
                        $listAddress[] = $member->name;
                    }
                }
//                else{
//                }
            }

            //This is a group. Let's expand it
            else{
                //Check if the group has already been checked for this current group explode
                if(!in_array($member->name, $listGroups)){
                    $name = $member->name.'_'.$member->location;

                    if (isset($processedGroups[$name])){
//                    $tmp_members = array_merge($tmp_members,$processedGroups[$name]); //WARNING, $processedGroups[$name] may be an ARRAY!  //TODO: This may not be necessary, those have already been included
                    }
                    else {
                        $query = "SELECT member_lid, table_name " .
                            "FROM   address_groups adg " .
                            "WHERE ".
                            // "adg.source='$source' AND adg.vsys='$vsys' AND BINARY" .
                            "       adg.lid='$member->name' ";
                        //echo "$query";
                        $getMember = $projectdb->query($query);
                        $member2 = array();
                        while ($row = $getMember->fetch_assoc()) {
                            $member_id = $row['member_lid'];
                            $member_location = $row['table_name'];
                            $member2[] = new MemberObject($member_id, $member_location);
                        }
                        $listGroups[] = $member->name;
                        $membersIn_member2 = GetRules::explodeGroups2Members($member2, $projectdb, $level+1, $processedGroups,  $listAddress, $listGroups);
                        $tmp_members = array_merge($tmp_members, $membersIn_member2);
                        if(!isset($processedGroups[$name])){
                            $processedGroups[$name] = $membersIn_member2;
                        }
                    }
                }
//                else{
//                }
            }
        }

        return $tmp_members;
    }

}