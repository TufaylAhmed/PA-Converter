<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Tools\Merger;

use PaloAltoNetworks\Expedition\BackgroundTaskSQLUpdate;
use PaloAltoNetworks\Expedition\MemoryObjects\Response;

class AddressMerger extends ObjectMerger
{
    protected $groupByFields;

    public function getInfoByIDs(array $ids):Response{
        return new Response(true, 0, json_encode($this->memoryObjectHandler->getAddresses($ids)));
    }

    public function __construct(STRING $project, INT $userID, STRING $source)
    {
        parent::__construct($project, $userID, $source);
        $this->queryGetRepresentativeID = "SELECT member_lid FROM tools_results WHERE table_name = 'address' AND source = '$this->source' AND user_id = '$this->userID';";
        $this->targetField = 'address';
    }

    protected function loadObjects(): bool
    {
        /** @var $response Response*/
        $response = $this->memoryObjectHandler->loadAddress($this->projectdb,$this->selectedIDs);
        if($response->success) {
            $response = $this->memoryObjectHandler->loadTags($this->projectdb);
        }
        if($response->success) {
            $response = $this->memoryObjectHandler->loadTagRelations($this->projectdb);
        }

        if($response->success)       return true;
        else                         return false;
    }

    public function setMergerByFields(ARRAY $fields){
        $this->groupByFields = $fields;
    }


    protected function getNonDeleteables(){
        $dummies = array();
        foreach ($this->groups as &$group) {
            if ($group['mergeable']) {
                $primaryID = $group['primary'];

                foreach ($group["$this->targetField"."_list"] as $memberID => $groupMember) {
                    if ($memberID != $primaryID) {
                        if($groupMember['dummy']==1) {
                            $dummies[] = $memberID;
                        }
                    }
                }
            }
        }

        return array_unique($dummies);
    }

    protected function updatePrimaries(): bool
    {
        $addingMergeTag = array();
        // TODO: Implement updatePrimaries() method.
        foreach ($this->groups as &$group){
            if($group['mergeable']) {
                if(count($group["$this->targetField"."_list"])<=1) {
                    continue;
                }

                unset($othersIDs, $description);
                $othersIDs = array();
                $description = array();
                $used = 0;
                $primaryID = $group['primary'];
                $description[0] = $group["$this->targetField"."_list"][$primaryID]['description']; //The description from the remaining (the object that others get merged into) object

                //Collect all the ids from the objects that will be removed because they get merged into the primary
                //Collect the descriptions of all the members to be merged

//                $dummies = array();
                foreach ($group["$this->targetField"."_list"] as $memberID => $groupMember) {
                    //if ($memberID != $primaryID) {
                        if($groupMember['dummy']==0) {
                            $othersIDs[$memberID] = $memberID; //The ids for all the other members
                            $description[$memberID] = $groupMember['description']; //The description for all the other members

                            if($groupMember['used'] == 1){
                                $used = 1;
                            }
                        }

//                        else {
//                            $dummies[$memberID] = $memberID;
//                        }
                    //}
                }
                unset($othersIDs[$primaryID]);
//                unset($dummies[$primaryID]);


//                //Collect the descriptions of all the members to be merged
//                $description = array();
//                $description[0] = $group["$this->targetField"."_list"][$primaryID]['description']; //The description from the remaining (the object that others get merged into) object
//                foreach ($group["$this->targetField"."_list"] as $memberID => $groupMember) {
//                    //if ($memberID != $primaryID) {
//                        $description[$memberID] = $groupMember['description']; //The description for all the other members
//                    //}

                unset($description[$primaryID]);

                $allDescription = array_filter(array_unique($description)); //Remove duplicate descriptions
                $final_description = implode(",", $allDescription);
                $final_description = truncate_descriptions($final_description, $this->version);


                //Transfer tags to the primary and add a "merged" tag if not already there (already controlled by the DB)
                if(count($othersIDs)>0) {
                    $queryMoveTags = "UPDATE tag_relations set member_lid = $primaryID WHERE table_name='address' and member_lid in (" . implode(",", $othersIDs) . ");";
                    $this->projectdb->query($queryMoveTags);

                    $addingMergeTagID[] = $primaryID;
                }

                //$tagMergedID = $this->getMergedTag();
                //$queryInsertTags = "INSERT INTO tag_relations (member_lid, table_name, tag_id) VALUES ($primaryID, 'address', $tagMergedID);";
                //$this->projectdb->query($queryInsertTags);

                //Check if any is used
//                $used = 0;
//                foreach ($group["$this->targetField"."_list"] as $memberID => $groupMember) {
//                    if($groupMember['used'] == 1){
//                        $used = 1;
//                        continue;
//                    }
//                }

                $query = "UPDATE address set vsys='" . $group['vsys'] . "', description='$final_description', used='$used' WHERE id='" . $primaryID . "';";
                $this->projectdb->query($query);
            }
        }

        //Insert the "merged" tag into all the merged objects
        $tagMergedID = $this->getMergedTag();
        foreach ($addingMergeTag as $id){
            $addingMergeTag[] = "($id, 'address', $tagMergedID)";
        }
        if(count($addingMergeTag)>0) {
            $queryInsertTags = "INSERT INTO tag_relations (member_lid, table_name, tag_id) VALUES " . implode(",", $addingMergeTag) . ";";
            $this->projectdb->query($queryInsertTags);
        }


        $success = true;
        return $success;
    }

    protected function updateDuplicates(): bool
    {
        $mapping = [];
        foreach ($this->groups as &$group){
            if($group['mergeable']) {
                if(count($group["$this->targetField"."_list"])<=1) {
                    continue;
                }

                $updateObjectsReferences = array();
                foreach ($group["$this->targetField" . "_list"] as $memberID => $member) {
                    if ($memberID != $group['primary']) {
                        $updateObjectsReferences[] = $memberID;
                    }
                }
                $mapping[$group['primary']] = $updateObjectsReferences;
                //$this->updateMemberLidBulks($group['primary'], $updateObjectsReferences);
            }
        }

        if(count($mapping)>0){
            $this->updateMemberLidBulks($mapping);
        }
        $success = true;
        return $success;
    }

    private function updateMemberLidBulks(ARRAY $mapping){
        foreach ($mapping as $primaryID => $repleaceable){
            $queryCaseSection[] = " WHEN member_lid in (".implode(",", $repleaceable).") AND table_name = 'address' THEN $primaryID";
            $queryCaseSection_tp_dat[] = " WHEN tp_dat_address_lid in (".implode(",", $repleaceable).") AND tp_dat_address_table = 'address' THEN $primaryID";
        }
        $queryCaseSection = implode(" ", $queryCaseSection);
        $queryCaseSection_tp_dat = implode(" ",$queryCaseSection_tp_dat);

//        //$query= "UPDATE address_groups           SET member_lid = '$primary_member_lid' WHERE member_lid IN (".implode(",",$member_lids).") AND table_name = 'address';";
//        $job_address_groups = new BackgroundTaskSQLUpdate(['dbName' => $this->projectName, 'query'=>$query]);
//        $job_address_groups->start();
        $job_address_groups             = $this->startJob("UPDATE address_groups                           SET member_lid = CASE $queryCaseSection ELSE member_lid END;","address_groups");
        $job_sec_rules_src              = $this->startJob("UPDATE security_rules_src                       SET member_lid = CASE $queryCaseSection ELSE member_lid END;","security_rules_src");
        $job_sec_rules_dst              = $this->startJob("UPDATE security_rules_dst                       SET member_lid = CASE $queryCaseSection ELSE member_lid END;","security_rules_dst");
        $job_nat_rules_src              = $this->startJob("UPDATE nat_rules_src                            SET member_lid = CASE $queryCaseSection ELSE member_lid END;","nat_rules_src");
        $job_nat_rules_dst              = $this->startJob("UPDATE nat_rules_dst                            SET member_lid = CASE $queryCaseSection ELSE member_lid END;","nat_rules_dst");
        $job_nat_rules_tranAdd          = $this->startJob("UPDATE nat_rules_translated_address             SET member_lid = CASE $queryCaseSection ELSE member_lid END;","nat_rules_translated_address");
        $job_nat_rules_tranAdd_fallback = $this->startJob("UPDATE nat_rules_translated_address_fallback    SET member_lid = CASE $queryCaseSection ELSE member_lid END;","nat_rules_translated_address_fallback");
        $job_appoverride_rules_src      = $this->startJob("UPDATE appoverride_rules_src                    SET member_lid = CASE $queryCaseSection ELSE member_lid END;","appoverride_rules_src");
        $job_appoverride_rules_dst      = $this->startJob("UPDATE appoverride_rules_dst                    SET member_lid = CASE $queryCaseSection ELSE member_lid END;","appoverride_rules_dst");
        $job_nat_rules                  = $this->startJob("UPDATE nat_rules                                SET tp_dat_address_lid = CASE $queryCaseSection_tp_dat ELSE tp_dat_address_lid END;","nat_rules");

//        # Add Other Rules
        $job_authentication_rules_src   = $this->startJob("UPDATE authentication_rules_src                 SET member_lid = CASE $queryCaseSection ELSE member_lid END;","authentication_rules_src");
        $job_authentication_rules_dst   = $this->startJob("UPDATE authentication_rules_dst                 SET member_lid = CASE $queryCaseSection ELSE member_lid END;","authentication_rules_dst");
        $job_decryption_rules_src       = $this->startJob("UPDATE decryption_rules_src                     SET member_lid = CASE $queryCaseSection ELSE member_lid END;","decryption_rules_src");
        $job_decryption_rules_dst       = $this->startJob("UPDATE decryption_rules_dst                     SET member_lid = CASE $queryCaseSection ELSE member_lid END;","decryption_rules_dst");
        $job_dos_rules_src              = $this->startJob("UPDATE dos_rules_src                            SET member_lid = CASE $queryCaseSection ELSE member_lid END;","dos_rules_src");
        $job_dos_rules_dst              = $this->startJob("UPDATE dos_rules_dst                            SET member_lid = CASE $queryCaseSection ELSE member_lid END;","dos_rules_dst");
        $job_pbf_rules_dst              = $this->startJob("UPDATE pbf_rules_dst                            SET member_lid = CASE $queryCaseSection ELSE member_lid END;","pbf_rules_dst");
        $job_pbf_rules_src              = $this->startJob("UPDATE pbf_rules_src                            SET member_lid = CASE $queryCaseSection ELSE member_lid END;","pbf_rules_src");
        $job_qos_rules_dst              = $this->startJob("UPDATE qos_rules_dst                            SET member_lid = CASE $queryCaseSection ELSE member_lid END;","qos_rules_dst");
        $job_qos_rules_src              = $this->startJob("UPDATE qos_rules_src                            SET member_lid = CASE $queryCaseSection ELSE member_lid END;","qos_rules_src");
        $job_tunnel_inspect_rules_dst   = $this->startJob("UPDATE tunnel_inspect_rules_dst                 SET member_lid = CASE $queryCaseSection ELSE member_lid END;","tunnel_inspect_rules_dst");
        $job_tunnel_inspect_rules_src   = $this->startJob("UPDATE tunnel_inspect_rules_src                 SET member_lid = CASE $queryCaseSection ELSE member_lid END;","tunnel_inspect_rules_src");
        $job_captiveportal_rules_src    = $this->startJob("UPDATE captiveportal_rules_src                  SET member_lid = CASE $queryCaseSection ELSE member_lid END;","captiveportal_rules_src");
        $job_captiveportal_rules_dst    = $this->startJob("UPDATE captiveportal_rules_dst                  SET member_lid = CASE $queryCaseSection ELSE member_lid END;","captiveportal_rules_dst");
//
//        # Update internal_list and external_list from zones
        $job_zones_include_list         = $this->startJob("UPDATE zones_include_list                       SET member_lid = CASE $queryCaseSection ELSE member_lid END;","zones_include_list");
        $job_zones_exclude_list         = $this->startJob("UPDATE zones_exclude_list                       SET member_lid = CASE $queryCaseSection ELSE member_lid END;","zones_exclude_list");

//        # Update routes_static
//        $projectdb->query("UPDATE routes_static SET nexthop_value_member_lid = '$primary_member_lid' WHERE nexthop_value_member_lid IN (".implode(",",$member_lids).") ;");
//        $projectdb->query("UPDATE routes_static SET destination_member_lid = '$primary_member_lid' WHERE destination_member_lid IN (".implode(",",$member_lids).") ;");
//        $projectdb->query("UPDATE routes_static_monitor_destinations SET dst_member_lid = '$primary_member_lid' WHERE dst_member_lid IN (".implode(",",$member_lids).") ;");
//
//
//        #UPDATE LOGS TO THE NEW Rule
//        $projectdb->query("UPDATE logs SET obj_id = '$primary_member_lid', obj_table = 'address' WHERE obj_id IN (".implode(",",$member_lids).") AND obj_table = 'address';");
        $job_address_groups->join();
        $job_sec_rules_src->join();
        $job_sec_rules_dst->join();
        $job_nat_rules->join();
        $job_nat_rules_src->join();
        $job_nat_rules_dst->join();
        $job_nat_rules_tranAdd->join();
        $job_nat_rules_tranAdd_fallback->join();
        $job_appoverride_rules_src->join();
        $job_appoverride_rules_dst->join();
        $job_authentication_rules_src->join();
        $job_authentication_rules_dst->join();
        $job_decryption_rules_src->join();
        $job_decryption_rules_dst->join();
        $job_dos_rules_src->join();
        $job_dos_rules_dst->join();
        $job_pbf_rules_src->join();
        $job_pbf_rules_dst->join();
        $job_qos_rules_src->join();
        $job_qos_rules_dst->join();
        $job_tunnel_inspect_rules_src->join();
        $job_tunnel_inspect_rules_dst->join();
        $job_captiveportal_rules_src->join();
        $job_captiveportal_rules_dst->join();
        $job_zones_include_list->join();
        $job_zones_exclude_list->join();



    }

    /***
     * Creates and initiates a job to update a specific table with a given query.
     * Runs in background with an own thread
     * @param STRING $query
     * @return BackgroundTaskSQLUpdate
     */
    protected function startJob(STRING $query, STRING $description = ''):BackgroundTaskSQLUpdate{
        $job = new BackgroundTaskSQLUpdate(['dbName' => $this->projectName, 'query'=>$query, 'description'=>$description]);
        $job->start();
        return $job;
    }

    protected function cleanDuplicatesUsages(): bool
    {
        global $projectdb;
        $projectdb = $this->projectdb;
        cleanDuplicatedUsages("security_rules_src", "address");
        cleanDuplicatedUsages("security_rules_dst", "address");
        cleanDuplicatedUsages("nat_rules_src", "address");
        cleanDuplicatedUsages("nat_rules_dst", "address");
        cleanDuplicatedUsages("nat_rules_translated_address", "address");
        cleanDuplicatedUsages("nat_rules_translated_address_fallback", "address");
        cleanDuplicatedUsages("appoverride_rules_dst", "address");
        cleanDuplicatedUsages("appoverride_rules_src", "address");
        cleanDuplicatedUsages("address_groups", "address");
        cleanDuplicatedUsages("tag_relations", "address");

        cleanDuplicatedUsages("authentication_rules_dst", "address");
        cleanDuplicatedUsages("authentication_rules_src", "address");
        cleanDuplicatedUsages("decryption_rules_src", "address");
        cleanDuplicatedUsages("decryption_rules_dst", "address");
        cleanDuplicatedUsages("dos_rules_dst", "address");
        cleanDuplicatedUsages("dos_rules_src", "address");
        cleanDuplicatedUsages("pbf_rules_dst", "address");
        cleanDuplicatedUsages("pbf_rules_src", "address");
        cleanDuplicatedUsages("qos_rules_dst", "address");
        cleanDuplicatedUsages("qos_rules_src", "address");
        cleanDuplicatedUsages("tunnel_inspect_rules_dst", "address");
        cleanDuplicatedUsages("tunnel_inspect_rules_src", "address");
        cleanDuplicatedUsages("captiveportal_rules_src", "address");
        cleanDuplicatedUsages("captiveportal_rules_dst", "address");

        $success = true;
        return $success;
    }

}