<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Tools\Merger;

use PaloAltoNetworks\Expedition\MemoryObjects\Response;

class RegionsMerger extends ObjectMerger
{
    protected $groupByFields;

    public function getInfoByIDs(array $ids):Response{
        return new Response(true, 0, json_encode($this->memoryObjectHandler->getRegions($ids)));
    }

    public function __construct(STRING $project, INT $userID, STRING $source)
    {
        parent::__construct($project, $userID, $source);
        $this->queryGetRepresentativeID = "SELECT member_lid FROM tools_results WHERE table_name = 'regions' AND source = '$this->source' AND user_id = '$this->userID';";
        $this->targetField = 'regions';
    }

    protected function loadObjects(): bool
    {
        /** @var $response Response*/
        $response = $this->memoryObjectHandler->loadRegions($this->projectdb,$this->selectedIDs);

        if($response->success)       return true;
        else                         return false;
    }

    public function setMergerByFields(ARRAY $fields){
        $this->groupByFields = $fields;
    }

    protected function updatePrimaries(): bool
    {
        // TODO: Implement updatePrimaries() method.
        foreach ($this->groups as &$group){
            if($group['mergeable']) {
                $primaryID = $group['primary'];

                //Collect the descriptions of all the members to be merged
                $description = array();

                //Check if any is used
                $used = 0;
                foreach ($group["$this->targetField"."_list"] as $memberID => $groupMember) {
                    if($groupMember['used'] == 1){
                        $used = 1;
                        continue;
                    }
                }

                //Collect the used tags


                $query = "UPDATE regions set vsys='" . $group['vsys'] . "', used='$used' WHERE id='" . $primaryID . "';";
                $this->projectdb->query($query);
            }
        }

        $success = true;
        return $success;

    }

    protected function updateDuplicates(): bool
    {
        foreach ($this->groups as &$group){
            if($group['mergeable']) {
                $updateObjectsReferences = array();
                foreach ($group["$this->targetField"."_list"] as $memberID => $member) {
                    if ($memberID != $group['primary']) {
                        $updateObjectsReferences[] = $memberID;
                    }
                }
                updateMemberLidBulks($this->projectdb, $group['primary'], $updateObjectsReferences, "regions");
            }
        }
        $success = true;
        return $success;
    }

    protected function cleanDuplicatesUsages(): bool
    {
        cleanDuplicatedUsages("security_rules_src", "regions");
        cleanDuplicatedUsages("security_rules_dst", "regions");
        cleanDuplicatedUsages("decryption_rules_src", "regions");
        cleanDuplicatedUsages("decryption_rules_dst", "regions");
        cleanDuplicatedUsages("dos_rules_dst", "regions");
        cleanDuplicatedUsages("dos_rules_src", "regions");
        cleanDuplicatedUsages("tunnel_inspect_rules_dst", "regions");
        cleanDuplicatedUsages("tunnel_inspect_rules_src", "regions");
        cleanDuplicatedUsages("captiveportal_rules_dst", "regions");
        cleanDuplicatedUsages("captiveportal_rules_src", "regions");
        cleanDuplicatedUsages("authentication_rules_dst", "regions");
        cleanDuplicatedUsages("authentication_rules_src", "regions");

        $success = true;
        return $success;
    }

}