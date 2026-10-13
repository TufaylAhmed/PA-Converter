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

class ServicesMerger extends ObjectMerger
{
    protected $groupByFields;

    public function getInfoByIDs(array $ids):Response{
        return new Response(true, 0, json_encode($this->memoryObjectHandler->getServices($ids)));
    }

    public function __construct(STRING $project, INT $userID, STRING $source)
    {
        parent::__construct($project, $userID, $source);
        $this->queryGetRepresentativeID = "SELECT member_lid FROM tools_results WHERE table_name = 'services' AND source = '$this->source' AND user_id = '$this->userID';";
        $this->targetField = 'services';
    }

    protected function loadObjects(): bool
    {
        /** @var $response Response*/
        $response = $this->memoryObjectHandler->loadServices($this->projectdb,$this->selectedIDs);
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
        if(isset($this->groups)) {
            foreach ($this->groups as &$group) {
                if ($group['mergeable']) {
                    $primaryID = $group['primary'];

                    foreach ($group["$this->targetField" . "_list"] as $memberID => $groupMember) {
                        if ($memberID != $primaryID) {
                            if ($groupMember['dummy'] == 1) {
                                $dummies[] = $memberID;
                            }
                        }
                    }
                }
            }
        }
        return array_unique($dummies);
    }

    protected function updatePrimaries(): bool
    {
        // TODO: Implement updatePrimaries() method.
        if(isset($this->groups)) {
            foreach ($this->groups as &$group) {
                if ($group['mergeable']) {
                    $primaryID = $group['primary'];

                    //Collect all the ids
                    $othersIDs = array();
                    $dummies = array();
                    foreach ($group["$this->targetField" . "_list"] as $memberID => $groupMember) {
                        if ($memberID != $primaryID) {
//                        print_r($groupMember);
                            if (!$groupMember['dummy'] == 1) {
                                $othersIDs[] = $memberID; //The ids for all the other members
                            } else {
                                $dummies[] = $memberID;
                            }
                        }
                    }

                    //Collect the descriptions of all the members to be merged
                    $description = array();
                    $description[] = $group["$this->targetField" . "_list"][$primaryID]['description']; //The description from the remaining object
                    foreach ($group["$this->targetField" . "_list"] as $memberID => $groupMember) {
                        if ($memberID != $primaryID) {
                            $description[] = $groupMember['description']; //The description for all the other members
                        }
                    }
                    $allDescription = array_filter(array_unique($description)); //Remove duplicate descriptions
                    $final_description = implode(",", $allDescription);
                    $final_description = truncate_descriptions($final_description, $this->version);


                    //Transfer tags to the primary and add a "merged" tag if not already there (already controlled by the DB)
                    if (count($othersIDs) > 0) {
                        $queryMoveTags = "UPDATE tag_relations set member_lid = $primaryID WHERE table_name='services' and member_lid in (" . implode(",", $othersIDs) . ");";
                        $this->projectdb->query($queryMoveTags);
                    }

                    $tagMergedID = $this->getMergedTag();
                    $queryInsertTags = "INSERT INTO tag_relations (member_lid, table_name, tag_id) VALUES ($primaryID, 'services', $tagMergedID);";
                    $this->projectdb->query($queryInsertTags);


                    //Check if any is used
                    $used = 0;
                    foreach ($group["$this->targetField" . "_list"] as $memberID => $groupMember) {
                        if ($groupMember['used'] == 1) {
                            $used = 1;
                            continue;
                        }
                    }

                    $query = "UPDATE services set vsys='" . $group['vsys'] . "', description='$final_description', used='$used' WHERE id='" . $primaryID . "';";
                    $this->projectdb->query($query);
                }
            }
        }
        $success = true;
        return $success;
    }

    protected function updateDuplicates(): bool
    {
        if(isset($this->groups)) {
            foreach ($this->groups as &$group) {
                if ($group['mergeable']) {
                    $updateObjectsReferences = array();
                    foreach ($group["$this->targetField" . "_list"] as $memberID => $member) {
                        if ($memberID != $group['primary']) {
                            $updateObjectsReferences[] = $memberID;
                        }
                    }
                    updateMemberLidBulks($this->projectdb, $group['primary'], $updateObjectsReferences, "services");
                }
            }
        }
        $success = true;
        return $success;
    }

    protected function cleanDuplicatesUsages(): bool
    {
        cleanDuplicatedUsages("security_rules_srv", "services");
        cleanDuplicatedUsages("services_groups", "services");

        cleanDuplicatedUsages("authentication_rules_srv", "services");
        cleanDuplicatedUsages("decryption_rules_srv", "services");
        cleanDuplicatedUsages("dos_rules_srv", "services");
        cleanDuplicatedUsages("pbf_rules_srv", "services");
        cleanDuplicatedUsages("qos_rules_srv", "services");

        $success = true;
        return $success;
    }

}