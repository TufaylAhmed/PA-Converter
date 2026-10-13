<?php

/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/
require_once INC_ROOT.'/libs/objects/PANObject.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

class ServiceGroupPANObject extends PANObject{
    protected $id;
    protected $name;
    protected $name_ext;
    protected $used;
    protected $checkit;
    protected $devicegroup;
    protected $vsys;
    protected $type;
    protected $source;
    protected $description;
    protected $tag;
    protected $filter;
    protected $invalid;
    protected $modified;
    protected $dummy;
    protected $members = array();

    protected $table = 'services_groups_id';
    protected $dependent_tables = ['services_groups'];
    protected $fillable = [
        'id', 'name', 'name_ext', 'used', 'checkit', 'devicegroup', 'vsys', 'type', 'source', 'description', 'tag', 'filter', 'invalid', 'modified', 'dummy'
    ];

    public function setSource(STRING $source){
        $this->source = $source;
    }

    public function setVsys(STRING $vsys){
        $this->vsys = $vsys;
    }

    public function setDeviceGroup(STRING $devicegroup){
        $this->devicegroup = $devicegroup;
    }

    public function prepareXML(){
        //TODO
        $xml = new SimpleXMLElement('<service-group></service-group>');
        return $xml;

    }

    public function load(STRING $name_ext, SimpleXMLElement $element=null, STRING $source, STRING $vsys, STRING $devicegroup)
    {
        $this->name_ext = $name_ext;
        $this->name = normalizeNames($name_ext);
        if (is_null($element)) {
            $this->invalid='1';
            $this->dummy='1';
            $this->modified='0';
            $this->checkit='1';
        }
        else {
            $this->invalid='0';
            $this->dummy='0';
            $this->modified='0';
            $this->checkit='0';

            $this->description = "";
            $this->type = isset($element->dynamic) ? 'dynamic' : 'static';
            $this->tag = "";
            $this->members = array();
            $tag = array();

            foreach ($element as $field => $value) {
                if ($field == "tag") {
                    foreach ($value as $kkey => $vvalue) {
                        $tag[] = $vvalue;
                    }
                    if (count($tag) > 0) {
                        sort($tag, SORT_STRING);
                        $this->tag = implode(',', $tag);
                        $tag = array();
                    }
                }
                elseif ($field == "description") {
                    $this->description = addslashes($value);
                }
                elseif ($field == "members") {
                    foreach ($value as $kkey => $vvalue) {
                        $this->members[] = $vvalue;
                    }
                } else {
                    #IS 5.X
                    $this->members[] = $value;
                }
            }
        }
    }

    public function loadFromProject(mysqli $connection, STRING $name_ext)
    {
        // TODO: Implement loadFromProject() method.
    }

    /***
     * Given an AddressGroup to compare with, it returns those fields that are different between this object and the compared one
     * @param PANObject $objectB
     * @return array
     */
    public function compare(PANObject $objectB){
        if(get_class($objectB) != get_class($this)){
            return array();
        }
        else {
            $differences = array();
            foreach ($this->fillable as $field) {
                if (is_array($this->{$field})) {
                    $diff = array_diff($this->{$field}, $objectB->{$field});
                    if (count($diff) != 0) {
                        $differences[] = $field;
                    }
                } else {
                    if ($this->{$field} != $objectB->{$field}) {
                        $differences[] = $field;
                    }
                }
            }
            return $differences;
        }
    }

    public function insert(mysqli $connection, STRING $name_ext){
        global $projectdb;
        if($this->exists($connection, $name_ext)){
            $updateList = $this->fillable;
            foreach($this->ignoreList as $ignoreField) {
                if (($key = array_search($ignoreField, $updateList)) !== false) {
                    unset($updateList[$key]);
                }
            }
            return $this->update($connection, $name_ext, $updateList);
        }
        else {
            $query = "INSERT INTO services_groups_id (name_ext,name,devicegroup,source,vsys,type,description,tag)
                  VALUES ('$name_ext','$name_ext','$this->devicegroup','$this->source','$this->vsys','$this->type','$this->description', '$this->tag')";
            $connection->query($query);
            $lid = $connection->insert_id;

            //Relate the members to the group
            $membersList = array();
            if (count($this->members) > 0) {
                sort($this->members, SORT_STRING);
                foreach ($this->members as $member) {
                    $projectdb = $connection;
                    $vsyses = getVsyses($connection, $this->vsys, $this->source);
                    if (!$memberObj = getServiceId($connection, $this->source, $vsyses, $member)) {
                        $member = initServiceMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $memberObj = createServiceMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $membersList[] = "('$this->devicegroup','$this->vsys','$memberObj->name','$memberObj->location','$lid','$this->source')";
                }
            }
            if (count($membersList) > 0) {
                $query = "INSERT INTO services_groups (devicegroup,vsys,member_lid,table_name ,lid,source) VALUES " . implode(",", $membersList);
                $connection->query($query);
            }

            $msg = [
                'code' => true,
                'msg' => "Inserted correctly"
            ];
            return $msg;
        }
    }

    public function update(mysqli $connection, STRING $name_ext, ARRAY $fields, INT &$id=null){
        $vsyses = getVsyses($connection, $this->vsys, $this->source);
        if(!$this->exists($connection, $name_ext, $vsyses)) {
            return $this->insert($connection,$name_ext);
        }
        else {
            global $projectdb;

            $query = "SELECT id FROM services_groups_id WHERE source='$this->source' AND vsys='$this->vsys' AND name='$name_ext'";
            $data = $connection->query($query)->fetch_assoc();
            $id = $data['id'];

            $updates = array();
            foreach ($fields as $field) {
                if (!is_array($this->{$field})) {
                    $updates[] = " '$field' = '" . $this->{$field} . "' ";
                }
            }

            $updatesString = implode(',', $updates);
            $query = "UPDATE address_groups_id SET $updatesString 
                  WHERE id='$id'";
            $connection->query($query);

            if (in_array('members', $fields)) {
                //Relate the members to the group
                $query = "DELETE FROM services_groups WHERE lid='$id'";
                $connection->query($query);
                $membersList = array();
                if (count($this->members) > 0) {
                    include_once INC_ROOT . '/libs/common/lib-objects.php';
                    sort($this->members, SORT_STRING);
                    foreach ($this->members as $member) {
                        $projectdb = $connection;
                        if (!$memberObj = getServiceId($connection, $this->source, $vsyses, $member)) {
                            $member = initServiceMember();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $memberObj = createServiceMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $membersList[] = "('$this->devicegroup','$this->vsys','$memberObj->name','$memberObj->location','$id','$this->source')";
                    }
                }
                if (count($membersList) > 0) {
                    $query = "INSERT INTO services_groups (devicegroup,vsys,member_lid,table_name ,lid,source) VALUES " . implode(",", $membersList);
                    $connection->query($query);
                }
            }

            $msg = [
                'code' => true,
                'msg' => "Udapted correctly"
            ];
            return $msg;
        }
    }

    public function checkUsed(mysqli $connection, STRING $name_ext=null){
        if(is_null($name_ext)) {
            $name_ext = $this->name;
        }
        $source = $this->source;
        $vsys = $this->vsys;

        $response = null;

        $query = "SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY name='$name_ext'";
        $result = $connection->query($query);
        if ($result->num_rows==1){
            $data = $result->fetch_assoc();
            $id = $data['id'];
            $query = "SELECT id,'services_groups'  as location FROM services_groups      WHERE member_lid='$id' AND table_name ='$this->table' UNION ".
                "SELECT id,'security_rules_srv'    as location FROM security_rules_srv  WHERE member_lid='$id' AND table_name ='$this->table' UNION ".
                "SELECT id,'nat_rules_srv'         as location FROM nat_rules_srv       WHERE member_lid='$id' AND table_name ='$this->table'";
            $result = $connection->query($query);
            $usages = array();
            $total =0;
            if($result->num_rows > 0){
                while($data = $result->fetch_assoc()){
                    $total ++;
                    $usages[$data['location']][] = [$data['id']];
                }

                $response = [
                    'total' => $total,
                    'usages'    => $usages,
                ];
            }
        }
        return $response;
    }

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null){
        return parent::exists($connection, $name_ext, $vsyses);
    }
}