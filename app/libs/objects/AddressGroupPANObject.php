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

class AddressGroupPANObject extends PANObject{
    protected $id;
    protected $name_ext;
    protected $name;
    protected $used;
    protected $checkit;
    protected $devicegroup;
    protected $type;
    protected $description;
    protected $tag;
    protected $filter;
    protected $zone;
    protected $invalid;
    protected $modified;
    protected $dummy;
    protected $members = array();


    protected $table = 'address_groups_id';
    protected $dependent_tables = ['address_groups'];
    protected $used_in_tables = [
        'address_groups','security_rules_src','security_rules_dst','nat_rules_src','nat_rules_dst','nat_rules_translated_address','nat_rules_translated_address_fallback'
    ];
    protected $fillable = [
        'id', 'name_ext', 'name', 'used', 'checkit', 'devicegroup', 'vsys', 'type', 'source', 'description', 'tag', 'filter', 'zone', 'invalid', 'modified', 'members', 'dummy'
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

    protected function prepareXML(){

        $xml = new SimpleXMLElement('<address-group></address-group>');
        $addressGroup = $xml->addChild('entry');
        $addressGroup->addAttribute('name', $this->name_ext);

        if (isset($this->members) && count($this->members) > 0) {
            if (($this->version >= 6) AND ( $this->type == "static")) {
                $addressGroup2 = $addressGroup->addChild('static');
            }
            else {
                $addressGroup2 = $addressGroup;
            }

            foreach ($this->members as $member){
                $addressGroup2->addChild('member', $member);
            }
        }
        else {
            if (($this->version >= 6) AND ( $this->type == "dynamic")) {
                $dynamic = $addressGroup->addChild('dynamic');
                $filter = str_replace("<br>", "\n", $this->filter);
                $dynamic->addChild('filter', $filter);
            }
        }

        if (isset($this->description) && $this->description != "") {
            $addressGroup->addChild('description');
            $addressGroup->description = $this->description;
        }
        if (isset($this->tag) && $this->tag != "") {
            $tags = explode(",", $this->tag);
            $shtag = $addressGroup->addChild('tag');
            foreach ($tags as $kkey => $vvalue) {
                $shtag->addChild('member', $vvalue);
            }
        }

        return $xml;
    }

    public function load(STRING $name_ext, SimpleXMLElement $element=null, STRING $source, STRING $vsys, STRING $devicegroup)
    {
        $this->source = $source;
        $this->vsys = $vsys;
        $this->devicegroup = $devicegroup;
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
            $this->filter = '';
            $this->type = isset($element->dynamic) ? 'dynamic' : 'static';
            $this->tag = '';
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
                elseif ($field == "static") {
                    foreach ($value as $kkey => $vvalue) {
                        $this->members[] = $vvalue;
                    }
                }
                elseif ($field == "dynamic") {
                    foreach ($value as $kkey => $vvalue) {
                        $this->filter = str_replace("\r", "", $vvalue);
                        $this->filter = str_replace("\n", "<br>", $this->filter);
                        $this->filter = addslashes($this->filter);
                    }
                }
                else {
                    #IS 5.X
                    $this->members[] = $value;
                }
            }
        }
    }

    public function loadFromProject(mysqli $connection, STRING $name_ext)
    {
        $query = "SELECT * FROM ".$this->table." WHERE source='$this->source' AND vsys='$this->vsys' AND BINARY name_ext='$name_ext'";
        $data = $connection->query($query)->fetch_assoc();
        $lid = $data['id'];
        foreach ($data as $key => $value){
            $this->{$key} = $value;
        }

        $query = "SELECT * FROM address_groups ad  WHERE lid='$lid'";
        $result = $connection->query($query);
        while ($data = $result->fetch_assoc()){
            $table_name = $data['table_name'];
            $member_lid = $data['member_lid'];

            $getName = $connection->query("SELECT name_ext, name FROM $table_name WHERE id='$member_lid'");
            if ($getName->num_rows==1){
                $data2 = $getName->fetch_assoc();
                $this->members[] = $data2['name'];
            }
        }
    }

    public function compare(PANObject $objectB){
        return parent::compare($objectB);
    }

    public function insert(mysqli $connection, STRING $name_ext)
    {
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

            $query = "INSERT INTO address_groups_id (name_ext,name,devicegroup,source,vsys,type, description, filter, tag) 
                      VALUES ('$name_ext','$name_ext','$this->devicegroup','$this->source','$this->vsys','$this->type','$this->description', '$this->filter','$this->tag')";
            $connection->query($query);
            $lid = $connection->insert_id;

            //Relate the members to the group
            $membersList = array();
            if (count($this->members) > 0) {
                sort($this->members, SORT_STRING);
                foreach ($this->members as $member) {
                    $projectdb = $connection;
                    $vsyses = getVsyses($connection, $this->vsys, $this->source);
                    if (!$memberObj = getMemberId($connection, $this->source, $vsyses, $member)) {
                        //Create a Checkit object
                        $member = initAddressMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $member['type'] = 'ip-netmask';
                        $memberObj = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $membersList[] = "('$this->devicegroup','$this->vsys','$memberObj->name','$memberObj->location','$lid','$this->source')";
                }
            }
            if (count($membersList) > 0) {
                $query = "INSERT INTO address_groups (devicegroup,vsys,member_lid,table_name ,lid,source) VALUES " . implode(",", $membersList);
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
        global $projectdb;
        $projectdb = $connection;

        $vsyses = getVsyses($connection, $this->vsys, $this->source);
        if(!$this->exists($connection, $name_ext, $vsyses)) {
            return $this->insert($connection, $name_ext);
        }
        else{
            parent::update($connection, $name_ext, $fields);

            if (in_array('members', $fields)) {
                //Relate the members to the group
                $query = "DELETE FROM address_groups WHERE lid='$id'";
                $connection->query($query);
                $membersList = array();
                if (count($this->members) > 0) {
                    sort($this->members, SORT_STRING);
                    foreach ($this->members as $member) {

                        if (!$memberObj = getMemberId($connection, $this->source, $vsyses, $member)) {
                            //Create a Checkit object
                            $member = initAddressMember();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $member['type'] = 'ip-netmask';
                            $memberObj = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $membersList[] = "('$this->devicegroup','$this->vsys','$memberObj->name','$memberObj->location','$id','$this->source')";
                    }
                }
                if (count($membersList) > 0) {
                    $query = "INSERT INTO address_groups (devicegroup,vsys,member_lid,table_name ,lid,source) VALUES " . implode(",", $membersList);
                    $connection->query($query);
                }
            }

            $msg = [
                'code' => true,
                'msg' => "Updated correctly"
            ];
            return $msg;
        }
    }

    public function checkUsed(mysqli $connection, STRING $name_ext=null){
        if(is_null($name_ext)) {
            $name_ext = $this->name_ext;
        }
        $source = $this->source;
        $vsys = $this->vsys;

        $response = null;

        $query = "SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$name_ext'";
        $result = $connection->query($query);
        if ($result->num_rows==1){
            $data = $result->fetch_assoc();
            $id = $data['id'];
            $query = "SELECT id,'address_groups'        as location FROM address_groups      WHERE member_lid='$id' AND table_name ='$this->table' UNION ".
                "SELECT id,'security_rules_src'    as location FROM security_rules_src  WHERE member_lid='$id' AND table_name ='$this->table' UNION ".
                "SELECT id,'security_rules_dst'    as location FROM security_rules_dst  WHERE member_lid='$id' AND table_name ='$this->table' UNION ".
                "SELECT id,'nat_rules_src'         as location FROM nat_rules_src       WHERE member_lid='$id' AND table_name ='$this->table' UNION ".
                "SELECT id,'nat_rules_dst'         as location FROM nat_rules_dst       WHERE member_lid='$id' AND table_name ='$this->table' UNION ".
                "SELECT id,'nat_rules_translated_address' as location FROM nat_rules_translated_address WHERE member_lid='$id' AND table_name ='$this->table' UNION ".
                "SELECT id,'nat_rules_translated_address_fallback' as location FROM nat_rules_translated_address_fallback WHERE member_lid='$id' AND table_name ='$this->table' ";
            //TODO en others
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
        return $response;    }

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null){
        return parent::exists($connection, $name_ext, $vsyses);
    }
}