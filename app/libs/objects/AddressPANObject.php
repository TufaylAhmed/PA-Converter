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

class AddressPANObject extends PANObject{
    protected $id;
    protected $name_ext;
    protected $name;
    protected $used;
    protected $checkit;
    protected $devicegroup;
    protected $type;
    protected $ipaddress;
    protected $cidr;
    protected $description;
    protected $fqdn;
    protected $v4;
    protected $v6;
    protected $vtype;
    protected $tag;
    protected $zone;
    protected $invalid;
    protected $modified;
    protected $dummy;

    protected $object = "Address";
    protected $table = 'address';
    protected $dependent_tables = [''];
    protected $used_in_tables = [
        'address_groups','security_rules_src','security_rules_dst','nat_rules_src','nat_rules_dst','nat_rules_translated_address','nat_rules_translated_address_fallback'
    ];

    protected $fillable = [
        'id', 'name_ext','name','used', 'checkit', 'devicegroup', 'vsys', 'type', 'ipaddress','cidr', 'description', 'fqdn', 'v4','v6','vtype','source', 'tag','zone','invalid','modified','dummy'
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
        $xml = new SimpleXMLElement('<address></address>');
        $address = $xml->addChild('entry');
        $address->addAttribute('name', $this->name);
        switch($this->type){
            case "ip-netmask":
                $address->addChild('ip-netmask', $this->ipaddress.'/'.$this->cidr);
                break;
            case "ip-range":
                $address->addChild('ip-range', $this->ipaddress);
                break;
            case "fqdn":
                $address->addChild('fqdn', $this->ipaddress);
                break;
            case "dynamic":
                if ($this->version == 5) {
                    $address->addChild('dynamic', $this->ipaddress);
                } elseif ($this->version >= 6) {
                    add_log('error', 'Exporting Shared Address', 'Dynamic Address Not supported in Panos 6.x [' . $this->name . ']', $this->source, 'Object was Not Migrated');
                }
                break;
            default:
                break;
        }
        if (isset($this->description) && $this->description != "") {
            $address->addChild('description', $this->description);
        }
        if (($this->tag != "") AND ( $this->version >= 6)) {
            $tags = $address->addChild('tag');
            $myTags = explode(",", $this->tag);
            foreach ($myTags as $key => $value) {
                $tags->addChild('member', $value);
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
            $this->invalid = '0';
            $this->dummy = '0';
            $this->modified = '0';
            $this->checkit = '0';

            $this->description = "";
            $this->ipaddress = "";
            $this->type = "";
            $this->tag = "";
            $tag = array();
            foreach ($element as $field => $value) {
                if (($field == "ip-netmask") OR ($field == "fqdn") OR ($field == "ip-range") OR ($field == "dynamic")) {
                    if (($field == "ip-netmask") AND (strpos($value, '/') === FALSE)) {
                        $this->ipaddress = $value;
                        $this->cidr = "32";
                        $this->type = $field;
                    }
                    elseif ($field == "ip-range") {
                        $this->ipaddress = $value;
                        $this->cidr = "";
                        $this->type = $field;
                    }
                    else {
                        $ip_mask = $value;
                        if (preg_match("/\//", $ip_mask)) {
                            list($this->ipaddress, $this->cidr) = explode("/", $ip_mask);
                        } else {
                            $this->ipaddress = $ip_mask;
                            $this->cidr = 32;
                        }
                        $this->type = $field;
                    }
                }
                elseif ($field == "description") {
                    $this->description = addslashes($value);
                }
                elseif ($field == "tag") {
                    foreach ($value as $kkey => $vvalue) {
                        $tag[] = $vvalue;
                    }
                    if (count($tag) > 0) {
                        sort($tag, SORT_STRING);
                        $this->tag = implode(',', $tag);
                        $tag = array();
                    }
                }
                $version = ip_version($this->ipaddress);
                if($version == 'v6'){
                    $this->v4=0;
                    $this->v6=1;
                }
                else{
                    $this->v4=1;
                    $this->v6=0;
                }
            }
        }
    }

    public function loadFromProject(mysqli $connection, STRING $name_ext)
    {
        $query = "SELECT * FROM ".$this->table." WHERE source='$this->source' AND vsys='$this->vsys' AND BINARY name_ext='$name_ext'";
        $data = $connection->query($query)->fetch_assoc();
        foreach ($data as $key => $value){
            $this->{$key} = $value;
        }
        if($this->ipaddress){
            $this->type = 'ip-netmask';
        }
        elseif(true){
            $this->type = 'ip-range';
        }
        else{
            $this->type = 'fqdn';
        }

    }

    public function insert(mysqli $connection, STRING $name_ext){
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
            $query = "INSERT INTO address (name_ext,name,type,ipaddress,cidr,description,devicegroup,source,vsys,tag,v4,v6) 
                            VALUES    ('$name_ext','$name_ext','$this->type','$this->ipaddress','$this->cidr','$this->description','$this->devicegroup','$this->source','$this->vsys','$this->tag','$this->v4','$this->v6')";
            $connection->query($query);

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
        else{
            return parent::update($connection, $name_ext, $fields);
        }
    }

    public function compare(PANObject $objectB){
        return parent::compare($objectB);
    }

    public function checkUsed(mysqli $connection, STRING $name_ext=null){
        if(is_null($name_ext)) {
            $name_ext = $this->name_ext;
        }
        $source = $this->source;
        $vsys = $this->vsys;

        $response = null;

        $query = "SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$name_ext'";
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
        return $response;
    }

    public function delete(mysqli $connection, STRING $name_ext){
        $usage = $this->checkUsed($connection, $name_ext);
        if(is_null($usage)) {
            $msg = parent::delete($connection, $name_ext);
        }
        else{
            $msg = [
                'code' => false,
                'msg'  => $usage
            ];
            global $projectdb;
            $projectdb= $connection;
            add_log2('conflict', 'RealTime Updates from device Config Changes', "Address \"$name_ext\"", $this->source, "Object not deleted because is being used", $this->table, $this->id, $this->table);
        }
        return $msg;
    }

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null)
    {
        return parent::exists($connection, $name_ext, $vsyses);
    }
}