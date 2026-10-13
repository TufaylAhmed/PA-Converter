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

class NatRulePANObject extends PANObject{
    protected $id;
    protected $position;
    protected $name_ext;
    protected $name;
    protected $description;
    protected $target;
    protected $target_negate;
    protected $disabled;
    protected $vsys;
    protected $lid;
    protected $source;
    protected $checkit;
    protected $migrate;
    protected $counter;
    protected $tp_sat_bidirectional;
    protected $op_zone_to;
    protected $op_to_interface;
    protected $is_dat;
    protected $op_service_lid;
    protected $op_service_table;
    protected $tp_sat_type;
    protected $tp_sat_address_type;
    protected $tp_sat_interface;
    protected $tp_sat_ipaddress;
    protected $tp_dat_port;
    protected $tp_dat_address_lid;
    protected $tp_dat_address_table;
    protected $implicit;
    protected $preorpost;
    protected $devicegroup;
    protected $tag;
    protected $active_active_device_binding;
    protected $nat_type;
    protected $tp_sat_interface_fallback;
    protected $tp_sat_ipaddress_fallback;
    protected $tp_fallback_type;
    protected $blocked;
    protected $invalid;
    protected $modified;
    protected $dummy;


    protected $tp_dat_address_name = array();
    protected $op_service_name = array();

    protected $nat_rules_from = array();
    protected $nat_rules_tag = array();
    protected $nat_rules_src = array();
    protected $nat_rules_dst = array();
    protected $nat_rules_translated_address_fallback = array();
    protected $nat_rules_translated_address = array();

    protected $table = 'nat_rules';
    protected $dependent_tables = [
        'nat_rules_dst', 'nat_rules_from', 'nat_rules_src', 'nat_rules_tag', 'nat_rules_translated_address_fallback', 'nat_rules_translated_address',
    ];

    protected $fillable = [
        'id', 'position', 'name_ext', 'name','description','target','target_negate','disabled','vsys','lid','source','checkit','migrate','counter','tp_sat_bidirectional','op_zone_to','op_to_interface','is_dat','op_service_lid','op_service_table','tp_sat_type','tp_sat_address_type','tp_sat_interface','tp_sat_ipaddress','tp_dat_port','tp_dat_address_lid','tp_dat_address_table','implicit','preorpost','devicegroup','tag','active_active_device_binding','nat_type','tp_sat_interface_fallback','tp_sat_ipaddress_fallback','tp_fallback_type','blocked','invalid','modified','dummy',
        'nat_rules_dst', 'nat_rules_from', 'nat_rules_src', 'nat_rules_tag', 'nat_rules_translated_address_fallback', 'nat_rules_translated_address',

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

    public function setPreOrPost($preOrPost){
        $this->preorpost = $preOrPost;
    }

    public function prepareXML(){
        //TODO
        $xml = new SimpleXMLElement('<rule></rule>');
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

            $this->op_service_table = '';
            $this->op_service_lid = '';
            $this->op_zone_to = '';
            $this->tp_sat_type = 'None';
            $this->tp_fallback_type = '';
            $this->tp_sat_address_type = '';
            $this->tp_sat_interface = '';
            $this->tp_sat_ipaddress = '';
            $this->is_dat = '0';
            $this->tp_sat_bidirectional = 0;
            $this->tp_dat_address_lid = '';
            $this->tp_dat_address_table = '';
            $this->tp_dat_port = '';

//            $this->name = $element->attributes()->name;

            $this->disabled = $element->disabled == "yes" ? '1' : '0';
            $this->description = addslashes($element->description);
            $this->op_to_interface = $element->{'to-interface'};
            $this->active_active_device_binding = (isset($element->{'active-active-device-binding'})) ? $element->{'active-active-device-binding'} : '';
            $this->target = (isset($element->target)) ? addslashes($element->target->asXML()) : '';
            $this->natType = isset($element->{'nat-type'}) ? $element->{'nat-type'} : '';

            $source_translation = $element->{'source-translation'};
            if (isset($source_translation)) {
                foreach ($source_translation as $type1 => $natA) {
                    foreach ($natA as $type => $nat0) {
                        $this->tp_sat_type = $type;

                        if ($type == "dynamic-ip") {
                            foreach ($nat0 as $falloraddress => $nat1) {
                                if ($falloraddress == "fallback") {
                                    foreach ($nat1 as $falltype => $nat2) {
                                        if ($falltype == "translated-address") {
                                            $this->tp_fallback_type = $falltype;
                                            foreach ($nat2 as $m => $member) {
                                                $this->nat_rules_translated_address_fallback[] = $member;
                                            }
                                        }
                                        elseif ($falltype == "interface-address") {
                                            foreach ($nat2 as $falltype2 => $value) {
                                                if ($falltype2 == "interface" OR $falltype2 == "ip") {
                                                    $this->tp_fallback_type = $falltype;
                                                }
                                            }
                                        }
                                    }
                                }
                                elseif ($falloraddress == "translated-address") {
                                    foreach ($nat1 as $m => $member) {
                                        $member = (String) $member;
                                        $this->nat_rules_translated_address[] = $member;
                                    }
                                }
                            }
                        }
                        elseif ($type == "dynamic-ip-and-port") {
                            foreach ($nat0 as $falloraddress => $nat1) {
                                $this->tp_sat_address_type = $falloraddress;
                                if ($falloraddress == "translated-address") {
                                    foreach ($nat1 as $m => $member) {
                                        $member = (String) $member;
                                        $this->nat_rules_translated_address[] = $member;
                                    }
                                }
                                elseif ($falloraddress == "interface-address") {
                                    foreach ($nat1 as $falltype2 => $value) {
                                        $value = (String) $value;
                                        if ($falltype2 == "interface") {
                                            $this->tp_sat_interface = $value;
                                        }
                                        elseif ($falltype2 == "ip") {
                                            $this->tp_sat_ipaddress = $value;
                                        }
                                    }
                                }
                            }
                        }
                        elseif ($type == "static-ip") {
                            foreach ($nat0 as $info => $value) {
                                $value = (String) $value;
                                if ($info == "bi-directional") {
                                    $this->tp_sat_bidirectional = ($value == "yes") ? 1 : 0;
                                }
                                elseif ($info = "translated-address") {
                                    $this->nat_rules_translated_address[] = $value;
                                }
                            }
                        }
                    }
                }
            }

            $destination_translation = $element->{'destination-translation'};
            if (isset($destination_translation)) {
                $this->is_dat = '1';
                foreach ($destination_translation as $type5 => $nat5) {
                    foreach ($nat5 as $type => $value) {
                        $value = (String) $value;
                        if ($type == "translated-address") {
                            $this->tp_dat_address_name = $value;
                        }
                        elseif ($type == "translated-port") {
                            $this->tp_dat_port = $value;
                        }
                    }
                }
            }

            foreach ($element->from as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (String) $memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        $this->nat_rules_from[] = $memberA;
                    }
                }
            }

            foreach ($element->to as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (String) $memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        $this->op_zone_to = $memberA;
                    }
                }
            }

            foreach ($element->tag as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (String) $memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        $this->nat_rules_tag[] = $memberA;
                    }
                }
            }

            foreach ($element->source as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (String) $memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        $this->nat_rules_src[] = $memberA;
                    }
                }
            }

            foreach ($element->destination as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (String) $memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        $this->nat_rules_dst[] = $memberA;
                    }
                }
            }

            $service = $element->service;
            if (($service != "") AND ($service != "any")) {
                $service = (String) $service;
                $this->op_service_name[] = $service;
            }
        }
    }

    public function loadFromProject(mysqli $connection, STRING $name_ext)
    {
        // TODO: Implement loadFromProject() method.
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
            global $projectdb;
            $projectdb = $connection;

            $name_int = normalizeNames($name_ext);

            $nat_rules_from = array();
            $nat_rules_tag = array();
            $nat_rules_src = array();
            $nat_rules_dst = array();
            $nat_rules_translated_address_fallback = array();
            $nat_rules_translated_address = array();

            $getlastlid = $connection->query("SELECT max(id) as max FROM nat_rules;")->fetch_assoc();
            $lid = intval($getlastlid['max']) + 1;
            $getlastlid = $connection->query("SELECT max(position) as max FROM nat_rules WHERE source='$this->source' AND vsys='$this->vsys' AND preorpost='$this->preorpost';")->fetch_assoc();
            $this->position = intval($getlastlid['max']) + 1;

            foreach ($this->nat_rules_translated_address as $member) {
                $vsyses = getVsyses($connection, $this->vsys, $this->source);
                if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $member)) {
                    $member = initAddressMember();
                    $member['name_ext'] = $member;
                    $member['name'] = normalizeNames($member);
                    $member['checkit'] = 1;
                    $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                }
                $nat_rules_translated_address[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
            }

            if (count($this->tp_dat_address_name) == 1) {
                $vsyses = getVsyses($connection, $this->vsys, $this->source);
                if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $this->tp_dat_address_name[0])) {
                    $member = initAddressMember();
                    $member['name_ext'] = $member;
                    $member['name'] = normalizeNames($member);
                    $member['checkit'] = 1;
                    $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                }
                $this->tp_dat_address_lid = $memberObject->name;
                $this->tp_dat_address_table = $memberObject->location;
            }

            foreach ($this->nat_rules_from as $memberA) {
                if (($memberA != "") AND ($memberA != "any")) {
                    $nat_rules_from[] = "('$this->source','$this->vsys','$memberA','$lid','$this->devicegroup')";
                }
            }

            foreach ($this->nat_rules_tag as $memberA) {
                if (($memberA != "") AND ($memberA != "any")) {
                    $vsyses = getVsyses($connection, $this->vsys, $this->source);
                    if (!$tagObject = getTagId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initTag();
                        $member['name_ext'] = $memberA;
                        $member['name'] = normalizeNames($memberA);
                        $member['checkit'] = 1;
                        $tagObject = createTagId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $nat_rules_tag[] = "('$this->source','$this->vsys','$tagObject->location','$tagObject->name','$lid','$this->devicegroup')";
                }
            }

            foreach ($this->nat_rules_src as $memberA) {
                if (($memberA != "") AND ($memberA != "any")) {
                    $vsyses = getVsyses($connection, $this->vsys, $this->source);
                    if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initAddressMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $nat_rules_src[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                }
            }

            foreach ($this->nat_rules_dst as $memberA) {
                if (($memberA != "") AND ($memberA != "any")) {
                    $vsyses = getVsyses($connection, $this->vsys, $this->source);
                    if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initAddressMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $nat_rules_dst[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                }
            }

            foreach ($this->nat_rules_translated_address_fallback as $memberA) {
                if (($memberA != "") AND ($memberA != "any")) {
                    $vsyses = getVsyses($connection, $this->vsys, $this->source);
                    if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initAddressMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $nat_rules_translated_address_fallback[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                }
            }

            if (count($this->op_service_name) == 1 AND ($this->op_service_name != "") AND ($this->op_service_name != "any")) {
                $vsyses = getVsyses($connection, $this->vsys, $this->source);
                if (!$serviceObject = getServiceId($connection, $this->source, $vsyses, $this->op_service_name[0])) {
                    $member = initServiceMember();
                    $member['name_ext'] = $member;
                    $member['name'] = normalizeNames($member);
                    $member['checkit'] = 1;
                    $serviceObject = createServiceMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                }
                $this->op_service_table = $serviceObject->location;
                $this->op_service_lid = $serviceObject->name;
            }

            $query = "INSERT INTO nat_rules (
                      target,preorpost,devicegroup,position,
                      id,description,name_ext,name,disabled,vsys,source,
                      op_to_interface,tp_sat_type,active_active_device_binding, 
                      is_dat, nat_type, op_zone_to, op_service_lid, op_service_table,
                      tp_fallback_type, tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,
                      tp_sat_bidirectional,tp_dat_address_lid,tp_dat_address_table,tp_dat_port) 
                 VALUES ('$this->target','$this->preorpost','$this->devicegroup','$this->position',
                      '$lid','$this->description','$name_ext','$name_int','$this->disabled','$this->vsys','$this->source',
                      '$this->op_to_interface','$this->tp_sat_type','$this->active_active_device_binding', 
                      '$this->is_dat', '$this->natType', '$this->op_zone_to','$this->op_service_lid','$this->op_service_table',
                      '$this->tp_fallback_type','$this->tp_sat_address_type','$this->tp_sat_interface','$this->tp_sat_ipaddress',
                      '$this->tp_sat_bidirectional','$this->tp_dat_address_lid','$this->tp_dat_address_table','$this->tp_dat_port');";

            $connection->query($query);


            if (count($nat_rules_from) > 0) {
                $connection->query("INSERT INTO nat_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_from) . ";");
            }
            if (count($nat_rules_tag) > 0) {
                $connection->query("INSERT INTO nat_rules_tag (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_tag) . ";");
            }
            if (count($nat_rules_src) > 0) {
                $connection->query("INSERT INTO nat_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_src) . ";");
            }
            if (count($nat_rules_dst) > 0) {
                $connection->query("INSERT INTO nat_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_dst) . ";");
            }
            if (count($nat_rules_translated_address_fallback) > 0) {
                $connection->query("INSERT INTO nat_rules_translated_address_fallback (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_translated_address_fallback) . ";");
            }
            if (count($nat_rules_translated_address) > 0) {
                $connection->query("INSERT INTO nat_rules_translated_address (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_translated_address) . ";");
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
            parent::update($connection, $name_ext, $fields);

            $query = "SELECT id FROM $this->table WHERE source='$this->source' AND vsys='$this->vsys' AND name_ext='$name_ext'";
            $data = $connection->query($query)->fetch_assoc();
            $lid = $data['id'];

            if (in_array('nat_rules_from', $fields)) {
                $connection->query("DELETE FROM nat_rules_from WHERE rule_lid='$lid'");
                $nat_rules_from = array();
                foreach ($this->nat_rules_from as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $nat_rules_from[] = "('$this->source','$this->vsys','$memberA','$lid','$this->devicegroup')";
                    }
                }
                $query = "INSERT INTO nat_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_from) . ";";
                $connection->query($query);
            }

            if (in_array('nat_rules_tag', $fields)) {
                $connection->query("DELETE FROM nat_rules_tag WHERE rule_lid='$lid'");
                $nat_rules_tag = array();
                foreach ($this->nat_rules_tag as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $vsyses = getVsyses($connection, $this->vsys, $this->source);
                        if (!$tagObject = getTagId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initTag();
                            $member['name_ext'] = $memberA;
                            $member['name'] = normalizeNames($memberA);
                            $member['checkit'] = 1;
                            $tagObject = createTagId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $nat_rules_tag[] = "('$this->source','$this->vsys','$tagObject->location','$tagObject->name','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO nat_rules_tag (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_tag) . ";");
            }

            if (in_array('nat_rules_src', $fields)) {
                $connection->query("DELETE FROM nat_rules_src WHERE rule_lid='$lid'");
                $nat_rules_src = array();
                foreach ($this->nat_rules_src as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $vsyses = getVsyses($connection, $this->vsys, $this->source);
                        if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initAddressMember();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $nat_rules_src[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO nat_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_src) . ";");
            }

            if (in_array('nat_rules_dst', $fields)) {
                $connection->query("DELETE FROM nat_rules_dst WHERE rule_lid='$lid'");
                $nat_rules_dst = array();
                foreach ($this->nat_rules_dst as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $vsyses = getVsyses($connection, $this->vsys, $this->source);
                        if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initAddressMember();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $nat_rules_dst[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO nat_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_dst) . ";");
            }

            if (in_array('nat_rules_translated_address_fallback', $fields)) {
                $connection->query("DELETE FROM nat_rules_translated_address_fallback WHERE rule_lid='$lid'");
                $nat_rules_translated_address_fallback = array();
                foreach ($this->nat_rules_translated_address_fallback as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $vsyses = getVsyses($connection, $this->vsys, $this->source);
                        if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initAddressMember();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $nat_rules_translated_address_fallback[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO nat_rules_translated_address_fallback (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_translated_address_fallback) . ";");
            }

            if (in_array('nat_rules_translated_address', $fields)) {
                $connection->query("DELETE FROM nat_rules_translated_address WHERE rule_lid='$lid'");
                $nat_rules_translated_address = array();
                foreach ($this->nat_rules_translated_address as $member) {
                    $vsyses = getVsyses($connection, $this->vsys, $this->source);
                    if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $member)) {
                        $member = initAddressMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $nat_rules_translated_address[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                }
                $connection->query("INSERT INTO nat_rules_translated_address (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $nat_rules_translated_address) . ";");
            }

            $msg = [
                'code' => true,
                'msg' => "Updated correctly"
            ];
            return $msg;
        }
    }

    public function compare(PANObject $objectB){
        return parent::compare($objectB);
    }

    public function move(mysqli $connection, STRING $ruleName, ARRAY $rulesUnder, STRING $source, STRING $vsys){
        $query = "SELECT position, preorpost FROM nat_rules WHERE name_ext='$ruleName' AND source='$source' AND vsys='$vsys'";
        $oldPositionResult = $connection->query($query)->fetch_assoc();
        $oldPosition = $oldPositionResult['position'];
        $preorpost = $oldPositionResult['preorpost'];

        $query = "SELECT max(position) as position FROM nat_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost'";
        $data = $connection->query($query)->fetch_assoc();
        $newPosition = $data['position']+1; //The last rule in the policy

        foreach ($rulesUnder as $ruleUnder){
            $query = "SELECT position FROM nat_rules WHERE name_ext='$ruleUnder' AND source='$source' AND vsys='$vsys' AND preorpost='$preorpost'";
            $results = $connection->query($query);
            if($results->num_rows==1){
                $data = $results->fetch_assoc();
                $newPosition = $data['position']-1;
                break;
            }
        }

        if($newPosition < $oldPosition){
            $query = "UPDATE nat_rules SET position=(position+1) WHERE position>=$newPosition AND position<$oldPosition AND source='$source' and vsys='$vsys'";
            $connection->query($query);
            $query = "UPDATE nat_rules SET position=$newPosition WHERE name_ext='$ruleName' AND source='$source' and vsys='$vsys'";
            $connection->query($query);
        }
        elseif($newPosition > $oldPosition){
            $query = "UPDATE nat_rules SET position=(position-1) WHERE position>$oldPosition AND position<=$newPosition AND source='$source' and vsys='$vsys'";
            $connection->query($query);
            $query = "UPDATE nat_rules SET position=$newPosition WHERE name_ext='$ruleName' AND source='$source' and vsys='$vsys'";
            $connection->query($query);
        }
    }

    public function delete(mysqli $connection, STRING $name_ext)
    {
        $query = "SELECT id FROM ".$this->table." WHERE source='$this->source' AND vsys='$this->vsys' AND name_ext='$name_ext'";
        $data = $connection->query($query)->fetch_assoc();
        $id = $data['id'];

        foreach ($this->dependent_tables as $table){
            $query = "DELETE FROM ".$table." WHERE rule_lid='$id'";
            $connection->query($query);
        }

        $query = "DELETE FROM ".$this->table." WHERE id='$id'";
        $connection->query($query);

    }

    public function checkUsed(mysqli $connection, STRING $name_ext=null){
        //TODO
        return false;
    }

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null){
        //TODO
        return null;
    }
}