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

class ZonePANObject extends PANObject{
    protected $id;
    protected $source;
    protected $template;
    protected $vsys;
    protected $name_ext;
    protected $name;
    protected $type;
    protected $interfaces;
    protected $zone_protection_profile;
    protected $log_setting_id;
    protected $include_list;
    protected $exclude_list;
    protected $enable_user_identification;
    protected $log_setting_table_name;
    protected $modified;
    protected $invalid;
    protected $dummy;
    protected $templates_mapping_id;
    protected $enable_packet_buffer_protection;

    protected $table = 'zones';
    protected $dependent_tables = [''];
    protected $fillable = [
        'id','source','template','vsys','name_ext','name','type','interfaces','zone_protection_profile','log_setting_id','include_list','exclude_list','enable_user_identification','log_setting_table_name','modified','invalid','dummy', 'interfaces','enable_packet_buffer_protection'
    ];

    public function setConnection(mysqli $connection){
        $this->connection = $connection;
    }

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
        $xml = new SimpleXMLElement('<zone></zone>');
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
            $this->dummy='1';
            $this->modified='0';
            $this->invalid='1';
        }
        else {
            $this->dummy = '0';
            $this->modified = '0';
            $this->invalid='0';

            $this->interfaces = '';

            $this->getTemplateID($this->connection);

            $this->enable_user_identification = isset($element->{'enable-user-identification'}) ? $element->{'enable-user-identification'} : '';
            $this->zone_protection_profile = isset($element->network->{'zone-protection-profile'}) ? $element->network->{'zone-protection-profile'} : '';
            $this->enable_packet_buffer_protection= (isset($element->network->{'enable-packet-buffer-protection'}))? $element->network->{'enable-packet-buffer-protection'}: '';

            if (isset($element->{'user-acl'}->{'include-list'})) {
                $mem = array();
                foreach ($element->{'user-acl'}->{'include-list'}->member as $key => $vvalue) {
                    $mem[] = $vvalue;
                }
                $this->include_list = implode(",", $mem);
            }
            else {
                $this->include_list = "";
            }

            if (isset($element->{'user-acl'}->{'exclude-list'})) {
                $mem = array();
                foreach ($element->{'user-acl'}->{'exclude-list'}->member as $key => $vvalue) {
                    $mem[] = $vvalue;
                }
                $this->exclude_list = implode(",", $mem);
            } else {
                $this->exclude_list = "";
            }

            if (isset($element->network->{'log-setting'})) {
                $log_setting = $element->network->{'log-setting'};
                $getLog = $this->connection->query("SELECT id FROM log_settings WHERE source='$source' AND vsys='$vsys' AND name_ext='$log_setting' AND template='$this->templates_mapping_id';");
                if ($getLog->num_rows == 1) {
                    $getData = $getLog->fetch_assoc();
                    $this->log_setting_table_name = "log_settings";
                    $this->log_setting_id = $getData['id'];
                }
                else {
                    $getLog = $this->connection->query("SELECT id FROM log_settings WHERE source='$source' AND name_ext='$log_setting' AND template='$this->templates_mapping_id' AND vsys = 'shared';");
                    if ($getLog->num_rows == 1) {
                        $getData = $getLog->fetch_assoc();
                        //$log_setting_table_name = "shared_log_settings";
                        $this->log_setting_table_name = "log_settings";
                        $this->log_setting_id = $getData['id'];
                    } else {
                        #PRINT "NO LOG SETTINGS FOUND";
                    }
                }
            }
            else {
                $this->log_setting_table_name = "";
                $this->log_setting_id = "";
            }

            if (isset($element->network->{'virtual-wire'})) {
                $this->type = "virtual-wire";
                foreach ($element->network->{'virtual-wire'}->member as $key => $vvalue) {
                    $this->interfaces[] = $vvalue;
                }
            }
            elseif (isset($element->network->layer3)) {
                $this->type = "layer3";
                foreach ($element->network->layer3->member as $key => $vvalue) {
                    $this->interfaces[] = $vvalue;
                }
            }
            elseif (isset($element->network->layer2)) {
                $this->type = "layer2";
                foreach ($element->network->layer2->member as $key => $vvalue) {
                    $this->interfaces[] = $vvalue;
                }
            }
            elseif (isset($element->network->tap)) {
                $this->type = "tap";
                foreach ($element->network->tap->member as $key => $vvalue) {
                    $this->interfaces[] = $vvalue;
                }
            }
            elseif (isset($element->network->external)) {
                $this->type = "external";
                foreach ($element->network->external->member as $key => $vvalue) {
                    $this->interfaces[] = $vvalue;
                }
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
            foreach ($this->interfaces as $m => $v) {
                $query = "UPDATE interfaces SET zone='$this->name' WHERE unitname='$v' AND source='$this->source' AND template='$this->templates_mapping_id';";
                $connection->query($query);
            }

            $query = "INSERT INTO zones (template,source,name_ext,name,interfaces,type,vsys,zone_protection_profile,log_setting_table_name,log_setting_id,include_list,exclude_list,enable_user_identification) 
             VALUES ('$this->templates_mapping_id','$this->source','$name_ext','$name_ext','" . implode(',', $this->interfaces) . "','$this->type','$this->vsys','$this->zone_protection_profile','$this->log_setting_table_name','$this->log_setting_id','$this->include_list','$this->exclude_list','$this->enable_user_identification')";
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
        else {
            parent::update($connection, $name_ext, $fields);

            if (in_array('interfaces', $fields)) {
                foreach ($this->interfaces as $m => $v) {
                    $query = "UPDATE interfaces SET zone='$this->name' WHERE unitname='$v' AND source='$this->source' AND template='$this->templates_mapping_id';";
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

    public function delete(mysqli $connection, STRING $name_ext){
        $usage = $this->checkUsed($connection, $name_ext);
        if(is_null($usage)) {
            $msg = parent::delete($connection, $name_ext);

            $this->getTemplateID($connection);
            foreach ($this->interfaces as $m => $v) {
                $query = "UPDATE interfaces SET zone='' WHERE zone='$this->name' AND source='$this->source' AND template='$this->templates_mapping_id';";
                $connection->query($query);
            }
        }
        else{
            $msg = ['code' => false, 'msg'  => $usage];
        }
        return $msg;
    }

    public function rename(mysqli $connection, STRING $oldName, STRING $newName)
    {
        parent::rename($connection, $oldName, $newName);

        $this->getTemplateID($connection);
        foreach ($this->interfaces as $m => $v) {
            $query = "UPDATE interfaces SET zone='$newName' WHERE zone='$oldName' AND source='$this->source' AND template='$this->templates_mapping_id';";
            $connection->query($query);
        }
    }

    public function compare(PANObject $objectB){
        return parent::compare($objectB);
    }

    private function getTemplateID(mysqli $connection){
        $query = "SELECT id from templates_mapping WHERE source='$this->source' GROUP BY name";
        $result = $connection->query($query);
        if ($result->num_rows == 1) {
            $data = $result->fetch_assoc();
            $this->templates_mapping_id = $data['id'];
        }
        else {
            //TODO: What is it expected to be here?
            $this->templates_mapping_id = 0;
        }
    }

    public function checkUsed(mysqli $connection, STRING $name_ext=null){
        if(!is_null($name_ext)) {
            $zoneName = $name_ext;
        }
        else{
            $zoneName = $this->name;
        }
        $source = $this->source;
        $vsys = $this->vsys;
        $template = $this->templates_mapping_id;

        $response = null;

        $query = "SELECT id,'interfaces'            as location FROM interfaces           WHERE source='$source' AND template='$template' AND zone='$zoneName' UNION ".
                 "SELECT id,'security_rules_from'   as location FROM security_rules_from  WHERE name='$zoneName' UNION ".
                 "SELECT id,'security_rules_to'     as location FROM security_rules_to    WHERE name='$zoneName' UNION ".
                 "SELECT id,'nat_rules_from'        as location FROM nat_rules_from       WHERE name='$zoneName' UNION ".
                 "SELECT id,'nat_rules'             as location FROM nat_rules            WHERE source='$source' AND vsys='$vsys' AND op_zone_to='$zoneName' UNION ".
                 "SELECT id,'appoverride_rules_from' as location FROM appoverride_rules_from WHERE name='$zoneName' UNION ".
                 "SELECT id,'appoverride_rules_to'   as location FROM appoverride_rules_to WHERE name='$zoneName'";
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

        return $response;
    }

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null){
        return parent::exists($connection, $name_ext, $vsyses);
    }

}