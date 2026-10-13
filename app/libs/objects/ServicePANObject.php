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

class ServicePANObject extends PANObject{
    protected $id;
    protected $name_ext;
    protected $name;
    protected $checkit;
    protected $used;
    protected $vsys;
    protected $devicegroup;
    protected $type;
    protected $description;
    protected $sport;
    protected $dport;
    protected $protocol;
    protected $icmp;
    protected $source;
    protected $tag;
    protected $invalid;
    protected $modified;
    protected $vtype;
    protected $dummy;

    protected $table = 'services';
    protected $dependent_tables = [''];
    protected $fillable = [
        'id','name_ext','name','checkit','used','vsys','devicegroup','type','description','sport','dport','protocol','icmp','source','tag','invalid','modified','vtype','dummy',
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
        $xml = new SimpleXMLElement('<service></service>');
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
            $this->dport = "";
            $this->protocol = "";
            $this->sport = "";
            $this->tag = "";

            $tag = array();

            //Getting parameters of this new service. All elements in this Service should be prior defined (such as tags)
            foreach ($element as $field => $value) {
                if ($field == "protocol") {
                    foreach ($value as $proto => $dataplus) {
                        $this->protocol = $proto;
                        foreach ($dataplus as $whereport => $port) {
                            if ($whereport == "port") {
                                $this->dport = $port;
                            } elseif ($whereport == "source-port") {
                                $this->sport = $port;
                            }
                        }
                    }
                }
                elseif ($field == "description") {
                    $this->description = addslashes($value);
                } elseif ($field == "tag") {
                    foreach ($value as $kkey => $vvalue) {
                        $tag[] = $vvalue;
                    }
                    if (count($tag) > 0) {
                        sort($tag, SORT_STRING);
                        $this->tag = implode(',', $tag);
                        $tag = array();
                    }
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
            $query = "INSERT INTO services (name_ext,name,protocol,dport,description,devicegroup,source,vsys,sport,tag) 
                               VALUES  ('$name_ext','$name_ext','$this->protocol','$this->dport','$this->description','$this->devicegroup','$this->source','$this->vsys','$this->sport','$this->tag')";
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
            return parent::update($connection, $name_ext, $fields);
        }
    }

    public function compare(PANObject $objectB){
        return parent::compare($objectB);
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
            add_log2('conflict', 'RealTime Updates from device Config Changes', "Service \"$name_ext\"", $this->source, "Object not deleted because is being used", $this->table, $this->id, $this->table);
        }
        return $msg;
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

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null)
    {
        return parent::exists($connection, $name_ext, $vsyses);
    }
}
