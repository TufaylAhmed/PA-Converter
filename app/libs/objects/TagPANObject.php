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

class TagPANObject extends PANObject{
    protected $id;
    protected $name_ext;
    protected $name;
    protected $color;
    protected $comments;
    protected $source;
    protected $vsys;
    protected $devicegroup;
    protected $modified;
    protected $vtype;
    protected $dummy;

    protected $table = 'tag';
    protected $dependent_tables = [''];
    protected $fillable = [
        'id','name_ext','name','color','comments','source','vsys','devicegroup','modified','vtype','dummy'
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
        $xml = new SimpleXMLElement('<tag></tag>');
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
        }
        else {
            $this->dummy = '0';
            $this->modified = '0';

            $this->comments = "";
            $this->color = "None";
            foreach ($element as $mykey => $myvalue) {
                if ($mykey == "comments") {
                    $this->comments = addslashes($myvalue);
                }
                elseif ($mykey == "color") {
                    $this->color = $myvalue;
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
            $query = "INSERT INTO tag (source, name, color, comments, devicegroup, vsys)  
                 VALUES          ('$this->source','$name_ext','$this->color','$this->comments','$this->devicegroup', '$this->vsys')";
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

    public function checkUsed(mysqli $connection, STRING $name_ext=null){
        //TODO
        return false;
    }

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null){
        //TODO
        return null;
    }

}