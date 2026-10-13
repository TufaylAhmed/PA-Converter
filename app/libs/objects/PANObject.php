<?php

/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

require_once INC_ROOT.'/libs/common/MemberObject.php';
use PaloaltoNetworks\Policy\Objects\MemberObject;

abstract class PANObject
{
    protected $id;
    protected $table;
    protected $source; //Protected, as the extended objects should be able to edit its content
    protected $vsys;

    protected $object = '';

    /**
     * @var mysqli
     */
    protected $connection;

    protected $version = 7; //Default version that objects are created as. Can be modified via setVersion(INT $version)
    protected $ignoreList = ['id','modified','used','version']; //Default list of ignorable fields in conflict checking

    abstract function load(STRING $name_ext, SimpleXMLElement $element=null, STRING $source, STRING $vsys, STRING $devicegroup);
    abstract function loadFromProject(mysqli $connection, STRING $name_ext);

    abstract function insert(mysqli $connection, STRING $name_ext);

    abstract function checkUsed(mysqli $connection, STRING $name_ext=null);

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null){
        $member = null;
        if(is_null($vsyses)){
            $query = "SELECT * FROM " . $this->table . " WHERE source='$this->source' AND vsys='$this->vsys' AND BINARY name_ext='$name_ext'";
            $result = $connection->query($query);
            if ($result->num_rows > 0) {
                $data = $result->fetch_assoc();
                $id = $data['id'];
                $location = $this->table;
                $member = new MemberObject($id, $location);
            }
        }
        else {
            foreach ($vsyses as $vsys) {
                $query = "SELECT * FROM " . $this->table . " WHERE source='$this->source' AND vsys='$vsys' AND BINARY name_ext='$name_ext'";
                $result = $connection->query($query);
                if ($result->num_rows > 0) {
                    $data = $result->fetch_assoc();
                    $id = $data['id'];
                    $location = $this->table;
                    $member = new MemberObject($id, $location);
                    break;
                }
            }
        }

        return $member;
    }

    public function getID(){
        return $this->id;
    }

    public function getTable(){
        return $this->table;
    }
    public function getSource(){
        return $this->source;
    }
    public function getVsys(){
        return $this->vsys;
    }

    public function setVersion(STRING $version){
        if (preg_match("/^6\.0/", $version)) {
            $version = 6;
        }
        elseif (preg_match("/^6\.1/", $version)) {
            $version = 6.1;
        }
        elseif (preg_match("/^5\./", $version)) {
            $version = 5;
        }
        elseif (preg_match("/^7\.0/", $version)) {
            $version = 7;
        }
        elseif (preg_match("/^7\.1/", $version)) {
            $version = 7.1;
        }
        elseif (preg_match("/^8\.0/", $version)) {
            $version = 8;
        }
        $this->version = $version;
    }

    public function reportConflicts(\mysqli $connection, ARRAY $difOnFirewall=NULL, ARRAY $diffOnLocal=NULL){
        global $projectdb;
        $projectdb= $connection;
        $diff = array_intersect($difOnFirewall, $diffOnLocal);
        foreach($this->ignoreList as $ignoreField) {
            if (($key = array_search($ignoreField, $diff)) !== false) {
                unset($diff[$key]);
            }
        }

        if(count($diff)>0){
            add_log2('conflict', 'RealTime Updates from device Config Changes', $this->toXML(), $this->source, "Conflict on fields: ".implode(',', $diff), $this->table, $this->id, $this->table);
        }
    }

    /***
     * @return SimpleXMLElement
     */
    abstract protected function prepareXML();

    public function toJSON(){
        $element = $this->prepareXML();
        return json_encode($element);
    }
    public function toXML(String $format=null){
        $element = $this->prepareXML();
        if(!isset($format)) {
            $dom = dom_import_simplexml($element);
            return $dom->ownerDocument->saveXML($dom->ownerDocument->documentElement);
        }
        elseif($format == 'complete'){
            return $element->asXML();
        }
        else{
            $dom = dom_import_simplexml($element);
            return $dom->ownerDocument->saveXML($dom->ownerDocument->documentElement);
        }
    }

    public function update(mysqli $connection, STRING $name_ext, ARRAY $fields, INT &$id=null){
        if(!isset($id)) {
            $query = "SELECT id FROM " . $this->table . " WHERE source='$this->source' AND vsys='$this->vsys' AND BINARY name_ext='$name_ext'";
            $data = $connection->query($query)->fetch_assoc();
            $id = $data['id'];
        }

        $updates = array();
        foreach ($fields as $field){
            if(!is_array($this->{$field})) {
                $updates[] = " $field = '" . $this->{$field} . "' ";
            }
        }

        $updatesString = implode(',', $updates);
        $query = "UPDATE ".$this->table." SET $updatesString 
                  WHERE id='$id'";
//        echo "$query\n";
        $connection->query($query);

        $msg = [
            'code' => true,
            'msg' => "Updated correctly"
        ];
        return $msg;
    }

    //Methods global to all Extended objects
    public function delete(mysqli $connection, STRING $name_ext)
    {
        $usage = $this->checkUsed($connection, $name_ext);
        if(is_null($usage)) {
            $query = "SELECT id FROM " . $this->table . " WHERE source='$this->source' AND vsys='$this->vsys' AND BINARY name_ext='$name_ext'";
            $data = $connection->query($query)->fetch_assoc();
            $id = $data['id'];

            foreach ($this->dependent_tables as $table) {
                $query = "DELETE FROM " . $table . " WHERE lid='$id'";
                $connection->query($query);
            }

            $query = "DELETE FROM " . $this->table . " WHERE id='$id'";
            $connection->query($query);
            $msg = [
                'code' => true,
                'msg'  => "$this->object \"$name_ext\" deleted"
            ];
            return $msg;
        }
        else{
            $msg = [
                'code' => false,
                'msg'  => $usage
            ];
            global $projectdb;
            $projectdb= $connection;
            add_log2('conflict', 'RealTime Updates from device Config Changes', $this->object." \"$name_ext\"", $this->source, "Object not deleted because is being used", $this->table, $this->id, $this->table);
        }
        return $msg;


    }

    public function rename(mysqli $connection, STRING $oldName, STRING $newName){
        $newName = trim($newName);
        if($this->checkUsed($connection,$newName)){
            $this->rename($connection, $newName, $newName."_1");
        }
        $query = "UPDATE $this->table
                      SET name_ext='$newName', name='$newName'
                      WHERE name_ext='$oldName' AND source='$this->source' AND vsys='$this->vsys'";
        $connection->query($query);
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
                    $diff2 = array_diff($objectB->{$field}, $this->{$field});
                    if (count($diff) != 0 OR count($diff2)!=0) {
                        $differences[] = $field;
                    }
                }
                elseif(is_string($this->{$field}) OR is_int($this->{$field})) {
                    if ($this->{$field} != $objectB->{$field}) {
                        $differences[] = $field;
                    }
                }
                elseif(get_class($this->{$field}) == 'SimpleXMLElement'){
                    if($this->{$field}->asXML() != $objectB->{$field}->asXML()){
                        $differences[] = $field;
                    }
                }

            }
            return $differences;
        }
    }

}