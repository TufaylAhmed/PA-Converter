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

class ApplicationGroupPANObject extends PANObject
{
    protected $id ;
    protected $name_ext ;
    protected $name ;
    protected $used ;
    protected $devicegroup ;
    protected $vsys ;
    protected $source ;
    protected $invalid ;
    protected $modified ;
    protected $dummy;
    protected $members = array();

    protected $version;
    protected $signature = array();

    protected $table = 'applications_groups_id';
    protected $dependent_tables = ['applications_groups'];

    protected $fillable = [
        'id','name_ext','name','used','devicegroup','vsys','source','invalid','modified','dummy', 'members'
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

    public function setVersion(STRING $version){
        $this->version = $version;
    }

    public function prepareXML(){
        //TODO
        $xml = new SimpleXMLElement('<application-group></application-group>');
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

            //Check the version of this PANOS device
            $full_version = $this->version;

            $version = 7; //Default value for version
            if (preg_match('/^6\.0/', $full_version)) {
                $version = 6;
            } elseif (preg_match('/^6\.1/', $full_version)) {
                $version = 6.1;
            } elseif (preg_match('/^5\./', $full_version)) {
                $version = 5;
            } elseif (preg_match('/^7\.0/', $full_version)) {
                $version = 7;
            } elseif (preg_match('/^7\.1/', $full_version)) {
                $version = 7.1;
            }

            if ($version >= 7) {
                foreach ($element as $field => $value) {
                    if ($field == "members") {
                        foreach ($value as $kkey => $memberss) {
                            $this->members[] = $memberss;
                        }
                    }
                }
            }
            else {
                foreach ($element->member as $memberss) {
                    $this->members[] = $memberss;
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
            global $projectdb;
            $query = "INSERT INTO applications_groups_id (name_ext, name, source, vsys, devicegroup) VALUES ('$name_ext','$name_ext', '$this->source', '$this->vsys', '$this->devicegroup')";
            $connection->query($query);
            $lid = $connection->insert_id;

            $sql = array();
            foreach ($this->members as $member) {
                $projectdb = $connection;
                $vsyses = getVsyses($connection, $this->vsys, $this->source);
                if (!$memberObject = getAppId($connection, $this->source, $vsyses, $member)) {
                    $member = initAddressMember();
                    $member['name_ext'] = $member;
                    $member['name'] = normalizeNames($member);
                    $member['checkit'] = 1;
                    $memberObject = createAppId($connection, $this->source, $this->dependent_tables, $this->vsys, $member);
                }
                $sql[] = "('$this->source', '', '$member', '$memberObject->name', '$memberObject->location', '$lid','$this->vsys', '$this->devicegroup')";
            }

            if (count($sql) > 0) {
                $query = "INSERT INTO applications_groups (source, xml, member, member_lid, table_name, lid, vsys, devicegroup) VALUES " . implode(',', $sql);
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
            $query = "SELECT id FROM " . $this->table . " WHERE source='$this->source' AND vsys='$this->vsys' AND name_ext='$name_ext'";
            $data = $connection->query($query)->fetch_assoc();
            $id = $data['id'];

            $updates = array();
            foreach ($fields as $field) {
                if (!is_array($this->{$field})) {
                    $updates[] = " $field = '" . $this->{$field} . "' ";
                }
            }

            if (count($updates) > 0) {
                $updatesString = implode(',', $updates);
                $query = "UPDATE " . $this->table . " SET $updatesString 
                  WHERE id='$id'";
                $connection->query($query);
            }

            if (in_array('members', $fields)) {
                $query = "DELETE from applications_groups WHERE lid='$id';";
                $connection->query($query);
                $sql = array();
                foreach ($this->members as $member) {
                    $projectdb = $connection;
                    if (!$memberObject = getAppId($connection, $this->source, $vsyses, $member)) {
                        $member = initApp();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $memberObject = createAppId($connection, $this->source, $this->dependent_tables, $this->vsys, $member);
                    }
                    $sql[] = "('$this->source', '', '$member', '$memberObject->name', '$memberObject->location', '$id','$this->vsys', '$this->devicegroup')";
                }

                if (count($sql) > 0) {
                    $query = "INSERT INTO applications_groups (source, xml, member, member_lid, table_name, lid, vsys, devicegroup) VALUES " . implode(',', $sql);
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

    public function compare(PANObject $objectB){
        return parent::compare($objectB);
    }

    public function checkUsed(mysqli $connection, STRING $name_ext=null){
        //TODO
        return false;
    }

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses = null)
    {
        return parent::exists($connection, $name_ext, $vsyses);
    }

    public function delete(mysqli $connection, STRING $name_ext)
    {
        return parent::delete($connection, $name_ext);
    }
}