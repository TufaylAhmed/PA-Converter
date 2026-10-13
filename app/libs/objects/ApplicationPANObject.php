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

class ApplicationPANObject extends PANObject{
    protected $id;
    protected $source;
    protected $devicegroup;
    protected $vsys;
    protected $name_ext;
    protected $name;
    protected $description;
    protected $category;
    protected $subcategory;
    protected $parent_app;
    protected $risk;
    protected $technology;
    protected $evasive_behavior;
    protected $consume_big_bandwidth;
    protected $used_by_malware;
    protected $able_to_transfer_file;
    protected $has_known_vulnerability;
    protected $tunnel_other_application;
    protected $tunnel_applications;
    protected $prone_to_misuse;
    protected $pervasive_use;
    protected $file_type_ident;
    protected $virus_ident;
    protected $data_ident;
    protected $default_type;
    protected $value;
    protected $type;
    protected $code;
    protected $timeout;
    protected $tcp_timeout;
    protected $udp_timeout;
    protected $tcp_half_closed_timeout;
    protected $tcp_time_wait_timeout;
    protected $spyware_ident;
    protected $modified;
    protected $vtype;
    protected $dummy;

    protected $version;
    protected $signature = array();

    protected $table = 'applications';
    protected $dependent_tables = ['applications_signatures'];

    protected $fillable = [
        'id', 'source', 'devicegroup', 'vsys', 'name_ext', 'name', 'description', 'category', 'subcategory', 'parent_app', 'risk', 'technology', 'evasive_behavior', 'consume_big_bandwidth', 'used_by_malware', 'able_to_transfer_file', 'has_known_vulnerability', 'tunnel_other_application', 'tunnel_applications', 'prone_to_misuse', 'pervasive_use', 'file_type_ident', 'virus_ident', 'data_ident', 'default_type', 'value', 'type', 'code', 'timeout', 'tcp_timeout', 'udp_timeout', 'tcp_half_closed_timeout', 'tcp_time_wait_timeout', 'spyware_ident', 'modified', 'vtype', 'dummy', 'signature'
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
        $xml = new SimpleXMLElement('<application></application>');
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

            $this->icmp_type = "";
            $this->icmp_code = "";
            $this->default_type = "";
//        $GroupName = $element->attributes()->name;
            $this->subcategory = $element->subcategory;
            $this->category = $element->category;
            $this->technology = $element->technology;
            $this->risk = $element->risk;
            $this->evasive_behavior = $element->{'evasive-behavior'};
            $this->consume_big_bandwidth = $element->{'consume-big-bandwidth'};
            $this->used_by_malware = $element->{'used-by-malware'};
            $this->able_to_transfer_file = $element->{'able-to-transfer-file'};
            $this->has_known_vulnerability = $element->{'has-known-vulnerability'};
            $this->tunnel_other_application = $element->{'tunnel-other-application'};
            $this->tunnel_applications = $element->{'tunnel-applications'};
            $this->prone_to_misuse = $element->{'prone-to-misuse'};
            $this->pervasive_use = $element->{'pervasive-use'};
            $this->file_type_ident = $element->{'file-type-ident'};
            $this->virus_ident = $element->{'virus-ident'};
            $this->spyware_ident = $element->{'spyware-ident'};
            $this->data_ident = $element->{'data-ident'};
            $this->parent_app = $element->{'parent-app'};
            $this->timeout = $element->timeout;
            $this->tcp_timeout = $element->{'tcp-timeout'};
            $this->udp_timeout = $element->{'udp-timeout'};
            if ($version >= 6) {
                $this->tcp_half_closed_timeout = $element->{'tcp-half-closed-timeout'};
                $this->tcp_time_wait_timeout = $element->{'tcp-time-wait-timeout'};
            }
            else {
                $this->tcp_half_closed_timeout = "";
                $this->tcp_time_wait_timeout = "";
            }

            if (isset($element->default->port)) {
                $this->default_type = "port";
                $default_value_array = array();
                foreach ($element->default->port->member as $vvvalue) {
                    $default_value_array[] = $vvvalue;
                }
                $this->value = implode(",", $default_value_array);
            }
            elseif (isset($element->default->{'ident-by-ip-protocol'})) {
                $this->default_type = "ident-by-ip-protocol";
                $this->value = $element->default->{'ident-by-ip-protocol'};
            }
            elseif (isset($element->default->{'ident-by-icmp-type'})) {
                $this->default_type = "ident-by-icmp-type";
                if ($version < 7) {
                    $this->value = $element->default->{'ident-by-icmp-type'};
                    $this->type = $this->value;
                }
                else {
                    $this->type = $element->default->{'ident-by-icmp-type'}->type;
                    $this->code = $element->default->{'ident-by-icmp-type'}->code;
                }
            }
            elseif (isset($element->default->{'ident-by-icmp6-type'})) {

                $this->default_type = "ident-by-icmp6-type";
                $this->type = $element->default->{'ident-by-icmp6-type'}->type;
                $this->code = $element->default->{'ident-by-icmp6-type'}->code;
                $this->value = "";
            }
            elseif (!isset($element->default)) {
                $this->default_type = "None";
                $this->value = "";
            }

            if (isset($element->description)) {
                $this->description = addslashes($element->description);
            } else {
                $this->description = "";
            }

            if (isset($element->signature)) {
                foreach ($element->signature->entry as $signature) {
                    $this->signature[] = addslashes($signature->asXML());
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
            $query = "INSERT INTO applications (default_type,value,type,code,parent_app,source,name_ext,name, vsys,devicegroup,subcategory,category,technology,risk,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,spyware_ident,data_ident,timeout,tcp_timeout,udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout,description) 
             VALUES ('$this->default_type','$this->value','$this->type','$this->code','$this->parent_app','$this->source','$this->name_ext','$this->name','$this->vsys','$this->devicegroup','$this->subcategory','$this->category','$this->technology','$this->risk','$this->evasive_behavior','$this->consume_big_bandwidth','$this->used_by_malware','$this->able_to_transfer_file','$this->has_known_vulnerability','$this->tunnel_other_application','$this->tunnel_applications','$this->prone_to_misuse','$this->pervasive_use','$this->file_type_ident','$this->virus_ident','$this->spyware_ident','$this->data_ident','$this->timeout','$this->tcp_timeout','$this->udp_timeout', '$this->tcp_half_closed_timeout', '$this->tcp_time_wait_timeout','$this->description');";
            $connection->query($query);
            $appid = $connection->insert_id;

            $signatures = array();
            foreach ($this->signature as $signature) {
                $signatures[] = "('$appid','applications','$signature','$this->vsys','$this->devicegroup','$this->source')";
            }
            $query = "INSERT INTO applications_signatures (member_lid,table_name,signature,vsys,devicegroup,source) VALUES " . implode(',', $signatures);
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
            $query = "SELECT id FROM " . $this->table . " WHERE source='$this->source' AND vsys='$this->vsys' AND name_ext='$name_ext'";
            $data = $connection->query($query)->fetch_assoc();
            $id = $data['id'];

            $updates = array();
            foreach ($fields as $field) {
                if (!is_array($this->{$field})) {
                    $updates[] = " $field = '" . $this->{$field} . "' ";
                }
            }

            $updatesString = implode(',', $updates);
            $query = "UPDATE " . $this->table . " SET $updatesString 
                  WHERE id='$id'";
            $connection->query($query);

            if (in_array('signature', $fields)) {
                $signatures = array();
                $query = "DELETE from applications_signatures WHERE member_lid='$id' AND table_name='applications'";
                $connection->query($query);
                foreach ($this->signature as $signature) {
                    $signatures[] = "('$id','applications','$signature','$this->vsys','$this->devicegroup','$this->source')";
                }
                $query = "INSERT INTO applications_signatures (member_lid,table_name,signature,vsys,devicegroup,source) VALUES " . implode(',', $signatures);
                $connection->query($query);
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

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses=null){
        //TODO
        return null;
    }
}