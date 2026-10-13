<?php

/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserverd.
 *
 * Development Team: Business Development
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com).
 * Date: 09/01/2017 - 08:46
 */

/***
 * This Class allows applying changes on the Database for Config Changes on a PANOS device
 *  Given a Config syslog entry, and the "commit" entry, it identifies the different nodes that have been reported as changed
 *  and looks for the differences between the XPath Elements comparing the last two ConfigBackup.xml
 *
 */

namespace realTimeConfigChanges;

use mysqli;
use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

require_once INC_ROOT.'/libs/objects/TagPANObject.php';

require_once INC_ROOT.'/libs/objects/AddressPANObject.php';
require_once INC_ROOT.'/libs/objects/AddressGroupPANObject.php';
require_once INC_ROOT.'/libs/objects/RegionPANObject.php';
require_once INC_ROOT.'/libs/objects/ExternalListPANObject.php';
require_once INC_ROOT.'/libs/objects/ServicePANObject.php';
require_once INC_ROOT.'/libs/objects/ServiceGroupPANObject.php';
require_once INC_ROOT.'/libs/objects/ApplicationPANObject.php';
require_once INC_ROOT.'/libs/objects/ApplicationGroupPANObject.php';

require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';
require_once INC_ROOT.'/libs/objects/NatRulePANObject.php';

require_once INC_ROOT.'/libs/objects/ZonePANObject.php';


class ProjectConfigChanger
{
    private $project = array();
    private $command;
    private $originalTarget;
    private $target;
    private $targetArray = array();
    private $before;
//    private $beforeArray = array();
    private $after;
//    private $afterArray = array();
    private $seqnu;
    private $deviceSerial;
    /**
     * @var \SimpleXMLElement
     */
    private $configXml;
    /**
     * @var \SimpleXMLElement
     */
    private $configXmlOld;
    /**
     * @var mysqli
     */
    private $connection;

    private $changeID;

    public function __construct(mysqli $RTUconnection, int $id=null){
        $this->changeID = $id;
        $this->connection = $RTUconnection;
    }

    public function setDeviceSerial(STRING $serial){
        global $app;
        $encryptActivated = true;
        $this->deviceSerial = $serial;

        if($encryptActivated){
            $deviceObj = $app->device->where("serial",$serial)->first();
            $keyObj = $app->accessKey->where("type","device")->where("lid",$deviceObj->id)->first();
            $encrypter = new OpenSSLTools($keyObj->key, $keyObj->iv);

            //Open the file resource
            $config_path     = USERSPACE_PATH.'/devices/'.$serial.'/RTUConfigBackup.xml.dat';
            $contentsRTU = $encrypter->decryptFromFile($config_path);
            $this->configXml    = simplexml_load_string($contentsRTU);


            $config_path_old = USERSPACE_PATH.'/devices/'.$serial.'/RTUConfigBackup.xml.old.dat';
            if (!file_exists($config_path_old)) { //The first time, there won't be a RTUConfigBackup.xml.old, then, get
                // the prior ConfigBackup.xml, as it is the prior configuration file
                $config_path_old = USERSPACE_PATH.'/devices/'.$serial.'/ConfigBackup.xml.dat';
            }
            $contents = $encrypter->decryptFromFile($config_path_old);
            $this->configXmlOld = simplexml_load_string($contents);
        }
        else{
            //Open the file resource
            $config_path     = USERSPACE_PATH.'/devices/'.$serial.'/RTUConfigBackup.xml';
            $this->configXml    = simplexml_load_file($config_path);

            $config_path_old = USERSPACE_PATH.'/devices/'.$serial.'/RTUConfigBackup.xml.old';
            if (!file_exists($config_path_old)) { //The first time, there won't be a RTUConfigBackup.xml.old, then, get
                // the prior ConfigBackup.xml, as it is the prior configuration file
                $config_path_old = USERSPACE_PATH.'/devices/'.$serial.'/ConfigBackup.xml';
            }
            $this->configXmlOld = simplexml_load_file($config_path_old);
        }


    }

    public function setFwSerial($serial){
        $this->deviceSerial =$serial;

    }

    public function setCommand($command){
        $this->command = $command;
    }

    public function setOriginalTarget($target){
        $this->originalTarget = $target;
    }

    public function setTarget($target){
        $this->target = $target;
        $this->setOriginalTarget($target);
    }

    public function setBefore($before){
        $this->before = $before;
    }

    public function setAfter($after){
        $this->after = $after;
    }

    public function setSeqnu($seqnu){
        $this->seqnu = $seqnu;
    }

    public function addProject(STRING $project, STRING $source){
        $this->project[$project] = $source;
    }

    public function addProjects(ARRAY $projects){
        foreach ($projects as $project=>$baseConfig){
            $this->project[$project] = $baseConfig;
        }
    }

    public function applyChange(){
        $errors = array(); //Variable to store errors seen during the execution

        $targetArray = explode('  ',$this->target);
        $this->target = str_replace("  ","=",$this->target);

        foreach ($targetArray as &$item){
            $item = trim($item);
        }

        for($i=1;$i<count($targetArray)-1; $i++){
            $arr = explode(' ',$targetArray[$i]);
            $count = count($arr);
            if($count>1){
                $targetArray[$i-1].="=".$arr[0];
                $newValue = '';
                for($j=1; $j<$count; $j++){
                    $newValue .= " ".$arr[$j];
                }
                $targetArray[$i] = $newValue;
            }
        }

        $targetArray[$i-1] .= "=".$targetArray[$i];
        unset($targetArray[$i]);
        foreach ($targetArray as $item){
            $pair = explode('=',$item);
            if(count($pair)==2){
                $key = trim($pair[0]);
                $value = trim($pair[1]);
                $this->targetArray[$key]=$value;
            }
        }
//        print_r($this->targetArray);

        switch ($this->command){
            case "set": //Creating a new entry
                $this->buildSetQueries();
                break;
            case "edit":
                $this->buildEditQueries();
                break;
            case "rename":
                $this->buildRenameQueries();
                break;
            case "move":
                $this->buildMoveQueries();
                break;
            case "delete":
                $this->buildDeleteQueries();
                break;
            case "multi-clone":
                $this->buildMultiCloneQueries();
                break;
            default:
                $errors[] = "Command '$this->command' not supported yet";
                break;
        }

        //Preparing the output based on seen errors
        $msg = array();
        if(count($errors)) {
            $msg['code'] = false;
            $msg['msg'] = implode(',',$errors);
        }
        else{
            $msg['code'] = true;
            $msg['msg'] = "All fine";
        }
        return $msg;
    }

    /***
     * Parses the before/after string and returns it into an iterable structure (JSON)
     * @param STRING $type
     */
//    private function parseBeforeToJSON(STRING $type){
//        $this->beforeArray = $this->parseToJSON($this->before, $type);
//    }

//    private function parseAfterToJSON(STRING $type){
//        $this->afterArray = $this->parseToJSON($this->after, $type);
//    }

//    private function parseToJSON(STRING $value, STRING $type){
//        switch ($type){
//            case "complex":
//                $result = null;
//                break;
//
//            case "simple":
//            default:
//            $result = $this->parserValueStringSimple($value);
//            break;
//        }
//        return $result;
//    }

//    private function parserValueString(STRING $input_line){
//        $firstOpeningPos = strpos($input_line, "{");
//        $firstParenthPos = strpos($input_line, '"');
//        if($firstOpeningPos < $firstParenthPos){
//            // We have a keyed area
//            $secondOpeningPos = strpos($input_line, "{");
//            $firstClosingPos = strpos($input_line, "}");
//
//        }else{
//            //Search the next closing parenth
//            $nextParenthPost = strpos($input_line, '"', $firstParenthPos);
//        }
//        echo "$firstOpeningPos $firstParenthPos\n";
//    }

//    private function parserValuesStringComplex(STRING $input_line){
//
//    }

//    private function parserValueStringSimple(STRING $input_line){
////        echo "\n";
////        echo "$input_line\n";
//        $arr = array();
//
//        preg_match("/^(?<Key>[^\{]*) { (?<Value>.*) } (?<Extra>.*)/", $input_line, $output_array);
//        if(isset($output_array['Key'])) {
//            //More nested elements
//            $objectKey = $output_array['Key'];
//            $objectValue = $output_array['Value'];
//            $objectExtra = $output_array['Extra'];
//
////            echo "Key: $objectKey\n";
////            echo "Val: $objectValue\n";
////            echo "Ext: $objectExtra\n";
//
////            print_r($output_array);
//            $arr[$objectKey] = $this->parserValueStringSimple($objectValue);
//            $arr= array_merge($arr, $this->parserValueStringSimple($objectExtra));
//
//            return $arr;
//        }
//        else{
//            //Only attributes
//            $attribs = explode(";",$input_line);
//            foreach ($attribs as $attrib){
//                $attrib = trim($attrib);
////                echo "Attrib: '$attrib'\n";
//                $separatorPos = strpos($attrib," ");
////                echo "Pos: $separatorPos\n";
//                if($separatorPos){
//                    $key = substr($attrib,0,$separatorPos);
//                    $value = substr($attrib,$separatorPos,strlen($attrib));
//                    $arr[$key] = $value;
//                }
//            }
//            return $arr;
//        }
//    }

//    private function parseMembers(STRING $value){
//        preg_match_all("/\w+|\"[\w\s]*\"/", $value, $output_array);
//        return $output_array[0];
//    }

    /***
     * Given an Xpath, returns the element in it. Pretty simple, but it will simplify reading the code.
     * @param $xpath String
     * @return \SimpleXMLElement[]
     */
    private function getPathElement(STRING $xpath){
        return $this->configXml->xpath("$xpath");
    }

    private function getPathElementOld(STRING $xpath){
        return $this->configXmlOld->xpath("$xpath");
    }

    private function getLastName(STRING $deviceSerial, STRING $original, STRING $localTarget){
        $noMoreRenames=false;

        $objectName = $original;

        while(!$noMoreRenames){
            //Check if this element has been renamed and get it's new name
            $query = "SELECT id, before_value, after_value, target 
                      FROM firewallUpdates 
                      WHERE target='".$localTarget."' AND command='rename' AND deviceID='".$deviceSerial."' AND
                        seqnu > ".$this->seqnu." AND active=1 
                      LIMIT 1";
            $realDB = selectDatabase('RealTimeUpdates');
            $result = $realDB->query($query);
            if($result->num_rows == 1){
                $data = $result->fetch_assoc();
                $newName = trim($data['after_value']);
                $oldName = trim($data['before_value']);
                $objectName = $newName;
                $localTarget = str_replace($oldName,$newName,$data['target']);
            }
            else{
                $noMoreRenames=true;
            }
        }

        return $objectName;
    }

    public function updateAppliedTime(STRING $projectToUpdate){
        $RTUpdatesDB = selectDatabase("RealTimeUpdates");
        $query = "SELECT projects FROM firewallUpdates WHERE id='$this->changeID'";
        $result = $RTUpdatesDB->query($query);
        $data = $result->fetch_assoc();
        $projects = json_decode($data['projects']);

        $projectsNew = array();
        foreach ($projects as $projectName=>$date){
            if ($projectName == $projectToUpdate){
                $projectsNew[$projectName] = [
                    "project"   => $projectName,
                    "date"      => date("Y-m-d H:i:s")
                ];
            }
            else{
                $projectsNew[$projectName] = [
                    "project"   => $projectName,
                    "date"      => $date
                ];
            }
        }

        $query = "UPDATE firewallUpdates SET projects = '".json_encode($projectsNew)."' WHERE id='$this->changeID'";
        $RTUpdatesDB->query($query);
    }

    public function updateBeforeAndAfterXML(\SimpleXMLElement $before=null, \SimpleXMLElement $after=null){
        $changes = false;
        $change = array();
        if(isset($before)){
            $changes = true;
            $change[] = "before_xml = '".$before->asXML()."'";
        }
        if(isset($after)){
            $changes = true;
            $change[] = "after_xml='".$after->asXML()."'";
        }

        if($changes) {
            $query = "UPDATE firewallUpdates SET ".implode(',', $change)." WHERE id='$this->changeID'";
            $this->connection->query($query);
        }
    }

    public function getBeforeAfterXML(){
        $query = "SELECT before_xml, after_xml FROM firewallUpdates WHERE id='$this->changeID'";
        $result = $this->connection->query($query);
        $elements[0] = null;
        $elements[1] = null;
        if($result->num_rows == 1){
            $data = $result->fetch_assoc();
            $elements[0] = ($data['before_xml']=='')? null: simplexml_load_string($data['before_xml']);
            $elements[1] = ($data['after_xml'] =='')? null: simplexml_load_string($data['after_xml']);
        }

        return $elements;
    }

    /***
     * GLOBAL ACTION QUERIES
     */
    private function buildSetQueries(){
        if(isset($this->targetArray['address'])){
            $this->buildSetQuery_Address();
        }
        elseif(isset($this->targetArray['address-group'])){
            $this->buildSetQuery_AddressGroup();
        }
        elseif(isset($this->targetArray['region'])){
            $this->buildSetQuery_Region();
        }
        elseif(isset($this->targetArray['external-list'])){
            $this->buildSetQuery_ExternalList();
        }
        elseif(isset($this->targetArray['service'])){
            $this->buildSetQuery_Service();
        }
        elseif(isset($this->targetArray['service-group'])) {
            $this->buildSetQuery_ServiceGroup();
        }
        elseif(isset($this->targetArray['application'])){
            $this->buildSetQuery_Application();
        }
        elseif(isset($this->targetArray['application-group'])) {
            $this->buildSetQuery_ApplicationGroup();
        }
        elseif(isset($this->targetArray['rulebase security rules'])){
            $this->buildSetQuery_SecurityRule();
        }
        elseif(isset($this->targetArray['post-rulebase security rules'])){
            $this->buildSetQuery_SecurityRule();
        }
        elseif(isset($this->targetArray['pre-rulebase security rules'])){
            $this->buildSetQuery_SecurityRule();
        }
        elseif(isset($this->targetArray['rulebase nat rules'])){
            $this->buildSetQuery_NatRule();
        }
        elseif(isset($this->targetArray['post-rulebase nat rules'])){
            $this->buildSetQuery_NatRule();
        }
        elseif(isset($this->targetArray['pre-rulebase nat rules'])){
            $this->buildSetQuery_NatRule();
        }
        elseif(isset($this->targetArray['tag'])){
            $this->buildSetQuery_Tag();
        }
        elseif(isset($this->targetArray['zone'])){
            $this->buildSetQuery_Zone();
        }
//        elseif(isset($this->targetArray['network interface ethernet'])){
//            $this->buildSetQuery_NetworkInterface();
//        }
        else{
            echo "This object is not supported yet. ".json_encode($this->targetArray)."\n";
        }
    }

    private function buildEditQueries(){
        if(isset($this->targetArray['address'])){
            $this->buildEdit_Address();
        }
        elseif(isset($this->targetArray['address-group'])){
            $this->buildEdit_AddressGroup();
        }
        elseif(isset($this->targetArray['region'])){
            $this->buildEdit_Region();
        }
        elseif(isset($this->targetArray['external-list'])){
            $this->buildEdit_ExternalList();
        }
        elseif(isset($this->targetArray['service'])){
            $this->buildEdit_Service();
        }
        elseif(isset($this->targetArray['service-group'])){
            $this->buildEdit_ServiceGroup();
        }
        elseif(isset($this->targetArray['application'])){
            $this->buildEdit_Application();
        }
        elseif(isset($this->targetArray['application-group'])) {
            $this->buildEdit_ApplicationGroup();
        }
        elseif(isset($this->targetArray['rulebase security rules'])){
            $this->buildEdit_SecurityRule();
        }
        elseif(isset($this->targetArray['post-rulebase security rules'])){
            $this->buildEdit_SecurityRule();
        }
        elseif(isset($this->targetArray['pre-rulebase security rules'])){
            $this->buildEdit_SecurityRule();
        }
        elseif(isset($this->targetArray['rulebase nat rules'])){
            $this->buildEdit_NatRule();
        }
        elseif(isset($this->targetArray['post-rulebase nat rules'])){
            $this->buildEdit_NatRule();
        }
        elseif(isset($this->targetArray['pre-rulebase nat rules'])){
            $this->buildEdit_NatRule();
        }
        elseif(isset($this->targetArray['tag'])){
            $this->buildEdit_Tag();
        }
        elseif(isset($this->targetArray['zone'])){
            $this->buildEdit_Zone();
        }
//        elseif(isset($this->targetArray['network interface ethernet'])){
//            $this->buildEdit_NetworkInterface();
//        }
    }

    private function buildRenameQueries(){
        if(isset($this->targetArray['address'])){
            $this->buildRename_Address();
        }
        elseif(isset($this->targetArray['address-group'])){
            $this->buildRename_AddressGroup();
        }
        elseif(isset($this->targetArray['region'])){
            $this->buildRename_Region();
        }
        elseif(isset($this->targetArray['external-list'])){
            $this->buildRename_ExternalList();
        }
        elseif(isset($this->targetArray['service'])){
            $this->buildRename_Service();
        }
        elseif(isset($this->targetArray['service-group'])){
            $this->buildRename_ServiceGroup();
        }
        elseif(isset($this->targetArray['application'])){
            $this->buildRename_Application();
        }
        elseif(isset($this->targetArray['application-group'])) {
            $this->buildRename_ApplicationGroup();
        }
        elseif(isset($this->targetArray['rulebase security rules'])){
            $this->buildRename_SecurityRule();
        }
        elseif(isset($this->targetArray['post-rulebase security rules'])){
            $this->buildRename_SecurityRule();
        }
        elseif(isset($this->targetArray['pre-rulebase security rules'])){
            $this->buildRename_SecurityRule();
        }
        elseif(isset($this->targetArray['rulebase nat rules'])){
            $this->buildRename_NatRule();
        }
        elseif(isset($this->targetArray['post-rulebase nat rules'])){
            $this->buildRename_NatRule();
        }
        elseif(isset($this->targetArray['pre-rulebase nat rules'])){
            $this->buildRename_NatRule();
        }
        elseif(isset($this->targetArray['tag'])){
            $this->buildRename_Tag();
        }
        elseif(isset($this->targetArray['zone'])){
            $this->buildRename_Zone();
        }
//        elseif(isset($this->targetArray['network interface ethernet'])){
//            $this->buildRename_NetworkInterface();
//        }

    }

    private function buildMoveQueries(){
        if(isset($this->targetArray['rulebase security rules'])){
            $this->buildMove_SecurityRule();
        }
        elseif(isset($this->targetArray['post-rulebase security rules'])){
            $this->buildMove_SecurityRule();
        }
        elseif(isset($this->targetArray['pre-rulebase security rules'])){
            $this->buildMove_SecurityRule();
        }
        elseif(isset($this->targetArray['rulebase nat rules'])){
            $this->buildMove_NatRule();
        }
        elseif(isset($this->targetArray['post-rulebase nat rules'])){
            $this->buildMove_NatRule();
        }
        elseif(isset($this->targetArray['pre-rulebase nat rules'])){
            $this->buildMove_NatRule();
        }
    }

    private function buildDeleteQueries(){
        if(isset($this->targetArray['address'])){
            $this->buildDelete_Address();
        }
        elseif(isset($this->targetArray['address-group'])){
            $this->buildDelete_AddressGroup();
        }
        elseif(isset($this->targetArray['region'])){
            $this->buildDelete_Region();
        }
        elseif(isset($this->targetArray['external-list'])){
            $this->buildDelete_ExternalList();
        }
        elseif(isset($this->targetArray['service'])){
            $this->buildDelete_Service();
        }
        elseif(isset($this->targetArray['service-group'])){
            $this->buildDelete_ServiceGroup();
        }
        elseif(isset($this->targetArray['application'])){
            $this->buildDelete_Application();
        }
        elseif(isset($this->targetArray['application-group'])) {
            $this->buildDelete_ApplicationGroup();
        }
        elseif(isset($this->targetArray['rulebase security rules'])){
            $this->buildDelete_SecurityRule();
        }
        elseif(isset($this->targetArray['post-rulebase security rules'])){
            $this->buildDelete_SecurityRule();
        }
        elseif(isset($this->targetArray['pre-rulebase security rules'])){
            $this->buildDelete_SecurityRule();
        }
        elseif(isset($this->targetArray['rulebase nat rules'])){
            $this->buildDelete_NatRule();
        }
        elseif(isset($this->targetArray['post-rulebase nat rules'])){
            $this->buildDelete_NatRule();
        }
        elseif(isset($this->targetArray['pre-rulebase nat rules'])){
            $this->buildDelete_NatRule();
        }
        elseif(isset($this->targetArray['tag'])){
            $this->buildDelete_Tag();
        }
        elseif(isset($this->targetArray['zone'])){
            $this->buildDelete_Zone();
        }
//        elseif(isset($this->targetArray['network interface ethernet'])){
//            $this->buildDelete_NetworkInterface();
//        }

    }

    private function buildMultiCloneQueries(){
        //In this case, the vsys field has "kiddnapped" another field name
        $vsys_wrong = $this->targetArray['vsys'];
        $vsys_wrong_ar = explode(' ', $vsys_wrong);
        $this->targetArray['vsys'] = $vsys_wrong_ar[0];
        unset($vsys_wrong_ar[0]);
        $new_field = implode(' ', $vsys_wrong_ar);

        $after = $this->after;
        $after_ar = explode('{', $after);
        $objectName = $after_ar[0];

        $this->targetArray[$new_field] = trim($objectName);

        if(isset($this->targetArray['address'])){
            $this->buildSetQuery_Address();
        }
        elseif(isset($this->targetArray['address-group'])){
            $this->buildSetQuery_AddressGroup();
        }
        elseif(isset($this->targetArray['region'])){
            $this->buildSetQuery_Region();
        }
        elseif(isset($this->targetArray['external-list'])){
            $this->buildSetQuery_ExternalList();
        }
        elseif(isset($this->targetArray['service'])){
            $this->buildSetQuery_Service();
        }
        elseif(isset($this->targetArray['service-group'])){
            $this->buildSetQuery_ServiceGroup();
        }
        elseif(isset($this->targetArray['application'])){
            $this->buildSetQuery_Application();
        }
        elseif(isset($this->targetArray['application-group'])) {
            $this->buildSetQuery_ApplicationGroup();
        }
        elseif(isset($this->targetArray['rulebase security rules'])){
            $this->buildClone_SecurityRule();
        }
        elseif(isset($this->targetArray['post-rulebase security rules'])){
            $this->buildClone_SecurityRule();
        }
        elseif(isset($this->targetArray['pre-rulebase security rules'])){
            $this->buildClone_SecurityRule();
        }
        elseif(isset($this->targetArray['rulebase nat rules'])){
            $this->buildClone_NatRule();
        }
        elseif(isset($this->targetArray['post-rulebase nat rules'])){
            $this->buildClone_NatRule();
        }
        elseif(isset($this->targetArray['pre-rulebase nat rules'])){
            $this->buildClone_NatRule();
        }
        elseif(isset($this->targetArray['tag'])){
            $this->buildSetQuery_Tag();
        }
        elseif(isset($this->targetArray['zone'])){
            $this->buildSetQuery_Zone();
        }


    }

    /***
     * ADDRESS METHODS
     */
    private function buildSetQuery_Address(){
        $addressName = $this->targetArray['address'];
        $originalName = $addressName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $addressName = $this->getLastName($this->deviceSerial, $addressName, $localTarget);

        list( ,$elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/address/entry[@name='$addressName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;
            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter:null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $address = new \AddressPANObject();
        $address->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $address->setVsys($vsys);
            $address->insert($projectdb, $originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_Address(){
        $addressName = $this->targetArray['address'];
        $originalName = $addressName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $addressName = $this->getLastName($this->deviceSerial, $addressName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/address/entry[@name='$addressName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/address/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0]))? $elementArray2[0] : null;

            $this->updateBeforeAndAfterXML($elementBefore,$elementAfter);
        }


        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $address = new \AddressPANObject();
        $address->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        $addressOld = new \AddressPANObject();
        $addressOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $addressOld->setSource($baseconfig);
            $differences = $address->compare($addressOld);

            $localAddress = new \AddressPANObject();
            $localAddress->setSource($baseconfig);
            $localAddress->setVsys($vsys);
            $localAddress->loadFromProject($projectdb, $originalName);

            $differencesLocal = $address->compare($localAddress);
            $localAddress->reportConflicts($projectdb, $differences, $differencesLocal);

            $address->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_Address(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }
        $oldAddressName = $this->before;
        $newAddressName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $address = new \AddressPANObject();
            $address->setSource($baseconfig);
            $address->setVsys($vsys);
            $address->rename($projectdb, $oldAddressName, $newAddressName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_Address(){
        $addressName = $this->targetArray['address'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }
        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address = new \AddressPANObject();
            $address->setSource($baseconfig);
            $address->setVsys($vsys);

            $address->delete($projectdb, $addressName);

            $this->updateAppliedTime($project);
        }
    }


    /***
     * ADDRESS GROUP METHODS
     */
    private function buildSetQuery_AddressGroup(){
        $addressGroupName = $this->targetArray['address-group'];
        $originalName = $addressGroupName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $addressGroupName = $this->getLastName($this->deviceSerial, $addressGroupName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/address-group/entry[@name='$addressGroupName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;
            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $addressGroup = new \AddressGroupPANObject();
        $addressGroup->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $addressGroup->setSource($baseconfig);
            $addressGroup->setVsys($vsys);
            $addressGroup->insert($projectdb, $originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_AddressGroup(){
        $addressGroupName = $this->targetArray['address-group'];
        $originalName = $addressGroupName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $addressGroupName = $this->getLastName($this->deviceSerial, $addressGroupName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/address-group/entry[@name='$addressGroupName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/address-group/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);

        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $addressGroup = new \AddressGroupPANObject();
        $addressGroup->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        $addressGroupOld = new \AddressGroupPANObject();
        $addressGroupOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $addressGroup->setSource($baseconfig);
            $addressGroupOld->setSource($baseconfig);
            $differences = $addressGroup->compare($addressGroupOld);

            $localAddress = new \AddressGroupPANObject();
            $localAddress->setSource($baseconfig);
            $localAddress->setVsys($vsys);
            $localAddress->loadFromProject($projectdb, $originalName);

            $differencesLocal = $addressGroup->compare($localAddress);
            $localAddress->reportConflicts($projectdb, $differences, $differencesLocal);

            $addressGroup->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_AddressGroup(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldAddressGroupName = $this->before;
        $newAddressGroupName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $addressGroup = new \AddressGroupPANObject();
            $addressGroup->setSource($baseconfig);
            $addressGroup->setVsys($vsys);
            $addressGroup->rename($projectdb, $oldAddressGroupName, $newAddressGroupName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_AddressGroup(){
        $addressGroupName = $this->targetArray['address-group'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $addressGroup = new \AddressGroupPANObject();
            $addressGroup->setSource($baseconfig);
            $addressGroup->setVsys($vsys);

            $addressGroup->delete($projectdb,$addressGroupName);

            $this->updateAppliedTime($project);
        }
    }


    /***
     * REGION METHODS
     */
    private function buildSetQuery_Region(){
        $addressName = $this->targetArray['region'];
        $originalName = $addressName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $addressName = $this->getLastName($this->deviceSerial, $addressName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/region/entry[@name='$addressName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;
            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $address = new \RegionPANObject();
        $address->load($originalName, $elementAfter, '', $vsys, $devicegroup);
        $address->setVsys($vsys);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $address->insert($projectdb, $originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_Region(){
        $addressName = $this->targetArray['region'];
        $originalName = $addressName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $addressName = $this->getLastName($this->deviceSerial, $addressName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/region/entry[@name='$addressName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/region/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0]))? $elementArray2[0]: null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $address = new \RegionPANObject();
        $address->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        $addressOld = new \RegionPANObject();
        $addressOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $addressOld->setSource($baseconfig);
            $differences = $address->compare($addressOld);

            $localAddress = new \RegionPANObject();
            $localAddress->setSource($baseconfig);
            $localAddress->setVsys($vsys);
            $localAddress->loadFromProject($projectdb, $originalName);

            $differencesLocal = $address->compare($localAddress);
            $localAddress->reportConflicts($projectdb, $differences, $differencesLocal);

            $address->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_Region(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldAddressName = $this->before;
        $newAddressName = $this->after;

        $address = new \RegionPANObject();
        $address->setVsys($vsys);
        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $address->rename($projectdb, $oldAddressName, $newAddressName);
            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_Region(){
        $addressName = $this->targetArray['region'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $address = new \RegionPANObject();
        $address->setVsys($vsys);
        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $address->delete($projectdb, $addressName);
            $this->updateAppliedTime($project);
        }
    }


    /***
     * EXTERNAL LIST METHODS
     */
    private function buildSetQuery_ExternalList(){
        $addressName = $this->targetArray['external-list'];
        $originalName = $addressName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $addressName = $this->getLastName($this->deviceSerial, $addressName, $localTarget);

        list( , $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/external-list/entry[@name='$addressName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;
            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);

        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $address = new \ExternalListPANObject();
        $address->load($originalName, $elementAfter, '', $vsys, $devicegroup);
        $address->setVsys($vsys);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $address->insert($projectdb, $originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_ExternalList(){
        $addressName = $this->targetArray['external-list'];
        $originalName = $addressName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $addressName = $this->getLastName($this->deviceSerial, $addressName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/external-list/entry[@name='$addressName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/external-list/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0]))? $elementArray2[0]: null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);

        }


        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $address = new \ExternalListPANObject();
        $address->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        $addressOld = new \ExternalListPANObject();
        $addressOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $addressOld->setSource($baseconfig);
            $differences = $address->compare($addressOld);

            $localAddress = new \RegionPANObject();
            $localAddress->setSource($baseconfig);
            $localAddress->setVsys($vsys);
            $localAddress->loadFromProject($projectdb, $originalName);

            $differencesLocal = $address->compare($localAddress);
            $localAddress->reportConflicts($projectdb, $differences, $differencesLocal);

            $address->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_ExternalList(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldAddressName = $this->before;
        $newAddressName = $this->after;

        $address = new \ExternalListPANObject();
        $address->setVsys($vsys);
        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $address->rename($projectdb, $oldAddressName, $newAddressName);
            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_ExternalList(){
        $addressName = $this->targetArray['external-list'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $address = new \ExternalListPANObject();
        $address->setVsys($vsys);
        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $address->setSource($baseconfig);
            $address->delete($projectdb, $addressName);
            $this->updateAppliedTime($project);
        }
    }


    /***
     * SERVICE METHODS
     */
    private function buildSetQuery_Service(){
        $serviceName = $this->targetArray['service'];
        $originalName = $serviceName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $serviceName = $this->getLastName($this->deviceSerial, $serviceName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/service/entry[@name='$serviceName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;
            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);

        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $service = new \ServicePANObject();
        $service->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $service->setSource($baseconfig);
            $service->setVsys($vsys);
            $service->insert($projectdb, $originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_Service(){
        $serviceName = $this->targetArray['service'];
        $originalName = $serviceName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $serviceName = $this->getLastName($this->deviceSerial, $serviceName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/service/entry[@name='$serviceName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/service/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);

        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $service = new \ServicePANObject();
        $service->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        $serviceOld = new \ServicePANObject();
        $serviceOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);

            $service->setSource($baseconfig);
            $serviceOld->setSource($baseconfig);
            print_r($service);
            print_r($serviceOld);
            $differences = $service->compare($serviceOld);
            print_r($differences);

            $service->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_Service(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldServiceName = $this->before;
        $newServiceName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $service = new \ServicePANObject();
            $service->setSource($baseconfig);
            $service->setVsys($vsys);
            $service->rename($projectdb, $oldServiceName, $newServiceName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_Service(){
        $serviceName = $this->targetArray['service'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $service = new \ServicePANObject();
            $service->setSource($baseconfig);
            $service->setVsys($vsys);

            $service->delete($projectdb,$serviceName);

            $this->updateAppliedTime($project);
        }
    }


    /***
     * SERVICE-GROUP METHODS
     */
    private function buildSetQuery_ServiceGroup(){
        $serviceName = $this->targetArray['service-group'];
        $originalName = $serviceName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $serviceName = $this->getLastName($this->deviceSerial, $serviceName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/service-group/entry[@name='$serviceName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;
            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);

        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $serviceGroup = new \ServiceGroupPANObject();
        $serviceGroup->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $serviceGroup->setSource($baseconfig);
            $serviceGroup->setVsys($vsys);
            $serviceGroup->insert($projectdb, $originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_ServiceGroup(){
        $serviceName = $this->targetArray['service-group'];
        $originalName = $serviceName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $serviceName = $this->getLastName($this->deviceSerial, $serviceName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/service-group/entry[@name='$serviceName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/service-group/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);

        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $serviceGroup = new \ServiceGroupPANObject();
        $serviceGroup->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        $serviceGroupOld = new \ServiceGroupPANObject();
        $serviceGroupOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $serviceGroup->setSource($baseconfig);
            $serviceGroup->setVsys($vsys);
            $serviceGroupOld->setSource($baseconfig);
            $serviceGroupOld->setVsys($vsys);
            $differences = $serviceGroup->compare($serviceGroupOld);

            $serviceGroup->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_ServiceGroup(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldServiceGroupName = $this->before;
        $newServiceGroupName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $addressGroup = new \ServiceGroupPANObject();
            $addressGroup->setSource($baseconfig);
            $addressGroup->setVsys($vsys);
            $addressGroup->rename($projectdb, $oldServiceGroupName, $newServiceGroupName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_ServiceGroup(){
        $serviceGroupName = $this->targetArray['service-group'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $serviceGroup = new \ServiceGroupPANObject();
            $serviceGroup->setSource($baseconfig);
            $serviceGroup->setVsys($vsys);

            $serviceGroup->delete($projectdb,$serviceGroupName);

            $this->updateAppliedTime($project);
        }
    }


    /***
     * APPLICATION METHODS
     */
    private function buildSetQuery_Application(){
        $applicationName = $this->targetArray['application'];
        $originalName = $applicationName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $applicationName = $this->getLastName($this->deviceSerial, $applicationName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/application/entry[@name='$applicationName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $application = new \ApplicationPANObject();

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $result = $projectdb->query("SELECT version FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
            $data = $result->fetch_assoc();
            $full_version = $data['version'];
            $application->setVersion($full_version);
            $application->load($originalName, $elementAfter, $baseconfig, $vsys, $devicegroup);
            $application->insert($projectdb, $originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_Application(){
        $applicationName = $this->targetArray['application'];
        $originalName = $applicationName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $applicationName = $this->getLastName($this->deviceSerial, $applicationName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/application/entry[@name='$applicationName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/application/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $application = new \ApplicationPANObject();

        $applicationOld = new \ApplicationPANObject();

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $result = $projectdb->query("SELECT version FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
            $data = $result->fetch_assoc();
            $full_version = $data['version'];
            $application->setVersion($full_version);
            $application->load($originalName, $elementAfter, $baseconfig, $vsys, $devicegroup);

            $applicationOld->setVersion($full_version);
            $applicationOld->load($originalName, $elementBefore, $baseconfig, $vsys, $devicegroup);

            $differences = $application->compare($applicationOld);

            $application->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_Application(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldAppName = $this->before;
        $newAppName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $application = new \ApplicationPANObject();
            $application->setSource($baseconfig);
            $application->setVsys($vsys);
            $application->rename($projectdb, $oldAppName, $newAppName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_Application(){
        $serviceGroupName = $this->targetArray['application'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $application = new \ApplicationPANObject();
            $application->setSource($baseconfig);
            $application->setVsys($vsys);

            $application->delete($projectdb,$serviceGroupName);

            $this->updateAppliedTime($project);
        }
    }


    /***
     * APPLICATION-GROUP METHODS
     */
    private function buildSetQuery_ApplicationGroup(){
        $appGroupName = $this->targetArray['application-group'];
        $originalName = $appGroupName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $appGroupName = $this->getLastName($this->deviceSerial, $appGroupName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/application-group/entry[@name='$appGroupName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $application = new \ApplicationGroupPANObject();
        $application->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $application->setSource($baseconfig);
            $application->setVsys($vsys);
            $application->insert($projectdb,$originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_ApplicationGroup(){
        $appGroupName = $this->targetArray['application-group'];
        $originalName = $appGroupName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $appGroupName = $this->getLastName($this->deviceSerial, $appGroupName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/application-group/entry[@name='$appGroupName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/application-group/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $applicationGroup = new \ApplicationGroupPANObject();
        $applicationGroup->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        $applicationGroupOld = new \ApplicationGroupPANObject();
        $applicationGroupOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $applicationGroup->setSource($baseconfig);
            $applicationGroup->setVsys($vsys);
            $applicationGroupOld->setSource($baseconfig);
            $applicationGroupOld->setVsys($vsys);
            $differences = $applicationGroup->compare($applicationGroupOld);

            $applicationGroup->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_ApplicationGroup(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldAppName = $this->before;
        $newAppName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $applicationGroup = new \ApplicationGroupPANObject();
            $applicationGroup->setSource($baseconfig);
            $applicationGroup->setVsys($vsys);

            $applicationGroup->rename($projectdb, $oldAppName, $newAppName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_ApplicationGroup(){
        $applicationGroupName = $this->targetArray['application-group'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $applicationGroup = new \ApplicationGroupPANObject();
            $applicationGroup->setSource($baseconfig);
            $applicationGroup->setVsys($vsys);

            $applicationGroup->delete($projectdb,$applicationGroupName);

            $this->updateAppliedTime($project);
        }
    }

    /**
     * TAG METHODS
     */
    private function buildSetQuery_Tag(){
        $tagName = $this->targetArray['tag'];
        $originalName = $tagName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $tagName = $this->getLastName($this->deviceSerial, $tagName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/tag/entry[@name='$tagName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $tag = new \TagPANObject();
        $tag->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $tag->setSource($baseconfig);
            $tag->setVsys($vsys);
            $tag->insert($projectdb,$originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_Tag(){
        $tagName = $this->targetArray['tag'];
        $originalName = $tagName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $tagName = $this->getLastName($this->deviceSerial, $tagName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/tag/entry[@name='$tagName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/tag/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $tag = new \TagPANObject();
        $tag->load($originalName, $elementAfter, '', $vsys, $devicegroup);

        $tagOld = new \TagPANObject();
        $tagOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);


        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $tag->setSource($baseconfig);
            $tag->setVsys($vsys);
            $tagOld->setSource($baseconfig);
            $tagOld->setVsys($vsys);
            $differences = $tag->compare($tagOld);

            $tag->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_Tag(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldTagName = $this->before;
        $newTagName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $tag = new \TagPANObject();
            $tag->setSource($baseconfig);
            $tag->setVsys($vsys);

            $tag->rename($projectdb, $oldTagName, $newTagName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_Tag(){
        $tagName = $this->targetArray['tag'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $tag = new \TagPANObject();
            $tag->setSource($baseconfig);
            $tag->setVsys($vsys);

            $tag->delete($projectdb,$tagName);

            $this->updateAppliedTime($project);
        }
    }


    /**
     * ZONE METHODS
     */
    private function buildSetQuery_Zone(){
        $zoneName = $this->targetArray['zone'];
        $originalName = $zoneName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $zoneName = $this->getLastName($this->deviceSerial, $zoneName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/zone/entry[@name='$zoneName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $zone = new \ZonePANObject();

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $zone->setConnection($projectdb);
            $zone->load($originalName, $elementAfter, '', $vsys, $devicegroup);

            $zone->setSource($baseconfig);
            $zone->setVsys($vsys);
            $zone->insert($projectdb,$originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_Zone(){
        $zoneName = $this->targetArray['zone'];
        $originalName = $zoneName;
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $localTarget = $this->originalTarget;
        $zoneName = $this->getLastName($this->deviceSerial, $zoneName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/zone/entry[@name='$zoneName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/zone/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $zone = new \ZonePANObject();
        $zoneOld = new \ZonePANObject();

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $zone->setConnection($projectdb);
            $zoneOld->setConnection($projectdb);
            $zone->load($originalName, $elementAfter, '', $vsys, $devicegroup);
            $zoneOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);

            $zone->setSource($baseconfig);
            $zone->setVsys($vsys);
            $zoneOld->setSource($baseconfig);
            $zoneOld->setVsys($vsys);
            $differences = $zone->compare($zoneOld);

            $zone->update($projectdb, $originalName, $differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_Zone(){
        if (isset($this->targetArray['vsys'])) {
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldZoneName = $this->before;
        $newZoneName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $zone = new \ZonePANObject();
            $zone->setSource($baseconfig);
            $zone->setVsys($vsys);

            $zone->rename($projectdb, $oldZoneName, $newZoneName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildDelete_Zone(){
        $zoneName = $this->targetArray['zone'];
        if(isset($this->targetArray['vsys'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $zone = new \ZonePANObject();
            $zone->setConnection($projectdb);
            $zone->setSource($baseconfig);
            $zone->setVsys($vsys);

            $zone->delete($projectdb, $zoneName);

            $this->updateAppliedTime($project);
        }
    }


    /***
     * SECURITY RULES METHODS
     */
    private function buildSetQuery_SecurityRule(){
        if(isset($this->targetArray['rulebase security rules'])){
            $ruleName = $this->targetArray['rulebase security rules'];
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
            $policy = 'rulebase';
            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase security rules'])){
                $ruleName = $this->targetArray['post-rulebase security rules'];
                $policy = "post-rulebase";
                $preOrPost = 1;
            }
            else{
                $ruleName = $this->targetArray['pre-rulebase security rules'];
                $policy = "pre-rulebase";
                $preOrPost = 0;
            }
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }
        $originalName = $ruleName;

        $localTarget = $this->originalTarget;
        $ruleName = $this->getLastName($this->deviceSerial, $ruleName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/security/rules/entry[@name='$ruleName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $securityRule = new \SecurityRulePANObject();
        $securityRule->load($originalName, $elementAfter, '', $vsys, $devicegroup);
        $securityRule->setPreOrPost($preOrPost);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);

            $securityRule->setSource($baseconfig);
            $securityRule->setVsys($vsys);
            $securityRule->insert($projectdb,$originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_SecurityRule(){
        if(isset($this->targetArray['rulebase security rules'])){
            $ruleName = $this->targetArray['rulebase security rules'];
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
            $policy = 'rulebase';
            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase security rules'])){
                $ruleName = $this->targetArray['post-rulebase security rules'];
                $policy = "post-rulebase";
                $preOrPost = 1;
            }
            else{
                $ruleName = $this->targetArray['pre-rulebase security rules'];
                $policy = "pre-rulebase";
                $preOrPost = 0;
            }
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        //Verify that the name is correct, and does not include a subpart of the Security Rule
        $nameArray = explode(" ", $ruleName);

        $afterValue = explode(" ", $this->after);
        if(count($afterValue)>0){
            $firstAfterValue = $afterValue[0];
            $numWords = count($nameArray);
            if($numWords>1){
                $lastWord = $nameArray[$numWords-1];
                switch ($lastWord){
                    case "to":
                    case "from":
                    case "application":
                    case "service":
                    case "tag":
                    case "source-user":
                    case "category":
                    case "hip-profiles":

                        if($firstAfterValue == $lastWord){
                            unset($nameArray[$numWords-1]);
                            $ruleNameNew = trim(implode(" ",$nameArray));
                            if(strlen($ruleNameNew)!=0){
                                $ruleName = $ruleNameNew;
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        $originalName = $ruleName;

        $localTarget = $this->originalTarget;
        $ruleName = $this->getLastName($this->deviceSerial, $ruleName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/security/rules/entry[@name='$ruleName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/security/rules/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;
            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $security = new \SecurityRulePANObject();
        $securityOld = new \SecurityRulePANObject();
        $security->load($originalName, $elementAfter, '', $vsys, $devicegroup);
        $securityOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);
        $security->setPreOrPost($preOrPost);
        $securityOld->setPreOrPost($preOrPost);
        $differences = $security->compare($securityOld);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $security->setSource($baseconfig);
            $security->update($projectdb,$originalName,$differences);

            $this->updateAppliedTime($project);
        }
    }

    private function buildRename_SecurityRule(){
        if(isset($this->targetArray['rulebase security rules'])){
//            $ruleName = $this->targetArray['rulebase security rules'];
//            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
//            $policy = 'rulebase';
//            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase security rules'])){
//                $ruleName = $this->targetArray['post-rulebase security rules'];
//                $policy = "post-rulebase";
//                $preOrPost = 1;
            }
            else{
//                $ruleName = $this->targetArray['pre-rulebase security rules'];
//                $policy = "pre-rulebase";
//                $preOrPost = 0;
            }
//            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }
        $oldSecName = $this->before;
        $newSecName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $security = new \SecurityRulePANObject();
            $security->setSource($baseconfig);
            $security->setVsys($vsys);
            $security->rename($projectdb, $oldSecName, $newSecName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildMove_SecurityRule(){
        if(isset($this->targetArray['rulebase security rules'])){
            $ruleName = $this->targetArray['rulebase security rules'];
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
            $policy = 'rulebase';
            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase security rules'])){
                $ruleName = $this->targetArray['post-rulebase security rules'];
                $policy = "post-rulebase";
                $preOrPost = 1;
            }
            else{
                $ruleName = $this->targetArray['pre-rulebase security rules'];
                $policy = "pre-rulebase";
                $preOrPost = 0;
            }
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $originalName = $ruleName;

        $localTarget = $this->originalTarget;
        $ruleName = $this->getLastName($this->deviceSerial, $ruleName, $localTarget);

        $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/security/rules/entry";
        $elements = $this->getPathElement($xpath);
        $rulesUnder = array();
        $found = false;
        foreach ($elements as $element) {
            if(!$found) {
                if ($element->attributes()->name == "$ruleName") {
                    $found = true;
                }
            }
            else{
                $nextRuleName = $element->attributes()->name;
                $rulesUnder[] = (string) $nextRuleName;
            }
        }

        $security = new \SecurityRulePANObject();
        $security->setPreOrPost($preOrPost);
        if($found) {
            foreach ($this->project as $project => $baseconfig) {
                $projectdb = selectDatabase($project);
                $security->move($projectdb, $originalName, $rulesUnder, $baseconfig, $vsys);

                $this->updateAppliedTime($project);
            }
        }
    }

    private function buildDelete_SecurityRule(){
        if(isset($this->targetArray['vsys'])){
            $securityRuleName = $this->targetArray['rulebase security rules'];
            $vsys = $this->targetArray['vsys'];
        }
        else{
            if(isset($this->targetArray['post-rulebase nat rules'])){
                $securityRuleName = $this->targetArray['post-rulebase security rules'];
            }
            else{
                $securityRuleName = $this->targetArray['pre-rulebase security rules'];
            }
            $vsys = $this->targetArray['device-group'];
        }

        $security = new \SecurityRulePANObject();
        $security->setVsys($vsys);
        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $security->setSource($baseconfig);
            $security->delete($projectdb, $securityRuleName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildClone_SecurityRule(){
        if(isset($this->targetArray['rulebase security rules'])){
            $ruleName = $this->targetArray['rulebase security rules'];
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
            $policy = 'rulebase';
            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase security rules'])){
                $ruleName = $this->targetArray['post-rulebase security rules'];
                $policy = "post-rulebase";
                $preOrPost = 1;
            }
            else{
                $ruleName = $this->targetArray['pre-rulebase security rules'];
                $policy = "pre-rulebase";
                $preOrPost = 0;
            }
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $originalName = $ruleName;

        $localTarget = $this->originalTarget;
        $ruleName = $this->getLastName($this->deviceSerial, $ruleName, $localTarget);

        $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/security/rules/entry[@name='$ruleName']";
        $element_toInsert = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?

        $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/security/rules/entry";
        $elements = $this->getPathElement($xpath);
        $rulesUnder = array();
        $found = false;
        foreach ($elements as $element) {
            if(!$found) {
                if ($element->attributes()->name == "$ruleName") {
                    $found = true;
                }
            }
            else{
                $nextRuleName = $element->attributes()->name;
                $rulesUnder[] = (string) $nextRuleName;
            }
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;
        $security = new \SecurityRulePANObject();
        $security->setPreOrPost($preOrPost);
        $security->load($ruleName, $element_toInsert[0], '',$vsys,$devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $security->setSource($baseconfig);
            $security->insert($projectdb, $ruleName);
            $security->move($projectdb,$originalName,$rulesUnder, $baseconfig, $vsys);

            $this->updateAppliedTime($project);
        }
    }


    /***
     * NAT RULES METHODS
     */
    private function buildSetQuery_NatRule(){
        if(isset($this->targetArray['rulebase nat rules'])){
            $ruleName = $this->targetArray['rulebase nat rules'];
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
            $policy = 'rulebase';
            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase nat rules'])){
                $ruleName = $this->targetArray['post-rulebase nat rules'];
                $policy = "post-rulebase";
                $preOrPost = 1;
            }
            else{
                $ruleName = $this->targetArray['pre-rulebase nat rules'];
                $policy = "pre-rulebase";
                $preOrPost = 0;
            }
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }
        $originalName = $ruleName;

        $localTarget = $this->originalTarget;
        $ruleName = $this->getLastName($this->deviceSerial, $ruleName, $localTarget);

        list(, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/nat/rules/entry[@name='$ruleName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementBeforeXML = null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $nat = new \NatRulePANObject();
        $nat->load($ruleName, $elementAfter,'', $vsys, $devicegroup);
        $nat->setPreOrPost($preOrPost);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $nat->setSource($baseconfig);
            $nat->insert($projectdb, $originalName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildEdit_NatRule(){
        if(isset($this->targetArray['rulebase nat rules'])){
            $ruleName = $this->targetArray['rulebase nat rules'];
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
            $policy = 'rulebase';
            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase nat rules'])){
                $ruleName = $this->targetArray['post-rulebase nat rules'];
                $policy = "post-rulebase";
                $preOrPost = 1;
            }
            else{
                $ruleName = $this->targetArray['pre-rulebase nat rules'];
                $policy = "pre-rulebase";
                $preOrPost = 0;
            }
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        //Verify that the name is correct, and does not include a subpart of the Security Rule
        $nameArray = explode(" ", $ruleName);

        $afterValue = explode(" ", $this->after);
        if(count($afterValue)>0){
            $firstAfterValue = $afterValue[0];
            $numWords = count($nameArray);
            if($numWords>1){
                $lastWord = $nameArray[$numWords-1];
                switch ($lastWord){
                    case "to":
                    case "from":
                    case "service":
                    case "tag":
                        if($firstAfterValue == $lastWord){
                            unset($nameArray[$numWords-1]);
                            $ruleNameNew = trim(implode(" ",$nameArray));
                            if(strlen($ruleNameNew)!=0){
                                $ruleName = $ruleNameNew;
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
        }

        $originalName = $ruleName;

        $localTarget = $this->originalTarget;
        $ruleName = $this->getLastName($this->deviceSerial, $ruleName, $localTarget);

        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }

        $localTarget = $this->originalTarget;
        $ruleName = $this->getLastName($this->deviceSerial, $ruleName, $localTarget);

        list($elementBefore, $elementAfter) = $this->getBeforeAfterXML();

        if(!$elementAfter) {
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/nat/rules/entry[@name='$ruleName']";
            $xpath2 = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/nat/rules/entry[@name='$originalName']";
            $elementArray = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?
            $elementAfter = (isset($elementArray[0])) ? $elementArray[0] : null;

            $elementArray2 = $this->getPathElementOld($xpath2); //Should return an Array with one single instance. Should we control this?
            $elementBefore = (isset($elementArray2[0])) ? $elementArray2[0] : null;

            $elementBeforeXML = !is_null($elementBefore) ? $elementBefore :null ;
            $elementAfterXML = !is_null($elementAfter) ? $elementAfter :null ;
            $this->updateBeforeAndAfterXML($elementBeforeXML,$elementAfterXML);
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;

        $nat = new \NatRulePANObject();
        $natOld = new \NatRulePANObject();

        $nat->load($originalName, $elementAfter, '', $vsys, $devicegroup);
        $natOld->load($originalName, $elementBefore, '', $vsys, $devicegroup);
        $nat->setPreOrPost($preOrPost);
        $natOld->setPreOrPost($preOrPost);
        $differences = $nat->compare($natOld);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $nat->setSource($baseconfig);
            $nat->update($projectdb,$originalName,$differences);

            $this->updateAppliedTime($project);
        }

    }

    private function buildRename_NatRule(){
        if(isset($this->targetArray['rulebase nat rules'])){
            $vsys = $this->targetArray['vsys'];
        }
        else{
            $vsys = $this->targetArray['device-group'];
        }

        $oldNatName = $this->before;
        $newNatName = $this->after;

        foreach ($this->project as $project => $baseconfig) {
            $projectdb = selectDatabase($project);
            $nat = new \NatRulePANObject();
            $nat->setSource($baseconfig);
            $nat->setVsys($vsys);
            $nat->rename($projectdb, $oldNatName, $newNatName);

            $this->updateAppliedTime($project);
        }

    }

    private function buildMove_NatRule(){
        if(isset($this->targetArray['rulebase nat rules'])){
            $ruleName = $this->targetArray['rulebase nat rules'];
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
            $policy = 'rulebase';
            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase nat rules'])){
                $ruleName = $this->targetArray['post-rulebase nat rules'];
                $policy = "post-rulebase";
                $preOrPost = 1;
            }
            else{
                $ruleName = $this->targetArray['pre-rulebase nat rules'];
                $policy = "pre-rulebase";
                $preOrPost = 0;
            }
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }

        $originalName = $ruleName;

        $localTarget = $this->originalTarget;
        $ruleName = $this->getLastName($this->deviceSerial, $ruleName, $localTarget);

        $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/nat/rules/entry";
        $elements = $this->getPathElement($xpath);
        $rulesUnder = array();
        $found = false;
        foreach ($elements as $element) {
            if(!$found) {
                if ($element->attributes()->name == "$ruleName") {
                    $found = true;
                }
            }
            else{
                $nextRuleName = $element->attributes()->name;
                $rulesUnder[] = (string) $nextRuleName;
            }
        }

        $nat = new \NatRulePANObject();
        $nat->setPreOrPost($preOrPost);

        if($found) {
            foreach ($this->project as $project => $baseconfig) {
                $projectdb = selectDatabase($project);
                $nat->move($projectdb, $originalName, $rulesUnder, $baseconfig, $vsys);

                $this->updateAppliedTime($project);
            }
        }
    }

    private function buildDelete_NatRule(){
        if(isset($this->targetArray['rulebase nat rules'])){
            $natRuleName = $this->targetArray['rulebase nat rules'];
            $vsys = $this->targetArray['vsys'];
        }
        else{
            if(isset($this->targetArray['post-rulebase nat rules'])){
                $natRuleName = $this->targetArray['post-rulebase nat rules'];
            }
            else{
                $natRuleName = $this->targetArray['pre-rulebase nat rules'];
            }
            $vsys = $this->targetArray['device-group'];
        }

        $nat = new \NatRulePANObject();
        $nat->setVsys($vsys);
        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $nat->setSource($baseconfig);
            $nat->delete($projectdb,$natRuleName);

            $this->updateAppliedTime($project);
        }
    }

    private function buildClone_NatRule(){
        if(isset($this->targetArray['rulebase nat rules'])){
            $ruleName = $this->targetArray['rulebase nat rules'];
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
            $policy = 'rulebase';
            $preOrPost = 0;
        }
        else{
            if(isset($this->targetArray['post-rulebase nat rules'])){
                $ruleName = $this->targetArray['post-rulebase nat rules'];
                $policy = "post-rulebase";
                $preOrPost = 1;
            }
            else{
                $ruleName = $this->targetArray['pre-rulebase nat rules'];
                $policy = "pre-rulebase";
                $preOrPost = 0;
            }
            $platform = 'device-group';
            $vsys = $this->targetArray['device-group'];
        }
        if(isset($this->targetArray['vsys'])){
            $platform = 'vsys';
            $vsys = $this->targetArray['vsys'];
        }

        $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/nat/rules/entry[@name='$ruleName']";
        $element_toInsert = $this->getPathElement($xpath); //Should return an Array with one single instance. Should we control this?

        $xpath = "/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']/$policy/nat/rules/entry";
        $elements = $this->getPathElement($xpath);
        $rulesUnder = array();
        $found = false;
        foreach ($elements as $element) {
            if(!$found) {
                if ($element->attributes()->name == "$ruleName") {
                    $found = true;
                }
            }
            else{
                $nextRuleName = $element->attributes()->name;
                $rulesUnder[] = (string) $nextRuleName;
            }
        }

        $devicegroup = "RealTimeUpdates_".$this->deviceSerial;
        $nat = new \NatRulePANObject();
        $nat->setPreOrPost($preOrPost);
        $nat->load($ruleName, $element_toInsert[0], '',$vsys,$devicegroup);

        foreach ($this->project as $project=>$baseconfig) {
            $projectdb = selectDatabase($project);
            $nat->setSource($baseconfig);
            $nat->insert($projectdb, $ruleName);
            $nat->move($projectdb,$ruleName,$rulesUnder, $baseconfig, $vsys);

            $this->updateAppliedTime($project);
        }
    }


    /***
     * NETWORK INTERFACE METHODS
     */
    private function buildSetQuery_NetworkInterface(){
//        $this->parseAfterToJSON("simple");
    }

}