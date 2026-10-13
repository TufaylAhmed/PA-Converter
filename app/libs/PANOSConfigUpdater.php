<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';

require_once INC_ROOT . '/libs/xmlapi.php';

require_once INC_ROOT . '/libs/common/lib-objects.php';
require_once INC_ROOT . '/libs/common/lib-rules.php';


use PaloaltoNetworks\Policy\Objects\MemberObject;
use PaloaltoNetworks\Policy\Objects\RuleObject;
use PaloaltoNetworks\Policy\Objects\CompleteSecRuleObject;

define('DEBUG', true);
define('TRACE', false);

class PANOSConfigUpdater
{
    private $projectdb;
    private $project;
    private $source;
    private $devicegroup;
    private $vsys;  //Temporary variable that keeps updated during parsing

    private $fileOld; //Original path from where we can get the old PANOS config
    private $fileNew; //Original path from where we can get the new PANOS config

    private $origXmlDoc; //DOMDocument with the original file
    private $diffXmlDoc; //DOMDocument with the changed between $fileOld and $fileNew. This is $origXMLDoc+$diffXmlDoc=$fileNew


    public function __construct($projectdb, $project, $source, $devicegroup, $fileOld, $fileNew){
        $this->projectdb = $projectdb;
        $this->project = $project;
        $this->source = $source;
        $this->devicegroup = $devicegroup;
        $this->fileOld = $fileOld;
        $this->fileNew = $fileNew;
    }

    protected function getXMLofChanges(STRING $original_file_path, STRING $modified_file_path)
    {
        $doc_xml = new XMLDiff\File;
        $diff = $doc_xml->diff($original_file_path, $modified_file_path);
        return $diff;
//    $difffile = 'difference_rename_modify.xml';
//    file_put_contents($difffile, $diff);
    }

    protected function test2_recursive($original_file, $xmlChanges, ARRAY $path = null, INT $level = 0)
    {

        foreach ($xmlChanges->children() as $xmlNode) {

            $nodeName = $xmlNode->getName();
            if ($nodeName == "PANdm_copy") {
                $count = $xmlNode['count'];
                for ($i = 0; $i < $level; $i++) {
                    echo " ";
                }
                echo "Copying $count nodes. " . $xmlNode->xpath() . "\n";
            } elseif ($nodeName == "PANdm_delete") {
                for ($i = 0; $i < $level; $i++) {
                    echo "$level";
                }
                echo "Deleting $xmlNode nodes\n";
            } elseif ($nodeName == "PANdm_insert") {
                for ($i = 0; $i < $level; $i++) {
                    echo "$level";
                }
                echo "Inserting $xmlNode nodes\n";
            } else {
                for ($i = 0; $i < $level; $i++) {
                    echo " ";
                }
                echo "$nodeName\n";
            }
            //echo $xmlNode->asXML();
            test2_recursive($original_file, $xmlNode, ++$level);
        }
    }

    protected function getNodePathPAN($node)
    {
        $path = $node->getNodePath();
        $path = str_replace("/dm:diff", "", $path);
        return $path;
    }

    protected function test3_recursive($original_file, $xmlChanges, ARRAY $path = null, INT $level = 0)
    {
        foreach ($xmlChanges->childNodes as $node) {
//        if ($node->nodeType != XML_TEXT_NODE) {
//            echo trim($node->nodeName);
//            continue;
//        }
//        $nodeValue = $node;
//        echo trim($node->nodeName) . " = " . trim($node->nodeValue) . "\n";
            $path = getNodePathPAN($node);
            echo $path . "\n";

            /*
            switch ($node->nodeName){
                case "dm:copy":
                    $number = $node->getAttribute('count');
                    echo "This is a copy instruction. $number\n";

                    break;
                case "dm:delete":
                    echo "This is a delete instruction. ".$node->nodeValue."\n";

                    break;
                case "dm:insert":
                    echo "This is a insert instruction. ".$node->nodeValue."\n";

                    break;
                case "#text":
    //                echo trim($node->nodeValue)."\n";
                    break;
                default:
    //                echo "Other\n";
                    echo "$node->nodeName.  ";
                    echo getNodePathPAN($node)."\n";
                    break;
            }
            */
            if ($node->hasChildNodes()) {
//        if($node->childNodes->length != 1) {
                test3_recursive($original_file, $node);
            }
        }
    }

    protected function processChanges(INT $level = 0)
    {
        $node = $this->diffXmlDoc->firstChild;
        $this->processChanges_root($node, "", $level + 1);
    }

    protected function processChanges_root($xmlChanges, STRING $path = "", INT $level = 0)
    {
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "config":
                    $this->processChanges_config($node, $path . "/" . $nodeName, $level + 1);
                    break;

                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_config($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 0;

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "mgt-config":
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "shared":
                    $this->processChanges_shared($node, $path."/".$nodeName, $level + 1);
                    break;
                case "devices":
                    $this->processChanges_devices($node, $path . "/" . $nodeName, $level + 1);
                    break;
                case "dm:copy":
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_shared($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                case "dm:delete":
                    //TODO
                    $this->processChanges_shared_Delete($xmlChanges, $path . "/" . $nodeName, $level + 1);
                    break;
                case "dm:insert":
                    $this->processChanges_shared_Insert($xmlChanges, $path . "/" . $nodeName, $level + 1);
                    //TODO
                    break;
                case "content-preview":
                    $this->processChanges_contentPreview($node, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_shared_Delete($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "content-preview":
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_shared_Insert($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "content-preview":
                    $this->processChanges_contentPreview($node, $path . "/" . $nodeName, $level + 1);
                    $position++;
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_devices($xmlChanges, STRING $path = "", INT $level = 0)
    {
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "entry":
                    //Here we can get the device name
                    if (TRACE) echo "$path -> " . $node->getAttribute('name') . "\n";
                    $this->processChanges_deviceEntry($node, $path."/".$nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_contentPreview($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                case "application":
                    $this->processChanges_application($node, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_application($xmlChanges, STRING $path = "", INT $level = 0)
    {
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    //TODO
                    $this->processChanges_applicationInsert($node, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_applicationInsert($xmlChanges, STRING $path = "", INT $level = 0)
    {
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "entry":
                    $this->processChanges_applicationInsertEntry($node, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_applicationInsertEntry($xmlChanges, STRING $path = "", INT $level = 0)
    {

        $appId = initApp();

//    $references = array();
        $appId['name'] = $xmlChanges->getAttribute('name');
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "able-to-transfer-file":
                    $appId['able_to_transfer_file'] = $node->nodeValue;
                    break;
                case "alg":
                    $appId['alg'] = $node->nodeValue;
                    break;
                case "applicable-decoders":
                    //TODO
                    if (DEBUG) echo "+Node $nodeName in $path is not supported\n";
                    break;
                case "application-container":
                    $appId['application_container'] = $node->nodeValue;
                    break;
                case "appident":
                    $appId['appident'] = $node->nodeValue;
                    break;
                case "breaks-decryption":
                    $appId['breaks_decryption'] = $node->nodeValue;
                    break;
                case "cachable":
                    $appId['cachable'] = $node->nodeValue;
                    break;
                case "can-disable":
                    $appId['can_disable'] = $node->nodeValue;
                    break;
                case "category":
                    $appId['category'] = $node->nodeValue;
                    break;
                case "consume-big-bandwidth":
                    $appId['consume_big_bandwidth'] = $node->nodeValue;
                    break;
                case "data-ident":
                    $appId['data_ident'] = $node->nodeValue;
                    break;
                case "decode":
                    $appId['decode'] = $node->nodeValue;
                    break;
                case "default":
                    $child = $node->firstChild;
                    $default_type = $child->nodeName;
                    if ($child->nodeName == "port") {
                        $values = array();
                        foreach ($child->childNodes as $childchild) {
                            $values[] = $childchild->nodeValue;
                        }
                        $appId['value'] = implode(',', $values);
                    } elseif ($child->nodeName == "ident-by-icmp-type") {
                        foreach ($child->childNodes as $childchild) {
                            $childchildName = $childchild->nodeName;
                            switch ($childchildName) {
                                case "type":
                                    $appId['type'] = $childchild->nodeValue;
                                    break;
                                case "code":
                                    $appId['code'] = $childchild->nodeValue;
                                    break;
                                default:
                                    echo "Attribute $childchildName in $path/$default_type is not supported\n";
                            }
                        }
                    }
                    break;
                case "deny-action":
                    $appId['deny_action'] = $node->nodeValue;
                    break;
                case "description":
                    $appId['description'] = addslashes($node->nodeValue);
                    break;
                case "evasive-behavior":
                    $appId['evasive_behavior'] = $node->nodeValue;
                    break;
                case "file-forward":
                    $appId['file_forward'] = $node->nodeValue;
                    break;
                case "file-type-ident":
                    $appId['file_type_ident'] = $node->nodeValue;
                    break;
                case "has-known-vulnerability":
                    $appId['has_known_vulnerability'] = $node->nodeValue;
                    break;
                case "icon":
                    $appId['icon'] = $node->nodeValue;
                    $appId['icon_min_ver'] = $node->getAttribute('minver');
                    break;
                case "implicit-use-applications":
                    //TODO
                    if (DEBUG) echo "+Node $nodeName in $path is not supported\n";
                    break;
                case "is-saas":
                    $appId['is_saas'] = $node->nodeValue;
                    break;
                case "parent_app":
                    $children = 0;
                    $memberParentApps = array();
                    foreach ($node->childNodes as $parentApps) {
                        $memberParentApps[] = $parentApps->nodeValue;
                        $children++;
                    }
                    if ($children == 0) {
                        $appId['parent_app'] = $node->nodeValue;
                    } else {
                        $appId['parent_app'] = implode(",", $memberParentApps);
                    }
                    break;
                case "per-direction-regex":
                    $appId['per_direction_regex'] = $node->nodeValue;
                    break;
                case "pervasive-use":
                    $appId['pervasive_use'] = $node->nodeValue;
                    break;
                case "preview":
                    $appId['preview'] = $node->nodeValue;
                    break;
                case "prone-to-misuse":
                    $appId['prone_to_misuse'] = $node->nodeValue;
                    break;
                case "ottawa-name":
                    $appId['ottawa_name'] = $node->nodeValue;
                    break;
                case "references":
                    //TODO
//                foreach($node->childNodes as $referenceItem){
//                    $reference['name'] = $referenceItem->getAttribute('name');
//                    $reference['link'] = $referenceItem->firstChild->nodeValue;
//                    $references[] = $reference;
//                }
                    break;
                case "risk":
                    $appId['risk'] = $node->nodeValue;
                    break;
                case "run-decoder":
                    $appId['run_decoder'] = $node->nodeValue;
                    break;
                case "spyware-ident":
                    $appId['spyware_ident'] = $node->nodeValue;
                    break;
                case "subcategory":
                    $appId['subcategory'] = $node->nodeValue;
                    break;
                case "tcp-halp-closed-timeout":
                    $appId['tcp_halp_closed_timeout'] = $node->nodeValue;
                    break;
                case "tcp-time-wait-timeout":
                    $appId['tcp_time_wait_timeout'] = $node->nodeValue;
                    break;
                case "tcp-timeout":
                    $appId['tcp_timeout'] = $node->nodeValue;
                    break;
                case "timeout":
                    $appId['timeout'] = $node->nodeValue;
                    break;
                case "technology":
                    $appId['technology'] = $node->nodeValue;
                    break;
                case "tunnel-applications":
                    $children = 0;
                    $memberTunnelApps = array();
                    foreach ($node->childNodes as $tunneledApps) {
                        $memberTunnelApps[] = $tunneledApps->nodeValue;
                        $children++;
                    }
                    if ($children == 0) {
                        $appId['tunnel_applications'] = $node->nodeValue;
                    } else {
                        $appId['tunnel_applications'] = implode(",", $memberTunnelApps);
                    }
                    break;
                case "tunnel-other-application":
                    $appId['tunnel_other_application'] = $node->nodeValue;
                    break;
                case "udp-timeout":
                    $appId['udp_timeout'] = $node->nodeValue;
                    break;
                case "url-category":
                    $appId['url_category'] = $node->nodeValue;
                    break;
                case "use-applications":
                    //TODO
                    if (DEBUG) echo "+Node $nodeName in $path is not supported\n";
                    break;
                case "used-by-malware":
                    $appId['used_by_malware'] = $node->nodeValue;
                    break;
                case "virus-ident":
                    $appId['virus_ident'] = $node->nodeValue;
                    break;
                case "vulnerability-ident":
                    $appId['vulnerability_ident'] = $node->nodeValue;
                    break;

                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }

        createAppId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $appId);
    }

    protected function processChanges_deviceEntry($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                case "vsys":
                    $this->processChanges_vsys($node, $path."/".$nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    /** /config/devices/entry/vsys
     * @param Mysqli $projectdb
     * @param STRING $source
     * @param STRING $devicegroup
     * @param STRING $vsys
     * @param DOMElement $original_file
     * @param DOMElement $xmlChanges
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_vsys($xmlChanges, STRING $path = "", INT $level = 0)
    {
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "entry":
                    $this->vsys = $node->getAttribute('name');
                    if (TRACE) echo "$this->vsys (in $path)\n";
                    $this->processChanges_vsysEntry($node, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    /** /config/devices/entry/vsys/entry
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_vsysEntry(DOMElement $xmlChanges, STRING $path = "", INT $level = 0)
    {
        //Get first the Address Objects that may be used in the new entries
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //At this level, there is nothing to do here.
                    break;
                case "address":
                    $this->processChanges_address($node, "modify", $path."/".$nodeName, $level+1);
                    break;
                case "application-group":
                    $this->processChanges_aplicationGroup($node, $path."/".$nodeName, $level+1);
                    break;
                case "dm:insert":
                    foreach($node->childNodes as $node2){
                        $node2Name = $node2->nodeName;
                        if (TRACE) echo "$node2Name\n";
                        switch ($node2Name) {
                            case "tag":
                                $this->processChanges_tag($node2, $path."/".$node2Name, $level+1);
                                break;
                            case "address":
                                $this->processChanges_address($node2, "create", $path."/".$node2Name,$level+1);
                                break;
                            default:
                                echo "$node2Name in $path not supported in ".__FUNCTION__." loop 1.2 in ".__FILE__." at ".__LINE__."\n";
                        }
                    }
//                    $this->processChanges_vsysEntry_Insert($node, $path."/".$nodeName, $level + 1);
                    break;

                case "profiles":
                    $this->processChanges_profiles($node, $path."/".$nodeName, $level+1);
                    break;

                case "rulebase":
                    //We process these below
                    break;

                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." loop 1.1 in ".__FILE__." at ".__LINE__."\n";
            }
        }

        //Afterwards, we can start processing the rest of the NodeOjects, which may include:
        //  rulebase - nats, rules, default_security_rules

        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                case "dm:insert":
                    //TODO We should check here that we are not trying to process application-group, address, tag, etc.
                    break;
                case "rulebase":
                    $this->processChanges_rulebase($node, $path."/".$nodeName, $level + 1);
                    break;

                case "address":
                case "application-group":
                    //Already processed in the upper loop
                    break;

                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." loop 2.1 in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_profiles(DOMElement $xmlChanges, STRING $path, INT $level){
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    break;
                case "dm:insert":
                    //TODO sort first the child objects, so hip-objects come before hip-profiles, as the second may contain first ones.
                    $result = $this->sortXML_subNode($node);
                    foreach ($node->childNodes as $profileNode){
                        $profileNodeName = $profileNode->nodeName;
                        switch ($profileNodeName){
                            case "hip-profiles":
                                $hipId = initHipProfile();
                                $profileDataNode = $profileNode->firstChild;
                                $hipId['name']= $profileDataNode->getAttribute('name');
                                $hipId['xml']=$profileDataNode->ownerDocument->saveHTML($profileDataNode);
                                $hipId['type']="hip-profiles";
                                createHIPProfile($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $hipId);
//                                echo "$profileNodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
                                break;
                            case "hip-objects":
                                $hipId = initHipProfile();
                                $profileDataNode = $profileNode->firstChild;
                                $hipId['name']= $profileDataNode->getAttribute('name');
                                $hipId['xml']=$profileDataNode->ownerDocument->saveHTML($profileDataNode);
                                $hipId['type']="hip-objects";
                                createHIPProfile($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $hipId);
//                                echo "$profileNodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
                                break;

                            default:
                                echo "$profileNodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
                        }
                    }
                    break;

                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_aplicationGroup(DOMElement $xmlChanges, STRING $path="", INT $level=0){
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    break;
                case "dm:insert":
                    $this->insertApplicationGroup($node, $path."/".$nodeName, $level+1);
                    break;
//                case "entry":
//                    //check if this appGroup is still in use. If it is not, then we can simply create it. Otherwise, we will update it.
//                    $addressName = $node->getAttribute('name');
//                    $memberToModify = getMemberId($this->projectdb, $this->source, $this->devicegroup, $this->vsys,$addressName);
//                    if(isset($memberToModify)){
//                        $this->modifyAddressObject($node, $memberToModify, $path."/".$nodeName, $level+1);
//                    }
//                    else{
//                        //This AddressObject has been deleted from the MT, but it is now in use. Recover it from the old config!
//                        $XMLPath = $xmlChanges->getNodePath();
//                        $member = $this->getAddressMemberFromConfig($this->origXmlDoc, $XMLPath, $addressName);
//                        $memberObj = createAddressMemberId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $member);
//                        $this->modifyAddressObject($node, $memberObj, $path."/".$nodeName, $level+1);
//                    }
//                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_address(DOMElement $xmlChanges, STRING $modify_or_create, STRING $path="", INT $level=0){
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    break;
                case "dm:insert":
                    //TODO
                    $this->insertAddressObject($node, $path."/".$nodeName, $level+1);

                    break;
                case "entry":
                    //check if this address is still in use. If it is not, then we can simply create it. Otherwise, we will update it.
                    $addressName = normalizeNames($node->getAttribute('name'));
                    $vsyses = getVsyses($this->projectdb,$this->vsys, $this->source);
                    $memberToModify = getMemberId($this->projectdb, $this->source, $vsyses, $addressName);
                    if(isset($memberToModify)){
//                        echo "Address $addressName is not new\n";
                        if($modify_or_create == "modify") {
                            $this->modifyAddressObject($node, $memberToModify, "alter", $path . "/" . $nodeName, $level + 1);
                        }
                        else{
                            $this->modifyAddressObject($node, $memberToModify, "new", $path."/".$nodeName, $level+1);
                        }
                    }
                    else{
//                        echo "Address $addressName is new\n";
                        if($modify_or_create == "modify") {
                            //This AddressObject has been deleted from the MT, but it is now in use. Recover it from the old config!
                            $XMLPath = $xmlChanges->getNodePath();
                            $member = $this->getAddressMemberFromConfig($this->origXmlDoc, $XMLPath, $addressName);
                            $memberObj = createAddressMemberId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $member);
                            $this->modifyAddressObject($node, $memberObj, "alter", $path . "/" . $nodeName, $level+1);
                        }
                        else{
                            //This is a new object, that was not in the prior FW config
                            $member = initAddressMember();
                            $member['name'] = $addressName;
                            $member['name_pan'] = normalizeNames($addressName);
                            $memberObj = createAddressMemberId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $member);
                            $this->modifyAddressObject($node, $memberObj, "new", $path."/".$nodeName, $level+1);
                        }
                    }
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function modifyAddressObject(DOMElement $xmlChanges, MemberObject $address, STRING $changeType, STRING $path="", INT $level=0){
//        echo "PANOSConfigUpdater@modifyAddressObject \n";

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "ip-netmask":
                    if($changeType == "alter") {
                        foreach ($node->childNodes as $ipChild) {
                            $action = $ipChild->nodeName;
                            switch ($action) {
                                case "dm:delete":
                                    $ipcidr = explode("/", $ipChild->nodeValue);
                                    $ip = $ipcidr[0];
                                    $cidr = isset($ipcidr[1]) ? $ipcidr[1] : '32';
                                    deleteIpAddressNetmask($this->projectdb, $address, 'ip-netmask', $ip, $cidr);
                                    break;
                                case "dm:insert":
                                    $ipcidr = explode("/", $ipChild->nodeValue);
                                    $ip = $ipcidr[0];
                                    $cidr = isset($ipcidr[1]) ? $ipcidr[1] : '32';
                                    $ipv = 'v4';
                                    setIpAddressNetmask($this->projectdb, $address, 'ip-netmask', $ip, $cidr, $ipv);
                                    break;

                                default:
                                    echo "$action not supported in " . __FUNCTION__ . " in " . __FILE__ . " at " . __LINE__ . "\n";
                            }
                            break;
                        }
                    }
                    else{
                        $ipcidr = explode("/", $node->nodeValue);
                        $ip = $ipcidr[0];
                        $cidr = isset($ipcidr[1]) ? $ipcidr[1] : '32';
                        $ipv = 'v4';
                        setIpAddressNetmask($this->projectdb, $address, 'ip-netmask', $ip, $cidr, $ipv);
                    }
                    break;

                case "ip-range":
                    if($changeType == "alter") {
                        foreach ($node->childNodes as $ipChild) {
                            $action = $ipChild->nodeName;
                            switch ($action) {
                                case "dm:delete":
                                    $range = $ipChild->nodeValue;
                                    $cidr = '32';
                                    deleteIpAddressNetmask($this->projectdb, $address, 'ip-range', $range, $cidr);
                                    break;
                                case "dm:insert":
                                    $range = $ipChild->nodeValue;
                                    $cidr = '32';
                                    setIpAddressNetmask($this->projectdb, $address, 'ip-range', $range, $cidr, 'v4');
                                    break;

                                default:
                                    echo "$action not supported in " . __FUNCTION__ . " in " . __FILE__ . " at " . __LINE__ . "\n";
                            }
                            break;
                        }
                    }
                    else{
                        $range = $node->nodeValue;
                        $cidr = '32';
                        setIpAddressNetmask($this->projectdb, $address, 'ip-range', $range, $cidr, 'v4');
                    }
                    break;

                case "fqdn":
                    if($changeType == "alter") {
                        foreach ($node->childNodes as $ipChild) {
                            $action = $ipChild->nodeName;
                            switch ($action) {
                                case "dm:delete":
                                    $fqdn = $ipChild->nodeValue;
                                    $cidr = '';
                                    deleteIpAddressNetmask($this->projectdb, $address, 'fqdn', $fqdn, $cidr);
                                    break;
                                case "dm:insert":
                                    $fqdn = $ipChild->nodeValue;
                                    $cidr = '';
                                    setIpAddressNetmask($this->projectdb, $address, 'fqdn', $fqdn, $cidr, 'v4');
                                    break;

                                default:
                                    echo "$action not supported in " . __FUNCTION__ . " in " . __FILE__ . " at " . __LINE__ . "\n";
                            }
                            break;
                        }
                    }
                    else{
                        $fqdn = $node->nodeValue;
                        $cidr = '';
                        setIpAddressNetmask($this->projectdb, $address, 'fqdn', $fqdn, $cidr, 'v4');
                    }
                    break;

                case "description":
                    if($changeType == "alter") {
                        foreach ($node->childNodes as $ipChild) {
                            $action = $ipChild->nodeName;
                            switch ($action) {
                                case "dm:delete":
                                    $description = addslashes($ipChild->nodeValue);
                                    deleteAddressDescription($this->projectdb, $address);
                                    break;
                                case "dm:insert":
                                    $description = addslashes($ipChild->nodeValue);
                                    setAddressDescription($this->projectdb, $address, $description);
                                    break;

                                default:
                                    echo "$action not supported in " . __FUNCTION__ . " in " . __FILE__ . " at " . __LINE__ . "\n";
                            }
                            break;
                        }
                    }
                    else{
                        $description = addslashes($node->nodeValue);
                        setAddressDescription($this->projectdb, $address, $description);
                    }
                    break;

                case "tag":
                    //TODO
                    break;

                default:
                    echo "++$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    public function getAddressMemberFromConfig(DOMDocument $origXmlDoc, $XMLPath, STRING $addressName){
//        $query = $XMLPath;
//        echo "$query\n";
        $xpath = new \DOMXpath($origXmlDoc);
        $query = "//config/devices/entry/vsys/entry[@name=\"$this->vsys\"]/address/entry[@name=\"$addressName\"]";
        $addressEntries = $xpath->query($query);

        foreach ($addressEntries as $entry){
            if($entry->getAttribute('name') == $addressName){
                $member = initAddressMember();
                $member['name']=$addressName;
                $member['name_pan']=normalizeNames($addressName);
                $this->getAddressMemberFromXMLNode($entry, $member);
                return $member;
            }
        }
        return null;
    }

    public function getAddressMemberFromXMLNode(DOMElement $entry, ARRAY &$member){
        $member['vsys']=$this->vsys;
        $member['source']=$this->source;
        $member['vtype']='object';

//        echo $entry->getAttribute('name')."\n";
        foreach($entry->childNodes as $node) {
            $nodeName = $node->nodeName;
            switch($nodeName) {
                //type, ipaddress, cidr, v4, v6
                case "ip-netmask":
                    $member['type']="ip-netmask";
                    $ipcidr=explode("/",$node->nodeValue);
                    $member['ipaddress'] = $ipcidr[0];
                    $member['cidr'] = isset($ipcidr[1])? $ipcidr[1]: '32';
                    $v4_6 = ip_version($ipcidr[0]);
                    if($v4_6 == "v4"){
                        $member['v4']=1;
                    }
                    if($v4_6 == "v6"){
                        $member['v6']=1;
                    }
                    break;
                case "ip-range":
                    $member['type']="ip-netmask";
                    $member['ipaddress'] = $node->nodeValue;
                    $member['cidr'] = '32';
                    $member['v4']=1;
                    break;
                case "fqdn":
                    $member['type']="fqdn";
                    $member['ipaddress'] = $node->nodeValue;
                    $member['v4']=1;
                    break;

//                case "members":
//                    foreach($node->childNodes as $memberNode){
//                        $memberName = $memberNode->nodeValue;
//                        echo "$memberName\n";
//                        $memberId = getMemberId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $memberName);
//                        var_dump($memberId);
//                    }
//
//                    break;

                //description
                case "description":
                    $member['description'] = $node->nodeValue;
                    break;

                //tag
                case "tag":
                    $tags = array();
                    foreach($node->childNodes as $tag){
                        $tags[] = $tag->nodeValue;
                    }
                    $member['tag'] = implode(",", $tags);
                    break;

                default:
                    echo "$nodeName in not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }


    public function getApplicationGroupsMemberFromXMLNode(DOMElement $entry, ARRAY &$member){
        $member['vsys']=$this->vsys;
        $member['source']=$this->source;
        $member['vtype']='';

        foreach($entry->childNodes as $node) {
            $nodeName = $node->nodeName;
            switch ($nodeName) {
                case "members":
                    foreach($node->childNodes as $memberNode){
                        $memberName = $memberNode->nodeValue;
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $memberId = getAppId($this->projectdb, $this->source, $vsyses, $memberName);
                        $member['members'][] = $memberId;
                    }

                    break;
                default:
                    echo "$nodeName in not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }


    protected function insertAddressObject(DOMElement $xmlChanges, STRING $path="", INT $level=0){
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "entry":
                    $member = initAddressMember();
                    $addressName = $node->getAttribute('name');
                    $member['name']=$addressName;
                    $member['name_pan']=normalizeNames($addressName);
//                    echo $node->C14N();
                    $this->getAddressMemberFromXMLNode($node, $member);
//                    var_dump($member);
                    $memberObj = createAddressMemberId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $member);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function insertApplicationGroup(DOMElement $xmlChanges, STRING $path="", INT $level=0){
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "entry":
                    $member = initAppGroup();
                    $addressName = $node->getAttribute('name');
                    $member['name']=$addressName;
                    $this->getApplicationGroupsMemberFromXMLNode($node, $member);
                    createAppGroupId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $member);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

//    protected function processChanges_vsysEntry_Insert($xmlChanges, STRING $path = "", INT $level = 0)
//    {
//        foreach ($xmlChanges->childNodes as $node) {
//            $nodeName = $node->nodeName;
//            if (TRACE) echo "$nodeName\n";
//            switch ($nodeName) {
//                case "tag":
//                    //TODO
//                    $this->processChanges_vsysEntryTag_Insert($node, $path . "/" . $nodeName, $level + 1);
//                    break;
//
//                default:
//                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
//            }
//        }
//    }

    protected function processChanges_tag($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $tagEntries = $xmlChanges->getElementsByTagName('entry');
        foreach ($tagEntries as $tagEntry) {
            $tagName = $tagEntry->getAttribute('name');
            if (TRACE) echo "$tagName\n";
            $tag = initTag();
            $tag['name'] = $tagName;
            foreach ($tagEntry->childNodes as $tagAttributeNode) {
                $attribName = $tagAttributeNode->nodeName;
                switch ($attribName) {
                    case "color":
                        $tag['color'] = $tagAttributeNode->nodeValue;
                        break;
                    case "comments":
                        $tag['comments'] = $tagAttributeNode->nodeValue;
                        break;
                    case "modified":
                        $tag['modified'] = $tagAttributeNode->nodeValue;
                        break;
                    case "vtype":
                        $tag['vtype'] = $tagAttributeNode->nodeValue;
                        break;

                    default:
                        echo "Attribute $attribName in $path is not supported\n";
                }
            }
            $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
            $tagObject_1 = getTagId($this->projectdb, $this->source, $vsyses, $tagName);

            if (!isset($tagObject_1)) {
                createTagId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $tag);
            }
            else {
                $tag['id'] = $tagObject_1->name;
                updateTagId($this->projectdb, $tag);
            }
        }
    }

    protected function processChanges_rulebase($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                case "nat":
//                    $this->processChanges_rulebase_nat($node, $path."/". $nodeName, $level + 1);
                    break;
                case "security":
                    $this->processChanges_rulebase_security($node, $path . "/" . $nodeName, $level + 1);
                    break;
                case "default-security-rules":
                    $this->processChanges_rulebase_defSecRul($node, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_rulebase_defSecRul($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                case "rules":
                    $this->processChanges_rulebase_defSecRulRules($node, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    /** /config/devices/entry/vsys/entry/rulebase/default-security-rules/rules
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_rulebase_defSecRulRules($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $position = 1;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            switch ($nodeName) {
                case "dm:copy":
                    $count = $node->getAttribute('count');
                    $position += $count;
                    break;
                case "dm:insert":
                    $this->processChanges_rulebase_defSecRulRules_Insert($node, $position, $path . "/" . $nodeName, $level + 1);
                    break;

                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    /** /config/devices/entry/vsys/entry/rulebase/default-security-rules/rules/dm:insert
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param $position
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_rulebase_defSecRulRules_Insert($xmlChanges, &$position, STRING $path = "", INT $level = 0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
//                $count = $node->getAttribute('count');
//                $position+=$count;
//                break;
                case "dm:insert":
                    //TODO
//                $count = $node->getAttribute('count');
//                $position+=$count;
//                break;
                case "rules":
//                processChanges_rulebase_defaultSecurityRules($node, $path."/".$nodeName, $level+1);
//                break;
                default:
                echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_rulebase_nat($xmlChanges, STRING $path="", INT $level=0){
        $position =0;

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttributes('count');
                    $position += $count;
                    break;
                case "rules":
                    $this->processChanges_NatRules($node, $path."/".$nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_NatRules($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $nat_rule_position = 1;

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttribute('count');
                    $nat_rule_position += $count;
                    //echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    //TODO
//                    echo "nat_rule_position before Insert $nat_rule_position\n";
                    $this->processChanges_NatRules_Insert($node, $nat_rule_position, $path."/".$nodeName, "insert", $level + 1);
//                    echo "nat_rule_position after Insert $nat_rule_position\n";
                    break;
                case "entry":
                    $this->processChanges_NatRulesEntry($node, $nat_rule_position, $path."/".$nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_NatRules_Insert(DOMElement $xmlChanges, INT &$nat_rule_position, STRING $path, STRING $mode, INT $level = 0)
    {

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "entry":
                    $ruleName = $node->getAttribute('name');
                    $newRule = initNatRule();
                    $newRule['name'] = $ruleName;
                    $newRule['position'] = $nat_rule_position;
                    $newRule['source'] = $this->source;
                    $newRule['devicegroup'] = $this->devicegroup;
                    $newRule['vsys'] = $this->vsys;

                    $matchingAddress = insertNatRule($this->projectdb, $newRule, "nat_rules", $nat_rule_position);
                    $ruleObject_1 = new RuleObject($matchingAddress, "nat_rules", $ruleName, "");
//                    $this->processChanges_NatRules_InsertAttributes($node, $ruleObject_1, $path."/".$nodeName, $level + 1);

//                    if($mode == "modify") {
                        $nat_rule_position++;
//                    }
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    protected function processChanges_rulebase_security($xmlChanges, STRING $path = "", INT $level=0)
    {
        $position = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttributes('count');
                    $position += $count;
                    break;
                case "rules":
                    $this->processChanges_SecRules($node, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    /** Processing nodes in /config/devices/entry/vsys/entry/rulebase/security/rules
     * @param Mysqli $projectdb
     * @param STRING $source
     * @param STRING $devicegroup
     * @param STRING $vsys
     * @param DOMElement $original_file
     * @param DOMElement $xmlChanges
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRules($xmlChanges, STRING $path = "", INT $level = 0)
    {
        $security_rule_position = 1;

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttribute('count');
                    $security_rule_position += $count;
                    //echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    $this->processChanges_SecRules_Insert($node, $security_rule_position, $path."/".$nodeName, "insert", $level + 1);
                    break;
                case "entry":
                    $this->processChanges_SecRulesEntry($node, $security_rule_position, $path."/".$nodeName, $level + 1);
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param DOMDocument $original_file
     * @param DOMElement $xmlChanges
     * @param INT $security_rule_position
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRules_Insert(DOMElement $xmlChanges, INT &$security_rule_position, STRING $path, STRING $mode, INT $level = 0)
    {

//        echo "Called in $path\n";
        foreach ($xmlChanges->childNodes as $node) {
//            echo "SecRules_Insert $security_rule_position\n";
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "entry":
                    $ruleName = $node->getAttribute('name');
                    $newRule = initSecRule();
                    $newRule['name'] = $ruleName;
                    $newRule['position'] = $security_rule_position;
                    $newRule['source'] = $this->source;
                    $newRule['devicegroup'] = $this->devicegroup;
                    $newRule['vsys'] = $this->vsys;

                    // First, we check if this rule already exists in the MT. It may have been defined in parallel both in the PANOS device and in the MT!
                    $ruleObjectOriginal = getSecRuleId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $ruleName);
                    if (isset($ruleObjectOriginal)) {
                        // This rule exists and is being modified
                        $modification = "modified";
                        $modificationName = $xmlChanges->getAttribute('dm_update');
                        if (isset($modificationName)) {
                            // There is now a new rule with the same name!
                            $ruleObjectNew = new CompleteSecRuleObject();
                            $ruleObjectNew->setParamenters($newRule);
                            $this->getSecRules_Attributes($node, $ruleObjectNew, $path."/".$nodeName, $level+1);
//                            $ruleObjectNew->printRuleObject();

                            //TODO: Uncomment the line below
                            $comparisonResult = compareSecRules($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $ruleObjectOriginal, $ruleObjectNew);
                            if ($comparisonResult == EQUAL){
                                //TODO apply updates to the old rule!
                            }
                            else{
                                //insert new rule
//                                echo "[PANOSConigUpdated.php@processChanges_SecRules_Insert] 1. ".$ruleObjectNew->getName()."\n";
                                insertSecRuleComplete($this->projectdb, $ruleObjectNew, "security_rules", $security_rule_position);
//                                var_dump($ruleObjectNew);
//                                echo "[PANOSConigUpdated.php@processChanges_SecRules_Insert] 2\n";
                            }
                        }
                        else {
                            // TODO
                        }
                    }
                    else{
                        //TODO Make the code using $ruleObjectNew->setParamenters($newRule);
                        $ruleObjectNew = new CompleteSecRuleObject();
                        $ruleObjectNew->setParamenters($newRule);
                        $this->getSecRules_Attributes($node, $ruleObjectNew, $path."/".$nodeName, $level+1);
                        insertSecRuleComplete($this->projectdb, $ruleObjectNew, "security_rules", $security_rule_position);
//                        var_dump($ruleObjectNew);

//                        $matchingAddress = insertSecRule($this->projectdb, $newRule, "security_rules", $security_rule_position);
//                        $ruleObject_1 = new RuleObject($matchingAddress, "security_rules", $ruleName, "");
//                        $this->processChanges_SecRules_InsertAttributes($node, $ruleObject_1, $path . "/" . $nodeName, $level + 1);

                    }

                    $security_rule_position++;
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }


    protected function getSecRules_Attributes(DOMElement $xmlChanges, CompleteSecRuleObject $ruleObject_1, STRING $path, INT $level=0)
    {

        foreach ($xmlChanges->childNodes as $node){
            $attribName = $node->nodeName;
            if (TRACE) echo "$attribName\n";
            switch ($attribName) {
                case "to":
//                    if (DEBUG) echo "[PANOSCOnfigUpdated.php@getSecRules_Attributes] $attribName \n";
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "to", $path."/".$attribName, $level + 1);
//                    if (DEBUG) echo "[PANOSCOnfigUpdated.php@getSecRules_Attributes] $attribName \n";
                    break;

                case "from":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "from", $path."/".$attribName, $level + 1);
                    break;

                case "source":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "source", $path."/".$attribName, $level + 1);
                    break;

                case "destination":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "destination", $path."/".$attribName, $level + 1);
                    break;

                case "source-user":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "source-user", $path."/".$attribName, $level + 1);
                    break;

                case "category":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "category", $path."/".$attribName, $level + 1);
                    break;

                case "application":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "application", $path."/".$attribName, $level + 1);
                    break;

                case "service":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "service", $path."/".$attribName, $level + 1);
                    break;

                case "hip-profiles":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "hip-profiles", $path."/".$attribName, $level + 1);
                    break;

                case "action":
                    $ruleObject_1->setAction($node->nodeValue);
                    break;

                case "tag":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "tag", $path."/".$attribName, $level + 1);
                    break;

                case "profile-setting":
                    $this->get_SecRuleAttributesMembers($node, $ruleObject_1, "profile-setting", $path."/".$attribName, $level + 1);
                    break;

                case "description":
                    $ruleObject_1->setDescription($node->nodeValue);
                    break;

                case "rule-type":
                    $ruleObject_1->setRuleType($node->nodeValue);
                    break;

                default:
                    echo "$attribName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param DOMDocument $original_file
     * @param DOMElement $xmlChanges
     * @param RuleObject $ruleObject_1
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRules_InsertAttributes(DOMElement $xmlChanges, RuleObject $ruleObject_1, STRING $path, INT $level = 0)
    {

        foreach ($xmlChanges->childNodes as $node) {
            $attribName = $node->nodeName;
            if (TRACE) echo "$attribName\n";
            switch ($attribName) {
                case "to":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "to", $path."/".$attribName, $level + 1);
                    break;

                case "from":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "from", $path."/".$attribName, $level + 1);
                    break;

                case "source":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "source", $path."/".$attribName, $level + 1);
                    break;

                case "destination":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "destination", $path."/".$attribName, $level + 1);
                    break;

                case "source-user":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "source-user", $path."/".$attribName, $level + 1);
                    break;

                case "category":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "category", $path."/".$attribName, $level + 1);
                    break;

                case "application":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "application", $path."/".$attribName, $level + 1);
                    break;

                case "service":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "service", $path."/".$attribName, $level + 1);
                    break;

                case "hip-profiles":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "hip-profiles", $path."/".$attribName, $level + 1);
                    break;

                case "action":
                    $action = new MemberObject("$node->nodeValue", "");
                    insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $action, "action", $ruleObject_1);
                    break;

                case "tag":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "tag", $path."/".$attribName, $level + 1);
                    break;

                case "profile-setting":
                    $this->processChanges_SecRules_InsertAttributesMembers($node, $ruleObject_1, "profile-setting", $path."/".$attribName, $level + 1);
                    break;

                default:
                    echo "$attribName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }

    }

    protected function get_SecRuleAttributesMembers(DOMElement $xmlChanges, CompleteSecRuleObject $ruleObject_1, STRING $attribute_type, STRING $path, INT $level = 0){
        switch ($attribute_type) {
            case "to":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $attribute = new MemberObject($value, "");
                        $parameter['to']=$attribute;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "from":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $attribute = new MemberObject($value, "");
                        $parameter['from'] = $attribute;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "source":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $memberObj = getMemberId($this->projectdb, $this->source, $vsyses, $value);
                        if(!isset($memberObj)){
                            $member = initAddressMember();
                            $member['name'] = $value;
                            $member['name_pan'] = normalizeNames($value);
                            //The source is not inserted yet, but we can create it now, and update it later when we find it in the XML
                            $memberObj = createAddressMemberId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $parameter['source'] = $memberObj;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "destination":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $memberObj = getMemberId($this->projectdb, $this->source, $vsyses, $value);
                        if(!isset($memberObj)){
                            $member = initAddressMember();
                            $member['name'] = $value;
                            $member['name_pan'] = normalizeNames($value);
                            //The destination is not inserted yet, but we can create it now, and update it later when we find it in the XML
                            $memberObj = createAddressMemberId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $parameter['destination'] = $memberObj;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "source-user":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $userMember = new MemberObject($value, "");
                        $parameter['source-user'] = $userMember;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "category":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $attribute = new MemberObject($value, "");
                        $parameter['category'] = $attribute;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "application":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $attribute = getAppId($this->projectdb, $this->source, $vsyses, $value);
                        $parameter['application'] = $attribute;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "service":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $attribute = getServiceId($this->projectdb, $this->source, $vsyses, $value);
                        $parameter['service'] = $attribute;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "hip-profiles":
                break;

            case "tag":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $tagObject_1 = getTagId($this->projectdb, $this->source, $vsyses, $value);
                        if (!isset($tagObject_1)) {
                            $tag = initTag();
                            $tag['name'] = $value;
                            //The tag is not inserted yet, but we can create it now, and update it later when we find it in the XML
                            $tagObject_1 = createTagId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $tag);
                        }
                        $parameter['tag'] = $tagObject_1;
                        $ruleObject_1->setParamenter($parameter);
                    }
                }
                break;

            case "profile-setting":
                $profile_setting = $xmlChanges->firstChild;
                if ($profile_setting->nodeName == "profiles") {
//                    $ruleObject_1->printRuleObject();
//                    insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profile_setting->nodeName, "profile_type", $ruleObject_1);
                    $ruleObject_1->setProfileType("profiles");

                    foreach ($profile_setting->childNodes as $typeNode) {
                        $type = $typeNode->nodeName;
                        $parameter = array();
                        switch ($type) {
                            case "url-filtering":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                $parameter['url-filtering'] = $profileObject;
                                $ruleObject_1->setParamenter($parameter);
                                break;
                            case "virus":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                $parameter['virus'] = $profileObject;
                                $ruleObject_1->setParamenter($parameter);
                                break;
                            case "file-blocking":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                $parameter['file-blocking'] = $profileObject;
                                $ruleObject_1->setParamenter($parameter);
                                break;
                            case "spyware":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                $parameter['spyware'] = $profileObject;
                                $ruleObject_1->setParamenter($parameter);
                                break;
                            case "vulnerability":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                $parameter['vulnerability'] = $profileObject;
                                $ruleObject_1->setParamenter($parameter);
                                break;
                            case "wildfire-analysis":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                if (!isset($profileObject)) {
                                    $profile = initProfile();
                                    $profile['type'] = $type;
                                    $profile['name'] = $typeName;
                                    $profile['vtype'] = "dummy";
                                    $profile['dummy'] = '1';
                                    $profileObject = createProfileId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profile);
                                }
                                $parameter['wildfire-analysis'] = $profileObject;
                                $ruleObject_1->setParamenter($parameter);
                                break;
                            default:
                                echo "Attribute \"$type\" as a profile-setting attribute (in $path) is not supported\n";
                        }
                    }
                }
                else {
                    echo "Attribute $attribute_type - $profile_setting->nodeName in $path is not supported\n";
                }
                break;

            default:
                echo "$attribute_type in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
        }
    }
    /** /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/to
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/from
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/source
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/destination
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/source-user
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/category
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/application
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/service
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/hip-profiles
     *  /config/devices/entry/vsys/entry/rulebase/security/rules/dm:insert/entry/tag
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param DOMDocument $original_file
     * @param DOMElement $xmlChanges
     * @param RuleObject $ruleObject_1
     * @param STRING $attributeType
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRules_InsertAttributesMembers(DOMElement $xmlChanges, RuleObject $ruleObject_1, STRING $attribute_type, STRING $path, INT $level = null)
    {
        if(is_null($level)){
            $level = 0;
        }

        switch ($attribute_type) {
            case "to":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $attribute = new MemberObject($value, "");
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $attribute, "to", $ruleObject_1);
                    }
                }
                break;

            case "from":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $attribute = new MemberObject($value, "");
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $attribute, "from", $ruleObject_1);
                    }
                }
                break;

            case "source":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $attribute = getMemberId($this->projectdb, $this->source, $vsyses, $value);
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $attribute, "source", $ruleObject_1);
                    }
                }
                break;

            case "destination":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $attribute = getMemberId($this->projectdb, $this->source, $vsyses, $value);
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $attribute, "destination", $ruleObject_1);
                    }
                }
                break;

            case "source-user":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $attribute = new MemberObject($value, "");
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $attribute, "source-user", $ruleObject_1);
                    }
                }
                break;

            case "category":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $attribute = new MemberObject($value, "");
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $attribute, "from", $ruleObject_1);
                    }
                }
                break;

            case "application":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $attribute = getAppId($this->projectdb, $this->source, $vsyses, $value);
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $attribute, "application", $ruleObject_1);
                    }
                }
                break;

            case "service":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $attribute = getServiceId($this->projectdb, $this->source, $vsyses, $value);
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $attribute, "service", $ruleObject_1);
                    }
                }
                break;

            case "hip-profiles":
                break;

            case "tag":
                foreach ($xmlChanges->childNodes as $member) {
                    $value = $member->nodeValue;
                    if ($value != "any") {
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $tagObject_1 = getTagId($this->projectdb, $this->source, $vsyses, $value);
                        if (!isset($tagObject_1)) {
                            $tag = initTag();
                            $tag['name'] = $value;
                            //The tag is not inserted yet, but we can create it now, and update it later when we find it in the XML
                            $tagObject_1 = createTagId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $tag);
                        }
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $tagObject_1, "tag", $ruleObject_1);
                    }
                }
                break;

            case "profile-setting":
                $profile_setting = $xmlChanges->firstChild;
                if ($profile_setting->nodeName == "profiles") {
//                    $ruleObject_1->printRuleObject();
                    insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profile_setting->nodeName, "profile_type", $ruleObject_1);
                    foreach ($profile_setting->childNodes as $typeNode) {
                        $type = $typeNode->nodeName;
                        switch ($type) {
                            case "url-filtering":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profileObject, $type, $ruleObject_1);
                                break;
                            case "virus":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profileObject, $type, $ruleObject_1);
                                break;
                            case "file-blocking":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profileObject, $type, $ruleObject_1);
                                break;
                            case "spyware":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profileObject, $type, $ruleObject_1);
                                break;
                            case "vulnerability":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $type, $typeName);
                                insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profileObject, $type, $ruleObject_1);
                                break;
                            case "wildfire-analysis":
                                $valueNode = $typeNode->firstChild;
                                $typeName = $valueNode->nodeValue;
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $profileObject = getProfileId($this->projectdb, $this->source, $vsyses, $this->vsys, $type, $typeName);
                                if (!isset($profileObject)) {
                                    $profile = initProfile();
                                    $profile['type'] = $type;
                                    $profile['name'] = $typeName;
                                    $profile['vtype'] = "dummy";
                                    $profile['dummy'] = '1';
                                    $profileObject = createProfileId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profile);
                                }
                                insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $profileObject, $type, $ruleObject_1);
                                break;
                            default:
                                echo "Attribute \"$type\" as a profile-setting attribute (in $path) is not supported\n";
                        }
                    }
                } else {
                    echo "$attribute_type - $profile_setting->nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
                }
                break;

            default:
                echo "$attribute_type in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
        }
    }


    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry/dm:insert
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param DOMDocument $original_file
     * @param DOMElement $xmlChanges
     * @param INT $security_rule_position
     * @param STRING $path
     * @param INT $level
     */
    /*
    private function processChanges_SecRules_InsertEntry($projectdb, $source, $devicegroup, STRING $vsys, DOMDocument $original_file, DOMElement $xmlChanges, INT $security_rule_position, STRING $path, INT $level=0){
    //private function processChanges_SecRules_Insert($projectdb, $source, $devicegroup, STRING $vsys, $original_file, $xmlChanges, $ruleObject, INT $security_rule_position, STRING $path="", INT $level=0){

        foreach($xmlChanges->childNodes as $node){
            $nodeName = $node->nodeName;
            switch ($nodeName){
                case "to":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "from":
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "source":
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "destination":
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "source-user":
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "category":
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "application":
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "service":
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "hip-profiles":
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                case "tag":
                    echo "$nodeName in $path is not yet supported\n";
                    break;


                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }
    */

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry
     * @param Mysqli $projectdb
     * @param STRING $source
     * @param STRING $devicegroup
     * @param STRING $vsys
     * @param DOMElement $original_file
     * @param DOMElement $xmlChanges
     * @param RuleObject $ruleObject_1
     * @param INT $security_rule_position
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRulesEntry($xmlChanges, &$security_rule_position, STRING $path = null, INT $level = null)
    {
        if(is_null($path)){
            $path ="";
        }
        if(is_null($level)){
            $level=0;
        }

        $ruleName = $xmlChanges->getAttribute('name');
        if (TRACE) echo "$ruleName (rulename in $path)\n";
        $ruleObject_1 = getSecRuleId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $ruleName);
        if (isset($ruleObject_1)) {
            // This rule exists and is being modified
            $modification = "modified";
            $modificationName = $xmlChanges->getAttribute('dm_update');
            if (isset($modificationName)) {
                // We are going to have an issue here. There is now a new rule with the same name!
                // TODO
                echo "We are going to have a problem here\n";
            } else {
                //
                // TODO
            }
        } else {
            // This rule does not exist in MT. It may have been renamed in MT or deleted.
            // TODO

            $newRule = initSecRule();
            $newRule['name'] = $ruleName;
            $newRule['position'] = $security_rule_position;
            $newRule['source'] = $this->source;
            $newRule['devicegroup'] = $this->devicegroup;
            $newRule['vsys'] = $this->vsys;
//            $pushed = pushSecRules($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $security_rule_position, 1);

            $matchingAddress = insertSecRule($this->projectdb, $newRule, "security_rules", $security_rule_position);
            $ruleObject_1 = new RuleObject($matchingAddress, "security_rules", $ruleName, "");
            $modification = "inserted";
//            if($pushed==1){
//                $security_rule_position++;
//            }

//        processChanges_SecRulesEntry($projectdb, $source, $devicegroup, $vsys, $original_file, $node, $ruleObject_1, $security_rule_position, $path."/".$nodeName, $level+1);
//        $security_rule_position++;  //We could not find this rule. It seems that the
        }

        // get the Rule Entry id
        $ruleName = $xmlChanges->getAttribute('name');
        if (TRACE) echo "RuleEntry $ruleName\n---------------\n";

        $attributePos = 0;
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    $count = $node->getAttribute('count');
                    $attributePos += $count;
                    break;
                case "dm:insert":
                    //TODO
                    // Adding a new attribute to the Rule, for instance, a Tag
                    $this->processChanges_SecRulesEntry_Insert($node, $ruleObject_1, $security_rule_position, $path."/".$nodeName, $level = 0);
                    break;
                case "dm:delete":
                    //TODO
                    if (DEBUG) echo "$nodeName in $path is not yet supported\n";
                    break;
                case "to":
                    $this->processChanges_SecRulesEntryGeneric($node, $modification, "to", $ruleObject_1, $path."/".$nodeName, $level + 1);
                    break;
                case "from":
                    $this->processChanges_SecRulesEntryGeneric($node, $modification, "from", $ruleObject_1, $path."/".$nodeName, $level + 1);
                    break;
                case "source":
                    $this->processChanges_SecRulesEntryGeneric($node, $modification, "source", $ruleObject_1, $path."/".$nodeName, $level + 1);
                    break;
                case "destination":
                    $this->processChanges_SecRulesEntryGeneric($node, $modification, "destination", $ruleObject_1, $path."/".$nodeName, $level + 1);
                    break;
                case "service":
                    $this->processChanges_SecRulesEntryGeneric($node, $modification, "service", $ruleObject_1, $path."/".$nodeName, $level + 1);
                    break;
//            case "source-user":
//                echo "$path -> ".$node->getAttribute('name')."\n";
////                processChanges_SecRulesEntrySource_User($original_file, $node, $path."/".$nodeName, $level+1);
//                break;
//            case "application":
//                echo "$path -> ".$node->getAttribute('name')."\n";
////                processChanges_SecRulesEntryApplication($original_file, $node, $path."/".$nodeName, $level+1);
//                break;
//            case "service":
//                echo "$path -> ".$node->getAttribute('name')."\n";
////                processChanges_SecRulesEntryService($original_file, $node, $path."/".$nodeName, $level+1);
//                break;
//            case "hip-profiles":
//                echo "$path -> ".$node->getAttribute('name')."\n";
////                processChanges_SecRulesEntryHip_Profiles($original_file, $node, $path."/".$nodeName, $level+1);
//                break;
                case "action":
                    $this->processChanges_SecRulesEntryAction($node, $ruleObject_1, $path."/".$nodeName, $level + 1);
                    break;
//            case "tag":
//                echo "$path -> ".$node->getAttribute('name')."\n";
////                processChanges_SecRulesEntryTag($original_file, $node, $path."/".$nodeName, $level+1);
//                break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
        if (TRACE) echo "---------------\n\n";

        if ($modification == "inserted") {
            $security_rule_position++;
        }
    }

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry/dm:insert
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param RuleObject $ruleObject
     * @param INT $security_rule_position
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRulesEntry_Insert($xmlChanges, $ruleObject, INT $security_rule_position, STRING $path = null, INT $level = null)
    {
        if(is_null($path)){
            $path ="";
        }
        if(is_null($level)){
            $level=0;
        }

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "tag":
                    $tagMembers = $node->getElementsByTagName('member');
                    foreach ($tagMembers as $tagMember) {
                        $tag_name = $tagMember->nodeValue;
                        $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                        $tagObject_1 = getTagId($this->projectdb, $this->source, $vsyses, $tag_name);
                        if (!isset($tagObject_1)) {
                            $tag = initTag();
                            $tag['name'] = $tag_name;
                            //The tag is not inserted yet, but we can create it now, and update it later when we find it in the XML
                            $tagObject_1 = createTagId($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $tag);
                        }
                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $tagObject_1, "tag", $ruleObject);
                    }
                    break;

                case "member":
                    //A member is deleted and inserted
                    echo "$nodeName in $path is not yet supported\n";
                    break;

                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry/service
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param RuleObject $ruleObject_1
     * @param STRING $path
     * @param INT $level
     */
    /*
    private function processChanges_SecRulesEntryService($projectdb, $source, $devicegroup, STRING $vsys, $original_file, $xmlChanges, RuleObject $ruleObject_1, STRING $path="", INT $level=0){
        foreach($xmlChanges->childNodes as $node){
            $nodeName = $node->nodeName;
            switch ($nodeName){
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    //TODO
                    processChanges_SecRulesEntryService_Insert($projectdb, $source, $devicegroup, $vsys, $original_file, $node, $ruleObject_1, $path."/".$nodeName, $level+1);
                    break;
                case "dm:delete":
                    processChanges_SecRulesEntryService_Delete($projectdb, $source, $devicegroup, $vsys, $original_file, $node, $ruleObject_1, $path."/".$nodeName, $level+1);
                    break;

                case "member":
                    //A member is deleted and inserted
                    processChanges_SecRulesEntryServiceMember($projectdb, $source, $devicegroup, $vsys, $original_file, $node, $ruleObject_1, $path."/".$nodeName, $level+1);
                    break;

                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }
    */

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry/service/member
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param RuleObject $ruleObject_1
     * @param STRING $path
     * @param INT $level
     */
    /*
    private function processChanges_SecRulesEntryServiceMember($projectdb, $source, $devicegroup, STRING $vsys, $original_file, $xmlChanges, RuleObject $ruleObject_1, STRING $path="", INT $level=0){
        $deleted  = array() ;
        $inserted = array() ;
        foreach($xmlChanges->childNodes as $node){
            $nodeName = $node->nodeName;
            switch ($nodeName){
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    if ($node->nodeValue != "any") {
                        $inserted[] = $node->nodeValue;
                        $serviceToInsert = getServiceId($projectdb, $source, $devicegroup, $vsys, $node->nodeValue);
                        insertSecRuleAttribute($projectdb, $source, $devicegroup, $vsys, $serviceToInsert, "service", $ruleObject_1);
                    }
                    break;
                case "dm:delete":
                    if ($node->nodeValue != "any") {
                        $deleted[] = $node->nodeValue;
                        $serviceToDelete = getServiceId($projectdb, $source, $devicegroup, $vsys, $node->nodeValue);
                        deleteSecRuleAttribute($projectdb, $source, $devicegroup, $vsys, $serviceToDelete, "service", $ruleObject_1);
                    }
                    break;
                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }
    */

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry/action
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param RuleObject $ruleObject_1
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRulesEntryAction($xmlChanges, RuleObject $ruleObject_1, STRING $path=null, INT $level = null)
    {
        if(is_null($path)){
            $path ="";
        }
        if(is_null($level)){
            $level=0;
        }

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    $action = new MemberObject($node->nodeValue, "");
                    updateSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $action, "action", $ruleObject_1);
                    break;
                case "dm:insert":
                    $action = new MemberObject($node->nodeValue, "");
                    updateSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $action, "action", $ruleObject_1);
                    break;
                case "dm:delete":
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
    }

    /*
    private function processChanges_SecRulesEntrySource($projectdb, $source, $devicegroup, STRING $vsys,$original_file, $xmlChanges, RuleObject $ruleObject_1, STRING $path="", INT $level=0){
        foreach($xmlChanges->childNodes as $node){
            $nodeName = $node->nodeName;
            switch ($nodeName){
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    //TODO
                    processChanges_SecRulesEntryDestination_Insert($projectdb, $source, $devicegroup, $vsys, $original_file, $node, $ruleObject_1, $path."/".$nodeName, $level+1);
                    break;
                case "member":
                    //A member is deleted and inserted
                    processChanges_SecRulesEntryDestinationMember($projectdb, $source, $devicegroup, $vsys, $original_file, $node, $ruleObject_1, $path."/".$nodeName, $level+1);
                    break;
                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }
    */

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry/service
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param RuleObject $ruleObject_1
     * @param STRING $field
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRulesEntryGeneric($xmlChanges, STRING $modification, STRING $field, RuleObject $ruleObject_1, STRING $path = null, INT $level = null)
    {
        if(is_null($path)){
            $path ="";
        }
        if(is_null($level)){
            $level=0;
        }

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    //TODO
                    $this->processChanges_SecRulesEntryGeneric_Insert($node, $field, $ruleObject_1, $path . "/" . $nodeName, $level + 1);
                    break;
                case "dm:delete":
                    if ($modification == "modified") {
                        $this->processChanges_SecRulesEntryGeneric_Delete($node, $field, $ruleObject_1, $path . "/" . $nodeName, $level + 1);
                    } elseif ($modification == "inserted") {
                        //This is a Rule that the diffxml says it changed, but actually it is not in the MT. Therefore, we are inserting it. There is nothing to dm:delete
                    }
                    break;
                case "member":
                    //A member is deleted and inserted
                    $this->processChanges_SecRulesEntryGenericMember($node, $modification, $field, $ruleObject_1, $path . "/" . $nodeName, $level + 1);
                    break;
                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry/destination/member
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param RuleObject $ruleObject_1
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRulesEntryGenericMember($xmlChanges, STRING $modification, STRING $field, RuleObject $ruleObject_1, STRING $path = null, INT $level = null)
    {
        if(is_null($path)){
            $path ="";
        }
        if(is_null($level)){
            $level=0;
        }

        $deleted = array();
        $inserted = array();
        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "dm:copy":
                    //TODO
                    echo "$nodeName in $path is not yet supported\n";
                    break;
                case "dm:insert":
                    if ($node->nodeValue != "any") {
                        $inserted[] = $node->nodeValue;
                        switch ($field) {
                            case "source":
                            case "destination":
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $memberToInsert = getMemberId($this->projectdb, $this->source, $vsyses, $node->nodeValue);
                                break;

                            case "service":
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $memberToInsert = getServiceId($this->projectdb, $this->source, $vsyses, $node->nodeValue);
                                break;

                            case "to":
                            case "from":
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $memberToInsert = getZoneId($this->projectdb, $this->source, $vsyses, $node->nodeValue);
                                break;

                            default:
                                echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
                        }

                        insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $memberToInsert, $field, $ruleObject_1);
                    }
                    break;
                case "dm:delete":
                    if ($modification == "modified") {
                        if ($node->nodeValue != "any") {
                            $deleted[] = $node->nodeValue;
                            switch ($field) {
                                case "source":
                                case "destination":
                                    $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                    $memberToDelete = getMemberId($this->projectdb, $this->source, $vsyses, $node->nodeValue);
                                    break;
                                case "service":
                                    $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                    $memberToDelete = getServiceId($this->projectdb, $this->source, $vsyses, $node->nodeValue);
                                    break;
                            }
                            deleteSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $memberToDelete, $field, $ruleObject_1);
                        }
                    } elseif ($modification == "inserted") {
//                    echo "I would not find this \"$node->nodeValue\" in Rule \"$ruleObject_1->name\" - \"$field\" because this rule does not exist anymore in the MT\n";
                        //This is a Rule that the diffxml says it changed, but actually it is not in the MT. Therefore, we are inserting it. There is nothing to dm:delete
                    }
                    break;
                default:
                    echo "$nodeName in $path not supported in ".__FUNCTION__." in ".__FILE__." at ".__LINE__."\n";
            }
        }
//    if (DEBUG) echo "DELETE \"".implode(',',$deleted)."\" AND INSERT \"".implode(',',$inserted)."\" IN Destination IN RULE \"$ruleObject_1->name\" \n";
    }

    protected function processChanges_SecRulesEntryGeneric_Insert($xmlChanges, STRING $field, RuleObject $ruleObject_1, STRING $path = null, INT $level = null)
    {
        if(is_null($path)){
            $path ="";
        }
        if(is_null($level)){
            $level=0;
        }

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "member":
                    $memberName = $node->nodeValue;
                    switch ($field) {
                        case "source":
                        case "destination":
                            $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                            $member = getMemberId($this->projectdb, $this->source, $vsyses, $memberName);
                            break;
                        case "service":
                            $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                            $member = getServiceId($this->projectdb, $this->source, $vsyses, $memberName);
                            break;
                    }
//                echo "INSERT \"$memberName\" ($member->name, $member->location) IN Destination IN RULE \"$ruleObject_1->name\" \n";
                    insertSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $member, $field, $ruleObject_1);
                    break;
                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }

    /** /config/devices/entry/vsys/entry/rulebase/security/rules/entry/service/dm:delete
     * @param $projectdb
     * @param $source
     * @param $devicegroup
     * @param STRING $vsys
     * @param $original_file
     * @param $xmlChanges
     * @param STRING $field
     * @param RuleObject $ruleObject_1
     * @param STRING $path
     * @param INT $level
     */
    protected function processChanges_SecRulesEntryGeneric_Delete($xmlChanges, STRING $field, RuleObject $ruleObject_1, STRING $path = null, INT $level = null)
    {
        if(is_null($path)){
            $path ="";
        }
        if(is_null($level)){
            $level=0;
        }

        foreach ($xmlChanges->childNodes as $node) {
            $nodeName = $node->nodeName;
            if (TRACE) echo "$nodeName\n";
            switch ($nodeName) {
                case "member":
                    $memberName = $node->nodeValue;
                    if (isset($memberName)) {
                        switch ($field) {
                            case "source":
                            case "destination":
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $memberToDelete = getMemberId($this->projectdb, $this->source, $vsyses, $node->nodeValue);
                                break;
                            case "service":
                                $vsyses = getVsyses($this->projectdb, $this->vsys, $this->source);
                                $memberToDelete = getServiceId($this->projectdb, $this->source, $vsyses, $node->nodeValue);
                                break;
                        }
                        deleteSecRuleAttribute($this->projectdb, $this->source, $this->devicegroup, $this->vsys, $memberToDelete, $field, $ruleObject_1);
                    }
                    break;
                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }

    /*
    private function processChanges_SecRulesEntryService_Insert($projectdb, $source, $devicegroup, STRING $vsys,$original_file, $xmlChanges, RuleObject $ruleObject_1, STRING $path="", INT $level=0){
        foreach($xmlChanges->childNodes as $node){
            $nodeName = $node->nodeName;
            switch ($nodeName){
                case "member":
                    $memberName = $node->nodeValue;
                    $member = getServiceId($projectdb, $source, $devicegroup, $vsys, $memberName);
    //                echo "INSERT \"$memberName\" ($member->name, $member->location) IN Destination IN RULE \"$ruleObject_1->name\" \n";
                    insertSecRuleAttribute($projectdb, $source, $devicegroup, $vsys, $member, "service", $ruleObject_1);
                    break;
                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }
    */

    /*
    private function processChanges_SecRulesEntryService_Delete($projectdb, $source, $devicegroup, STRING $vsys,$original_file, $xmlChanges, RuleObject $ruleObject_1, STRING $path="", INT $level=0){
        foreach($xmlChanges->childNodes as $node){
            $nodeName = $node->nodeName;
            switch ($nodeName){
                case "member":
                    $memberName = $node->nodeValue;
                    if(isset($memberName) && $memberName!="") {
                        $member = getMemberId($projectdb, $source, $devicegroup, $vsys, $memberName);
                        echo "DELETE \"$memberName\" ($member->name, $member->location) IN Destination IN RULE \"$ruleObject_1->name\" \n";
                        deleteSecRuleAttribute($projectdb, $source, $devicegroup, $vsys, $member, "service", $ruleObject_1);
                    }
                    break;
                default:
                    echo "Node $nodeName in $path is not supported\n";
            }
        }
    }
    */

    protected function sortXMLNodes_inFile(STRING $file_path)
    {
        $unsorted = new DOMDocument("1.0", "utf-8");
        $unsorted->preserveWhiteSpace = false;
        $unsorted->formatOutput = true;
        $unsorted->load($file_path);
        $resultCode = $this->sortXMLNodes($unsorted);
        $unsorted->C14NFile($file_path);
    }

    protected function sortXMLNodes(DOMDocument $xmlOriginal)
    {

        $config = $xmlOriginal->firstChild;
        foreach ($config->childNodes as $child) {
            $childName = $child->nodeName;
            switch ($childName) {
                case "mgt-config":
                    $result = $this->sortXML_subNode($child);
                    break;

                case "shared":
                    $result = $this->sortXML_subNode($child);
                    break;

                case "devices":
                    break;

                default:
                    echo "Node $childName not supported for sorting in sortXMLNodes()\n";
            }
        }
        return null;
    }

    protected function sortXML_subNode(DOMElement &$nodeOriginal)
    {

        $children = array();
        foreach ($nodeOriginal->childNodes as $child) {
            $childName = $child->nodeName;
            $children[$childName] = $child;
        }
        ksort($children);

        //Remove all the children, to insert them sorted afterwards
        while ($nodeOriginal->firstChild) {
            $nodeOriginal->removeChild($nodeOriginal->firstChild);
        }

        //Inserting the children, but sorted
        foreach ($children as $key => $child) {
            $nodeOriginal->appendChild($child);
        }

        return true;
    }

    public function processPANOSChanges()
    {

        $original_file_path = "../temp/original.xml";
        $modified_file_path = "../temp/modified.xml";
        $differences_file_path = "difference_rename_modify.xml";

//      Standarize the <config version="x.x.x"..> to help the getXMLofChanges to do its work
        $pattern = '/<config version="(.)*" /i';
        $pattern = '/<config version="(.\..\..)*" (.)*>/i';
        file_put_contents($original_file_path,
            preg_replace($pattern, '<config version="x.x.x"> ', file_get_contents($this->fileOld)));
        file_put_contents($modified_file_path,
            preg_replace($pattern, '<config version="x.x.x"> ', file_get_contents($this->fileNew)));


//      Sort Sortable nodes to avoid misleading Delete and Insert actions
        $this->sortXMLNodes_inFile($original_file_path);
        $this->sortXMLNodes_inFile($modified_file_path);

//      Look for updates in the PANOS configs
        $xml_of_changes = $this->getXMLofChanges($original_file_path, $modified_file_path);
        file_put_contents($differences_file_path, $xml_of_changes);


        $this->origXmlDoc = new DOMDocument("1.0", "utf-8");
        $this->origXmlDoc->preserveWhiteSpace = false;
        $this->origXmlDoc->formatOutput = true;
        $this->origXmlDoc->load($original_file_path);

        $this->diffXmlDoc = new DOMDocument("1.0", "utf-8");
        $this->diffXmlDoc->preserveWhiteSpace = false;
        $this->diffXmlDoc->formatOutput = true;
        $this->diffXmlDoc->load($differences_file_path);

//      echo utf8_decode($diffXmlDoc->saveHTML()); //Print the XML structure

        $this->processChanges();
    }
}
