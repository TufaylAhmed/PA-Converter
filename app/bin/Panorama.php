<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
	case 'GET':
		$action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
		$type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
		$project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
		$source 	= (string) 	(isset($_GET['source']) 	? $_GET['source'] : '');
		break;
	case 'POST':
		$action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
		$type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
		$project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
		$source 	= (string) 	(isset($_POST['source']) 	? $_POST['source'] : '');
		break;

	default:
		$action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
		$type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
		$project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
		$source 	= (string) 	(isset($_POST['source']) 	? $_POST['source'] : '');
		break;
}
//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']);

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$source = $projectdb->real_escape_string($source);

if ($action=="get"){

    if(!checkProjectRights($project,'view')){
        echo '{"total":"0","devicegroups":'.json_encode(array()).'}';
        return;
    }

	if($type=="devicegroups"){
//		$source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
		if ($source==0){$query="";}
		else{$query="WHERE source='$source'";}
		$getAll=$projectdb->query("SELECT id,name,master_device,devices,device_mapping_id,source,description,parent_dg FROM devicegroups $query;");
//		$myData[]=array("id"=>0, "name"=>"shared", "parent_dg"=>0, "device_mapping_id"=>0,"devices"=>"");
        $myData = array();
		while ($data=$getAll->fetch_object()){
			$mapid=$data->device_mapping_id;
			$k=$projectdb->query("SELECT vsys FROM device_mapping WHERE id='$mapid';");
            if ($k->num_rows==1){
                $datas=$k->fetch_assoc();
                $data->name=$datas['vsys'];
            }
			$parent_dg=$data->parent_dg;
			$q=$projectdb->query("SELECT vsys FROM device_mapping WHERE id='$parent_dg';");
			if ($q->num_rows==1){
                $datas=$q->fetch_assoc();
                $data->parent_dg_name=$datas['vsys'];
            }else{
                $data->parent_dg_name="shared";
                $parent_dg=0;
            }

            if ($data->devices!=""){
                $DataSerial=array();
                $device=simplexml_load_string($data->devices);

                foreach ($device as $entry){
                    if (isset($entry->vsys)){
                        $DataSerial[]="<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".(string)$entry->attributes()->name."/".$entry->vsys->entry->attributes()->name;
                    }
                    else{
                        $DataSerial[]="<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".(string)$entry->attributes()->name;
                    }

                }

                $data->devices=implode("<br>",$DataSerial);
            }

			$myData[]=$data;
		}

		echo '{"total":"'.count($myData).'","devicegroups":'.json_encode($myData).'}';
	}
	elseif($type=="templates"){
//		$source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
		if ($source==0){$query="";}
		else{$query="WHERE source='$source'";}
		$getAll=$projectdb->query("SELECT id,name,description,multi_vsys,operational_mode,vpn_disable_mode,devices,source,templates_mapping_id FROM templates $query;");
		$count=$getAll->num_rows;
		while ($data=$getAll->fetch_object()){
			$mapid=$data->templates_mapping_id;
			$k=$projectdb->query("SELECT name FROM templates_mapping WHERE id='$mapid';");
			$datas=$k->fetch_assoc();
			$data->name=$datas['name'];

            if ($data->devices!=""){
                $DataSerial=array();
                $device=simplexml_load_string($data->devices);

                foreach ($device as $entry){
                    if (isset($entry->vsys)){
                        $DataSerial[]="<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".(string)$entry->attributes()->name."/".$entry->vsys->entry->attributes()->name;
                    }
                    else{
                        $DataSerial[]="<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".(string)$entry->attributes()->name;
                    }

                }

                $data->devices=implode("<br>",$DataSerial);
            }

			$myData[]=$data;
		}
		if ($count==0){$myData="";}
		echo '{"total":"'.$count.'","templates":'.json_encode($myData).'}';
	}
}
elseif ($action=="set"){
	if ($type=="devicegroups"){

	    $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
		$source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
		$name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
		$description = $projectdb->real_escape_string((string) (isset($_POST['description']) ? $_POST['description'] : $_GET['description']));
		$device_mapping_id = $projectdb->real_escape_string((string) (isset($_POST['device_mapping_id']) ? $_POST['device_mapping_id'] : $_GET['device_mapping_id']));
        $parent_dg = $projectdb->real_escape_string(isset($_POST['parent_dg']) ? $_POST['parent_dg'] : '');

        take_snapshot_last($project);

        if($parent_dg == ''){
            //Find out the ID of the shared DG
            $query = "SELECT id from device_mapping WHERE vsys = 'shared'";
            $result = $projectdb->query($query);
            if($result->num_rows>0){
                $data = $result->fetch_assoc();
                $parent_dg = $data['id'];
            }
            else{
                $parent_dg = '';
            }
        }

		if (isset($description)){$description=addslashes($description);}

        $getMax=$projectdb->query("SELECT max(max_internal_id) as max_internal_id FROM devicegroups WHERE source='$source';");
        $max=0;
		if ($getMax->num_rows==1){
		    $getMaxData=$getMax->fetch_assoc();
		    $max=$getMaxData['max_internal_id'];
        }

		if ($id==""){
			#NEW
            $max++;
			$getDST=$projectdb->query("SELECT id,device,ispanorama,active,version,project,vsys,filename,map_devicegroup,map_vsys,baseconfig,vendor FROM device_mapping WHERE id='$source';");
			if ($getDST->num_rows>0){
				while ($DST=$getDST->fetch_assoc()){
					$DST["id"]="";
					$DST["vsys"]=$name;
					$projectdb->query("INSERT INTO device_mapping (".implode(", ",array_keys($DST)).") VALUES ('".implode("', '",array_values($DST))."')"); 	
					$device_mapping_id=$projectdb->insert_id;
				}
			}
			$projectdb->query("INSERT INTO devicegroups (description,source,device_mapping_id,parent_dg,max_internal_id,internal_id) VALUES ('$description','$source','$device_mapping_id','$parent_dg','$max','$max');");
		}
		else {
			#EDIT
			$getDST=$projectdb->query("SELECT vsys FROM device_mapping WHERE id ='$device_mapping_id';");

			if ($getDST->num_rows==1){
				$getDSTData=$getDST->fetch_assoc();
				$oldname=$getDSTData['vsys'];

				if ($oldname!=$name){
					$projectdb->query("UPDATE device_mapping SET vsys='$name' WHERE id='$device_mapping_id';");

					// Update all objects
                    $tables = [
                        "security_rules","nat_rules","appoverride_rules","authentication_rules","decryption_rules",
                        "address","address_groups_id","services","dos_rules","pbf_rules","qos_rules","tunnel_inspect_rules",
                        "captiveportal_rules","services_groups_id","applications","applications_groups_id","applications_filters",
                        "regions","tag","bpat_topic","cisco_nat_global","connectors_dg_devices","algosec_tags_mapping","appid_adoption_mapping",
                        "applications_from_log","applications_signatures","authentication_profile","authentication_sequence","certificate",
                        "certificate_profile","cisco_icmp_groups","cisco_policy_mapping","cisco_protocol_groups","connectors","device_usage",
                        "devicegroup_mapping","dhcp","dns_proxy","edit_table","external_list","tools_rename",
                        "fortinet_ippools","fortinet_vip","fortinet_vipgrp","group_mapping","hash","hash_rules","ike_crypto_profiles","global_protect_portal",
                        "global_protect_gateway","global_protect_mdm","global_protect_app_ipsec_crypto_profiles","ike_gateways_profiles",
                        "ipsec_crypto_profiles","ipsec_tunnel","proxy_id_ipsec_tunnel","interface_management_profile","interfaces","known_traffic_by_app",
                        "log_settings","monitor_profile","netscreen_dip","netscreen_dip_mapping","netscreen_natdst","ocsp_responder","override",
                        "pending_tasks","policy_filters","policy_filters_nat","profiles,profiles_groups","qos_interface","qos_profile","regions","reports",
                        "response_pages","routes_static","schedules","search_replace","server_profile","split_rules_unknown","relation_lid_rule_name",
                        "tmp_calc_zone","tmp_dup_name_val","tools_filters","ts_agent","unknown_traffic_by_app","user_id_agent","user_id_collector",
                        "virtual_routers","virtual_wires","vlans","zone_protection_profile","connectors_userid","zones","userid_from_log","custom_url_category"
                    ];

                    foreach ($tables as $table){
                        $projectdb->query(  "UPDATE $table SET vsys = '$name' WHERE vsys = '$oldname' AND source = '$source';");
                        //echo "UPDATE $table SET vsys = '$name' WHERE vsys = '$oldname' AND source = '$source';\n";
                    }
				}
				$projectdb->query("UPDATE devicegroups SET description='$description', parent_dg='$parent_dg' WHERE id='$id';");
			}
		}
		$projectdb->query("UPDATE devicegroups SET max_internal_id='$max' WHERE source='$source';");
	}
	elseif($type=="remove_devicegroup"){
		//take_snapshot_last($project);   //The snapshot will only take place if we really need to execute the modifications, not when the delete will be rejected because of trying to delete the shared
		$ids = $projectdb->real_escape_string((string) ($_POST['ids'] ?? $_GET['ids']));
		$source = $projectdb->real_escape_string((string) ($_POST['source'] ?? $_GET['source']));
		$alldata=explode(",",$ids);
		foreach ($alldata as $tuples){
			list($id, $name, $device_mapping_id) = explode(";",$tuples);
//			$id=$data[0];
//            $name=$data[1];
//            $device_mapping_id = $data[2];

            $entryTODelete =$projectdb->query("SELECT vsys,filename FROM device_mapping WHERE id='$id';");
            if($entryTODelete->num_rows>0){
                $dataToDelete = $entryTODelete->fetch_assoc();
                $filename =$dataToDelete['filename'];

                if($dataToDelete['vsys'] !== 'shared') {
                    take_snapshot_last($project);
                    $update_children_parent_dg = "UPDATE devicegroups SET parent_dg = (SELECT parent_dg FROM (SELECT parent_dg FROM devicegroups WHERE id='$id') t) WHERE parent_dg = '$id';";
                    $projectdb->query($update_children_parent_dg);

                    $projectdb->query("DELETE FROM devicegroups WHERE device_mapping_id='$device_mapping_id';");

//                    $getFilename = $projectdb->query("SELECT filename FROM device_mapping WHERE id='$source' AND vsys!='shared';");
//                    if ($getFilename->num_rows == 1) {
                       // $get = $getFilename->fetch_assoc();
                       // $filename = $get['filename'];
                        $result = $projectdb->query("SELECT id FROM device_mapping WHERE filename ='$filename' GROUP BY filename;");
                        if ($result->num_rows > 0) {
                            while ($data = $result->fetch_assoc()) {
                                $source = $data['id'];
                                #Delete by Source
                                $getTables = $projectdb->query("SHOW TABLES;");
                                $tables_list = array();
                                while ($data = $getTables->fetch_array()) {
                                    if (($data[0] == "config_views")
                                        || preg_match("/security_rules/",$data[0])
                                        || preg_match("/nat_rules/",$data[0])
                                        || preg_match("/appoverride_rules/",$data[0])
                                        || preg_match("/decryption_rules/",$data[0])
                                        || preg_match("/pbf_rules/",$data[0])
                                        || preg_match("/qos_rules/",$data[0])
                                        || ($data[0] === "tag")
                                    ){}
                                    else {
                                        $tables_list[] = $data[0];
                                    }
                                }
                                foreach ($tables_list as $value_table) {
                                    $projectdb->query("DELETE FROM $value_table WHERE source='$source' AND vsys='$name';");
                                }

                            }
                        }
                        $projectdb->query("DELETE FROM device_mapping WHERE id='$device_mapping_id';");

                        #Remove Security Rules
                        $getRules=$projectdb->query("SELECT id FROM security_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_security_rule($name, $source, $rulelids);
                        }

                        #Remove Nat Rules
                        $getRules=$projectdb->query("SELECT id FROM nat_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_nat_rule($name, $source, $rulelids);
                        }

                        #Remove AppOverride Rules
                        $getRules=$projectdb->query("SELECT id FROM appoverride_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_appoverride_rule($name, $source, $rulelids);
                        }

                        #Remove QoS Rules
                        $getRules=$projectdb->query("SELECT id FROM qos_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_qos_rule($name, $source, $rulelids);
                        }

                        #Remove PBF Rules
                        $getRules=$projectdb->query("SELECT id FROM pbf_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_pbf_rule($name, $source, $rulelids);
                        }

                        #Remove Decryption Rules
                        $getRules=$projectdb->query("SELECT id FROM decryption_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_decryption_rule($name, $source, $rulelids);
                        }

                        #Remove Tunnel Inspection Rules
                        $getRules=$projectdb->query("SELECT id FROM tunnel_inspect_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_tunnel_inspect_rules($name, $source, $rulelids);
                        }

                        #Remove Authentication Rules
                        $getRules=$projectdb->query("SELECT id FROM authentication_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_authentication_rules($name, $source, $rulelids);
                        }

                        #Remove Captive Portal Rules
                        $getRules=$projectdb->query("SELECT id FROM captiveportal_rules WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_captiveportal_rules($name, $source, $rulelids);
                        }

                        #Remove Address Groups and Members
                        $getRules=$projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_address_group($name, $source, $rulelids);
                        }

                        #Remove Service Groups and Members
                        $getRules=$projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_services_group($name, $source, $rulelids);
                        }

                        #Remove Application Groups and Members
                        $getRules=$projectdb->query("SELECT id FROM applications_groups_id WHERE source='$source' AND vsys='$name';");
                        if ($getRules->num_rows>0){
                            $rulelids='';$ruleids=array();
                            while ($getRulesData=$getRules->fetch_assoc()){
                                $ruleids[]=$getRulesData['id'];
                            }
                            $rulelids=implode(",",$ruleids);
                            delete_application_group($name, $source, $rulelids);
                        }

                        echo json_encode(array('success' => true));

                }
                else{
                    echo json_encode(array('success' => false, 'msg'=>'DG Shared cannot be removed.'));
                }
            }
            else{
                echo json_encode(array('success' => false, 'msg'=>'No DGs found for this configuration'));
            }
		}
	}
	elseif ($type=="templates"){
		$id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
		$source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
		$name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
		$description = $projectdb->real_escape_string((string) (isset($_POST['description']) ? $_POST['description'] : $_GET['description']));
		$templates_mapping_id = $projectdb->real_escape_string((string) (isset($_POST['templates_mapping_id']) ? $_POST['templates_mapping_id'] : $_GET['templates_mapping_id']));
		$multi_vsys = $projectdb->real_escape_string((string) (isset($_POST['multi_vsys']) ? $_POST['multi_vsys'] : ''));
		$operational_mode = $projectdb->real_escape_string((string) (isset($_POST['operational_mode']) ? $_POST['operational_mode'] : ''));
		$vpn_disable_mode = $projectdb->real_escape_string((string) (isset($_POST['vpn_disable_mode']) ? $_POST['vpn_disable_mode'] : ''));
                if (isset($description)){$description=addslashes($description);}
		if ($id==""){
			#NEW
			$getDST=$projectdb->query("SELECT filename FROM device_mapping WHERE id='$source';");
			if ($getDST->num_rows==1){
				$getDSTData=$getDST->fetch_object();
				$filename=$getDSTData->filename;
				$projectdb->query("INSERT INTO templates_mapping (name,filename,source,project) VALUES ('$name','$filename','$source','$project');");
				$templates_mapping_id=$projectdb->insert_id;
				if ($multi_vsys!="yes"){$multi_vsys="no";} if ($vpn_disable_mode!="yes"){$vpn_disable_mode="no";}
				$projectdb->query("INSERT INTO templates (description,multi_vsys,operational_mode,vpn_disable_mode,source,templates_mapping_id) VALUES ('$description','$multi_vsys','$operational_mode','$vpn_disable_mode','$source','$templates_mapping_id');");
			}
		}
		else {
			#EDIT
			$getDST=$projectdb->query("SELECT name FROM templates_mapping WHERE id ='$templates_mapping_id';");
			if ($getDST->num_rows==1){
				$getDSTData=$getDST->fetch_assoc();
				$oldname=$getDSTData['name'];
				if ($oldname!=$name){
					$projectdb->query("UPDATE templates_mapping SET name='$name' WHERE id='$templates_mapping_id';");
				}
				$projectdb->query("UPDATE templates SET name='$name',description='$description', multi_vsys='$multi_vsys',operational_mode='$operational_mode',vpn_disable_mode='$vpn_disable_mode' WHERE id='$id';");
			}
			
		}
		echo json_encode(array('success'=>true)); 
	}
	elseif($type=="remove_template"){
		take_snapshot_last($project);
		$ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
		$source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
		$alldata=explode(",",$ids);
		foreach ($alldata as $tuples){
			$data=explode(";",$tuples);
			$name=$data[1];
			$template=$data[0];
			$templates_mapping_id=$data[2];
			$projectdb->query("DELETE FROM templates WHERE id='$template';");
			
			$getFilename=$projectdb->query("SELECT filename FROM device_mapping WHERE id='$source';");
			if ($getFilename->num_rows==1){
				$get=$getFilename->fetch_assoc();
				$filename=$get['filename'];
				$result=$projectdb->query("SELECT id FROM device_mapping WHERE filename ='$filename' GROUP BY filename;");
				if ($result->num_rows>0){
					while($data=$result->fetch_assoc()){
						$source=$data['id'];
						#Delete by Source
						$getTables=$projectdb->query("SHOW TABLES;");
						$tables_list=array();
						while($data=$getTables->fetch_array()){
							if ($data[0]!=""){
								$tables_list[]=$data[0];
							}
						}
						foreach($tables_list as $value_table){
							$projectdb->query("DELETE FROM $value_table WHERE source='$source' AND template='$template';");
						}
			
					}
				}
				$projectdb->query("DELETE FROM templates_mapping WHERE id='$templates_mapping_id';");

			}
		}
        echo json_encode(array('success'=>true));
    }
}
?>