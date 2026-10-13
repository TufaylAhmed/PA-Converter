<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/database.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
//        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $MTvsys     = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $connector  = (string)  (isset($_GET['connector'])  ? $_GET['connector'] : ''); // connectorn ID
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        $rulelid    = (string)  (isset($_GET['rulelid'])    ? $_GET['rulelid'] : '');

        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
//        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $MTvsys     = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $connector  = (string)  (isset($_POST['connector']) ? $_POST['connector'] : ''); // connectorn ID
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $rulelid    = (string)  (isset($_POST['rulelid'])   ? $_POST['rulelid'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
//        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $MTvsys     = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $connector  = (string)  (isset($_POST['connector']) ? $_POST['connector'] : ''); // connectorn ID
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $rulelid    = (string)  (isset($_POST['rulelid'])   ? $_POST['rulelid'] : '');

        break;
}
//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$MTvsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//$project="USERANDAPPS";
//$action="send_api_calls";

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$project = $projectdb->real_escape_string($project);
$MTvsys = $projectdb->real_escape_string($MTvsys);
$connector = $projectdb->real_escape_string($connector);
$source = $projectdb->real_escape_string($source);
$rulelid = $projectdb->real_escape_string($rulelid);

if ($action == "retrieve_appid_by_rule") {
//    $connector = (string) (isset($_POST['connector']) ? $_POST['connector'] : $_GET['connector']); // connectorn ID
//    $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
    $panorama = false;
    $target = "";

    #check if the Source is panorama but the logs has to be retrieved from the Firewall isntead of Panorama
    $isPanoramaSource = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE id='$source';");
    if ($isPanoramaSource->num_rows == 1) {
        $getPanoramaSource = $isPanoramaSource->fetch_assoc();
        if ($getPanoramaSource['ispanorama'] == 1) {
            $sourcePanorma = true;
        } else {
            $sourcePanorma = false;
        }
    }

    $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime,top FROM connectors WHERE id='$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnVendor = $data['vendor'];
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        $ConnPanorama = $data['panorama'];
        $ConnPeriod = $data['period'];
        $ConnStart = $data['startdate'] . " " . $data['starttime'];
        $ConnEnd = $data['enddate'] . " " . $data['endtime'];
        $ConnTop = $data['top'];

        #Get Device
        $getDevice = $pandbRBAC->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        //echo "SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';";
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_api_key = $datadevice['api_key'];
            $device_hostname = $datadevice['hostname'];
            $device_ispanorama = $datadevice['ispanorama'];
            $device_port = $datadevice['port'];
            $device_serial = $datadevice['serial'];
            $device_id = $datadevice['id'];
            $device = $datadevice['device'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];

            if ($ConnPanorama == "1") {
                $panorama = TRUE;
                $getDG = $projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND devicegroup='$MTvsys' AND active=1;");
                if ($getDG->num_rows > 0) {
                    $dg_query = array();
                    while ($getDGData = $getDG->fetch_assoc()) {
                        $dg_serial = $getDGData['serial'];
                        $dg_vsys = $getDGData['vsys'];
                        $dg_query[] = "(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                    }
                    $dg_query_all = "(" . implode(" OR ", $dg_query) . ")";
                } else {
                    $dg_query_all = "";
                }
            } else {
                # Check if we have the API key or we need to use Panorama as a PROXY
                if ($device_api_key == "") {
                    $getPanorama = $pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
                    if ($getPanorama->num_rows == 1) {
                        $getPanoramaData = $getPanorama->fetch_assoc();
                        $device_hostname = $getPanoramaData['hostname'];
                        $device_port = $getPanoramaData['port'];
                        $panorama_devicename = $getPanoramaData['name'];
                        $device_api_key = $getPanoramaData['api_key'];
                        $target = $device_serial;
                    }
                }
                if ($ConnVsys == "all") {
                    $dg_query_all = "";
                } else {
                    $dg_query_all = "(vsys eq '$ConnVsys')";
                }
            }
        }
        else {
            echo json_encode(array('success' => false, 'message' => 'The Device doesn\'t exist.'));
            exit(0);
        }

        $projectdb->query("TRUNCATE TABLE project_status;");
        add_progress($project, '0.00', 'Retrieving Reports');
        take_snapshot_last($project);

        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $data = (string) (isset($_GET['data']) ? $_GET['data'] : '');
                break;
            case 'POST':
                $data = (string) (isset($_POST['data']) ? $_POST['data'] : '');
                break;

            default:
                $data = (string) (isset($_POST['data']) ? $_POST['data'] : '');

                break;
        }
//        $data = (string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']);

        $data = $projectdb->real_escape_string($data);

        if ($data != "") {
            $rules = explode(",", $data);
            $tuCurl = curl_init();
            $theRules = array();
            $theRulesTotal = array();
            $delete = array();
            $allrules = count($rules);
            $x = 0;

            foreach ($rules as $key => $value) {
                $thedata2 = explode(";", $value);
                $rule_lid = $thedata2[0];
                $rulename = $thedata2[1];

                $projectdb->query("DELETE FROM split_rules_unknown WHERE rule_lid='$rule_lid';");
                $x++;
                if ($panorama == FALSE) {

                    if ($target != "") {
                        # USe Panorama as a Proxy to retrueve the reports.
                        if ($model == "pa7000") {
                            $theRules = get_dynamic_report_appsbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                        } else {
                            $theRules = get_dynamic_report_appsbyrule_panos($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                        }
                    } else {
                        if ($model == "pa7000") {
                            $theRules = get_dynamic_report_appsbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                        } else {
                            $theRules = get_dynamic_report_appsbyrule_panos($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                        }
                    }
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO applications_from_log (source,vsys,rule_lid,app,dport,bytes,packets,proto,date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                } else {
                    $theRules = get_dynamic_report_appsbyrule_panorama($MTvsys, $tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, "",$target, $ConnTop);

                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO applications_from_log (source,vsys,rule_lid,app,dport,bytes,packets,proto,date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                }
                $progress = $x / $allrules;
                if ($progress == 1) {
                    $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
                    update_progress($project, '1.00', 'Finished.');
                    //sleep(4); update_progress($project,'0.00','Ready.');
                } else {
                    update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                }
            }
            curl_close($tuCurl);

            echo json_encode(array('success' => true));
        } else {
            $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
            update_progress($project, '1.00', 'Finished.');
            echo json_encode(array('success' => true));
        }
    }
    else {
        echo json_encode(array('success' => false, 'message' => 'The connector doesn\'t exist.'));
        exit(0);
    }
} 
elseif ($action == "activate") {
    $panorama = false;
    $target = "";

    #check if the Source is panorama but the logs has to be retrieved from the Firewall isntead of Panorama
    $isPanoramaSource = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE id='$source';");
    if ($isPanoramaSource->num_rows == 1) {
        $getPanoramaSource = $isPanoramaSource->fetch_assoc();
        if ($getPanoramaSource['ispanorama'] == 1) {
            $sourcePanorma = true;
        } else {
            $sourcePanorma = false;
        }
    }

    $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime,top FROM connectors WHERE id='$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnVendor = $data['vendor'];
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        $ConnPanorama = $data['panorama'];
        $ConnPeriod = $data['period'];
        $ConnStart = $data['startdate'] . " " . $data['starttime'];
        $ConnEnd = $data['enddate'] . " " . $data['endtime'];
        $ConnTop = $data['top'];

        #Get Device
        $getDevice = $pandbRBAC->query("SELECT id,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_serial = $datadevice['serial'];
            $device_ispanorama = $datadevice['ispanorama'];
            if ($ConnPanorama==0){
                $role="admin";
                $keyName=$device_serial."_".$role;
                $getKey=$pandbRBAC->query("SELECT api_key FROM device_keys WHERE role='$role' AND key_name='$keyName';");
                if ($getKey->num_rows==1){
                    $getKeyData=$getKey->fetch_assoc();
                    $device_api_key = $getKeyData['api_key'];
                }
            }


            $device_hostname = $datadevice['hostname'];
            $device_port = $datadevice['port'];
            $device_id = $datadevice['id'];
            $device = $datadevice['device'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];

            if ($ConnPanorama == "1") {
                $panorama = TRUE;
                $getDG = $projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND devicegroup='$MTvsys' AND active=1;");
                if ($getDG->num_rows > 0) {
                    $dg_query = array();
                    while ($getDGData = $getDG->fetch_assoc()) {
                        $dg_serial = $getDGData['serial'];
                        $dg_vsys = $getDGData['vsys'];
                        $dg_query[] = "(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                    }
                    $dg_query_all = "(" . implode(" OR ", $dg_query) . ")";
                } else {
                    $dg_query_all = "";
                }
            } else {
                # Check if we have the API key or we need to use Panorama as a PROXY
                if ($device_api_key == "") {
                    $getPanorama = $pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
                    if ($getPanorama->num_rows == 1) {
                        $getPanoramaData = $getPanorama->fetch_assoc();
                        $device_hostname = $getPanoramaData['hostname'];
                        $device_port = $getPanoramaData['port'];
                        $panorama_devicename = $getPanoramaData['name'];
                        $device_api_key = $getPanoramaData['api_key'];
                        $target = $device_serial;
                    }
                }
                if ($ConnVsys == "all") {
                    $dg_query_all = "";
                } else {
                    $dg_query_all = "(vsys eq '$ConnVsys')";
                }
            }
        } else {
            echo json_encode(array('success' => false, 'message' => 'The Device doesn\'t exist.'));
            exit(0);
        }

        $projectdb->query("TRUNCATE TABLE project_status;");
        add_progress($project, '0.00', 'Retrieving Reports');

        #Retrieve Active and Allowed Rules
        $getRulesActive = $projectdb->query("SELECT id, name FROM security_rules WHERE disabled=0 AND action='allow' AND source='$source' AND vsys='$MTvsys';");

        if ($getRulesActive->num_rows > 0) {
            take_snapshot_last($project);

            $projectdb->query("DELETE FROM split_rules_unknown WHERE source='$source' AND vsys='$MTvsys';");
            //$projectdb->query("DELETE FROM split_rules_appid WHERE source='$source' AND vsys='$MTvsys';");
            $tuCurl = curl_init();
            $theRules = array();
            $theRulesTotal = array();
            $delete = array();
            $allrules = $getRulesActive->num_rows;
            $x = 0;
            while ($ruledata = $getRulesActive->fetch_assoc()) {
                $rulename = $ruledata['name'];
                $rule_lid = $ruledata['id'];
                $x++;

                if ($panorama == FALSE) {

                    if ($target != "") {
                        # USe Panorama as a Proxy to retrueve the reports.
                        if ($model == "pa7000") {
                            $theRules = get_dynamic_report_appsbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                        } else {
                            $theRules = get_dynamic_report_appsbyrule_panos($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                        }
                    } else {
                        if ($model == "pa7000") {
                            $theRules = get_dynamic_report_appsbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                        } else {
                            $theRules = get_dynamic_report_appsbyrule_panos($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                        }
                    }
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO applications_from_log (source,vsys,rule_lid,app,dport,bytes,packets,proto,date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                } else {
                    $theRules = get_dynamic_report_appsbyrule_panorama($MTvsys, $tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, "",$target, $ConnTop);

                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO applications_from_log (source,vsys,rule_lid,app,dport,bytes,packets,proto,date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                }
                $progress = $x / $allrules;
                if ($progress == 1) {
                    $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
                    update_progress($project, '1.00', 'Finished.');
                } else {
                    update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                }
            }
            curl_close($tuCurl);
            echo json_encode(array('success' => true));
        } else {
            $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
            update_progress($project, '1.00', 'Finished.');
            echo json_encode(array('success' => true));
        }
    } else {
        echo json_encode(array('success' => false, 'message' => 'The connector doesn\'t exist.'));
        exit(0);
    }
} 
elseif ($action == "retrieve_userid_by_rule") {
//    $connector = (string) (isset($_POST['connector']) ? $_POST['connector'] : $_GET['connector']); // connectorn ID
//    $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
    $panorama = false;
    $target = "";

    #check if the Source is panorama but the logs has to be retrieved from the Firewall isntead of Panorama
    $isPanoramaSource = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE id='$source';");
    if ($isPanoramaSource->num_rows == 1) {
        $getPanoramaSource = $isPanoramaSource->fetch_assoc();
        if ($getPanoramaSource['ispanorama'] == 1) {
            $sourcePanorma = true;
        } else {
            $sourcePanorma = false;
        }
    }

    $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime FROM connectors WHERE id='$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnVendor = $data['vendor'];
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        $ConnPanorama = $data['panorama'];
        $ConnPeriod = $data['period'];
        $ConnStart = $data['startdate'] . " " . $data['starttime'];
        $ConnEnd = $data['enddate'] . " " . $data['endtime'];

        #Get Device
        $getDevice = $pandb->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_api_key = $datadevice['api_key'];
            $device_hostname = $datadevice['hostname'];
            $device_ispanorama = $datadevice['ispanorama'];
            $device_port = $datadevice['port'];
            $device_serial = $datadevice['serial'];
            $device_id = $datadevice['id'];
            $device = $datadevice['device'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];

            if ($ConnPanorama == "1") {
                $panorama = TRUE;
                $getDG = $projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND devicegroup='$MTvsys' AND active=1;");
                if ($getDG->num_rows > 0) {
                    $dg_query = array();
                    while ($getDGData = $getDG->fetch_assoc()) {
                        $dg_serial = $getDGData['serial'];
                        $dg_vsys = $getDGData['vsys'];
                        $dg_query[] = "(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                    }
                    $dg_query_all = "(" . implode(" OR ", $dg_query) . ")";
                } else {
                    $dg_query_all = "";
                }
            } else {
                # Check if we have the API key or we need to use Panorama as a PROXY
                if ($device_api_key == "") {
                    $getPanorama = $pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
                    if ($getPanorama->num_rows == 1) {
                        $getPanoramaData = $getPanorama->fetch_assoc();
                        $device_hostname = $getPanoramaData['hostname'];
                        $device_port = $getPanoramaData['port'];
                        $panorama_devicename = $getPanoramaData['name'];
                        $device_api_key = $getPanoramaData['api_key'];
                        $target = $device_serial;
                    }
                }
                if ($ConnVsys == "all") {
                    $dg_query_all = "";
                } else {
                    $dg_query_all = "(vsys eq '$ConnVsys')";
                }
            }
        } else {
            echo json_encode(array('success' => false, 'message' => 'The Device doesn\'t exist.'));
            exit(0);
        }

        $projectdb->query("TRUNCATE TABLE project_status;");
        add_progress($project, '0.00', 'Retrieving Reports');
        take_snapshot_last($project);
        #Retrieve Active and Allowed Rules
        #This is to retrieve logs without vsys because the source is panorama vys=devicegroup but the collector is a vsys
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $data = (string) (isset($_GET['data']) ? $_GET['data'] : '');

                break;
            case 'POST':
                $data = (string) (isset($_POST['data']) ? $_POST['data'] : '');
                break;

            default:
                $data = (string) (isset($_POST['data']) ? $_POST['data'] : '');

                break;
        }

        $data = $projectdb->real_escape_string($data);

        if ($data != "") {
            $rules = explode(",", $data);

            $tuCurl = curl_init();
            $theRules = array();
            $theRulesTotal = array();
            $delete = array();
            $allrules = count($rules);
            $x = 0;

            foreach ($rules as $key => $value) {

                $thedata2 = explode(";", $value);
                $rule_lid = $thedata2[0];
                $rulename = $thedata2[1];
                $x++;

                if ($panorama == FALSE) {
                    # USe Panorama as a Proxy to retrueve the reports.
                    if ($model == "pa7000") {
                        $theRules = get_dynamic_report_usersbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target);
                    } else {
                        $theRules = get_dynamic_report_usersbyrule_panos($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target);
                    }
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO userid_from_log (source, vsys, rule_lid, name, bytes, sessions, date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                } else {
                    $theRules = get_dynamic_report_usersbyrule_panorama($MTvsys, $tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target);
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO userid_from_log (source, vsys, rule_lid, name, bytes, sessions, date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                }
                $progress = $x / $allrules;
                if ($progress == 1) {
                    $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
                    update_progress($project, '1.00', 'Finished.');
                    //sleep(4); update_progress($project,'0.00','Ready.');
                } else {
                    update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                }
            }
            curl_close($tuCurl);

            echo json_encode(array('success' => true));
        } else {
            $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
            update_progress($project, '1.00', 'Finished.');
            echo json_encode(array('success' => true));
            //sleep(4); update_progress($project,'0.00','Ready.');
        }
    } else {
        echo json_encode(array('success' => false, 'message' => 'The connector doesn\'t exist.'));
        exit(0);
    }
} 
elseif ($action == "activate_userid") {
//    $connector = (string) (isset($_POST['connector']) ? $_POST['connector'] : $_GET['connector']); // connectorn ID
//    $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
    $panorama = false;
    $target = "";

    #check if the Source is panorama but the logs has to be retrieved from the Firewall isntead of Panorama
    $isPanoramaSource = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE id='$source';");
    if ($isPanoramaSource->num_rows == 1) {
        $getPanoramaSource = $isPanoramaSource->fetch_assoc();
        if ($getPanoramaSource['ispanorama'] == 1) {
            $sourcePanorma = true;
        } else {
            $sourcePanorma = false;
        }
    }

    $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime FROM connectors WHERE id='$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnVendor = $data['vendor'];
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        $ConnPanorama = $data['panorama'];
        $ConnPeriod = $data['period'];
        $ConnStart = $data['startdate'] . " " . $data['starttime'];
        $ConnEnd = $data['enddate'] . " " . $data['endtime'];

        #Get Device
        $getDevice = $pandb->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_api_key = $datadevice['api_key'];
            $device_hostname = $datadevice['hostname'];
            $device_ispanorama = $datadevice['ispanorama'];
            $device_port = $datadevice['port'];
            $device_serial = $datadevice['serial'];
            $device_id = $datadevice['id'];
            $device = $datadevice['device'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];

            if ($ConnPanorama == "1") {
                $panorama = TRUE;
                $getDG = $projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND devicegroup='$MTvsys' AND active=1;");
                if ($getDG->num_rows > 0) {
                    $dg_query = array();
                    while ($getDGData = $getDG->fetch_assoc()) {
                        $dg_serial = $getDGData['serial'];
                        $dg_vsys = $getDGData['vsys'];
                        $dg_query[] = "(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                    }
                    $dg_query_all = "(" . implode(" OR ", $dg_query) . ")";
                } else {
                    $dg_query_all = "";
                }
            } else {
                # Check if we have the API key or we need to use Panorama as a PROXY
                if ($device_api_key == "") {
                    $getPanorama = $pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
                    if ($getPanorama->num_rows == 1) {
                        $getPanoramaData = $getPanorama->fetch_assoc();
                        $device_hostname = $getPanoramaData['hostname'];
                        $device_port = $getPanoramaData['port'];
                        $panorama_devicename = $getPanoramaData['name'];
                        $device_api_key = $getPanoramaData['api_key'];
                        $target = $device_serial;
                    }
                }
                if ($ConnVsys == "all") {
                    $dg_query_all = "";
                } else {
                    $dg_query_all = "(vsys eq '$ConnVsys')";
                }
            }
        } else {
            echo json_encode(array('success' => false, 'message' => 'The Device doesn\'t exist.'));
            exit(0);
        }

        $projectdb->query("TRUNCATE TABLE project_status;");
        add_progress($project, '0.00', 'Retrieving Reports');

        #Retrieve Active and Allowed Rules
        $getRulesActive = $projectdb->query("SELECT id, name, vsys FROM security_rules WHERE disabled=0 AND action='allow' AND source='$source' AND vsys='$MTvsys';");

        if ($getRulesActive->num_rows > 0) {
            take_snapshot_last($project);

            $tuCurl = curl_init();
            $theRules = array();
            $theRulesTotal = array();
            $delete = array();
            $allrules = $getRulesActive->num_rows;
            $x = 0;

            while ($ruledata = $getRulesActive->fetch_assoc()) {
                $rulename = $ruledata['name'];
                $rule_lid = $ruledata['id'];
                $x++;

                if ($panorama == FALSE) {
                    # USe Panorama as a Proxy to retrueve the reports.
                    if ($model == "pa7000") {
                        $theRules = get_dynamic_report_usersbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target);
                    } else {
                        $theRules = get_dynamic_report_usersbyrule_panos($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target);
                    }
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO userid_from_log (source, vsys, rule_lid, name, bytes, sessions, date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                } else {
                    $theRules = get_dynamic_report_usersbyrule_panorama($MTvsys, $tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target);
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO userid_from_log (source, vsys, rule_lid, name, bytes, sessions, date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                }
                $progress = $x / $allrules;
                if ($progress == 1) {
                    $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
                    update_progress($project, '1.00', 'Finished.');
                } else {
                    update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                }
            }
            curl_close($tuCurl);

            echo json_encode(array('success' => true));
        } else {
            $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
            update_progress($project, '1.00', 'Finished.');
            echo json_encode(array('success' => true));
        }
    } else {
        echo json_encode(array('success' => false, 'message' => 'The connector doesn\'t exist.'));
        exit(0);
    }
} 
elseif ($action == "investigate") {
//    $connector = (string) (isset($_POST['connector']) ? $_POST['connector'] : $_GET['connector']); // connectorn ID
//    $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
    $panorama = false;
    $target = "";

    #check if the Source is panorama but the logs has to be retrieved from the Firewall isntead of Panorama
    $isPanoramaSource = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE id='$source';");
    if ($isPanoramaSource->num_rows == 1) {
        $getPanoramaSource = $isPanoramaSource->fetch_assoc();
        if ($getPanoramaSource['ispanorama'] == 1) {
            $sourcePanorma = true;
        } else {
            $sourcePanorma = false;
        }
    }

    $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime FROM connectors WHERE id='$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnVendor = $data['vendor'];
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        $ConnPanorama = $data['panorama'];
        $ConnPeriod = $data['period'];
        $ConnStart = $data['startdate'] . " " . $data['starttime'];
        $ConnEnd = $data['enddate'] . " " . $data['endtime'];

        #Get Device
        $getDevice = $pandb->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_api_key = $datadevice['api_key'];
            $device_hostname = $datadevice['hostname'];
            $device_ispanorama = $datadevice['ispanorama'];
            $device_port = $datadevice['port'];
            $device_serial = $datadevice['serial'];
            $device_id = $datadevice['id'];
            $device = $datadevice['device'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];

            if ($ConnPanorama == "1") {
                $panorama = TRUE;
                $getDG = $projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND devicegroup='$MTvsys' AND active=1;");
                if ($getDG->num_rows > 0) {
                    $dg_query = array();
                    while ($getDGData = $getDG->fetch_assoc()) {
                        $dg_serial = $getDGData['serial'];
                        $dg_vsys = $getDGData['vsys'];
                        $dg_query[] = "(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                    }
                    $dg_query_all = "(" . implode(" OR ", $dg_query) . ")";
                } else {
                    $dg_query_all = "";
                }
            } else {
                # Check if we have the API key or we need to use Panorama as a PROXY
                if ($device_api_key == "") {
                    $getPanorama = $pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
                    if ($getPanorama->num_rows == 1) {
                        $getPanoramaData = $getPanorama->fetch_assoc();
                        $device_hostname = $getPanoramaData['hostname'];
                        $device_port = $getPanoramaData['port'];
                        $panorama_devicename = $getPanoramaData['name'];
                        $device_api_key = $getPanoramaData['api_key'];
                        $target = $device_serial;
                    }
                }
                if ($ConnVsys == "all") {
                    $dg_query_all = "";
                } else {
                    $dg_query_all = "(vsys eq '$ConnVsys')";
                }
            }
        } else {
            echo json_encode(array('success' => false, 'message' => 'The Device doesn\'t exist.'));
            exit(0);
        }

        $projectdb->query("TRUNCATE TABLE project_status;");
        add_progress($project, '0.00', 'Retrieving Reports'); #print "DELETE FROM unknown_traffic_by_app WHERE vsys='$vsys' AND source='$source';";


        $getRulesUnk = $projectdb->query("SELECT original_rule_lid,rule_lid,source,vsys FROM split_rules_unknown;");
        if ($getRulesUnk->num_rows > 0) {
            take_snapshot_last($project);
            $allrules = $getRulesUnk->num_rows;
            $x = 0;
            while ($data = $getRulesUnk->fetch_assoc()) {
                $original_rule_lid = $data['original_rule_lid'];
                $rule_lid = $data['rule_lid'];
                $source = $data['source'];
                $vsys = $data['vsys'];


                #Clean First by vsys
                $projectdb->query("DELETE FROM unknown_traffic_by_app WHERE vsys='$vsys' AND source='$source';");

                $getRuleName = $projectdb->query("SELECT name FROM security_rules WHERE id='$original_rule_lid';");
                $x++;
                if ($getRuleName->num_rows == 1) {
                    $getdata = $getRuleName->fetch_assoc();
                    $rulename = $getdata['name'];

                    $getUnkApp = $projectdb->query("SELECT app,dport FROM applications_from_log WHERE rule_lid='$rule_lid';");
                    if ($getUnkApp->num_rows > 0) {
                        $tuCurl = curl_init();
                        $theTraffic = array();
                        $content = array();
                        while ($data2 = $getUnkApp->fetch_assoc()) {
                            $app = $data2['app'];
                            $dport = $data2['dport'];
                            if ($panorama == FALSE) {
                                if ($model == "pa7000") {
                                    $theTraffic[] = get_dynamic_report_appsbyrule_destination_pa7000($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target);
                                } else {
                                    $theTraffic[] = get_dynamic_report_appsbyrule_destination_panos($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target);
                                }
                            } else {
                                $theTraffic[] = get_dynamic_report_appsbyrule_destination_panorama($ConnVsys, $tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target);
                            }
                        }
                        curl_close($tuCurl);
                        if (count($theTraffic) > 0) {
                            foreach ($theTraffic as $kkey => $vvalue) {
                                foreach ($vvalue as $key => $value) {
                                    $content[] = $value;
                                }
                            }
                        }
                        if (count($content) > 0) {
                            $out = implode(",", $content);
                            $query = "INSERT INTO unknown_traffic_by_app (source,vsys,rule_lid,app,dport,dst,proto,packets,bytes) VALUES " . $out . ";";
                            $projectdb->query($query);
                        }
                    }
                }
                $progress = $x / $allrules;
                if ($progress == 1) {
                    update_progress($project, '1.00', 'Finished.');
                    $pandb->query("UPDATE projects SET progress='3' WHERE name='$project'");
                } else {
                    update_progress($project, $progress, 'Analyzed ' . $x . ' Rule from ' . $allrules);
                }
            }
        } else {
            update_progress($project, '1.00', 'Finished.');
            $pandb->query("UPDATE projects SET progress='3' WHERE name='$project'");
        }
    }
} 
elseif ($action == "investigate_by_rule") {

    $panorama = false;
    $target = "";

    #check if the Source is panorama but the logs has to be retrieved from the Firewall isntead of Panorama
    $isPanoramaSource = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE id='$source';");
    if ($isPanoramaSource->num_rows == 1) {
        $getPanoramaSource = $isPanoramaSource->fetch_assoc();
        if ($getPanoramaSource['ispanorama'] == 1) {
            $sourcePanorma = true;
        } else {
            $sourcePanorma = false;
        }
    }

    $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime FROM connectors WHERE id='$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnVendor = $data['vendor'];
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        $ConnPanorama = $data['panorama'];
        $ConnPeriod = $data['period'];
        $ConnStart = $data['startdate'] . " " . $data['starttime'];
        $ConnEnd = $data['enddate'] . " " . $data['endtime'];

        #Get Device

        $getDevice = $pandbRBAC->query("SELECT id,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_serial = $datadevice['serial'];
            $device_ispanorama = $datadevice['ispanorama'];
            $device_hostname = $datadevice['hostname'];
            $device_ispanorama = $datadevice['ispanorama'];
            $device_port = $datadevice['port'];
            $device_serial = $datadevice['serial'];
            $device_id = $datadevice['id'];
            $device = $datadevice['device'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];

            if ($ConnPanorama==0){
                $role="admin";
                $keyName=$device_serial."_".$role;
                $getKey=$pandbRBAC->query("SELECT api_key FROM device_keys WHERE role='$role' AND key_name='$keyName';");
                if ($getKey->num_rows==1){
                    $getKeyData=$getKey->fetch_assoc();
                    $device_api_key = $getKeyData['api_key'];
                }
            }

//            $getDevice = $pandbRBAC->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
//
//        if ($getDevice->num_rows == 1) {
//            $datadevice = $getDevice->fetch_assoc();
//            $device_api_key = $datadevice['api_key'];
//            $device_hostname = $datadevice['hostname'];
//            $device_ispanorama = $datadevice['ispanorama'];
//            $device_port = $datadevice['port'];
//            $device_serial = $datadevice['serial'];
//            $device_id = $datadevice['id'];
//            $device = $datadevice['device'];
//            $model = $datadevice['type'];
//            $device_management = $datadevice['management'];

            if ($ConnPanorama == "1") {
                $panorama = TRUE;
                $getDG = $projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND devicegroup='$MTvsys' AND active=1;");
                if ($getDG->num_rows > 0) {
                    $dg_query = array();
                    while ($getDGData = $getDG->fetch_assoc()) {
                        $dg_serial = $getDGData['serial'];
                        $dg_vsys = $getDGData['vsys'];
                        $dg_query[] = "(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                    }
                    $dg_query_all = "(" . implode(" OR ", $dg_query) . ")";
                } else {
                    $dg_query_all = "";
                }
            } else {
                # Check if we have the API key or we need to use Panorama as a PROXY
                if ($device_api_key == "") {
                    $getPanorama = $pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
                    if ($getPanorama->num_rows == 1) {
                        $getPanoramaData = $getPanorama->fetch_assoc();
                        $device_hostname = $getPanoramaData['hostname'];
                        $device_port = $getPanoramaData['port'];
                        $panorama_devicename = $getPanoramaData['name'];
                        $device_api_key = $getPanoramaData['api_key'];
                        $target = $device_serial;
                    }
                }
                if ($ConnVsys == "all") {
                    $dg_query_all = "";
                } else {
                    $dg_query_all = "(vsys eq '$ConnVsys')";
                }
            }
        } else {
            echo json_encode(array('success' => false, 'message' => 'The Device doesn\'t exist.'));
            exit(0);
        }

        $projectdb->query("TRUNCATE TABLE project_status;");
        add_progress($project, '0.00', 'Retrieving Reports'); #print "DELETE FROM unknown_traffic_by_app WHERE vsys='$vsys' AND source='$source';";


        $getRulesUnk = $projectdb->query("SELECT original_rule_lid,rule_lid,source,vsys FROM split_rules_unknown WHERE rule_lid='$rulelid';");
        if ($getRulesUnk->num_rows > 0) {
            take_snapshot_last($project);
            $allrules = $getRulesUnk->num_rows;
            $x = 0;
            while ($data = $getRulesUnk->fetch_assoc()) {
                $original_rule_lid = $data['original_rule_lid'];
                $rule_lid = $data['rule_lid'];
                $source = $data['source'];

                #Clean First by vsys
                $projectdb->query("DELETE FROM unknown_traffic_by_app WHERE rule_lid='$rulelid';");

                $getRuleName = $projectdb->query("SELECT name FROM security_rules WHERE id='$original_rule_lid';");
                $x++;
                if ($getRuleName->num_rows == 1) {
                    $getdata = $getRuleName->fetch_assoc();
                    $rulename = $getdata['name'];

                    $getUnkApp = $projectdb->query("SELECT app,dport FROM applications_from_log WHERE rule_lid='$rule_lid' GROUP BY app,dport;");
                    if ($getUnkApp->num_rows > 0) {
                        $tuCurl = curl_init();
                        $theTraffic = array();
                        $content = array();
                        while ($data2 = $getUnkApp->fetch_assoc()) {
                            $app = $data2['app'];
                            $dport = $data2['dport'];
                            if ($panorama == FALSE) {
                                if ($model == "pa7000") {
                                    $theTraffic[] = get_dynamic_report_appsbyrule_destination_pa7000($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target);
                                } else {
                                    $theTraffic[] = get_dynamic_report_appsbyrule_destination_panos($tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target);
                                }
                            } else {
                                $theTraffic[] = get_dynamic_report_appsbyrule_destination_panorama($MTvsys, $tuCurl, $device_hostname, $device_api_key, $MTvsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target);
                            }
                        }


                        curl_close($tuCurl);
                        if (count($theTraffic) > 0) {
                            foreach ($theTraffic as $kkey => $vvalue) {
                                foreach ($vvalue as $key => $value) {
                                    $content[] = $value;
                                }
                            }
                        }
                        if (count($content) > 0) {
                            $out = implode(",", $content);
                            $query = "INSERT INTO unknown_traffic_by_app (source,vsys,rule_lid,app,dport,dst,proto,packets,bytes) VALUES " . $out . ";";
                            $projectdb->query($query);
                        }
                    }
                }
                $progress = $x / $allrules;
                if ($progress == 1) {
                    update_progress($project, '1.00', 'Finished.');
                    $pandb->query("UPDATE projects SET progress='3' WHERE name='$project'");
                } else {
                    update_progress($project, $progress, 'Analyzed ' . $x . ' Rule from ' . $allrules);
                }
            }
        } else {
            update_progress($project, '1.00', 'Finished.');
            $pandb->query("UPDATE projects SET progress='3' WHERE name='$project'");
        }
    }
} 
elseif ($action == "remove_unknown_app_port") {
    $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
    $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
    $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
    $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
    take_snapshot_last($project);
    $get = $projectdb->query("SELECT app,dport FROM applications_from_log WHERE rule_lid='$rule_lid' AND id IN ($ids);");
    while ($data = $get->fetch_assoc()) {
        $app = $data['app'];
        if ($app == "unknown-tcp") {
            $proto = "tcp";
        } elseif ($app == "unknown-udp") {
            $proto = "udp";
        }
        $dport = $data['dport'];
        $projectdb->query("DELETE FROM unknown_traffic_by_app WHERE rule_lid='$rule_lid' AND dport='$dport' AND proto='$proto' AND app='$app';");
    }
    $projectdb->query("DELETE FROM applications_from_log WHERE id IN ($ids);");

    $check = $projectdb->query("SELECT id FROM applications_from_log WHERE rule_lid='$rule_lid';");
    if ($check->num_rows == 0) {
        delete_security_rule($vsys, $source, $rule_lid);
    }
} 
elseif ($action == "remove_known_app_port") {
    $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));
    $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
    $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
    $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
    take_snapshot_last($project);
    if ($data != "") {
        $data_split = explode(",", $data);
        foreach ($data_split as $key => $value) {
            $data2_split = explode(";", $value);
            $appid = $data2_split[0];
            $app = $data2_split[1];
            if (is_numeric($appid)) {
                $appids[] = $appid;
            } else {
                $apps[] = "'" . $app . "'";
            }
        }
        if (count($appids) > 0) {
            $projectdb->query("DELETE FROM applications_from_log WHERE id IN (" . implode(",", $appids) . ");");
        }
        if (count($apps) > 0) {
            $projectdb->query("DELETE FROM applications_from_log WHERE app IN (" . implode(",", $apps) . ") AND vsys='$vsys' AND source='$source';");
        }
    }
    if ($ids != "") {
        $projectdb->query("DELETE FROM applications_from_log WHERE id IN ($ids);");
    }
} 
elseif ($action == "remove_userid") {
    $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));
    $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
    $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
    $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
    take_snapshot_last($project);
    if ($data != "") {
        $data_split = explode(",", $data);
        foreach ($data_split as $key => $value) {
            $data2_split = explode(";", $value);
            $date = $data2_split[0];
            $user = $data2_split[1];
            if ($user == "all") {
                $date2 = explode(" ", $date);
                $projectdb->query("DELETE FROM userid_from_log WHERE DATE(date_retrieve) = '$date2[0]';");
            } else {
                $projectdb->query("DELETE FROM userid_from_log WHERE name = '$user';");
            }
        }
    }
} 
elseif ($action == "remove_recommended_group") {
    $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));
    $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
    $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
    $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
    take_snapshot_last($project);
    if ($data != "") {
        $data_split = explode(",", $data);
        foreach ($data_split as $key => $value) {
            $data2_split = explode(";", $value);
            $id = $data2_split[0];
            $user = $data2_split[1];
            $projectdb->query("DELETE FROM userid_group_recommended WHERE id = '$id';");
            //echo "DELETE FROM userid_group_recommended WHERE id = '$id';";
        }
    }
} 
elseif ($action == "split_known_unknown") {
    
    $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
    $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));
    if ($data != "") {
        $sql_rule_lid = " AND rule_lid IN ($data) ";
    } else {
        $sql_rule_lid = "";
    }
    $projectdb->query("TRUNCATE TABLE project_status;");
    add_progress($project, '0.00', 'Searching Unknown traffic');
    
    
    $getUnknown = $projectdb->query("SELECT vsys,source,rule_lid FROM applications_from_log WHERE source='$source' AND (app='unknown-tcp' OR app='unknown-udp' OR app='unknown-p2p') $sql_rule_lid GROUP BY source,rule_lid;");
    //echo "SELECT vsys,source,rule_lid FROM applications_from_log WHERE source='$source' AND (app='unknown-tcp' OR app='unknown-udp' OR app='unknown-p2p') $sql_rule_lid GROUP BY source,rule_lid;\n";
    $x = 0;
    if ($getUnknown->num_rows > 0) {
        $finalPosition = "";
        $allrules = $getUnknown->num_rows;
        $update_split_table = array();
        $update_applications_from_log = array();
        take_snapshot_last($project);
        while ($data = $getUnknown->fetch_assoc()) {
            $x++;
            $rule_lid = $data['rule_lid'];
            $source = $data['source'];
            $vsys = $data['vsys'];

            # If number of unknown apps is equal total apps found all apps are unknown then add only the tag
            $countAppsbyRule = $projectdb->query("SELECT id FROM applications_from_log WHERE rule_lid='$rule_lid';");
            $countAppsbyRuleUnk = $projectdb->query("SELECT id FROM applications_from_log WHERE rule_lid='$rule_lid' AND (app='unknown-tcp' OR app='unknown-udp' OR app='unknown-p2p');");
            if ($countAppsbyRule->num_rows == $countAppsbyRuleUnk->num_rows) {
                $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='Unknown Traffic';");
                if ($getTag->num_rows == 1) {
                    $data = $getTag->fetch_assoc();
                    $tagId = $data['id'];
                    $tagTable = "tag";
                } else {
                    $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys,devicegroup) VALUES ('Unknown Traffic','color1','Identify Unknown Traffic','$source','$vsys','$project');");
                    $tagId = $projectdb->insert_id;
                    $tagTable = "tag";
                }
                $dup = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid='$rule_lid' AND table_name='$tagTable' AND member_lid='$tagId' ");
                if ($dup->num_rows == 0) {
                    $projectdb->query("INSERT INTO security_rules_tag (source,table_name,member_lid,rule_lid,vsys,devicegroup) VALUES ('$source','$tagTable','$tagId','$rule_lid','$vsys','$project');");
                }
            } 
            else {
                # If the rule was previosly created for the same process is reflected in split table dont create again.
                $getSplit = $projectdb->query("SELECT id FROM split_rules_unknown WHERE rule_lid='$rule_lid';");
                if ($getSplit->num_rows == 0) {
                    $getRulePosition = $projectdb->query("SELECT position FROM security_rules WHERE id='$rule_lid';");
                    if ($getRulePosition->num_rows == 1) {
                        $data2 = $getRulePosition->fetch_assoc();
                        $position = $data2['position'];
                        /* $finalPosition = $position - 1;
                          if ($finalPosition == 0) {
                          $finalPosition = 1;
                          $position = 2;
                          } */
                        $finalPosition = "-1";
                        $theNewlid = clone_security_rule($position, $finalPosition, $vsys, $source, $rule_lid, "Unk-", $project);
                        $update_split_table[] = "('$rule_lid','$theNewlid','$source','$vsys')";
                        $projectdb->query("UPDATE applications_from_log SET rule_lid='$theNewlid' WHERE rule_lid='$rule_lid' AND (app='unknown-tcp' OR  app='unknown-udp' OR app='unknown-p2p')");

                    }
                }
            }
            $progress = $x / $allrules;
            if ($progress == 1) {
                update_progress($project, '1.00', 'Finished.');
                $pandb->query("UPDATE projects SET progress='2' WHERE name='$project'");
            } else {
                update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
            }
        }
        $projectdb->query("DELETE FROM split_rules_unknown WHERE source='$source' AND vsys='$vsys';");
        $outunique = array_unique($update_split_table);
        if (!$projectdb->query("INSERT INTO split_rules_unknown (original_rule_lid,rule_lid,source,vsys) VALUES " . implode(",", $outunique) . ";")) {
            //printf("Errormessage: %s\n", $projectdb->error);
        }
    }

    if ($x == 0) {
        update_progress($project, '1.00', 'Finished.');
        $pandb->query("UPDATE projects SET progress='2' WHERE name='$project'");
    }
} 
elseif ($action == "split_known_unknown_userid") {

    $projectdb->query("TRUNCATE TABLE project_status;");
    add_progress($project, '0.00', 'Searching Unknown User');
    $getUnknown = $projectdb->query("SELECT vsys, source, rule_lid FROM userid_from_log WHERE name ='unknown' GROUP BY source,rule_lid;");
    $x = 0;
    if ($getUnknown->num_rows > 0) {
        $finalPosition = "";
        $allrules = $getUnknown->num_rows;
        $update_split_table = array();
        $update_applications_from_log = array();
        take_snapshot_last($project);
        while ($data = $getUnknown->fetch_assoc()) {
            $x++;
            $rule_lid = $data['rule_lid'];
            $source = $data['source'];
            $vsys = $data['vsys'];

            # If number of unknown apps is equal total apps found all apps are unknown then add only the tag
            $countAppsbyRule = $projectdb->query("SELECT id FROM userid_from_log WHERE rule_lid='$rule_lid';");
            $countAppsbyRuleUnk = $projectdb->query("SELECT id FROM userid_from_log WHERE rule_lid='$rule_lid' AND name ='unknown';");
            if ($countAppsbyRule->num_rows == $countAppsbyRuleUnk->num_rows) {
                $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='Unknown Users';");
                if ($getTag->num_rows == 1) {
                    $data = $getTag->fetch_assoc();
                    $tagId = $data['id'];
                    $tagTable = "tag";
                } else {
                    $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys,devicegroup) VALUES ('Unknown Users','color1','Identify Unknown Users','$source','$vsys','$project');");
                    $tagId = $projectdb->insert_id;
                    $tagTable = "tag";
                }
                $dup = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid='$rule_lid' AND table_name='$tagTable' AND member_lid='$tagId' ");
                if ($dup->num_rows == 0) {
                    $projectdb->query("INSERT INTO security_rules_tag (source,table_name,member_lid,rule_lid,vsys,devicegroup) VALUES ('$source','$tagTable','$tagId','$rule_lid','$vsys','$project');");
                }
            } else {
                # If the rule was previosly created for the same process is reflected in split table dont create again.
                $getSplit = $projectdb->query("SELECT id FROM split_rules_unknown WHERE rule_lid='$rule_lid';");
                if ($getSplit->num_rows == 0) {
                    $getRulePosition = $projectdb->query("SELECT position FROM security_rules WHERE id='$rule_lid';");
                    if ($getRulePosition->num_rows == 1) {
                        $data2 = $getRulePosition->fetch_assoc();
                        $position = $data2['position'];
                        $finalPosition = "-1";
                        $theNewlid = clone_security_rule($position, $finalPosition, $vsys, $source, $rule_lid, "Usr-", $project);
                        $update_split_table[] = "('$rule_lid','$theNewlid','$source','$vsys')";
                        $projectdb->query("UPDATE userid_from_log SET rule_lid='$theNewlid' WHERE rule_lid='$rule_lid' AND name = 'unknown'");

                        //$projectdb->query("UPDATE applications_from_log SET rule_lid='$theNewlid' WHERE source='$source' AND vsys='$vsys' AND rule_lid='$rule_lid' AND (app='unknown-tcp' OR  app='unknown-udp' OR app='unknown-p2p')");
                    }
                }
            }
            $progress = $x / $allrules;
            if ($progress == 1) {
                update_progress($project, '1.00', 'Finished.');
                $pandb->query("UPDATE projects SET progress='2' WHERE name='$project'");
            } else {
                update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
            }
        }
        $projectdb->query("DELETE FROM split_rules_unknown WHERE source='$source' AND vsys='$vsys';");
        $outunique = array_unique($update_split_table);
        if (!$projectdb->query("INSERT INTO split_rules_unknown (original_rule_lid,rule_lid,source,vsys) VALUES " . implode(",", $outunique) . ";")) {
            //printf("Errormessage: %s\n", $projectdb->error);
        }
    }
    if ($x == 0) {
        update_progress($project, '1.00', 'Finished.');
        $pandb->query("UPDATE projects SET progress='2' WHERE name='$project'");
    }
} 
elseif ($action == "consolidate_known_appid") {

    $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
    $preorpost = $projectdb->real_escape_string((string) (isset($_POST['preorpost']) ? $_POST['preorpost'] : $_GET['preorpost']));
    $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));
    $optionselected = $projectdb->real_escape_string((string) (isset($_POST['optionselected']) ? $_POST['optionselected'] : $_GET['optionselected']));

    //8,2
    if ($data != "") {
        $sql_rule_lid = " AND rule_lid IN ($data) ";
    } else {
        $sql_rule_lid = "";
    }

    #DEBUG
    //$source=1;
    //$vsys="vsys1";	
    #DEBUG
    $projectdb->query("TRUNCATE TABLE project_status;");
    add_progress($project, '0.00', 'Reconciling Services with App-id');
    $projectdb->query("TRUNCATE TABLE appid_adoption_mapping;");
    $projectdb->query("TRUNCATE TABLE phase2_known_apps;");
    $getAppsvialog = $projectdb->query("SELECT rule_lid,vsys FROM applications_from_log WHERE source='$source' $sql_rule_lid GROUP BY rule_lid;");
    if ($getAppsvialog->num_rows > 0) {
        take_snapshot_last($project);
        $allrules = $getAppsvialog->num_rows;
        $x = 1;
        while ($getAppsvialogData = $getAppsvialog->fetch_assoc()) {

            $rule_lid = $getAppsvialogData['rule_lid'];
            $vsys = $getAppsvialogData['vsys'];

            $rule_lid_origin = "";

            // Check if rule_lid is cloned.
            $getIsCloned = $projectdb->query("SELECT origin FROM appid_rule_relation WHERE clone = '$rule_lid' ORDER BY id DESC LIMIT 1;");
            if ($getIsCloned->num_rows == 1) {
                $dataIC = $getIsCloned->fetch_assoc();
                $rule_lid_origin = $dataIC['origin'];
            }
            else {
                // Check if exist one rule with his name is the name without 'Cl-' and position is superior to it.
                $getNameRule = $projectdb->query("SELECT name, position FROM security_rules WHERE id = '$rule_lid';");
                if ($getNameRule->num_rows == 1) {
                    $dataNR = $getNameRule->fetch_assoc();
                    $rule_name = $dataNR['name'];
                    $position_rule = $dataNR['position'];
                }

                $rule_name_without_cl = str_replace("Cl-", "", $rule_name);

                $getNameRuleExist = $projectdb->query("SELECT id, name, position FROM security_rules WHERE name = '$rule_name_without_cl' AND position < '$position_rule' AND vsys='$vsys' AND source='$source';");
                if ($getNameRuleExist->num_rows == 1) {

                    $dataNR = $getNameRuleExist->fetch_assoc();
                    $rule_name_origin = $dataNR['name'];
                    $rule_lid_origin = $dataNR['id'];
                }
            }

            #Get Application-default data
            $getAppdef = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND source='$source' AND vsys = 'shared' LIMIT 1;");
            
            if ($getAppdef->num_rows == 1) {
                $appdef = $getAppdef->fetch_assoc();
                $appdef_id = $appdef['id'];
            }
            $getServices = $projectdb->query("SELECT member_lid,table_name FROM security_rules_srv WHERE rule_lid='$rule_lid' AND table_name!='services' AND table_name!='services_groups_id' AND member_lid!='$appdef_id';");
            $CountServices = $getServices->num_rows;
            if ($CountServices > 0) {
                while ($getServicesData = $getServices->fetch_object()) {
                    if ($getServicesData->table_name == "services_groups_id") {
                        $getSrv = $projectdb->query("SELECT name FROM $getServicesData->table_name WHERE id='$getServicesData->member_lid';");
                        if ($getSrv->num_rows == 1) {
                            $getSrvData = $getSrv->fetch_object();
                            $srv_name = $getSrvData->name;
                            $projectdb->query("INSERT INTO appid_adoption_mapping (source,vsys,rule_lid,name,member_lid,table_name,dport,protocol,isgroup,application_default) VALUES ('$source','$vsys','$rule_lid','$srv_name','$getServicesData->member_lid','$getServicesData->table_name','','','1','0');");
                        }
                    }
                    else {
                        $getSrv = $projectdb->query("SELECT name,dport,protocol FROM $getServicesData->table_name WHERE id='$getServicesData->member_lid';");
                        if ($getSrv->num_rows == 1) {
                            $getSrvData = $getSrv->fetch_object();
                            $srv_dport = $getSrvData->dport;
                            $srv_protocol = $getSrvData->protocol;
                            $srv_name = $getSrvData->name;

                            $getAllServices = explode(",", $srv_dport);
                            $dport_search_array = array();
                            foreach ($getAllServices as $mysrvkey => $value) {
                                if (is_numeric($value)) {
                                    $dport_search_array[] = "(dport='$value')";
                                } elseif (preg_match("/\d-\d/", $value)) {
                                    $break1 = explode("-", $value);
                                    $start = $break1[0];
                                    $end = $break1[1];
                                    $dport_search_array[] = "(dport BETWEEN $start AND $end)";
                                }
                            }
                            $dport_search = "AND (" . implode(" OR ", $dport_search_array) . ")";


                            $getAppid = $projectdb->query("SELECT app,dport,proto FROM applications_from_log WHERE rule_lid='$rule_lid' $dport_search AND proto='$srv_protocol' group by app;");
                            if ($getAppid->num_rows == 0) {
                                $projectdb->query("INSERT INTO appid_adoption_mapping (source,vsys,rule_lid,name,member_lid,table_name,dport,protocol,isgroup,application_default) VALUES ('$source','$vsys','$rule_lid','$srv_name','$getServicesData->member_lid','$getServicesData->table_name','$srv_dport','$srv_protocol','0','0');");
                            }
                            else {
                                $CountAppsbyport = $getAppid->num_rows;
                                while ($getAppidData = $getAppid->fetch_object()) {
                                    # Identify where is the app
                                    $getDefaultApp = $projectdb->query("SELECT id FROM default_applications WHERE BINARY name ='$getAppidData->app';");
                                    if ($getDefaultApp->num_rows == 1) {
                                        $getDefaultAppData = $getDefaultApp->fetch_object();
                                        $app_id = $getDefaultAppData->id;
                                        $app_table = "default_applications";
                                    } else {
                                        $getDefaultApp = $projectdb->query("SELECT id FROM applications WHERE BINARY name ='$getAppidData->app' AND source='$source' AND vsys='$vsys';");
                                        if ($getDefaultApp->num_rows == 1) {
                                            $getDefaultAppData = $getDefaultApp->fetch_object();
                                            $app_id = $getDefaultAppData->id;
                                            $app_table = "applications";
                                        } else {
                                            //$getDefaultApp = $projectdb->query("SELECT id FROM shared_applications WHERE BINARY name ='$getAppidData->app' AND source='$source';");
                                            $getDefaultApp = $projectdb->query("SELECT id FROM applications WHERE BINARY name ='$getAppidData->app' AND source='$source' AND vsys = 'shared';");
                                            if ($getDefaultApp->num_rows == 1) {
                                                $getDefaultAppData = $getDefaultApp->fetch_object();
                                                $app_id = $getDefaultAppData->id;
                                                //$app_table = "shared_applications";
                                                $app_table = "applications";
                                            }
                                        }
                                    }
                                    #Check if port is default port from Appid
                                    if ($app_table == "default_applications") {
                                        $search = $getAppidData->proto . "/" . $getAppidData->dport;
                                        $searchPort = $getAppidData->dport;
                                        $searchProto = $getAppidData->proto;
                                        $searchdynamic = $getAppidData->proto . "/dynamic";
                                        $getDP = $projectdb->query("SELECT id FROM $app_table WHERE BINARY name='$getAppidData->app' AND (default_port LIKE '%$search' OR default_port LIKE '%$search,%' OR default_port LIKE '%,$search' OR default_port LIKE '%$searchdynamic%' OR default_port LIKE '%$searchProto/%,$searchPort%');");
                                        if ($getDP->num_rows == 1) {
                                            $application_default = 1;
                                        } else {
                                            $application_default = 0;
                                        }
                                    } else {
                                        $application_default = 0;
                                    }
                                    $projectdb->query("INSERT INTO appid_adoption_mapping (source,vsys,rule_lid,name,member_lid,table_name,dport,protocol,isgroup,app_via_log,proto_via_log,dport_via_log,app_id,app_table,application_default) VALUES ('$source','$vsys','$rule_lid','$srv_name','$getServicesData->member_lid','$getServicesData->table_name','$srv_dport','$srv_protocol',0,'$getAppidData->app','$getAppidData->proto','$getAppidData->dport','$app_id','$app_table','$application_default');");
                                }
                            }
                        }
                    }
                }
            }
            else {
                # field Services is ANY/application-default raise and alert to do it manually
                add_log('error', 'Appid Adoption', 'Rule ID [' . $rule_lid . '] has Service ANY defined or Shared Services or Services Groups.', $source, 'Edit the Rule Manually');

                # If its Any in the service column add the applications

                if($optionselected == "recommended" || $optionselected == "recommended_deps" ){
                    $getIdApp = $projectdb->query("SELECT id, app, dport, proto FROM applications_from_log WHERE rule_lid='$rule_lid'
                      AND app NOT LIKE 'unknown-%' AND app != 'non-syn-tcp' AND app != 'insufficient-data' AND app != 'not-applicable' GROUP BY app, dport;");

                    if ($getIdApp->num_rows > 0) {
                        while ($data_id_app = $getIdApp->fetch_assoc()) {

                            $id_app_selected = $data_id_app['id'];
                            $name_app = $data_id_app['app'];
                            $dport_app_selected = $data_id_app['dport'];
                            $proto_app_selected = $data_id_app['proto'];

                            calculateKnownApp($name_app, $id_app_selected, $dport_app_selected, $proto_app_selected, $rule_lid, $rule_lid);
                        }
                    }
                }



                $getAllApps = $projectdb->query("SELECT id, app FROM applications_from_log WHERE rule_lid='$rule_lid' AND app NOT LIKE 'unknown-%' AND app != 'non-syn-tcp' AND app != 'insufficient-data' AND app != 'not-applicable' GROUP BY app;");
                if ($getAllApps->num_rows > 0) {

                    $add_app = array();
                    $theapps = array();

                    while ($mydata = $getAllApps->fetch_assoc()) {

                        $id_app_2 = $mydata['id'];
                        $app_list = array($mydata['app']);
                        $theapps[] = $mydata['app'];

                        if ($rule_lid_origin != "") {
                            $insert_rule_lid = $rule_lid_origin;
                        } else {
                            $insert_rule_lid = $rule_lid;
                        }

                        if($optionselected == "recommended" || $optionselected == "recommended_deps"){
                            $app = array();
                            $getRecommendedApp = $projectdb->query("SELECT recommended, recommended_requires FROM phase2_known_apps WHERE app_id = '$id_app_2';");
                            if ($getRecommendedApp->num_rows > 0) {
                                $dataRA = $getRecommendedApp->fetch_assoc();
                                if($optionselected == "recommended") {
                                    $app_list = array_unique(array_merge($app_list, array($dataRA['recommended'])));
                                }
                                else{
                                    $app_list = array_unique(array_merge($app_list, explode(",",$dataRA['recommended_requires'])));
                                }
                            }
                        }

                        foreach ($app_list as $app) {
                            $map = $projectdb->query("SELECT id FROM default_applications WHERE name='$app';");
                            if ($map->num_rows > 0) {

                                $mapdata = $map->fetch_assoc();
                                $mapdata_id = $mapdata['id'];
                                $mapdata_table = "default_applications";
                                $add_app[] = "('$insert_rule_lid','$vsys','$source','$mapdata_id','$mapdata_table')";
                            } else {
                                $search2 = $projectdb->query("SELECT id FROM applications WHERE source='$source' AND vsys='$vsys' AND name='$app';");
                                if ($search2->num_rows > 0) {

                                    $mapdata = $search2->fetch_assoc();
                                    $mapdata_id = $mapdata['id'];
                                    $mapdata_table = "applications";
                                    $add_app[] = "('$insert_rule_lid','$vsys','$source','$mapdata_id','$mapdata_table')";
                                } else {
                                    $search3 = $projectdb->query("SELECT id FROM applications WHERE source='$source' AND vsys='shared' AND name='$app';");
                                    if ($search3->num_rows > 0) {

                                        $mapdata = $search3->fetch_assoc();
                                        $mapdata_id = $mapdata['id'];
                                        //$mapdata_table = "shared_applications";
                                        $mapdata_table = "applications";
                                        $add_app[] = "('$insert_rule_lid','$vsys','$source','$mapdata_id','$mapdata_table')";
                                    }
                                }
                            }
                        }
                    }

                    //print_r($add_app);
                    if (count($add_app) > 0) {
                        if ($rule_lid_origin != "") {
                            $sql_rule_lid = "  rule_lid = '$rule_lid_origin' ";
                        } else {
                            $sql_rule_lid = "  rule_lid = '$rule_lid' ";
                        }

                        //$getCurrentapps = $projectdb->query("SELECT rule_lid, member_lid,table_name from security_rules_app WHERE source='$source' AND vsys='$vsys' AND rule_lid = '$rule_lid'  ;");
                        $getCurrentapps = $projectdb->query("SELECT rule_lid, member_lid,table_name from security_rules_app WHERE $sql_rule_lid ;");
                        if ($getCurrentapps->num_rows > 0) {
                            while ($current = $getCurrentapps->fetch_assoc()) {
                                $mapdata_id = $current['member_lid'];
                                $mapdata_table = $current['table_name'];
                                $rule_lid_in = $current['rule_lid'];

                                $add_app[] = "('$rule_lid_in','$vsys','$source','$mapdata_id','$mapdata_table')";
                            }
                        }
                        $unique = array_unique($add_app);

                        //$projectdb->query("DELETE FROM security_rules_app WHERE source='$source' AND vsys='$vsys' AND rule_lid='$rule_lid';");
                        $projectdb->query("DELETE FROM security_rules_app WHERE $sql_rule_lid;");

                        //$projectdb->query("INSERT INTO security_rules_app (rule_lid,vsys,source,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                        $projectdb->query("INSERT INTO security_rules_app (rule_lid,vsys,source,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                        //echo "INSERT INTO security_rules_app (rule_lid,vsys,source,member_lid,table_name) VALUES " . implode(",", $unique) . ";\n";
                        foreach ($theapps as $key => $value) {
                            $projectdb->query("DELETE FROM applications_from_log WHERE rule_lid='$rule_lid' AND app='$value';");
                        }

                    }

                }
            }

            # Move to Applications From Applications via logs
            $getAppidServices = $projectdb->query("SELECT id,name,member_lid,table_name,dport,protocol,isgroup,app_via_log,proto_via_log,dport_via_log,app_id,app_table,application_default FROM appid_adoption_mapping WHERE rule_lid='$rule_lid';");
            $maxServices = $getAppidServices->num_rows;
            if ($maxServices > 0) {
                $service_map_app = array();
                $application_default = 0;
                while ($myData = $getAppidServices->fetch_object()) {
                    if (($myData->app_via_log != "") AND ( $myData->app_via_log != "unknown-tcp") AND ( $myData->app_via_log != "unknown-udp") AND ( $myData->app_via_log != "unknown-p2p") AND ( $myData->app_via_log != "insufficient-data") AND ( $myData->app_via_log != "not-applicable") AND ( $myData->app_via_log != "non-syn-tcp")) {
                        $service_map_app[] = "$myData->name;$myData->member_lid;$myData->table_name;$myData->dport;$myData->protocol;$myData->app_via_log;$myData->proto_via_log;$myData->dport_via_log;$myData->app_id;$myData->app_table;$myData->id;$myData->application_default";
                        $application_default = $application_default + $myData->application_default;
                    }
                }
                //print_r($service_map_app);
                if (count($service_map_app) == $maxServices) {
                    # Just replace it in the Same Rule
                    foreach ($service_map_app as $kkey => $vvalue) {
                        $apps = explode(";", $vvalue);
                        $serviceNames[] = $apps[0];

                        if ($rule_lid_origin != "") {
                            $sql_rule_lid = " AND rule_lid = '$rule_lid_origin' ";
                            $insert_rule_lid = $rule_lid_origin;
                        } else {
                            $sql_rule_lid = " AND rule_lid = '$rule_lid' ";
                            $insert_rule_lid = $rule_lid;
                        }

                        $dup = $projectdb->query("SELECT id FROM security_rules_app WHERE member_lid='$apps[8]' AND table_name='$apps[9]' $sql_rule_lid;");

                        if ($dup->num_rows == 0) {

                            $projectdb->query("INSERT INTO security_rules_app (rule_lid,vsys,source,member_lid,table_name,devicegroup) VALUES ('$insert_rule_lid','$vsys','$source','$apps[8]','$apps[9]','$devicegroup');");
                        }

                        // Remove app to the applications_from_log
                        $projectdb->query("DELETE FROM applications_from_log WHERE rule_lid='$rule_lid' AND app = '$apps[5]';");
                    }
                    if ($application_default == $maxServices) {
                        #Application Default YES
                        $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid='$rule_lid';");
                        $searchAD = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND vsys = 'shared' AND source='$source';");
                        $searchADData = $searchAD->fetch_object();
                        $projectdb->query("INSERT INTO security_rules_srv (rule_lid,vsys,source,member_lid,table_name) VALUES ('$rule_lid','$vsys','$source','$searchADData->id','services');");
                        $uniqueservicenames = array_unique($serviceNames);
                        add_log('ok', 'Appid Adoption', 'In Rule ID [' . $rule_lid . '] we have replaced services [' . implode(",", $uniqueservicenames) . '] with Application-default', $source, 'No Action required.');
                    }
                    $getTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='Appid Adoption';");
                    if ($getTag->num_rows == 1) {
                        $data = $getTag->fetch_assoc();
                        $tagId = $data['id'];
                        $tagTable = "tag";
                    } else {
                        $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys,devicegroup) VALUES ('Appid Adoption','color2','Appid Adoption by MT3','$source','$vsys','$project');");
                        $tagId = $projectdb->insert_id;
                        $tagTable = "tag";
                    }
                    $dup = $projectdb->query("SELECT id FROM security_rules_tag WHERE rule_lid='$rule_lid' AND table_name='$tagTable' AND member_lid='$tagId' ");
                    if ($dup->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_tag (source,table_name,member_lid,rule_lid,vsys,devicegroup) VALUES ('$source','$tagTable','$tagId','$rule_lid','$vsys','$project');");
                    }
                } elseif (count($service_map_app) == 0) {
                    
                }
                else {
                    # Clone the Rule above current Rule
                    $getRulePos = $projectdb->query("SELECT position FROM security_rules WHERE id='$rule_lid';");
                    $getRulePosData = $getRulePos->fetch_object();
                    $initialPosition = $getRulePosData->position;
                    $finalPosition = intval($initialPosition) - 1;
                    # GEt rule_lid for the new finalposition to see if was cloned previosly

                    /* $ruleExists = $projectdb->query("SELECT rule_lid FROM split_rules_appid WHERE source='$source' AND vsys='$vsys' AND original_rule_lid='$rule_lid';");
                      if ($ruleExists->num_rows == 1) {
                      $ruleExistsData = $ruleExists->fetch_object();
                      $new_rule_lid = $ruleExistsData->rule_lid;
                      } else {
                      $new_rule_lid = clone_security_rule($initialPosition, $finalPosition, $vsys, $source, $rule_lid, "Appid", $project);
                      $projectdb->query("DELETE FROM security_rules_srv WHERE source='$source' AND vsys='$vsys' AND rule_lid='$new_rule_lid';");
                      $projectdb->query("INSERT INTO split_rules_appid (original_rule_lid,rule_lid,source,vsys) VALUES ('$rule_lid','$new_rule_lid','$source','$vsys')");
                      } */
                    if ($rule_lid_origin != "") {
                        $new_rule_lid = $rule_lid_origin;
                    } else {
                        $new_rule_lid = clone_security_rule($initialPosition, $finalPosition, $vsys, $source, $rule_lid, "Appid", $project);
                        $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid';");
                        $projectdb->query("INSERT INTO appid_rule_relation (origin, clone) VALUES ('$rule_lid', '$new_rule_lid');");
                    }

                    $add_srv = array();
                    foreach ($service_map_app as $kkey => $vvalue) {
                        $apps = explode(";", $vvalue);
                        $serviceNames[] = $apps[0];
                        if (count($service_map_app) == $application_default) {
                            # Application Default
                            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid='$new_rule_lid';");
                            $searchAD = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND vsys = 'shared' AND source='$source';");
                            $searchADData = $searchAD->fetch_object();
                            $projectdb->query("INSERT INTO security_rules_srv (rule_lid,vsys,source,member_lid,table_name) VALUES ('$new_rule_lid','$vsys','$source','$searchADData->id','services');");
                            $uniqueservicenames = array_unique($serviceNames);
                            $projectdb->query("UPDATE applications_from_log SET rule_lid='$new_rule_lid' WHERE rule_lid='$rule_lid' AND app='$apps[5]' AND dport='$apps[7]' AND proto='$apps[6]';");
                            add_log('ok', 'Appid Adoption', 'In Rule ID [' . $new_rule_lid . '] we have replaced services [' . implode(",", $uniqueservicenames) . '] with Application-default', $source, 'No Action required.');
                            #Remove old Services
                            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid='$rule_lid' AND member_lid='$apps[1]' AND table_name='$apps[2]';");
                        } else {
                            #Add Services
                            $add_srv[] = "('$source','$new_rule_lid','$apps[1]','$apps[2]','$vsys','$devicegroup')";
                            #UPDATE apps from log with the new rule_lid
                            $projectdb->query("UPDATE applications_from_log SET rule_lid='$new_rule_lid' WHERE rule_lid='$rule_lid' AND app='$apps[5]' AND dport='$apps[7]' AND proto='$apps[6]';");
                            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid='$rule_lid' AND member_lid='$apps[1]' AND table_name='$apps[2]';");
                        }
                        #Add APPS
                        $dup = $projectdb->query("SELECT id FROM security_rules_app WHERE member_lid='$apps[8]' AND table_name='$apps[9]' AND rule_lid='$new_rule_lid';");
                        if ($dup->num_rows == 0) {
                            $projectdb->query("INSERT INTO security_rules_app (rule_lid,vsys,source,member_lid,table_name,devicegroup) VALUES ('$new_rule_lid','$vsys','$source','$apps[8]','$apps[9]','$devicegroup');");
                        }
                    }
                    if (count($add_srv) > 0) {
                        $unique = array_unique($add_srv);
                        $projectdb->query("INSERT INTO security_rules_srv (source,rule_lid,member_lid,table_name,vsys,devicegroup) VALUES " . implode(",", $unique) . ";");
                    }
                }// fin else clone
            }

            $progress = $x / $allrules;
            if ($progress == 1) {
                update_progress($project, '1.00', 'Finished.');
                $pandb->query("UPDATE projects SET progress='4' WHERE name='$project'");
            } else {
                update_progress($project, $progress, 'Reconciling Rule ' . $x . ' from ' . $allrules);
            }
            $x++;

            checkGetParentApp($rule_lid);

        }// fin while rule_lid
    } else {
        update_progress($project, '1.00', 'Finished.');
        $pandb->query("UPDATE projects SET progress='3' WHERE name='$project'");
    }
} 
elseif ($action == "export_apps_from_log") {
    export_apps_form_log($project);
} 
elseif ($action == "consolidate_known_userid") {

    $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
    $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));

    take_snapshot_last($project);

    if ($data != "") {
        $rules_selected = explode(",", $data);
    } else {
        $getRulesAppId = $projectdb->query("SELECT DISTINCT(rule_lid) FROM userid_from_log;");
        if ($getRulesAppId->num_rows > 0) {
            while ($data = $getRulesAppId->fetch_assoc()) {
                $rules_selected[] = $data['rule_lid'];
            }
        }
    }

    foreach ($rules_selected as $key => $rule_lid) {

        $done = 0;
        $are_unknown = 0;

        $getSourceVsys = $projectdb->query("SELECT source, vsys FROM security_rules WHERE id = '$rule_lid';");
        if ($getSourceVsys->num_rows == 1) {
            $data = $getSourceVsys->fetch_assoc();
            $source = $data['source'];
            $vsys = $data['vsys'];
        }

        $getUsers = $projectdb->query("SELECT DISTINCT(name) FROM userid_from_log WHERE rule_lid = '$rule_lid' ;");
        if ($getUsers->num_rows == 1) {
            while ($dataU = $getUsers->fetch_assoc()) {
                $user = addslashes($dataU['name']);
                if ($user == "unknown") {
                    $getExistUsr = $projectdb->query("SELECT id FROM security_rules_usr WHERE rule_lid = '$rule_lid' AND name = '$user' ;");
                    if ($getExistUsr->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_usr (source, vsys, name, rule_lid) VALUES ('$source','$vsys','$user','$rule_lid');");
                        $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name = 'unknown';");
                        $done = 1;
                    }
                }
            }
        } elseif ($getUsers->num_rows == 2) {
            while ($dataU = $getUsers->fetch_assoc()) {
                $user = addslashes($dataU['name']);
                if ($user == "unknown") {
                    $are_unknown = 1;
                } else {
                    $user_no_unknown = addslashes($dataU['name']);
                }
            }
            if ($are_unknown == 1) {
                $getExistUsr = $projectdb->query("SELECT id FROM security_rules_usr WHERE rule_lid = '$rule_lid' AND name = '$user_no_unknown';");
                if ($getExistUsr->num_rows == 0) {
                    $projectdb->query("INSERT INTO security_rules_usr (source, vsys, name, rule_lid) VALUES ('$source','$vsys','$user_no_unknown','$rule_lid');");
                    $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name = '$user_no_unknown';");
                    $done = 1;
                }
            }
        }

        if ($done == 0) {

            list($groups_math_finish, $groups_math_finish_reco) = getRecommendedGroupsUserId($rule_lid, "all", $source);

            foreach ($groups_math_finish_reco as $key => $user) {

                $getExistUsr = $projectdb->query("SELECT id FROM security_rules_usr WHERE rule_lid = '$rule_lid' AND name = '$user';");
                if ($getExistUsr->num_rows == 0) {
                    if ($user != "unknown") {
                        $projectdb->query("INSERT INTO security_rules_usr (source, vsys, name, rule_lid) VALUES ('$source','$vsys','$user','$rule_lid');");
                    }
                }
            }

            add_log('ok', 'Userid Adoption', 'In Rule ID [' . $rule_lid . '] we have Reconciliation.', $source, 'No Action required.');

            $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name != 'unknown';");
        }
    }
} 
elseif ($action == "get") {
    $type = $projectdb->real_escape_string((string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']));
    if ($type == "applicationsfromlog") {
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));

        $getApps = $projectdb->query("SELECT id,app,dport,bytes,packets,source,rule_lid,vsys,proto FROM applications_from_log WHERE rule_lid='$rule_lid' GROUP BY app,dport;");
        $count = $getApps->num_rows;
        while ($data = $getApps->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif ($type == "applicationoverride_by_app") {
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $app = $projectdb->real_escape_string((string) (isset($_POST['app']) ? $_POST['app'] : $_GET['app']));
        $dport = $projectdb->real_escape_string((string) (isset($_POST['dport']) ? $_POST['dport'] : $_GET['dport']));

        $getApps = $projectdb->query("SELECT app,dst,dport,bytes,packets,source,rule_lid,vsys,proto FROM unknown_traffic_by_app WHERE rule_lid='$rule_lid' AND dport='$dport' AND app='$app';");
        $count = $getApps->num_rows;
        while ($data = $getApps->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif ($type == "known_traffic_by_app") {
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $app = $projectdb->real_escape_string((string) (isset($_POST['app']) ? $_POST['app'] : $_GET['app']));
        $dport = $projectdb->real_escape_string((string) (isset($_POST['dport']) ? $_POST['dport'] : $_GET['dport']));

        $getApps = $projectdb->query("SELECT app,dst,dport,bytes,packets,source,rule_lid,vsys,proto FROM known_traffic_by_app WHERE rule_lid='$rule_lid' AND dport='$dport' AND app='$app';");
        $count = $getApps->num_rows;
        while ($data = $getApps->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif ($type == "known_traffic_by_app_new_old") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $filter_tech = $projectdb->real_escape_string((string) (isset($_POST['filter_tech']) ? $_POST['filter_tech'] : $_GET['filter_tech']));
        $filter_sub = $projectdb->real_escape_string((string) (isset($_POST['filter_sub']) ? $_POST['filter_sub'] : $_GET['filter_sub']));
        $filter_port = $projectdb->real_escape_string((string) (isset($_POST['filter_port']) ? $_POST['filter_port'] : $_GET['filter_port']));

        $is_first = 0;
        $total_apps_first = array();
        $total_apps_follow = array();

        $filter_tech_array = array();
        $filters_tech_array = array();
        // Filters
        if ($filter_tech != "") {
            $filter_tech_array = explode(",", $filter_tech);
            foreach ($filter_tech_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_tech_array[] = " '$filter' ";
            }
            $sql_filters_tech = " AND da.technology IN ( " . implode(',', $filters_tech_array) . " ) ";
        } else {
            $sql_filters_tech = "";
        }

        $filter_sub_array = array();
        $filters_sub_array = array();
        // Filters
        if ($filter_sub != "") {
            $filter_sub_array = explode(",", $filter_sub);
            foreach ($filter_sub_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_sub_array[] = " '$filter' ";
            }
            $sql_filters_sub = " AND da.subcategory IN ( " . implode(',', $filters_sub_array) . " ) ";
        } else {
            $sql_filters_sub = "";
        }

        $filter_port_array = array();
        $filters_port_array = array();
        $filters_protocol_array = array();
        // Filters
        if ($filter_port != "") {
            $filter_port_array = explode(",", $filter_port);
            foreach ($filter_port_array as $key => $filter) {

                $data_array_p = explode("/", $filter);

                if (!in_array(" '$data_array_p[0]' ", $filters_protocol_array)) {
                    $filters_protocol_array[] = " '$data_array_p[0]' ";
                }
                if (!in_array(" '$data_array_p[1]' ", $filters_port_array)) {
                    $filters_port_array[] = " '$data_array_p[1]' ";
                }
            }
            $sql_filters_port = " AND af.dport IN ( " . implode(',', $filters_port_array) . " ) ";
            $sql_filters_protocol = " AND af.proto IN ( " . implode(',', $filters_protocol_array) . " ) ";
        } else {
            $sql_filters_port = "";
            $sql_filters_protocol = "";
        }

        $expanded = "true";
        $rama_date = "";

        $getDateFromLogUnique = $projectdb->query("SELECT DISTINCT(DATE(date_retrieve)) AS date_retrieve, DATE_FORMAT(date_retrieve, '%Y-%m-%d %H:%i') AS date_retrieve2 "
                . "FROM applications_from_log "
                . "WHERE rule_lid = '$rule_lid' "
                . "ORDER BY date_retrieve ASC;");

        $count_unique = $getDateFromLogUnique->num_rows;

        $i = "1";
        $rama_global_x_app = array();
        $rama_global_x_app_fin = array();
        $app_name_total = array();

        while ($data_uniqueF = $getDateFromLogUnique->fetch_assoc()) {

            $date_retrieve = $data_uniqueF['date_retrieve'];
            $date_retrieve2 = $data_uniqueF['date_retrieve2'];

            //Construir la primera rama principal    
            $rama_date = "expanded:$expanded, app:'$date_retrieve2', text:'$date_retrieve2', value:'$date_retrieve2', date:'$date_retrieve2', category:'', subcategory:'', technology:'', 
            default_port:'', protocol:'', dport:'', bytes:'', packets:'', leaf:false, iconCls: 'icon-schedules', ";

            $getAppsFromLogUnique = $projectdb->query("SELECT DISTINCT(af.app) FROM applications_from_log af, default_applications da "
                    . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND DATE(af.date_retrieve) = '$date_retrieve' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol "
                    . "ORDER BY af.app ASC; ");

            if ($getAppsFromLogUnique->num_rows > 0) {
                while ($data_unique = $getAppsFromLogUnique->fetch_assoc()) {
                    $app_name_total[] = $data_unique['app'];
                }
            }

            $getAppsFromLogUnique2 = $projectdb->query("SELECT DISTINCT(af.app) FROM applications_from_log af, applications da "
                    . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND DATE(af.date_retrieve) = '$date_retrieve' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol "
                    . "ORDER BY af.app ASC; ");

            if ($getAppsFromLogUnique2->num_rows > 0) {
                while ($data_unique2 = $getAppsFromLogUnique2->fetch_assoc()) {
                    if (!in_array($data_unique2['app'], $app_name_total)) {
                        $app_name_total[] = $data_unique2['app'];
                    }
                }
            }

            $getAppsFromLogUnique3 = $projectdb->query("SELECT DISTINCT(af.app) FROM applications_from_log af, applications da "
                    . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.vsys = 'shared' AND DATE(af.date_retrieve) = '$date_retrieve' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol "
                    . "ORDER BY af.app ASC; ");

            if ($getAppsFromLogUnique3->num_rows > 0) {
                while ($data_unique3 = $getAppsFromLogUnique3->fetch_assoc()) {
                    if (!in_array($data_unique3['app'], $app_name_total)) {
                        $app_name_total[] = $data_unique3['app'];
                    }
                }
            }

            $total_apps_follow = array();
            $rama_global_x_app = array();
            $port_proto_array = array();

            $rama_app = "";

            //while ($data_unique = $getAppsFromLogUnique->fetch_assoc()) {
            foreach ($app_name_total as $key => $app) {

                //$app = $data_unique['app'];
                $no_app = 0;

                if ($is_first == 0) {

                    //$total_apps_first[] = $data_unique['app'];
                    $total_apps_first[] = $app;

                    $i++;
                    $getDefaults = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.default_port, da.risk "
                            . "FROM default_applications da, applications_from_log af WHERE af.app = da.name AND da.name = '$app' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol;");

                    if ($getDefaults->num_rows > 0) {
                        while ($data_defaults = $getDefaults->fetch_assoc()) {
                            $category = $data_defaults['category'];
                            $subcategory = $data_defaults['subcategory'];
                            $technology = $data_defaults['technology'];
                            $default_port = $data_defaults['default_port'];
                            $risk = $data_defaults['risk'];
                        }
                    } else {
                        $getDefaults2 = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.risk "
                                . "FROM applications da, applications_from_log af WHERE af.app = da.name AND da.name = '$app' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol;");
                        if ($getDefaults2->num_rows > 0) {
                            while ($data_defaults2 = $getDefaults2->fetch_assoc()) {
                                $category = $data_defaults2['category'];
                                $subcategory = $data_defaults2['subcategory'];
                                $technology = $data_defaults2['technology'];
                                $risk = $data_defaults2['risk'];
                                $default_port = "";
                            }
                        } else {
                            $getDefaults3 = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.risk "
                                    . "FROM applications da, applications_from_log af WHERE af.app = da.name AND da.vsys = 'shared' AND da.name = '$app' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol;");
                            
                            if ($getDefaults3->num_rows > 0) {
                                while ($data_defaults3 = $getDefaults3->fetch_assoc()) {
                                    $category = $data_defaults3['category'];
                                    $subcategory = $data_defaults3['subcategory'];
                                    $technology = $data_defaults3['technology'];
                                    $risk = $data_defaults3['risk'];
                                    $default_port = "";
                                }
                            } else {
                                $no_app = 1;
                            }
                        }
                    }

                    if ($risk == "1") {
                        $icon_risk = "icon-risk1";
                    } elseif ($risk == "2") {
                        $icon_risk = "icon-risk2";
                    } elseif ($risk == "3") {
                        $icon_risk = "icon-risk3";
                    } elseif ($risk == "4") {
                        $icon_risk = "icon-risk4";
                    } elseif ($risk == "5") {
                        $icon_risk = "icon-risk5";
                    }

                    $getAppsFromLog2 = $projectdb->query("SELECT dport, proto FROM applications_from_log "
                            . "WHERE app = '$app' AND rule_lid = '$rule_lid' GROUP BY dport, proto LIMIT 5;");
                    //AND DATE(date_retrieve) = '$date_retrieve'  

                    while ($data_app_log2 = $getAppsFromLog2->fetch_assoc()) {
                        $dport = $data_app_log2['dport'];
                        $proto = $data_app_log2['proto'];
                        $port_proto_array[] = $proto . "/" . $dport;
                    }

                    $app_with_ports = $app . " (" . implode(",", $port_proto_array) . ")";

                    if ($no_app == 0) {
                        $rama_app = "expanded:$expanded, app:'$app_with_ports',  text:'$app', value:'$app', date:'$date_retrieve2', category:'', subcategory:'', technology:'', 
                        default_port:'', protocol:'', dport:'', bytes:'', packets:'', leaf:true, iconCls:'$icon_risk', ";
                    }

                    $getAppsFromLog = $projectdb->query("SELECT id, app, dport, bytes, packets, source, rule_lid, vsys, proto "
                            . "FROM applications_from_log "
                            . "WHERE app = '$app' "
                            . "AND rule_lid = '$rule_lid' "
                            . "AND DATE(date_retrieve) = '$date_retrieve'  "
                            . "AND source = '$source' ;");

                    $count = $getAppsFromLog->num_rows;

                    unset($rama_children);
                    $rama_children = array();

                    while ($data_app_log = $getAppsFromLog->fetch_assoc()) {

                        $app_id = $data_app_log['id'];
                        $dport = $data_app_log['dport'];
                        $bytes = $data_app_log['bytes'];
                        $packets = $data_app_log['packets'];
                        $source = $data_app_log['source'];
                        $proto = $data_app_log['proto'];

                        $rama_children[] = "{expanded:$expanded, app:'$app', date:'$date_retrieve2', app_id: '$app_id', text:'$app', value:'$count',  risk: '$risk', category:'$category', subcategory:'$subcategory', technology:'$technology', default_port:'$default_port', protocol:'$proto', dport:'$dport', bytes:'$bytes', packets:'$packets' , iconCls:'icon-applications', leaf:true}";

                        $i ++;
                    }

                    $rama_global_x_app[] = "{ $rama_app  children:[" . implode(',', $rama_children) . "] }";

                    unset($rama_children);
                    $no_app = 0;
                    $rama_app = "";
                } else {

                    if (in_array($app, $total_apps_first)) {
                        //exit();
                    } else {

                        $port_proto_array = array();

                        $i++;
                        $getDefaults = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.default_port, da.risk "
                                . "FROM default_applications da, applications_from_log af WHERE af.app = da.name AND da.name = '$app' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol;");
                        if ($getDefaults->num_rows > 0) {
                            while ($data_defaults = $getDefaults->fetch_assoc()) {
                                $category = $data_defaults['category'];
                                $subcategory = $data_defaults['subcategory'];
                                $technology = $data_defaults['technology'];
                                $default_port = $data_defaults['default_port'];
                                $risk = $data_defaults['risk'];
                            }
                        } else {
                            $getDefaults2 = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.risk "
                                    . "FROM applications da, applications_from_log af WHERE af.app = da.name AND da.name = '$app' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol;");
                            if ($getDefaults2->num_rows > 0) {
                                while ($data_defaults2 = $getDefaults2->fetch_assoc()) {
                                    $category = $data_defaults2['category'];
                                    $subcategory = $data_defaults2['subcategory'];
                                    $technology = $data_defaults2['technology'];
                                    $risk = $data_defaults2['risk'];
                                    $default_port = "";
                                }
                            } else {
                                $getDefaults3 = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.risk "
                                        . "FROM applications da, applications_from_log af WHERE af.app = da.name AND da.vsys = 'shared' AND da.name = '$app' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol;");
                                
                                if ($getDefaults3->num_rows > 0) {
                                    while ($data_defaults3 = $getDefaults3->fetch_assoc()) {
                                        $category = $data_defaults3['category'];
                                        $subcategory = $data_defaults3['subcategory'];
                                        $technology = $data_defaults3['technology'];
                                        $risk = $data_defaults3['risk'];
                                        $default_port = "";
                                    }
                                } else {
                                    $no_app = 1;
                                }
                            }
                        }

                        if ($risk == "1") {
                            $icon_risk = "icon-risk1";
                        } elseif ($risk == "2") {
                            $icon_risk = "icon-risk2";
                        } elseif ($risk == "3") {
                            $icon_risk = "icon-risk3";
                        } elseif ($risk == "4") {
                            $icon_risk = "icon-risk4";
                        } elseif ($risk == "5") {
                            $icon_risk = "icon-risk5";
                        }

                        $getAppsFromLog2 = $projectdb->query("SELECT dport, proto FROM applications_from_log "
                                . "WHERE app = '$app' AND rule_lid = '$rule_lid'  GROUP BY dport, proto LIMIT 5;");
                        //AND DATE(date_retrieve) = '$date_retrieve' 
                        while ($data_app_log2 = $getAppsFromLog2->fetch_assoc()) {
                            $dport = $data_app_log2['dport'];
                            $proto = $data_app_log2['proto'];
                            $port_proto_array[] = $proto . "/" . $dport;
                        }

                        $app_with_ports = $app . " (" . implode(",", $port_proto_array) . ")";

                        if ($no_app == 0) {
                            $rama_app = "expanded:$expanded, app:'$app_with_ports',  text:'$app', value:'$app', date:'$date_retrieve2', category:'', subcategory:'', technology:'', 
                            default_port:'', protocol:'', dport:'', bytes:'', packets:'', leaf:true, iconCls:'$icon_risk', ";
                        }

                        $getAppsFromLog = $projectdb->query("SELECT id, app, dport, bytes, packets, source, rule_lid, vsys, proto "
                                . "FROM applications_from_log "
                                . "WHERE app = '$app' "
                                . "AND rule_lid = '$rule_lid' "
                                . "AND DATE(date_retrieve) = '$date_retrieve' ;");

                        $count = $getAppsFromLog->num_rows;

                        unset($rama_children);
                        $rama_children = array();

                        while ($data_app_log = $getAppsFromLog->fetch_assoc()) {

                            $app_id = $data_app_log['id'];
                            $dport = $data_app_log['dport'];
                            $bytes = $data_app_log['bytes'];
                            $packets = $data_app_log['packets'];
                            $source = $data_app_log['source'];
                            $proto = $data_app_log['proto'];

                            $rama_children[] = "{expanded:$expanded,  app:'$app', date:'$date_retrieve2', app_id: '$app_id', text:'$app', value:'$count',  risk: '$risk', category:'$category', subcategory:'$subcategory', technology:'$technology', default_port:'$default_port', protocol:'$proto', dport:'$dport', bytes:'$bytes', packets:'$packets' , iconCls:'icon-log', leaf:true}";

                            $i ++;
                        }

                        $rama_global_x_app[] = "{ $rama_app  children:[" . implode(',', $rama_children) . "] }";

                        unset($rama_children);

                        $total_apps_first[] = $app;
                        $rama_app = "";
                    }
                    $no_app = 0;
                    $rama_app = "";
                }

                $no_app = 0;
                $rama_app = "";
                $is_first = 1;
            }

            $rama_global_x_app_fin[] = "{ $rama_date  children:[" . implode(',', $rama_global_x_app) . "] }";
        }// fin while principal date

        echo "{text:'.',  \"expanded\":true,  children:[" . implode(',', $rama_global_x_app_fin) . "] }";
    }
    elseif ($type == "known_traffic_by_app_new") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $filter_tech = $projectdb->real_escape_string((string) (isset($_POST['filter_tech']) ? $_POST['filter_tech'] : $_GET['filter_tech']));
        $filter_sub = $projectdb->real_escape_string((string) (isset($_POST['filter_sub']) ? $_POST['filter_sub'] : $_GET['filter_sub']));
        $filter_port = $projectdb->real_escape_string((string) (isset($_POST['filter_port']) ? $_POST['filter_port'] : $_GET['filter_port']));

        $is_first = 0;
        $total_apps_first = array();
        $total_apps_follow = array();

        $filter_tech_array = array();
        $filters_tech_array = array();
        // Filters
        if ($filter_tech != "") {
            $filter_tech_array = explode(",", $filter_tech);
            foreach ($filter_tech_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_tech_array[] = " '$filter' ";
            }
            $sql_filters_tech = " AND da.technology IN ( " . implode(',', $filters_tech_array) . " ) ";
        } else {
            $sql_filters_tech = "";
        }

        $filter_sub_array = array();
        $filters_sub_array = array();
        // Filters
        if ($filter_sub != "") {
            $filter_sub_array = explode(",", $filter_sub);
            foreach ($filter_sub_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_sub_array[] = " '$filter' ";
            }
            $sql_filters_sub = " AND da.subcategory IN ( " . implode(',', $filters_sub_array) . " ) ";
        } else {
            $sql_filters_sub = "";
        }

        $filter_port_array = array();
        $filters_port_array = array();
        $filters_protocol_array = array();
        // Filters
        if ($filter_port != "") {
            $filter_port_array = explode(",", $filter_port);
            foreach ($filter_port_array as $key => $filter) {

                $data_array_p = explode("/", $filter);

                if (!in_array(" '$data_array_p[0]' ", $filters_protocol_array)) {
                    $filters_protocol_array[] = " '$data_array_p[0]' ";
                }
                if (!in_array(" '$data_array_p[1]' ", $filters_port_array)) {
                    $filters_port_array[] = " '$data_array_p[1]' ";
                }
            }
            $sql_filters_port = " AND af.dport IN ( " . implode(',', $filters_port_array) . " ) ";
            $sql_filters_protocol = " AND af.proto IN ( " . implode(',', $filters_protocol_array) . " ) ";
        } else {
            $sql_filters_port = "";
            $sql_filters_protocol = "";
        }

        $expanded = "true";
        $rama_date = "";

        $getDateFromLogUnique = $projectdb->query("SELECT DISTINCT(DATE(date_retrieve)) AS date_retrieve, DATE_FORMAT(date_retrieve, '%Y-%m-%d %H:%i') AS date_retrieve2 "
            . "FROM applications_from_log "
            . "WHERE rule_lid = '$rule_lid' "
            . "ORDER BY date_retrieve ASC;");

        $count_unique = $getDateFromLogUnique->num_rows;

        $i = "1";
        $rama_global_x_app = array();
        $rama_global_x_app_fin = array();
        $app_name_total = array();

        while ($data_uniqueF = $getDateFromLogUnique->fetch_assoc()) {

            $date_retrieve = $data_uniqueF['date_retrieve'];
            $date_retrieve2 = $data_uniqueF['date_retrieve2'];

            //Construir la primera rama principal

            $rama_date = '
                "expanded": '.$expanded.', 
                "app": "'.$date_retrieve2.'", 
                "text": "'.$date_retrieve2.'", 
                "value": "'.$date_retrieve2.'", 
                "date": "'.$date_retrieve2.'", 
                "category": "", 
                "subcategory": "", 
                "technology": "",
                "default_port": "", 
                "protocol": "", 
                "dport": "", 
                "bytes": "", 
                "packets": "",
                "leaf": false, 
                "iconCls": "icon-schedules", 
            ';

            $getAppsFromLogUnique = $projectdb->query("SELECT DISTINCT(af.app) FROM applications_from_log af, default_applications da "
                . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND DATE(af.date_retrieve) = '$date_retrieve' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol "
                . "ORDER BY af.app ASC; ");

            if ($getAppsFromLogUnique->num_rows > 0) {
                while ($data_unique = $getAppsFromLogUnique->fetch_assoc()) {
                    $app_name_total[] = $data_unique['app'];
                }
            }

            $getAppsFromLogUnique2 = $projectdb->query("SELECT DISTINCT(af.app) FROM applications_from_log af, applications da "
                . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND DATE(af.date_retrieve) = '$date_retrieve' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol "
                . "ORDER BY af.app ASC; ");

            if ($getAppsFromLogUnique2->num_rows > 0) {
                while ($data_unique2 = $getAppsFromLogUnique2->fetch_assoc()) {
                    if (!in_array($data_unique2['app'], $app_name_total)) {
                        $app_name_total[] = $data_unique2['app'];
                    }
                }
            }

            $total_apps_follow = array();
            $rama_global_x_app = array();
            $port_proto_array = array();

            $rama_app = "";

            foreach ($app_name_total as $key => $app) {

                $no_app = 0;

                if (in_array($app, $total_apps_first)) {
                    //exit();
                }
                else {

                    $port_proto_array = array();

                    $i++;
                    $getDefaults = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.default_port, da.risk "
                        . "FROM default_applications da, applications_from_log af WHERE af.app = da.name AND da.name = '$app' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol;");

                    if ($getDefaults->num_rows > 0) {
                        while ($data_defaults = $getDefaults->fetch_assoc()) {
                            $category = $data_defaults['category'];
                            $subcategory = $data_defaults['subcategory'];
                            $technology = $data_defaults['technology'];
                            $default_port = $data_defaults['default_port'];
                            $risk = $data_defaults['risk'];
                        }
                    }
                    else {
                        $getDefaults2 = $projectdb->query("SELECT da.category, da.subcategory, da.technology, da.risk "
                            . "FROM applications da, applications_from_log af WHERE af.app = da.name AND da.name = '$app' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol;");

                        if ($getDefaults2->num_rows > 0) {
                            while ($data_defaults2 = $getDefaults2->fetch_assoc()) {
                                $category = $data_defaults2['category'];
                                $subcategory = $data_defaults2['subcategory'];
                                $technology = $data_defaults2['technology'];
                                $risk = $data_defaults2['risk'];
                                $default_port = "";
                            }
                        }
                        else {
                            $no_app = 1;
                        }
                    }

                    $icon_risk = getIconRisk($risk);

                    $getAppsFromLog2 = $projectdb->query("SELECT dport, proto FROM applications_from_log "
                        . "WHERE app = '$app' AND rule_lid = '$rule_lid'  GROUP BY dport, proto LIMIT 5;");

                    while ($data_app_log2 = $getAppsFromLog2->fetch_assoc()) {
                        $dport = $data_app_log2['dport'];
                        $proto = $data_app_log2['proto'];
                        $port_proto_array[] = $proto . "/" . $dport;
                    }

                    $app_with_ports = $app . " (" . implode(",", $port_proto_array) . ")";

                    if ($no_app == 0) {

                        $rama_app = '
                            "expanded": '.$expanded.', 
                            "app": "'.$app_with_ports.'",  
                            "text": "'.$app.'", 
                            "value": "'.$app.'", 
                            "date": "'.$date_retrieve2.'", 
                            "category": "", 
                            "subcategory": "", 
                            "technology": "",
                            "default_port": "", 
                            "protocol": "", 
                            "dport": "", 
                            "bytes": "", 
                            "packets": "",
                            "leaf": true, 
                            "iconCls": "'.$icon_risk.'", 
                        ';
                    }

                    $getAppsFromLog = $projectdb->query("SELECT id, app, dport, bytes, packets, source, rule_lid, vsys, proto "
                        . "FROM applications_from_log "
                        . "WHERE app = '$app' "
                        . "AND rule_lid = '$rule_lid' "
                        . "AND DATE(date_retrieve) = '$date_retrieve' ;");

                    $count = $getAppsFromLog->num_rows;

                    unset($rama_children);
                    $rama_children = array();

                    while ($data_app_log = $getAppsFromLog->fetch_assoc()) {

                        $app_id = $data_app_log['id'];
                        $dport = $data_app_log['dport'];
                        $bytes = $data_app_log['bytes'];
                        $packets = $data_app_log['packets'];
                        $source = $data_app_log['source'];
                        $proto = $data_app_log['proto'];

                        $rama_children[] = '{
                            "expanded": '.$expanded.', 
                            "app": "'.$app.'", 
                            "text": "'.$app.'", 
                            "date": "'.$date_retrieve2.'", 
                            "app_id": "'.$app_id.'", 
                            "value": "'.$count.'", 
                            "risk": "'.$risk.'", 
                            "category": "'.$category.'", 
                            "subcategory": "'.$subcategory.'", 
                            "technology": "'.$technology.'", 
                            "default_port": "'.$default_port.'", 
                            "protocol": "'.$proto.'", 
                            "dport": "'.$dport.'", 
                            "bytes": "'.$bytes.'", 
                            "packets": "'.$packets.'",
                            "iconCls":"icon-applications", 
                            "leaf":true
                        }';

                        $i ++;
                    }

                    $rama_global_x_app[] = '{ '.$rama_app.'  "children":[' . implode(",", $rama_children) . '] }';
                    //$rama_global_x_app[] = '{ '.$rama_app.' }';

                    unset($rama_children);

                    $total_apps_first[] = $app;
                    $rama_app = "";
                }

                $no_app = 0;
                $rama_app = "";
                $is_first = 1;
            }


            $rama_global_x_app_fin[] = '{ '.$rama_date.'  "children":[' . implode(",", $rama_global_x_app) . '] }';
            //$rama_global_x_app_fin[] = "{ $rama_date   }";
        }// fin while principal date

        /*$root = [
            'text' => 'Root',
            'expanded' => true,
            'children' => $master_parent_0
        ];

        echo json_encode($root);*/

        echo '{"text":"Root", "expanded":true, "children":[' . implode(",", $rama_global_x_app_fin) . '] }';

    }
    elseif ($type == "create_rule_known") {

        $rule_old_id = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        $getAppsPhase2 = $projectdb->query("SELECT id, app_id, name, port, default_port, requires, recommended, recommended_requires, app_default, rule_id, rule_old_id "
                . "FROM phase2_known_apps WHERE rule_old_id = '$rule_old_id';");

        $count = $getAppsPhase2->num_rows;

        while ($data = $getAppsPhase2->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif ($type == "graphic_technology") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $app = $projectdb->real_escape_string((string) (isset($_POST['app']) ? $_POST['app'] : $_GET['app']));
        $filter_tech = $projectdb->real_escape_string((string) (isset($_POST['filter_tech']) ? $_POST['filter_tech'] : $_GET['filter_tech']));
        $filter_sub = $projectdb->real_escape_string((string) (isset($_POST['filter_sub']) ? $_POST['filter_sub'] : $_GET['filter_sub']));
        $filter_port = $projectdb->real_escape_string((string) (isset($_POST['filter_port']) ? $_POST['filter_port'] : $_GET['filter_port']));

        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));

        if ($data != "all") {

            $apps_selected = explode(";", $data);

            $date = array();
            $app_array = array();

            $date_sql = "";
            $app_sql = "";

            foreach ($apps_selected as $key => $value) {

                $data_array = explode(",", $value);
                $parser = " af.date_retrieve LIKE '$data_array[1]%' ";

                if (!in_array($parser, $date)) {
                    $date[] = $parser;
                }

                if (!strstr($data_array[0], ':')) {
                    $app_array[] = " '$data_array[0]' ";
                }
            }

            if (count($date) > 0) {
                $date_sql = " AND (  " . implode('OR', $date) . " ) ";
            }
            if (count($app_array) > 0) {
                $app_sql = " AND af.app IN ( " . implode(',', $app_array) . " ) ";
            }
        } else {
            $date_sql = "";
            $app_sql = "";
        }

        $filter_tech_array = array();
        $filters_tech_array = array();
        // Filters
        if ($filter_tech != "") {

            $filter_tech_array = explode(",", $filter_tech);
            foreach ($filter_tech_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_tech_array[] = " '$filter' ";
            }
            $sql_filters_tech = " AND da.technology IN ( " . implode(',', $filters_tech_array) . " ) ";
        } else {
            $sql_filters_tech = "";
        }

        $filter_sub_array = array();
        $filters_sub_array = array();
        // Filters
        if ($filter_sub != "") {
            $filter_sub_array = explode(",", $filter_sub);
            foreach ($filter_sub_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_sub_array[] = " '$filter' ";
            }
            $sql_filters_sub = " AND da.subcategory IN ( " . implode(',', $filters_sub_array) . " ) ";
        } else {
            $sql_filters_sub = "";
        }

        $filter_port_array = array();
        $filters_port_array = array();
        $filters_protocol_array = array();
        // Filters
        if ($filter_port != "") {
            $filter_port_array = explode(",", $filter_port);
            foreach ($filter_port_array as $key => $filter) {

                $data_array_p = explode("/", $filter);

                if (!in_array(" '$data_array_p[0]' ", $filters_protocol_array)) {
                    $filters_protocol_array[] = " '$data_array_p[0]' ";
                }
                if (!in_array(" '$data_array_p[1]' ", $filters_port_array)) {
                    $filters_port_array[] = " '$data_array_p[1]' ";
                }
            }
            $sql_filters_port = " AND af.dport IN ( " . implode(',', $filters_port_array) . " ) ";
            $sql_filters_protocol = " AND af.proto IN ( " . implode(',', $filters_protocol_array) . " ) ";
        } else {
            $sql_filters_port = "";
            $sql_filters_protocol = "";
        }

        $technology = array();
        $array_tech = array();
        $array_tech2 = array();

        $total_all = 0;

        $getTech = $projectdb->query("SELECT COUNT(af.app) AS total, da.technology FROM applications_from_log af, default_applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY da.technology;");

        if ($getTech->num_rows > 0) {
            while ($dataTech = $getTech->fetch_assoc()) {
                $technology[] = $dataTech['technology'];
            }
        }

        $getTech2 = $projectdb->query("SELECT COUNT(af.app) AS total, da.technology FROM applications_from_log af, applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY da.technology;");
        if ($getTech2->num_rows > 0) {
            while ($dataTech2 = $getTech2->fetch_assoc()) {
                $tech = $dataTech2['technology'];
                if (!in_array($tech, $technology)) {
                    $technology[] = $dataTech2['technology'];
                }
            }
        }

        $getTech3 = $projectdb->query("SELECT COUNT(af.app) AS total, da.technology FROM applications_from_log af, applications da "
                . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND af.source = '$source' AND da.vsys = 'shared' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY da.technology;");
        
        if ($getTech3->num_rows > 0) {
            while ($dataTech3 = $getTech3->fetch_assoc()) {
                $tech = $dataTech3['technology'];
                if (!in_array($tech, $technology)) {
                    $technology[] = $dataTech3['technology'];
                }
            }
        }

        //print_r($technology);

        foreach ($technology as $key => $value) {

            $getTotalAppTech = $projectdb->query("SELECT af.app, technology FROM applications_from_log af, default_applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.technology = '$value' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app;");
            $count_app_x_tech = $getTotalAppTech->num_rows;

            $getTotalAppTech2 = $projectdb->query("SELECT af.app, technology FROM applications_from_log af, applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.technology = '$value' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app;");
            $count_app_x_tech2 = $getTotalAppTech2->num_rows;

            $getTotalAppTech3 = $projectdb->query("SELECT af.app, technology FROM applications_from_log af, applications da "
                    . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.vsys = 'shared' AND da.technology = '$value' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app;");
            
            $count_app_x_tech3 = $getTotalAppTech3->num_rows;

            $total = $count_app_x_tech + $count_app_x_tech2 + $count_app_x_tech3;

            $total_all += $total;

            if ($value == "") {
                $value = "unknown";
            }

            $array_tech[] = '{ "technology":"' . $value . '", "total":"' . $total . '"';
        }

        $total_all_array = ', "total_all":"' . $total_all . '" }';
        foreach ($array_tech as $key => $value) {
            $array_tech2[] = $value . $total_all_array;
        }

        echo '{"total":"' . $total_all . '","graphs_tech":[' . implode(",", $array_tech2) . ']}';
    } 
    elseif ($type == "graphic_ports") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $app = $projectdb->real_escape_string((string) (isset($_POST['app']) ? $_POST['app'] : $_GET['app']));
        $filter_tech = $projectdb->real_escape_string((string) (isset($_POST['filter_tech']) ? $_POST['filter_tech'] : $_GET['filter_tech']));
        $filter_sub = $projectdb->real_escape_string((string) (isset($_POST['filter_sub']) ? $_POST['filter_sub'] : $_GET['filter_sub']));
        $filter_port = $projectdb->real_escape_string((string) (isset($_POST['filter_port']) ? $_POST['filter_port'] : $_GET['filter_port']));

        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));

        if ($data != "all") {

            $apps_selected = explode(";", $data);

            $date = array();
            $app_array = array();

            $date_sql = "";
            $app_sql = "";

            foreach ($apps_selected as $key => $value) {

                $data_array = explode(",", $value);
                $parser = " af.date_retrieve LIKE '$data_array[1]%' ";

                if (!in_array($parser, $date)) {
                    $date[] = $parser;
                }

                if (!strstr($data_array[0], ':')) {
                    $app_array[] = " '$data_array[0]' ";
                }
            }

            if (count($date) > 0) {
                $date_sql = " AND (  " . implode('OR', $date) . " ) ";
            }
            if (count($app_array) > 0) {
                $app_sql = " AND af.app IN ( " . implode(',', $app_array) . " ) ";
            }
        } else {
            $date_sql = "";
            $app_sql = "";
        }

        $filter_tech_array = array();
        $filters_tech_array = array();
        // Filters
        if ($filter_tech != "") {
            $filter_tech_array = explode(",", $filter_tech);
            foreach ($filter_tech_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_tech_array[] = " '$filter' ";
            }
            $sql_filters_tech = " AND da.technology IN ( " . implode(',', $filters_tech_array) . " ) ";
        } else {
            $sql_filters_tech = "";
        }

        $filter_sub_array = array();
        $filters_sub_array = array();
        // Filters
        if ($filter_sub != "") {
            $filter_sub_array = explode(",", $filter_sub);
            foreach ($filter_sub_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_sub_array[] = " '$filter' ";
            }
            $sql_filters_sub = " AND da.subcategory IN ( " . implode(',', $filters_sub_array) . " ) ";
        } else {
            $sql_filters_sub = "";
        }

        $filter_port_array = array();
        $filters_port_array = array();
        $filters_protocol_array = array();
        // Filters
        if ($filter_port != "") {
            $filter_port_array = explode(",", $filter_port);
            foreach ($filter_port_array as $key => $filter) {

                $data_array_p = explode("/", $filter);

                if (!in_array(" '$data_array_p[0]' ", $filters_protocol_array)) {
                    $filters_protocol_array[] = " '$data_array_p[0]' ";
                }
                if (!in_array(" '$data_array_p[1]' ", $filters_port_array)) {
                    $filters_port_array[] = " '$data_array_p[1]' ";
                }
            }
            $sql_filters_port = " AND af.dport IN ( " . implode(',', $filters_port_array) . " ) ";
            $sql_filters_protocol = " AND af.proto IN ( " . implode(',', $filters_protocol_array) . " ) ";
        } else {
            $sql_filters_port = "";
            $sql_filters_protocol = "";
        }

        $total_all = 0;
        $array_ports = array();
        $array_ports2 = array();
        $port_proto_array = array();

        $getPorts = $projectdb->query("SELECT af.app, af.dport, af.proto AS protocol FROM applications_from_log af, default_applications da  WHERE af.app = da.name AND af.rule_lid = '$rule_lid' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.dport, af.proto;");
        if ($getPorts->num_rows > 0) {
            while ($dataPorts = $getPorts->fetch_assoc()) {
                $port = $dataPorts['dport'];
                $protocol = $dataPorts['protocol'];

                $port_proto_array[] = $dataPorts['dport'] . ";" . $dataPorts['protocol'];
            }
        }

        $getPorts2 = $projectdb->query("SELECT af.app, af.dport, af.proto AS protocol FROM applications_from_log af, applications da  WHERE af.app = da.name AND af.rule_lid = '$rule_lid' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.dport, af.proto;");
        if ($getPorts2->num_rows > 0) {
            while ($dataPorts2 = $getPorts2->fetch_assoc()) {
                $port = $dataPorts2['dport'];
                $protocol = $dataPorts2['protocol'];

                $port2 = $dataPorts2['dport'] . ";" . $dataPorts2['protocol'];
                if (!in_array($port2, $port_proto_array)) {
                    $port_proto_array[] = $dataPorts2['dport'] . ";" . $dataPorts2['protocol'];
                }

            }
        }

        $getPorts3 = $projectdb->query("SELECT af.app, af.dport, af.proto AS protocol "
                . "FROM applications_from_log af, applications da  "
                . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND af.source = '$source' AND da.vsys = 'shared' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.dport, af.proto;");
        
        if ($getPorts3->num_rows > 0) {
            while ($dataPorts3 = $getPorts3->fetch_assoc()) {
                $port = $dataPorts3['dport'];
                $protocol = $dataPorts3['protocol'];

                $port3 = $dataPorts3['dport'] . ";" . $dataPorts3['protocol'];
                if (!in_array($port3, $port_proto_array)) {
                    $port_proto_array[] = $dataPorts3['dport'] . ";" . $dataPorts3['protocol'];
                }
            }
        }

        foreach ($port_proto_array as $key => $value) {

            $data_array_pp = explode(";", $value);
            $port = $data_array_pp[0];
            $protocol = $data_array_pp[1];

            $getPortsApp = $projectdb->query("SELECT COUNT(af.app) AS total, af.dport, af.proto AS protocol FROM applications_from_log af, default_applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND dport = '$port' AND proto = '$protocol' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app, af.dport, af.proto;");
            $total_app_ports = $getPortsApp->num_rows;

            $getPortsApp2 = $projectdb->query("SELECT COUNT(af.app) AS total, af.dport, af.proto AS protocol FROM applications_from_log af, applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND dport = '$port' AND proto = '$protocol' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app, af.dport, af.proto;");
            $total_app_ports2 = $getPortsApp2->num_rows;

            $getPortsApp3 = $projectdb->query("SELECT COUNT(af.app) AS total, af.dport, af.proto AS protocol FROM applications_from_log af, applications da "
                    . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND af.source = '$source' AND da.vsys = 'shared' AND dport = '$port' AND proto = '$protocol' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app, af.dport, af.proto;");
            $total_app_ports3 = $getPortsApp3->num_rows;

            $total = $total_app_ports + $total_app_ports2 + $total_app_ports3;

            $total_all += $total;

        }

        foreach ($port_proto_array as $key => $value) {

            $data_array_pp = explode(";", $value);
            $port = $data_array_pp[0];
            $protocol = $data_array_pp[1];

            $getPortsApp = $projectdb->query("SELECT COUNT(af.app) AS total, af.dport, af.proto AS protocol FROM applications_from_log af, default_applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND dport = '$port' AND proto = '$protocol' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app, af.dport, af.proto;");
            $total_app_ports = $getPortsApp->num_rows;

            $getPortsApp2 = $projectdb->query("SELECT COUNT(af.app) AS total, af.dport, af.proto AS protocol FROM applications_from_log af, applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND dport = '$port' AND proto = '$protocol' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app, af.dport, af.proto;");
            $total_app_ports2 = $getPortsApp2->num_rows;

            $getPortsApp3 = $projectdb->query("SELECT COUNT(af.app) AS total, af.dport, af.proto AS protocol FROM applications_from_log af, applications da "
                . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND af.source = '$source' AND da.vsys = 'shared' AND dport = '$port' AND proto = '$protocol' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app, af.dport, af.proto;");
            $total_app_ports3 = $getPortsApp3->num_rows;

            $total = $total_app_ports + $total_app_ports2 + $total_app_ports3;

            $pct = ($total / $total_all);

            $array_ports[] = '{ "dport":"' . $protocol . '/' . $port . '", "protocol":"' . $protocol . '", "total":"' . $total . '", "pct":"' . $pct . '" ';
        }


        $total_all_array = ', "total_all":"' . $total_all . '" }';
        foreach ($array_ports as $key => $value) {
            $array_ports2[] = $value . $total_all_array;
        }

        echo '{"total":"' . $total_all . '","graphs_ports":[' . implode(",", $array_ports2) . ']}';
    } 
    elseif ($type == "graphic_sub_risk") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $app = $projectdb->real_escape_string((string) (isset($_POST['app']) ? $_POST['app'] : $_GET['app']));
        $filter_tech = $projectdb->real_escape_string((string) (isset($_POST['filter_tech']) ? $_POST['filter_tech'] : $_GET['filter_tech']));
        $filter_sub = $projectdb->real_escape_string((string) (isset($_POST['filter_sub']) ? $_POST['filter_sub'] : $_GET['filter_sub']));
        $filter_port = $projectdb->real_escape_string((string) (isset($_POST['filter_port']) ? $_POST['filter_port'] : $_GET['filter_port']));

        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));

        if ($data != "all") {

            $apps_selected = explode(";", $data);

            $date = array();
            $app_array = array();

            $date_sql = "";
            $app_sql = "";

            foreach ($apps_selected as $key => $value) {

                $data_array = explode(",", $value);
                $parser = " af.date_retrieve LIKE '$data_array[1]%' ";

                if (!in_array($parser, $date)) {
                    $date[] = $parser;
                }

                if (!strstr($data_array[0], ':')) {
                    $app_array[] = " '$data_array[0]' ";
                }
            }

            if (count($date) > 0) {
                $date_sql = " AND (  " . implode('OR', $date) . " ) ";
            }
            if (count($app_array) > 0) {
                $app_sql = " AND af.app IN ( " . implode(',', $app_array) . " ) ";
            }
        } else {
            $date_sql = "";
            $app_sql = "";
        }

        $filter_tech_array = array();
        $filters_tech_array = array();
        // Filters
        if ($filter_tech != "") {
            $filter_tech_array = explode(",", $filter_tech);
            foreach ($filter_tech_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_tech_array[] = " '$filter' ";
            }
            $sql_filters_tech = " AND da.technology IN ( " . implode(',', $filters_tech_array) . " ) ";
        } else {
            $sql_filters_tech = "";
        }

        $filter_sub_array = array();
        $filters_sub_array = array();
        // Filters
        if ($filter_sub != "") {
            $filter_sub_array = explode(",", $filter_sub);
            foreach ($filter_sub_array as $key => $filter) {
                if ($filter == "unknown") {
                    $filter = "";
                }
                $filters_sub_array[] = " '$filter' ";
            }
            $sql_filters_sub = " AND da.subcategory IN ( " . implode(',', $filters_sub_array) . " ) ";
        } else {
            $sql_filters_sub = "";
        }

        $filter_port_array = array();
        $filters_port_array = array();
        $filters_protocol_array = array();
        // Filters
        if ($filter_port != "") {
            $filter_port_array = explode(",", $filter_port);
            foreach ($filter_port_array as $key => $filter) {

                $data_array_p = explode("/", $filter);

                if (!in_array(" '$data_array_p[0]' ", $filters_protocol_array)) {
                    $filters_protocol_array[] = " '$data_array_p[0]' ";
                }
                if (!in_array(" '$data_array_p[1]' ", $filters_port_array)) {
                    $filters_port_array[] = " '$data_array_p[1]' ";
                }
            }
            $sql_filters_port = " AND af.dport IN ( " . implode(',', $filters_port_array) . " ) ";
            $sql_filters_protocol = " AND af.proto IN ( " . implode(',', $filters_protocol_array) . " ) ";
        } else {
            $sql_filters_port = "";
            $sql_filters_protocol = "";
        }

        $subcategory = array();
        $array_sub = array();

        $getSub = $projectdb->query("SELECT COUNT(af.app) AS total, da.subcategory FROM applications_from_log af, default_applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY da.subcategory;");
        if ($getSub->num_rows > 0) {
            while ($dataSub = $getSub->fetch_assoc()) {
                $subcategory[] = $dataSub['subcategory'];
            }
        }

        $getSub2 = $projectdb->query("SELECT COUNT(af.app) AS total, da.subcategory FROM applications_from_log af, applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY da.subcategory;");

        if ($getSub2->num_rows > 0) {
            while ($dataSub2 = $getSub2->fetch_assoc()) {
                $sub = $dataSub2['subcategory'];
                if (!in_array($sub, $subcategory)) {
                    $subcategory[] = $dataSub2['subcategory'];
                }
            }
        }

        $getSub3 = $projectdb->query("SELECT COUNT(af.app) AS total, da.subcategory FROM applications_from_log af, applications da "
                . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.vsys = 'shared' AND af.source = '$source' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY da.subcategory;");

        if ($getSub3->num_rows > 0) {
            while ($dataSub3 = $getSub3->fetch_assoc()) {
                $sub = $dataSub3['subcategory'];
                if (!in_array($sub, $subcategory)) {
                    $subcategory[] = $dataSub3['subcategory'];
                }
            }
        }

        $risk_array = array(1, 2, 3, 4, 5);

        $total = 0;
        foreach ($subcategory as $key => $value) {

            $risk1 = 0;
            $risk2 = 0;
            $risk3 = 0;
            $risk4 = 0;
            $risk5 = 0;

            foreach ($risk_array as $key => $risk) {

                $getTotalAppRisk = $projectdb->query("SELECT af.app, risk FROM applications_from_log af, default_applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.subcategory = '$value' AND risk = '$risk' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app;");
                $count_app_x_risk = $getTotalAppRisk->num_rows;

                $getTotalAppRisk2 = $projectdb->query("SELECT af.app, risk FROM applications_from_log af, applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.subcategory = '$value' AND risk = '$risk' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app;");
                $count_app_x_risk2 = $getTotalAppRisk2->num_rows;

                $getTotalAppRisk3 = $projectdb->query("SELECT af.app, risk FROM applications_from_log af, applications da "
                        . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.vsys = 'shared' AND da.subcategory = '$value' AND risk = '$risk' $app_sql $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol GROUP BY af.app;");
                $count_app_x_risk3 = $getTotalAppRisk3->num_rows;

                $total = $count_app_x_risk + $count_app_x_risk2 + $count_app_x_risk3;

                if ($risk == "1") {
                    $risk1 = $total;
                } elseif ($risk == "2") {
                    $risk2 = $total;
                } elseif ($risk == "3") {
                    $risk3 = $total;
                } elseif ($risk == "4") {
                    $risk4 = $total;
                } elseif ($risk == "5") {
                    $risk5 = $total;
                }
            }

            $getTotalBytes = $projectdb->query("SELECT SUM(af.bytes) AS total_bytes, da.subcategory FROM applications_from_log af, default_applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.subcategory = '$value' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol $app_sql;");
            if ($getTotalBytes->num_rows > 0) {
                $dataBytes = $getTotalBytes->fetch_assoc();
                $total_bytes = $dataBytes['total_bytes'];
            }

            $getTotalBytes2 = $projectdb->query("SELECT SUM(af.bytes) AS total_bytes, da.subcategory FROM applications_from_log af, applications da WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.subcategory = '$value' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol $app_sql;");
            if ($getTotalBytes2->num_rows > 0) {
                $dataBytes2 = $getTotalBytes2->fetch_assoc();
                $total_bytes2 = $dataBytes2['total_bytes'];
            }

            $getTotalBytes3 = $projectdb->query("SELECT SUM(af.bytes) AS total_bytes, da.subcategory FROM applications_from_log af, applications da "
                    . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND da.vsys = 'shared' AND da.subcategory = '$value' $sql_filters_tech $sql_filters_sub $sql_filters_port $sql_filters_protocol $app_sql;");
            if ($getTotalBytes3->num_rows > 0) {
                $dataBytes3 = $getTotalBytes3->fetch_assoc();
                $total_bytes3 = $dataBytes3['total_bytes'];
            }

            $total_bytes_fin = $total_bytes + $total_bytes2 + $total_bytes3;

            if ($value == "") {
                $value = "unknown";
            }

            $array_sub[] = '{ "sub":"' . $value . '", "risk1":"' . $risk1 . '", "risk2":"' . $risk2 . '", "risk3":"' . $risk3 . '", "risk4":"' . $risk4 . '", "risk5":"' . $risk5 . '", "total_bytes":"' . $total_bytes_fin . '" }';
        }

        echo '{"total":"' . $total . '","graphs_sub":[' . implode(",", $array_sub) . ']}';
    } 
    elseif ($type == "filters_tech") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $technology = array();
        $array_tech = array();

        $getTech = $projectdb->query("SELECT DISTINCT(da.technology) FROM default_applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid' ;");
        if ($getTech->num_rows > 0) {
            while ($dataTech = $getTech->fetch_assoc()) {
                $technology[] = $dataTech['technology'];
            }
        }

        $getTech2 = $projectdb->query("SELECT DISTINCT(da.technology) FROM applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid' ;");
        if ($getTech2->num_rows > 0) {
            while ($dataTech2 = $getTech2->fetch_assoc()) {
                $tech = $dataTech2['technology'];
                if (!in_array($tech, $technology)) {
                    $technology[] = $dataTech2['technology'];
                }
            }
        }

        $getTech3 = $projectdb->query("SELECT DISTINCT(da.technology) FROM applications da, applications_from_log af "
                . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND af.source = '$source' AND da.vsys = 'shared';");
        if ($getTech3->num_rows > 0) {
            while ($dataTech3 = $getTech3->fetch_assoc()) {
                $tech = $dataTech3['technology'];
                if (!in_array($tech, $technology)) {
                    $technology[] = $dataTech3['technology'];
                }
            }
        }

        $total = count($technology);
        foreach ($technology as $key => $value) {
            if ($value == "") {
                $value = "unknown";
            }
            $array_tech[] = '{ "technology":"' . $value . '", "total":"' . $total . '"}';
        }

        echo '{"total":"' . $total . '","filters_tech":[' . implode(",", $array_tech) . ']}';
    } 
    elseif ($type == "filters_sub") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $subcategory = array();
        $array_sub = array();

        $getSub = $projectdb->query("SELECT DISTINCT(da.subcategory) FROM default_applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid' ;");
        if ($getSub->num_rows > 0) {
            while ($dataSub = $getSub->fetch_assoc()) {
                $subcategory[] = $dataSub['subcategory'];
            }
        }

        $getSub2 = $projectdb->query("SELECT DISTINCT(da.subcategory) FROM applications da, applications_from_log af WHERE af.app = da.name AND af.rule_lid = '$rule_lid' ;");
        if ($getSub2->num_rows > 0) {
            while ($dataSub2 = $getSub2->fetch_assoc()) {
                $sub = $dataSub2['subcategory'];
                if (!in_array($sub, $subcategory)) {
                    $subcategory[] = $dataSub2['subcategory'];
                }
            }
        }

        $getSub3 = $projectdb->query("SELECT DISTINCT(da.subcategory) FROM applications da, applications_from_log af "
                . "WHERE af.app = da.name AND af.rule_lid = '$rule_lid' AND af.source = '$source' AND da.vsys = 'shared';");
        if ($getSub3->num_rows > 0) {
            while ($dataSub3 = $getSub3->fetch_assoc()) {
                $sub = $dataSub3['subcategory'];
                if (!in_array($sub, $subcategory)) {
                    $subcategory[] = $dataSub3['subcategory'];
                }
            }
        }

        $total = count($subcategory);
        foreach ($subcategory as $key => $value) {
            if ($value == "") {
                $value = "unknown";
            }
            $array_sub[] = '{ "subcategory":"' . $value . '", "total":"' . $total . '"}';
        }

        echo '{"total":"' . $total . '","filters_sub":[' . implode(",", $array_sub) . ']}';
    } 
    elseif ($type == "filters_ports") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $subcategory = array();
        $array_ports = array();

        $getPorts = $projectdb->query("SELECT af.dport, af.proto AS protocol FROM applications_from_log af WHERE af.rule_lid = '$rule_lid'  GROUP BY af.dport, af.proto;");

        if ($getPorts->num_rows > 0) {
            while ($dataPorts = $getPorts->fetch_assoc()) {

                $port = $dataPorts['dport'];
                $protocol = $dataPorts['protocol'];

                $array_ports[] = '{ "dport":"' . $protocol . '/' . $port . '", "protocol":"' . $protocol . '", "total":"' . $getPorts->num_rows . '" }';
            }
        }

        echo '{"total":"' . $getPorts->num_rows . '","filters_ports":[' . implode(",", $array_ports) . ']}';
    } 
    elseif ($type == "remove_app_id") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        take_snapshot_last($project);

        if ($rule_lid == "all") {
            if ($vsys == "all") {
                $projectdb->query("DELETE FROM applications_from_log WHERE source = '$source';");
            } else {
                $projectdb->query("DELETE FROM applications_from_log WHERE source = '$source' AND vsys = '$vsys';");
            }
        } else {
            $projectdb->query("DELETE FROM applications_from_log WHERE rule_lid IN ($rule_lid);");
        }
        add_log('ok', 'Appid Adoption', 'Remove App-ID via LOG in Rule ID [' . $rule_lid . '].', $source, 'No Action required.');

        echo json_encode(array("success" => true));
    } 
    elseif ($type == "remove_user_id") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        take_snapshot_last($project);

        if ($rule_lid == "all") {
            //$projectdb->query("TRUNCATE table userid_from_log;");
            if ($vsys == "all") {
                $projectdb->query("DELETE FROM userid_from_log WHERE source = '$source';");
            } else {
                $projectdb->query("DELETE FROM userid_from_log WHERE source = '$source' AND vsys = '$vsys';");
            }
        } else {
            $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid IN ($rule_lid) ;");
        }
        add_log('ok', 'Userid Adoption', 'Remove User-ID via LOG in Rule ID [' . $rule_lid . '].', $source, 'No Action required.');

        echo json_encode(array("success" => true));
    } 
    elseif ($type == "known_user_new") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $is_first = 0;
        $total_apps_first = array();
        $total_apps_follow = array();

        $expanded = "true";

        $rama_date = "";

        $getDateFromLogUnique = $projectdb->query("SELECT DISTINCT(DATE(date_retrieve)) AS date_retrieve, DATE_FORMAT(date_retrieve, '%Y-%m-%d %H:%i') AS date_retrieve2 "
                . "FROM userid_from_log "
                . "WHERE rule_lid = '$rule_lid' "
                . "ORDER BY date_retrieve ASC;");

        //, date_retrieve AS date_retrieve3
        $count_unique = $getDateFromLogUnique->num_rows;

        $i = "1";
        $rama_global_x_app = array();
        $rama_global_x_app_fin = array();
        $app_name_total = array();

        while ($data_uniqueF = $getDateFromLogUnique->fetch_assoc()) {

            $date_retrieve = $data_uniqueF['date_retrieve'];
            $date_retrieve2 = $data_uniqueF['date_retrieve2'];
            $date_retrieve3 = $data_uniqueF['date_retrieve3'];

            //Construir la primera rama principal    
            $rama_date = "expanded:$expanded, name:'$date_retrieve2', text:'$date_retrieve2', value:'$date_retrieve2', date:'$date_retrieve2', 
            bytes:'', sessions:'', leaf:false, iconCls: 'icon-schedules', ";

            $getUserFromLogUnique = $projectdb->query("SELECT DISTINCT(name) "
                    . "FROM userid_from_log "
                    . "WHERE rule_lid = '$rule_lid' "
                    . "AND source = '$source' "
                    . "AND date_retrieve LIKE '$date_retrieve2%' "
                    . "ORDER BY name ASC; ");

            if ($getUserFromLogUnique->num_rows > 0) {
                while ($data_unique = $getUserFromLogUnique->fetch_assoc()) {
                    $app_name_total[] = $data_unique['name'];
                }
            }

            $total_apps_follow = array();
            $rama_global_x_app = array();
            $port_proto_array = array();

            $rama_app = "";

            foreach ($app_name_total as $key => $app) {

                $app = addslashes($app);

                if ($is_first == 0) {

                    $total_apps_first[] = $app;
                    $i++;

                    $getAppsFromLog2 = $projectdb->query("SELECT SUM(sessions) AS sessions, SUM(bytes) AS bytes FROM userid_from_log "
                            . "WHERE name = '$app' AND rule_lid = '$rule_lid' GROUP BY name;");

                    while ($data_app_log2 = $getAppsFromLog2->fetch_assoc()) {
                        $sessions = $data_app_log2['sessions'];
                        $bytes = $data_app_log2['bytes'];
                    }

                    $rama_app = "expanded:$expanded, name:'$app',  text:'$app', value:'$app', date:'$date_retrieve2', 
                        bytes:'$bytes', sessions:'$sessions', leaf:false, iconCls:'icon-user', ";

                    $getAppsFromLog = $projectdb->query("SELECT id, app, dport, bytes, packets, source, rule_lid, vsys, proto "
                            . "FROM applications_from_log "
                            . "WHERE app = '$app' "
                            . "AND rule_lid = '$rule_lid' "
                            . "AND date_retrieve = '$date_retrieve' ;");

                    $count = $getAppsFromLog->num_rows;

                    unset($rama_children);
                    $rama_children = array();

                    while ($data_app_log = $getAppsFromLog->fetch_assoc()) {

                        $app_id = $data_app_log['id'];
                        $dport = $data_app_log['dport'];
                        $bytes = $data_app_log['bytes'];
                        $packets = $data_app_log['packets'];
                        $source = $data_app_log['source'];
                        $proto = $data_app_log['proto'];

                        $rama_children[] = "{expanded:$expanded, name:'$app', date:'$date_retrieve2', app_id: '$app_id', text:'$app', value:'$app',  risk: '$risk', category:'$category', subcategory:'$subcategory', technology:'$technology', default_port:'$default_port', protocol:'$proto', dport:'$dport', bytes:'$bytes', packets:'$packets' , iconCls:'icon-applications', leaf:true}";

                        $i ++;
                    }

                    $rama_global_x_app[] = "{ $rama_app  children:[" . implode(',', $rama_children) . "] }";

                    unset($rama_children);
                    $no_app = 0;
                    $rama_app = "";
                } else {

                    if (in_array($app, $total_apps_first)) {
                        //exit();
                    } else {

                        $port_proto_array = array();

                        $i++;

                        $getAppsFromLog2 = $projectdb->query("SELECT SUM(sessions) AS sessions, SUM(bytes) AS bytes FROM userid_from_log "
                                . "WHERE name = '$app' AND rule_lid = '$rule_lid' GROUP BY name;");

                        while ($data_app_log2 = $getAppsFromLog2->fetch_assoc()) {
                            $session = $data_app_log2['sessions'];
                            $bytes = $data_app_log2['bytes'];
                        }

                        $rama_app = "expanded:$expanded, name:'$app',  text:'$app', value:'$app', date:'$date_retrieve2',  
                            bytes:'$bytes', sessions:'$session', leaf:false, iconCls:'icon-user', ";


                        $getAppsFromLog = $projectdb->query("SELECT id, app, dport, bytes, packets, source, rule_lid, vsys, proto "
                                . "FROM applications_from_log "
                                . "WHERE app = '$app' "
                                . "AND rule_lid = '$rule_lid' "
                                . "AND date_retrieve = '$date_retrieve' ;");

                        $count = $getAppsFromLog->num_rows;

                        unset($rama_children);
                        $rama_children = array();

                        while ($data_app_log = $getAppsFromLog->fetch_assoc()) {

                            $app_id = $data_app_log['id'];
                            $dport = $data_app_log['dport'];
                            $bytes = $data_app_log['bytes'];
                            $packets = $data_app_log['packets'];
                            $source = $data_app_log['source'];
                            $proto = $data_app_log['proto'];

                            $rama_children[] = "{expanded:$expanded,  name:'$app', date:'$date_retrieve2', app_id: '$app_id', text:'$app', value:'$app',  risk: '$risk', category:'$category', subcategory:'$subcategory', technology:'$technology', default_port:'$default_port', protocol:'$proto', dport:'$dport', bytes:'$bytes', packets:'$packets' , iconCls:'icon-log', leaf:true}";

                            $i ++;
                        }

                        $rama_global_x_app[] = "{ $rama_app  children:[" . implode(',', $rama_children) . "] }";

                        unset($rama_children);

                        $total_apps_first[] = $app;
                        $rama_app = "";
                    }
                    $no_app = 0;
                    $rama_app = "";
                }

                $no_app = 0;
                $rama_app = "";
                $is_first = 1;
            }

            $rama_global_x_app_fin[] = "{ $rama_date  children:[" . implode(',', $rama_global_x_app) . "] }";
        }// fin while principal date


        echo "{text:'.', children:[" . implode(',', $rama_global_x_app_fin) . "] }";
    } 
    elseif ($type == "recommended_groups") {

        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        if ($data != "") {
            $groups_math_finish = array();
            //$groups_math_finish = getRecommendedGroupsUserId($rule_lid, $data, $source);

            if ($data != "no_calculate") {
                list($groups_math_finish, $groups_math_finish_reco) = getRecommendedGroupsUserId($rule_lid, $data, $source);
            }

        }
        $getRecommended = $projectdb->query("SELECT id, name, img, rule_lid FROM userid_group_recommended WHERE rule_lid = '$rule_lid';");

        if ($getRecommended->num_rows > 0) {
            while ($dataR = $getRecommended->fetch_assoc()) {

                $id = $dataR['id'];
                $name = addslashes($dataR['name']);
                $img = $dataR['img'];
                $rule_lid = $dataR['rule_lid'];

                $total_results[] = '{ "idx":"' . $id . '", "img":"' . $img . '", "name":"' . $name . '", "rule_lid":"' . $rule_lid . '"  }';
            }
            echo '{"total":"' . count($total_results) . '","recommended":[' . implode(",", $total_results) . ']}';
        } else {
            echo '{"total":"0"}';
        }
    } 
    elseif ($type == "graphic_bytes_userid") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));

        $total_results = array();

        if ($data != "all") {

            $apps_selected = explode(";", $data);

            $date = array();
            $app_array = array();

            $date_sql = "";
            $app_sql = "";

            foreach ($apps_selected as $key => $value) {

                $data_array = explode(",", $value);
                $parser = " date_retrieve LIKE '$data_array[1]%' ";

                if (!in_array($parser, $date)) {
                    $date[] = $parser;
                }

                if (!strstr($data_array[0], ':')) {
                    $name = addslashes($data_array[0]);
                    $app_array[] = " '$name' ";
                }
            }

            if (count($date) > 0) {
                $date_sql = " AND (  " . implode('OR', $date) . " ) ";
            }
            if (count($app_array) > 0) {
                $app_sql = " AND name IN ( " . implode(',', $app_array) . " ) ";
            }
        } else {
            $date_sql = "";
            $app_sql = "";
        }

        $getBytes = $projectdb->query("SELECT SUM(bytes) AS total_bytes, SUM(sessions) AS total_sessions, name FROM userid_from_log WHERE rule_lid = '$rule_lid' $app_sql GROUP BY name ORDER BY total_bytes DESC LIMIT 10;");
        if ($getBytes->num_rows > 0) {
            while ($dataB = $getBytes->fetch_assoc()) {

                $total_bytes = $dataB['total_bytes'];
                $total_sessions = $dataB['total_sessions'];
                $name = addslashes($dataB['name']);

                $total_results[] = '{ "name":"' . $name . '", "total_bytes":"' . $total_bytes . '", "total_sessions":"' . $total_sessions . '" }';
            }
        }


        echo '{"total":"' . count($total_results) . '","graphs_bytes":[' . implode(",", $total_results) . ']}';
    } 
    elseif ($type == "useridxml") {

        $data_reco = $projectdb->real_escape_string((string) (isset($_POST['data_reco']) ? $_POST['data_reco'] : $_GET['data_reco']));
        $data_users = $projectdb->real_escape_string((string) (isset($_POST['data_users']) ? $_POST['data_users'] : $_GET['data_users']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $options = $projectdb->real_escape_string((string) (isset($_POST['options']) ? $_POST['options'] : $_GET['options']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        take_snapshot_last($project);

        if (($data_reco != "") || ($data_users != "")) {

            $getSourceVsys = $projectdb->query("SELECT source, vsys FROM security_rules WHERE id = '$rule_lid';");
            if ($getSourceVsys->num_rows == 1) {
                $data = $getSourceVsys->fetch_assoc();
                $source = $data['source'];
                $vsys = $data['vsys'];
            }
            $user = array();
            if ($options == "recommended") {
                $id = array();
                $data_split = explode(",", $data_reco);
                foreach ($data_split as $key => $value) {
                    $data2_split = explode(";", $value);
                    $id[] = $data2_split[0];
                    $user[] = addslashes($data2_split[1]);
                }
                if (count($user) > 0) {
                    $elements = "";
                    foreach ($user as $key => $value) {
                        if (($value != "unknown") AND ( $value != "known-user") AND ( $value != "pre-logon") AND ( $value != "")) {
                            $elements.='<entry name="' . $value . '"/>';
                        }
                    }
                    if ($elements != "") {
                        $result = '<uid-message><version>2.0</version><type>update</type><payload><groups><entry name="' . $name . '"><members>' . $elements . '</members></entry></groups></payload></uid-message>';
                        echo json_encode(array("success" => true, "result" => $result));
                    } else {
                        echo json_encode(array("success" => false, "result" => ""));
                    }
                }
            } elseif ($options == "users selection") {
                $data_split2 = explode(",", $data_users);
                foreach ($data_split2 as $key => $value) {
                    $data2_split = explode(";", $value);
                    if (!strstr($data2_split[1], ':')) {
                        $id = $data2_split[0];
                        $user[] = addslashes($data2_split[1]);
                    }
                }
                if (count($user) > 0) {
                    $elements = "";
                    foreach ($user as $key => $value) {
                        if (($value != "unknown") AND ( $value != "known-user") AND ( $value != "pre-logon") AND ( $value != "")) {
                            $elements.='<entry name="' . $value . '"/>';
                        }
                    }
                    if ($elements != "") {
                        $result = '<uid-message><version>2.0</version><type>update</type><payload><groups><entry name="' . $name . '"><members>' . $elements . '</members></entry></groups></payload></uid-message>';
                        echo json_encode(array("success" => true, "result" => $result));
                    } else {
                        echo json_encode(array("success" => false, "result" => ""));
                    }
                }
            }
        } else {
            echo json_encode(array("success" => false, "result" => ""));
        }
    }
} 
elseif ($action == "set") {

    $type = $projectdb->real_escape_string((string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']));

    if ($type == "create_rule_known") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $oldRule = $rule_lid;
        $message = "Appid";

        $projectdb->query("DELETE FROM phase2_known_apps;");

        $getPosition = $projectdb->query("SELECT position FROM security_rules WHERE id='$oldRule' ;");
        $getPosData = $getPosition->fetch_assoc();
        $initialPosition = $getPosData['position'];
        $finalPosition = $initialPosition - 1;
        // 1. Crear rule, clonoandola, por debajo
        $newlid = clone_security_rule($initialPosition, $finalPosition, $vsys, $source, $oldRule, $message, $project);
        //$newlid = "20";
        //delete from security_rules_app (las aplicaciones) / security_rules_srv --> table name??
        $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid = '$newlid';");
        $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$newlid';");
        $data_selected = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));

        $apps_selected = explode("_", $data_selected);

        foreach ($apps_selected as $key => $value) {
            //echo "Los valores son: " .$value. "<br>";
            $app_array[] = explode(";", $value);
        }

        //NUEVOS!!
        // Caso 1. Si seleccionan el padre, es todos los puertos, ir a buscar los ids a la tabla applications_from_log de la aplicacion
        // Caso 2. Si seleccionan el/los hijos, son solo los puertos de esa aplicacion, ya tengo los ids aqui


        $total_app_selected = count($app_array);

        // 1. Primero leer si hay aplicaciones, si es así, las añado a la BBDD y luego update de todas y arreando
        for ($i = 0; $i < $total_app_selected; $i ++) {

            //echo "Las aplicaciones son: " .$app_array[$i][1]. "<br>";
            // Caso 1
            if ($app_array[$i][1] != "") {

                $name_app = $app_array[$i][1];
                //Buscar los ids del padre y añadirlos en la tabla
                $getIdApp = $projectdb->query("SELECT id, dport, proto "
                        . "FROM applications_from_log WHERE app = '$name_app' AND rule_lid='$oldRule' GROUP BY app, dport;");

                while ($data_id_app = $getIdApp->fetch_assoc()) {

                    $id_app_selected = $data_id_app['id'];
                    $dport_app_selected = $data_id_app['dport'];
                    $proto_app_selected = $data_id_app['proto'];

                    calculateKnownApp($name_app, $id_app_selected, $dport_app_selected, $proto_app_selected, $newlid, $rule_lid);
                }//FIN WHILE
                // Caso 2
                // Han seleccionado por puertos ya que el campo de la aplicaciópn esta vacia
            }
            elseif ($app_array[$i][1] == "") {
                // Buscar el nombre de la applicacion
                $id_app = $app_array[$i][0];
                //echo "El ID de la aplicacion  es: " .$id_app. "<br>";

                $getNameApp = $projectdb->query("SELECT app, id, dport, proto "
                        . "FROM applications_from_log WHERE id = '$id_app' GROUP BY app, dport;");

                while ($data_name_app = $getNameApp->fetch_assoc()) {
                    $name_app = $data_name_app['app'];
                    $id_app_selected = $data_name_app['id'];
                    $dport_app_selected = $data_name_app['dport'];
                    $proto_app_selected = $data_name_app['proto'];
                    //echo "La app seleccionada hija es: " .$name_app. "<br>";

                    calculateKnownApp($name_app, $id_app_selected, $dport_app_selected, $proto_app_selected, $newlid, $rule_lid);
                }
            }//if de si es x aplicación o por puerto
        }//for por cada item que ha pasado   
        // IMPORTANTE: Sacar de la rule_id origen las aplicaciones que se han migrado en la nueva rule que se ha creado 
        // IMPORTANTE: Sacar de la application_form_log las aplicaciones app_id que se han convertido en la nueva rule
    } 
    elseif ($type == "create_rule_known_finish") {

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $comboaction = $projectdb->real_escape_string((string) (isset($_POST['comboaction']) ? $_POST['comboaction'] : $_GET['comboaction']));
        $rulename = $projectdb->real_escape_string((string) (isset($_POST['rulename']) ? $_POST['rulename'] : $_GET['rulename']));
        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']));
        $optionselected = $projectdb->real_escape_string((string) (isset($_POST['optionselected']) ? $_POST['optionselected'] : $_GET['optionselected']));

        $getRule = $projectdb->query("SELECT rule_id FROM phase2_known_apps GROUP BY rule_id;");
        if ($getRule->num_rows == 1) {
            $getRuleData = $getRule->fetch_assoc();
            $rule_lid = $getRuleData['rule_id'];
            $projectdb->query("UPDATE security_rules SET name='$rulename', action='$comboaction' WHERE id='$rule_lid';");

            #Load Apps from Rule
            $getActualApps = $projectdb->query("SELECT table_name,member_lid FROM security_rules_app WHERE rule_lid='$rule_lid';");
            if ($getActualApps->num_rows > 0) {
                while ($getActualAppsData = $getActualApps->fetch_assoc()) {
                    $table_name = $getActualAppsData['table_name'];
                    $member_lid = $getActualAppsData['member_lid'];
                    $getActualAppsName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid';");
                    if ($getActualAppsName->num_rows == 1) {
                        $getActualAppsNameData = $getActualAppsName->fetch_assoc();
                        $appname = $getActualAppsNameData['name'];
                        $apptemp[] = array("name" => $appname, "table_name" => $table_name, "member_lid" => $member_lid);
                    }
                }
            }
            $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid='$rule_lid';");
            $knownids = explode(",", $data);
            foreach ($knownids as $key => $value) {
                $getApps = $projectdb->query("SELECT name,requires,recommended,recommended_requires,app_default FROM phase2_known_apps WHERE id='$value';");
                $count_apps = $getApps->num_rows;
                $count_app_default = 0;
                while ($getAppsData = $getApps->fetch_assoc()) {
                    if (($optionselected == "applications") OR ( $optionselected == "applications_deps")) {
                        $selected = $getAppsData["name"];
                        $app_default = $getAppsData['app_default'];
                        $count_app_default = $app_default + $count_app_default;
                        $getMember = $projectdb->query("SELECT id FROM default_applications WHERE name='$selected';");
                        if ($getMember->num_rows == 1) {
                            $getMemberData = $getMember->fetch_assoc();
                            $member_lid = $getMemberData['id'];
                            $table_name = "default_applications";
                            $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                        } else {
                            # search on applications and shared_applications
                            $getMember = $projectdb->query("SELECT id FROM applications WHERE name='$selected' AND source='$source' AND vsys='$vsys';");
                            if ($getMember->num_rows == 1) {
                                $getMemberData = $getMember->fetch_assoc();
                                $member_lid = $getMemberData['id'];
                                $table_name = "applications";
                                $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                            } else{
                                $getMember = $projectdb->query("SELECT id FROM applications WHERE name='$selected' AND source='$source' AND vsys='shared';");
                                if ($getMember->num_rows == 1) {
                                    $getMemberData = $getMember->fetch_assoc();
                                    $member_lid = $getMemberData['id'];
                                    $table_name = "applications";
                                    $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                                }
                            }
                        }

                        if ($optionselected == "applications_deps") {
                            $requires = $getAppsData["requires"];
                            $requires_array = explode(",", $requires);
                            foreach ($requires_array as $required) {
                                $getMember = $projectdb->query("SELECT id FROM default_applications WHERE name='$required';");
                                if ($getMember->num_rows == 1) {
                                    $getMemberData = $getMember->fetch_assoc();
                                    $member_lid = $getMemberData['id'];
                                    $table_name = "default_applications";
                                    $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                                } else {
                                    # search on applications and shared_applications
                                    $getMember = $projectdb->query("SELECT id FROM applications WHERE name='$selected' AND source='$source' AND vsys='$vsys';");
                                    if ($getMember->num_rows == 1) {
                                        $getMemberData = $getMember->fetch_assoc();
                                        $member_lid = $getMemberData['id'];
                                        $table_name = "applications";
                                        $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                                    } else{
                                        $getMember = $projectdb->query("SELECT id FROM applications WHERE name='$selected' AND source='$source' AND vsys='shared';");
                                        if ($getMember->num_rows == 1) {
                                            $getMemberData = $getMember->fetch_assoc();
                                            $member_lid = $getMemberData['id'];
                                            $table_name = "applications";
                                            $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    elseif (($optionselected == "recommended") OR ( $optionselected == "recommended_deps")) {
                        $selected = $getAppsData["recommended"];
                        $app_default = $getAppsData['app_default'];
                        $count_app_default = $app_default + $count_app_default;
                        $getMember = $projectdb->query("SELECT id FROM default_applications WHERE name='$selected';");
                        if ($getMember->num_rows == 1) {
                            $getMemberData = $getMember->fetch_assoc();
                            $member_lid = $getMemberData['id'];
                            $table_name = "default_applications";
                            $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                        } else {
                            # search on applications and shared_applications
                            $getMember = $projectdb->query("SELECT id FROM applications WHERE name='$selected' AND source='$source' AND vsys='$vsys';");
                            if ($getMember->num_rows == 1) {
                                $getMemberData = $getMember->fetch_assoc();
                                $member_lid = $getMemberData['id'];
                                $table_name = "applications";
                                $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                            } else{
                                $getMember = $projectdb->query("SELECT id FROM applications WHERE name='$selected' AND source='$source' AND vsys='shared';");
                                if ($getMember->num_rows == 1) {
                                    $getMemberData = $getMember->fetch_assoc();
                                    $member_lid = $getMemberData['id'];
                                    $table_name = "applications";
                                    $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                                }
                            }
                        }

                        if ($optionselected == "recommended_deps") {
                            $requires = $getAppsData["recommended_requires"];
                            $requires_array = explode(",", $requires);
                            foreach ($requires_array as $required) {
                                $getMember = $projectdb->query("SELECT id FROM default_applications WHERE name='$required';");
                                if ($getMember->num_rows == 1) {
                                    $getMemberData = $getMember->fetch_assoc();
                                    $member_lid = $getMemberData['id'];
                                    $table_name = "default_applications";
                                    $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                                } else {
                                    # search on applications and shared_applications
                                    $getMember = $projectdb->query("SELECT id FROM applications WHERE name='$selected' AND source='$source' AND vsys='$vsys';");
                                    if ($getMember->num_rows == 1) {
                                        $getMemberData = $getMember->fetch_assoc();
                                        $member_lid = $getMemberData['id'];
                                        $table_name = "applications";
                                        $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                                    } else{
                                        $getMember = $projectdb->query("SELECT id FROM applications WHERE name='$selected' AND source='$source' AND vsys='shared';");
                                        if ($getMember->num_rows == 1) {
                                            $getMemberData = $getMember->fetch_assoc();
                                            $member_lid = $getMemberData['id'];
                                            $table_name = "applications";
                                            $apptemp[] = array("name" => $selected, "table_name" => $table_name, "member_lid" => $member_lid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            #$getUnique=arrayUnique($ultimate,true);

            foreach ($apptemp as $key => $values) {
                $myarray[] = "('$rule_lid','$source','$vsys','" . $values['member_lid'] . "','" . $values['table_name'] . "')";
            }
            $myunique = array_unique($myarray);
            $projectdb->query("INSERT INTO security_rules_app (rule_lid,source,vsys,member_lid,table_name) VALUES " . implode(",", $myunique) . ";");

            checkGetParentApp($rule_lid);

            if ($count_app_default == $count_apps) {
                $getAppdefault = $projectdb->query("SELECT id FROM services WHERE name='application-default' AND source='$source' AND vsys = 'shared';");
                if ($getAppdefault->num_rows == 1) {
                    $getAppdefaultData = $getAppdefault->fetch_assoc();
                    $appid_default = $getAppdefaultData['id'];
                    $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid='$rule_lid';");
                    $projectdb->query("INSERT INTO security_rules_srv (source,vsys,member_lid,table_name,rule_lid) VALUES ('$source','$vsys','$appid_default','services','$rule_lid')");
                }
            }
        }

        echo json_encode(array("success" => true));
    } 
    elseif ($type == "create_rule_known_finish_all") {

        $delete_from_log = $projectdb->real_escape_string((string) (isset($_POST['delete_from_log']) ? $_POST['delete_from_log'] : $_GET['delete_from_log']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $comboaction = $projectdb->real_escape_string((string) (isset($_POST['comboaction']) ? $_POST['comboaction'] : $_GET['comboaction']));
        $rulename = $projectdb->real_escape_string((string) (isset($_POST['rulename']) ? $_POST['rulename'] : $_GET['rulename']));
        //$data = (string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data']);
        //$optionselected = (string) (isset($_POST['optionselected']) ? $_POST['optionselected'] : $_GET['optionselected']);
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        $getApp = $projectdb->query("SELECT DISTINCT(app) FROM applications_from_log WHERE id IN($delete_from_log);");

        while ($dataApp = $getApp->fetch_assoc()) {
            $app = $dataApp['app'];
            $projectdb->query("DELETE FROM applications_from_log WHERE app = '$app' WHERE rule_lid='$rule_lid';");
        }
        $projectdb->query("TRUNCATE TABLE phase2_known_apps;");
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "remove_create_rule") {

        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $getRuleId = $projectdb->query("SELECT rule_id FROM phase2_known_apps limit 1;");

        if ($getRuleId->num_rows > 0) {
            while ($data_rule = $getRuleId->fetch_assoc()) {
                $rule_id = $data_rule['rule_id'];
                delete_security_rule($vsys, $source, $rule_id);
            }
        }

        $projectdb->query("DELETE FROM phase2_known_apps;");
    } 
    elseif ($type == "add_group_recommended") {

        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        $getExistGroup = $projectdb->query("SELECT id FROM userid_group_recommended WHERE name = '$name' AND rule_lid = '$rule_lid';");
        if ($getExistGroup->num_rows == 0) {

            $isGroup = $projectdb->query("SELECT name FROM userid_group WHERE name = '$name' OR short_name = '$name';");
            if ($isGroup->num_rows > 0) {
                $image = 'user-groups.png';
            } else {
                $image = 'userp.png';
            }
            $projectdb->query("INSERT INTO userid_group_recommended (name, img, rule_lid) VALUES ('$name','$image','$rule_lid');");
        }
    } 
    elseif ($type == "add_group_recommended_to_rule") {

        $data_reco = $projectdb->real_escape_string((string) (isset($_POST['data_reco']) ? $_POST['data_reco'] : $_GET['data_reco']));
        $data_users = $projectdb->real_escape_string((string) (isset($_POST['data_users']) ? $_POST['data_users'] : $_GET['data_users']));
        $options = $projectdb->real_escape_string((string) (isset($_POST['options']) ? $_POST['options'] : $_GET['options']));

        $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));

        take_snapshot_last($project);

        if (($data_reco != "") || ($data_users != "")) {

            $getSourceVsys = $projectdb->query("SELECT source, vsys FROM security_rules WHERE id = '$rule_lid';");
            if ($getSourceVsys->num_rows == 1) {
                $data = $getSourceVsys->fetch_assoc();
                $source = $data['source'];
                $vsys = $data['vsys'];
            }

            if ($options == "recommended") {
                $id = array();
                $data_split = explode(",", $data_reco);
                $total_reco = count($data_split);
                if ($data_reco != "") {

                    foreach ($data_split as $key => $value) {
                        $data2_split = explode(";", $value);
                        $id[] = $data2_split[0];
                        $user = addslashes($data2_split[1]);

                        if ($user != "unknown") {
                            $getExistUsr = $projectdb->query("SELECT id FROM security_rules_usr WHERE rule_lid = '$rule_lid' AND name = '$user' ;");
                            if ($getExistUsr->num_rows == 0) {
                                $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid = '$rule_lid' AND name IN ('pre-logon', 'known-user', 'unknown');");
                                $projectdb->query("INSERT INTO security_rules_usr (source, vsys, name, rule_lid) VALUES ('$source','$vsys','$user','$rule_lid');");
                            }
                        }

                        if (($total_reco == 1) && ($user == "unknown")) {
                            $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid = '$rule_lid';");
                            $projectdb->query("INSERT INTO security_rules_usr (source, vsys, name, rule_lid) VALUES ('$source','$vsys','$user','$rule_lid');");
                            $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name = 'unknown';");
                        }
                    }
                    if ($data_users != "") {
                        $data_split2 = explode(",", $data_users);
                        foreach ($data_split2 as $key => $value) {
                            $data2_split = explode(";", $value);

                            if (!strstr($data2_split[1], ':')) {
                                $id = $data2_split[0];
                                $user_from = addslashes($data2_split[1]);
                                $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name = '$user_from';");
                            }
                        }
                    } else {
                        $getType = $projectdb->query("SELECT img, name FROM userid_group_recommended WHERE id IN (" . implode(",", $id) . ");");
                        if ($getType->num_rows > 0) {
                            while ($dataT = $getType->fetch_assoc()) {
                                $img = $dataT['img'];
                                $name = addslashes($dataT['name']);
                                if (preg_match("/groups/i", $img)) {
                                    $getGroup = $projectdb->query("SELECT id FROM userid_group WHERE name = '$name' OR short_name = '$name';");
                                    if ($getGroup->num_rows > 0) {
                                        $dataG = $getGroup->fetch_assoc();
                                        $lid_group = $dataG['id'];
                                        $getUsers = $projectdb->query("SELECT name FROM userid_group_members WHERE lid = '$lid_group';");
                                        if ($getUsers->num_rows > 0) {
                                            while ($dataU = $getUsers->fetch_assoc()) {
                                                $user_f = addslashes($dataU['name']);
                                                $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name = '$user_f' AND name != 'unknown';");
                                            }
                                        }
                                    }
                                } else {
                                    $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name = '$name' AND name != 'unknown';");
                                }
                            }
                        }
                    }
                }
            }
            elseif ($options == "users selection") {

                $data_split2 = explode(",", $data_users);
                $total_reco = count($data_split);
                if ($data_users != "") {
                    foreach ($data_split2 as $key => $value) {
                        $data2_split = explode(";", $value);
                        if (!strstr($data2_split[1], ':')) {
                            $id = $data2_split[0];
                            $user_from = addslashes($data2_split[1]);

                            if ($user_from != "unknown") {
                                $getExistUsr = $projectdb->query("SELECT id FROM security_rules_usr WHERE rule_lid = '$rule_lid' AND name = '$user_from' ;");
                                if ($getExistUsr->num_rows == 0) {
                                    $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid = '$rule_lid' AND name IN ('pre-logon', 'known-user', 'unknown');");
                                    $projectdb->query("INSERT INTO security_rules_usr (source, vsys, name, rule_lid) VALUES ('$source','$vsys','$user_from','$rule_lid');");
                                }
                                $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name = '$user_from' AND name != 'unknown';");
                            }
                            if (($total_reco == 1) && ($user == "unknown")) {
                                $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid = '$rule_lid';");
                                $projectdb->query("INSERT INTO security_rules_usr (source, vsys, name, rule_lid) VALUES ('$source','$vsys','$user','$rule_lid');");
                                $projectdb->query("DELETE FROM userid_from_log WHERE rule_lid = '$rule_lid' AND name = 'unknown';");
                            }
                        }
                    }
                }
            } else {

                if ($options == "any") {
                    $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid = '$rule_lid';");
                } else {
                    $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid = '$rule_lid';");
                    $projectdb->query("INSERT INTO security_rules_usr (source, vsys, name, rule_lid) VALUES ('$source','$vsys','$options','$rule_lid');");
                }
            }
        }
    }
} 
elseif ($action == "send_api_calls") {
    #PHP VARS
    ini_set('max_execution_time', 10000);
    ini_set("memory_limit", PARSER_max_execution_memory);
    $device = $projectdb->real_escape_string((string) (isset($_POST['device']) ? $_POST['device'] : $_GET['device']));
    $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
    $cmd = $projectdb->real_escape_string((string) (isset($_POST['cmd']) ? $_POST['cmd'] : $_GET['cmd']));
    $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
    $replace = $projectdb->real_escape_string((string) (isset($_POST['replace']) ? $_POST['replace'] : $_GET['replace']));
    $rule_lid = $projectdb->real_escape_string((string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']));
    $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
    $data_reco = $projectdb->real_escape_string((string) (isset($_POST['data_reco']) ? $_POST['data_reco'] : $_GET['data_reco']));
    $data_users = $projectdb->real_escape_string((string) (isset($_POST['data_users']) ? $_POST['data_users'] : $_GET['data_users']));
    $options = $projectdb->real_escape_string((string) (isset($_POST['options']) ? $_POST['options'] : $_GET['options']));

    if ($vsys == "all") {
        $vsys = "vsys1";
    }

    #DEBUG
    //$device=2;
    //$vsys="vsys1";
    //$replace=0;
    //$name="group7";
    //$cmd='<uid-message><version>2.0</version><type>update</type><payload><groups><entry name="group100"><members><entry name="aestevez"/></members></entry></groups></payload></uid-message>';
    #DEBUG
    $target = "";
    $getDevice = $pandb->query("SELECT hostname,port,serial,ispanorama,api_key,management FROM devices WHERE id='$device';");
    if ($getDevice->num_rows == 1) {
        $deviceData = $getDevice->fetch_assoc();
        $hostname = $deviceData['hostname'];
        $serial = $deviceData['serial'];
        $port = $deviceData['port'];
        $ispanorama = $deviceData['ispanorama'];
        $api_key = $deviceData['api_key'];
        $device_management = $deviceData['management'];
        if ($port == "") {
            $port = "443";
        }
        if ($api_key == "") {
            $getPanorama = $pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
            if ($getPanorama->num_rows == 1) {
                $getPanoramaData = $getPanorama->fetch_assoc();
                $hostname = $getPanoramaData['hostname'];
                $port = $getPanoramaData['port'];
                $panorama_devicename = $getPanoramaData['name'];
                $api_key = $getPanoramaData['api_key'];
                $target = $serial;
            }
        }
        # Send the API CALL to the DEVICE
        $devicePath = $hostname . "/api";
        $tuCurl = curl_init();

        $action = "set";
        if (($target != "") Or ( $ispanorma == 1)) {
            $datatopost = array(
                "type" => "user-id",
                "action" => $action,
                //"key" => $api_key,
                "target" => $serial,
                "cmd" => $cmd,
                "vsys" => $vsys
            );
        } else {
            $datatopost = array(
                "type" => "user-id",
                "action" => $action,
                //"key" => $api_key,
                "cmd" => $cmd,
                "vsys" => $vsys
            );
        }
        $debugapi = USERSPACE_PATH."/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');
        /*foreach ($datatopost as $key1 => $value1) {
            if ($key1 == "key") {
                
            } else {
                $fields_string[] = $key1 . '=' . $value1;
            }
        }
        $url0 = "https://" . $devicePath . "?" . implode("&", $fields_string);
        $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        fwrite($curl_log, $url);*/
        $fields_string = array();

        if (!defined('PARSER_max_number_address_per_group')) {
            define('PARSER_max_number_address_per_group', -1);
        }

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
        curl_setopt($tuCurl, CURLOPT_PORT, $port);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT);
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
        curl_setopt($tuCurl, CURLOPT_POST, 1);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 15);
        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        if (curl_errno($tuCurl) == 28) {
            echo json_encode(array('success' => false, 'msg' => 'The connection with the device cannot be established.'));
            exit(0);
        } else {
            $line = curl_multi_getcontent($tuCurl);
            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
            $xml = simplexml_load_string($newline);
            if (preg_match("/Not authorized to access/i", $newline)) {
                echo json_encode(array('success' => false, 'msg' => 'You do not have access to the device'));
                exit;
            } elseif (preg_match("/Authentication failed: Invalid username or password/i", $newline)) {
                echo json_encode(array('success' => false, 'msg' => 'Authentication failed: Invalid username or password'));
                exit;
            } else {
                echo json_encode(array("success" => true));
            }
        }
        curl_close($tuCurl);
        fclose($curl_log);
    }

    if ($replace == "on") {
        $dup = $projectdb->query("SELECT id FROM userid_group_recommended WHERE name='$name' AND rule_lid='$rule_lid';");
        if ($dup->num_rows == 0) {
            $projectdb->query("INSERT INTO userid_group_recommended (name,img,rule_lid) VALUES ('$name','user-groups.png','$rule_lid');");
        }
    }

    if ($options == "users selection") {

        $data_split2 = explode(",", $data_users);
        $total_reco = count($data_split);
        if ($data_users != "") {
            $getConnector = $pandb->query("SELECT userid_connector FROM projects WHERE name = '$project' ;");
            if ($getConnector->num_rows > 0) {
                $dataC = $getConnector->fetch_assoc();
                $connector_id = $dataC['userid_connector'];
                $getDup = $projectdb->query("SELECT id FROM userid_group WHERE name='$name' AND connector='$connector_id';");
                if ($getDup->num_rows == 0) {
                    $projectdb->query("INSERT INTO userid_group (id, connector, name, enabled) VALUES (NULL, '$connector_id', '$name', '1')");
                    $lid_group = $projectdb->insert_id;
                    foreach ($data_split2 as $key => $value) {
                        $data2_split = explode(";", $value);
                        if (!strstr($data2_split[1], ':')) {
                            $id = $data2_split[0];
                            $user_from = addslashes($data2_split[1]);
                            $projectdb->query("INSERT INTO userid_group_members (id, connector, lid, name) VALUES (NULL, '$connector_id', '$lid_group', '$user_from')");
                            //$projectdb->query("DELETE FROM userid_from_log WHERE name = '$user_from'");
                        }
                    }
                }
            }
            $projectdb->query("INSERT INTO userid_from_log (id, name, lid, name) VALUES (NULL, '$connector_id', '$lid_group', '$user_from')");
        }
    }
}

function calculateKnownApp($name_app, $id_app_selected, $dport_app_selected, $proto_app_selected, $newlid, $rule_lid) {

    global $projectdb;
    // 1. Buscar en default_app la dependency          
    $getDependency = $projectdb->query("SELECT container, dependency, default_port "
            . "FROM default_applications WHERE name = '$name_app'");

    $getDependencyData = $getDependency->fetch_assoc();

    $dependency = $getDependencyData['dependency'];
    $default_port = $getDependencyData['default_port'];
    $recommended = $getDependencyData['container'];
    $getRecommended = $projectdb->query("SELECT name, functions, dependency "
            . "FROM default_applications WHERE name = '$recommended'");
    $getRecommendedData = $getRecommended->fetch_assoc();

    # $recommended = $getRecommendedData['name'];
    //Si está vacío, es que se recomienda la aplicación seleccionada
    if ($recommended == "") {
        $recommended = $name_app;
        $recommended_requires_final = $dependency;
    }
    else {
        $getImplicit = $projectdb->query("SELECT implicit FROM default_applications WHERE container='$recommended';");
        if ($getImplicit->num_rows > 0) {
            $implicit = array();
            while ($getImplicitData = $getImplicit->fetch_assoc()) {
                $kk = explode(",", $getImplicitData['implicit']);
                foreach ($kk as $tmp) {
                    $implicit[] = $tmp;
                }
            }
            $implicitAll = array_unique($implicit);

            $recommended_deps = explode(",", $getRecommendedData['dependency']);
            $recommended_requires_final1 = array_diff($recommended_deps, $implicitAll);
            $recommended_requires_final = implode(",", $recommended_requires_final1);
        } else {
            $recommended_requires_final = $getRecommendedData['dependency'];
        }
    }
    //echo "LAS RECOMENDED REQUIRES SON----------------->: " .$recommended_requires_final. "\n";
    // Comprobación de puertos, si están en el default_port
    $app_default = 0;
    $have_dymanic = strpos($default_port, "$proto_app_selected/dynamic");

    if ($have_dymanic === false) {

        $break = explode(",", $default_port);

        foreach ($break as $key => $value) {

            if ($app_default == 0) {

                if (is_numeric($value)) {
                    //Solo un número
                    if ($value == $dport_app_selected) {
                        $app_default = 1;
                    }
                } elseif (preg_match("/\d-\d/", $value)) {
                    //Interval -
                    $break1 = explode("-", $value);
                    $start = $break1[0];
                    $end = $break1[1];
                    //Si está dentro del ranto, app_default = 1
                    if (($dport_app_selected <= $end) && ($dport_app_selected >= $start)) {
                        $app_default = 1;
                    }
                } else {
                    $break1 = explode("/", $value);
                    $proto_default = $break1[0];
                    $port_proto = $break1[1];
                    if (($proto_default == $proto_app_selected) && ($port_proto == $dport_app_selected)) {
                        $app_default = 1;
                    }
                }
            }
        }// fin foreach
    } else {
        //Tiene dymanic
        $app_default = 1;
    }

    //INSERT EN LA TABLA PHASE2
    $projectdb->query("INSERT INTO phase2_known_apps "
            . "(id, app_id, name, port , default_port, requires, recommended, recommended_requires, app_default, rule_id, rule_old_id) "
            . "VALUES (NULL, '$id_app_selected', '$name_app', '$proto_app_selected/$dport_app_selected', '$default_port', '$dependency', '$recommended', '$recommended_requires_final','$app_default','$newlid', '$rule_lid');");
}


function checkGetParentApp($rule_lid){

    global $projectdb;

    $getMembersApp = $projectdb->query("SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid = '$rule_lid' AND table_name = 'default_applications';");
    //echo "1. SELECT member_lid, table_name FROM security_rules_app WHERE rule_lid = '$rule_lid' AND table_name = 'default_applications';\n";

    if ($getMembersApp->num_rows > 0) {

        while($dataMA = $getMembersApp->fetch_assoc()) {
            $member_lid[] = $dataMA['member_lid'];
        }
        $getNameApp = $projectdb->query("SELECT id, name, functions FROM default_applications WHERE id IN (".implode(',', $member_lid).") AND functions != '';");
        //echo "2. SELECT id, name, functions FROM default_applications WHERE id IN (".implode(',', $member_lid).") AND functions != '';\n";

        if ($getNameApp->num_rows > 0) {
            while($dataNA = $getNameApp->fetch_assoc()){

                $name = $dataNA['name'];
                $functions = $dataNA['functions'];
                $fuctions_array = explode(',', $functions);

                // Check with apps
                $getNameAppChilds = $projectdb->query("SELECT id, name, functions FROM default_applications WHERE id IN (".implode(',', $member_lid).") AND functions = '';");
                //echo "3. SELECT id, name, functions FROM default_applications WHERE id IN (".implode(',', $member_lid).") AND functions = '';\n";

                if ($getNameAppChilds->num_rows > 0) {
                    while ($dataNAC = $getNameAppChilds->fetch_assoc()) {

                        $id_child = $dataNAC['id'];
                        $name_child = $dataNAC['name'];

                        if (in_array($name_child, $fuctions_array)) {

                            $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid = '$rule_lid' AND member_lid = '$id_child' AND table_name = 'default_applications';");
                            //echo "4.DELETE FROM security_rules_app WHERE rule_lid = '$rule_lid' AND member_lid = '$id_child' AND table_name = 'default_applications';\n";
                        }
                    }
                }
            }
        }
    }
}


function getIconRisk($risk){

    if ($risk == "1") {
        $icon_risk = "icon-risk1";
    } elseif ($risk == "2") {
        $icon_risk = "icon-risk2";
    } elseif ($risk == "3") {
        $icon_risk = "icon-risk3";
    } elseif ($risk == "4") {
        $icon_risk = "icon-risk4";
    } elseif ($risk == "5") {
        $icon_risk = "icon-risk5";
    }

    return $icon_risk;

}


?>